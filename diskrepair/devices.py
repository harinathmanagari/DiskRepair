"""Device enumeration: raw identities from the safety layer, enriched with what Windows reports."""

import base64
import json
import os
import subprocess
from dataclasses import dataclass, field

from . import safety, winapi

CREATE_NO_WINDOW = 0x08000000

_ENUM_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$disks = @(Get-Disk | ForEach-Object { [pscustomobject]@{
    Number=$_.Number; FriendlyName="$($_.FriendlyName)"; BusType="$($_.BusType)"; Size=$_.Size
    PartitionStyle="$($_.PartitionStyle)"; OperationalStatus="$($_.OperationalStatus)"
    HealthStatus="$($_.HealthStatus)"; IsBoot=[bool]$_.IsBoot; IsSystem=[bool]$_.IsSystem
    IsReadOnly=[bool]$_.IsReadOnly; IsOffline=[bool]$_.IsOffline } })
$parts = @(Get-Partition | ForEach-Object { [pscustomobject]@{
    DiskNumber=$_.DiskNumber; PartitionNumber=$_.PartitionNumber
    DriveLetter="$($_.DriveLetter)".Trim([char]0); Offset=$_.Offset; Size=$_.Size; Type="$($_.Type)" } })
$vols = @(Get-Volume | ForEach-Object { [pscustomobject]@{
    Path="$($_.Path)"; FileSystem="$($_.FileSystem)"; Label="$($_.FileSystemLabel)"
    Size=$_.Size; SizeRemaining=$_.SizeRemaining; HealthStatus="$($_.HealthStatus)" } })
$pnp = @(Get-PnpDevice -PresentOnly | Where-Object {
    $_.Status -ne 'OK' -and (@('DiskDrive','USB','SDHost','WPD','Volume') -contains "$($_.Class)" -or $_.InstanceId -like 'USB*')
  } | ForEach-Object { [pscustomobject]@{
    Name="$($_.FriendlyName)"; Class="$($_.Class)"; Status="$($_.Status)"; Problem="$($_.Problem)"
    InstanceId="$($_.InstanceId)" } })
[pscustomobject]@{ disks=$disks; partitions=$parts; volumes=$vols; pnp=$pnp } | ConvertTo-Json -Depth 4 -Compress
"""


def run_ps(script, timeout=120):
    """Run a PowerShell script; returns (returncode, stdout, stderr)."""
    script = "$ProgressPreference = 'SilentlyContinue'\n" + script
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    # Windows PowerShell must not inherit a PowerShell 7 module path, or its Storage module breaks.
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text",
         "-EncodedCommand", encoded],
        capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW, env=env,
        stdin=subprocess.DEVNULL)
    err = proc.stderr.decode("utf-8", "replace").strip()
    if err.startswith("#< CLIXML") and 'S="Error"' not in err:
        err = ""  # only serialized progress records
    return proc.returncode, proc.stdout.decode("utf-8", "replace").strip(), err


@dataclass
class DiskInfo:
    identity: safety.DriveIdentity
    os: dict = field(default_factory=dict)          # what Windows reports about the disk
    partitions: list = field(default_factory=list)  # Windows' view of the partition table
    volumes: list = field(default_factory=list)     # mounted / mountable volumes on this disk

    @property
    def number(self):
        return self.identity.number

    @property
    def fingerprint(self):
        return self.identity.fingerprint

    @property
    def letters(self):
        return [l for v in self.volumes for l in v["letters"]]

    @property
    def title(self):
        from .task import human_size
        size = human_size(self.identity.size) if self.identity.size else "no media"
        letters = f" [{', '.join(self.letters)}]" if self.letters else ""
        return f"Disk {self.number}: {self.identity.model} - {size} ({self.identity.bus_name}){letters}"

    def os_summary(self):
        """Compact dict consumed by diagnose()."""
        return {"is_read_only": bool(self.os.get("IsReadOnly")),
                "is_offline": bool(self.os.get("IsOffline")),
                "health": self.os.get("HealthStatus", ""),
                "operational": self.os.get("OperationalStatus", ""),
                "partition_style": self.os.get("PartitionStyle", ""),
                "volumes": self.volumes}


@dataclass
class Inventory:
    external: list           # [DiskInfo] - the only disks this program will touch
    protected: list          # [(DriveIdentity, reason)] - shown for transparency, never opened
    pnp_problems: list       # USB / storage devices Windows reports as failed
    warning: str = ""


def enumerate_devices():
    drives = safety.scan_drives()
    os_data, warning = {}, ""
    for attempt in range(2):  # the storage service occasionally answers empty on first call
        try:
            rc, out, err = run_ps(_ENUM_SCRIPT, timeout=90)
            start = out.find("{")
            if start != -1:
                os_data = json.loads(out[start:])
                warning = ""
                break
            warning = f"Windows storage query returned nothing ({err[:200] or rc})"
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            warning = f"Windows storage query failed: {exc}"

    def as_list(value):
        return value if isinstance(value, list) else ([] if value is None else [value])

    os_disks = {d.get("Number"): d for d in as_list(os_data.get("disks"))}
    os_parts = as_list(os_data.get("partitions"))
    os_vols = {v.get("Path"): v for v in as_list(os_data.get("volumes"))}
    try:
        raw_vols = winapi.list_volumes()
    except OSError:
        raw_vols = []

    external, protected = [], []
    for ident, reason in drives:
        os_disk = os_disks.get(ident.number, {})
        # Second opinion from Windows: anything flagged boot/system is protected too.
        if reason is None and (os_disk.get("IsBoot") or os_disk.get("IsSystem")):
            reason = f"disk {ident.number} is flagged by Windows as a boot/system disk"
        if reason:
            protected.append((ident, reason))
            continue
        info = DiskInfo(ident, os_disk)
        info.partitions = [p for p in os_parts if p.get("DiskNumber") == ident.number]
        for vol in raw_vols:
            if {d for d, _s, _l in vol["extents"]} == {ident.number}:
                meta = os_vols.get(vol["guid_path"], {})
                info.volumes.append({"guid_path": vol["guid_path"], "letters": vol["letters"],
                                     "offset": vol["extents"][0][1],
                                     "fs": meta.get("FileSystem", "") or "",
                                     "label": meta.get("Label", "") or "",
                                     "size": meta.get("Size") or 0,
                                     "free": meta.get("SizeRemaining") or 0,
                                     "health": meta.get("HealthStatus", "") or ""})
        external.append(info)
    return Inventory(external, protected, as_list(os_data.get("pnp")), warning)


def find_disk(number):
    for info in enumerate_devices().external:
        if info.number == number:
            return info
    return None
