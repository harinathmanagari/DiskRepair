"""Repairs. Everything that writes saves the sectors it replaces first, so metadata fixes can be undone."""

import json
import os
import subprocess
import tempfile
import time

from . import fat32fmt, layout, safety, winapi
from .blockdev import DeviceIOError, PhysicalDevice, volumes_on_disk
from .devices import CREATE_NO_WINDOW, run_ps
from .task import Task, human_size

MIB = 1024 * 1024
GIB = 1024 * MIB

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(APP_DIR, "DiskRepair-data")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")


class RepairError(Exception):
    pass


def _explain_write_failure(exc):
    if getattr(exc, "winerror_code", None) == winapi.ERROR_WRITE_PROTECT:
        return RepairError(
            "The device is write-protected and rejected the write. Check the lock switch on the "
            "SD adapter, then try 'Clear write protection'. If it stays protected, the flash "
            "controller has locked itself read-only (its end-of-life safety mode) - copy your "
            "data off and replace the device; no software can unlock it.")
    return RepairError(f"The device failed while being written: {exc}")


# ------------------------------------------------------------------ sector backups / undo

def save_backup(dev, lba, count, note, backup_dir=BACKUP_DIR, fingerprint=""):
    """Save sectors that are about to be overwritten. Returns the manifest path."""
    os.makedirs(backup_dir, exist_ok=True)
    try:
        data = dev.read_sectors(lba, count)
    except OSError:
        data = None  # unreadable: nothing to preserve
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = os.path.join(backup_dir, f"{stamp}_lba{lba}_{count}")
    n = 0
    while os.path.exists(base + ".json"):
        n += 1
        base = os.path.join(backup_dir, f"{stamp}_lba{lba}_{count}_{n}")
    if data is not None:
        with open(base + ".bin", "wb") as f:
            f.write(data)
    manifest = {"device": dev.name, "fingerprint": fingerprint, "lba": lba, "sectors": count,
                "sector_size": dev.sector_size, "note": note, "time": stamp,
                "data_file": os.path.basename(base + ".bin") if data is not None else None}
    with open(base + ".json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return base + ".json"


def list_backups(fingerprint=None, backup_dir=BACKUP_DIR):
    items = []
    if not os.path.isdir(backup_dir):
        return items
    for name in sorted(os.listdir(backup_dir), reverse=True):
        if name.endswith(".json"):
            try:
                with open(os.path.join(backup_dir, name), encoding="utf-8") as f:
                    manifest = json.load(f)
            except (OSError, ValueError):
                continue
            manifest["path"] = os.path.join(backup_dir, name)
            if fingerprint is None or manifest.get("fingerprint") == fingerprint:
                items.append(manifest)
    return items


def undo_backup(dev, manifest, task=None):
    """Write a saved sector backup back to where it came from."""
    task = task or Task()
    if not manifest.get("data_file"):
        raise RepairError("This backup holds no data (the original sectors were unreadable).")
    path = os.path.join(os.path.dirname(manifest["path"]), manifest["data_file"])
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != manifest["sectors"] * dev.sector_size:
        raise RepairError("Backup file size does not match its manifest.")
    try:
        dev.write_sectors(manifest["lba"], data)
        dev.flush()
    except DeviceIOError as exc:
        raise _explain_write_failure(exc) from exc
    task.log(f"Restored {manifest['sectors']} sector(s) at sector {manifest['lba']} "
             f"from backup {manifest['time']}.")


def _write_checked(dev, lba, data, what):
    """Write, flush, read back and compare - catches devices that silently drop writes."""
    try:
        dev.write_sectors(lba, data)
        dev.flush()
    except DeviceIOError as exc:
        raise _explain_write_failure(exc) from exc
    try:
        back = dev.read_sectors(lba, len(data) // dev.sector_size)
    except OSError as exc:
        raise RepairError(f"Wrote the {what} but could not read it back: {exc}") from exc
    if back != data:
        raise RepairError(
            f"The device accepted the {what} but returned different data when read back. "
            "It is not storing writes: the flash controller has failed or locked itself "
            "read-only. This cannot be repaired by software.")


# ------------------------------------------------------------------ boot sector / partition table

def restore_boot_sector(dev, start_lba, part_sectors=0, task=None, fingerprint="",
                        backup_dir=BACKUP_DIR):
    """Copy an intact backup boot sector over a damaged primary one."""
    task = task or Task()
    info = layout.inspect_fs(dev, start_lba, part_sectors)
    if info is None:
        raise RepairError("No intact backup boot sector was found for this volume.")
    if not info.from_backup:
        if info.healthy:
            raise RepairError("The primary boot sector is valid - nothing to restore.")
        raise RepairError("The primary boot sector is readable but inconsistent; its backup "
                          "cannot be assumed better. Use the file extractor or CHKDSK instead.")
    count = {"FAT32": 3, "exFAT": 12, "NTFS": 1}[info.fs]
    data = dev.read_sectors(info.backup_lba, count)
    if layout.detect_fs(data) != info.fs:
        raise RepairError("The backup boot sector changed while being read; aborting.")
    manifest = save_backup(dev, start_lba, count, f"primary {info.fs} boot sector before restore",
                           backup_dir, fingerprint)
    task.log(f"Saved the damaged sectors to {manifest}")
    _write_checked(dev, start_lba, data, "boot sector")
    task.log(f"Restored the {info.fs} boot sector at sector {start_lba} from its backup at "
             f"sector {info.backup_lba}.")
    check = layout.inspect_fs(dev, start_lba, part_sectors)
    if check is None or check.from_backup:
        raise RepairError("Boot sector was written but still does not validate.")
    return check


def rebuild_partition_table(dev, found, task=None, fingerprint="", backup_dir=BACKUP_DIR):
    """Write a new partition table that points at the filesystems found on the device."""
    task = task or Task()
    parts = [f for f in found if f.windows_readable and f.total_sectors]
    if not parts:
        raise RepairError("No recoverable filesystem to build a partition table from.")
    if any(f.start_lba == 0 for f in parts):
        raise RepairError("A filesystem starts at sector 0 (no partition table is needed). "
                          "If Windows still cannot open it, use 'Restore boot sector'.")
    parts.sort(key=lambda f: f.start_lba)
    for a, b in zip(parts, parts[1:]):
        if a.start_lba + a.total_sectors > b.start_lba:
            raise RepairError("The filesystems found overlap; cannot build a consistent table.")
    if parts[-1].start_lba + parts[-1].total_sectors > dev.sectors + 1:
        raise RepairError("A filesystem found is larger than the device (fake capacity or a "
                          "truncated device). Run the capacity test.")
    ss = dev.sector_size

    def span(f):  # NTFS keeps its backup boot sector in the partition's final sector
        return min(f.total_sectors, dev.sectors - f.start_lba)

    use_gpt = len(parts) > 4 or any(f.start_lba + span(f) >= 2 ** 32 for f in parts)
    if use_gpt:
        blocks = layout.build_gpt(dev.sectors, ss, [(f.start_lba, span(f), f.label) for f in parts])
    else:
        blocks = {0: layout.build_mbr([(f.start_lba, span(f), layout.mbr_type_for(f.fs))
                                       for f in parts])}
    for lba, data in blocks.items():
        manifest = save_backup(dev, lba, len(data) // ss, "partition table area before rebuild",
                               backup_dir, fingerprint)
        task.log(f"Saved sectors at {lba} to {manifest}")
    for lba, data in blocks.items():
        _write_checked(dev, lba, data, "partition table")
    task.log(f"Wrote a new {'GPT' if use_gpt else 'MBR'} partition table with {len(parts)} "
             "partition(s): " + ", ".join(f"{f.fs} at sector {f.start_lba}" for f in parts))
    return "GPT" if use_gpt else "MBR"


# ------------------------------------------------------------------ erase + format

def choose_fs(size, fs="auto"):
    if fs and fs.lower() != "auto":
        return {"fat32": "FAT32", "exfat": "exFAT", "ntfs": "NTFS"}[fs.lower()]
    return "FAT32" if size <= 32 * GIB else "exFAT"


def prepare_disk(dev, fs="auto", label="", full_wipe=False, task=None, removable=True,
                 force_own_fat32=False, limit_bytes=None):
    """Wipe old structures, write a fresh partition table and (for large FAT32) the filesystem.

    limit_bytes confines the partition to the first N bytes - used for fake-capacity devices so
    that only the part that really stores data is ever used.

    Returns {'fs', 'scheme', 'start_lba', 'sectors', 'formatted'}; when 'formatted' is False the
    caller still has to let Windows format the new partition.
    """
    task = task or Task()
    ss = dev.sector_size
    usable = min(dev.size, limit_bytes) if limit_bytes else dev.size
    usable -= usable % MIB
    fs = choose_fs(usable, fs)
    if usable < 8 * MIB:
        raise RepairError("The device is too small to partition.")

    zero = bytes(MIB)
    try:
        if full_wipe:
            pos, started = 0, time.monotonic()
            while pos < usable:
                n = min(MIB, usable - pos)
                dev.write(pos, zero[:n])
                pos += n
                rate = pos / max(time.monotonic() - started, 0.001)
                task.progress(pos / usable * 0.9,
                              f"Zero-filling {human_size(pos)} / {human_size(usable)} "
                              f"({human_size(rate)}/s)")
        else:
            # old partition tables, boot sectors and the backup GPT live at the two ends
            edge = min(16 * MIB, usable // 4)
            edge -= edge % ss
            tail_start = (dev.size - edge) // ss * ss
            done = 0
            # with a capacity limit the far end does not really exist, so leave it alone
            for begin, stop in ((0, edge),) + (() if limit_bytes else ((tail_start, dev.size),)):
                pos = begin
                while pos < stop:
                    n = min(MIB, stop - pos)
                    dev.write(pos, zero[:n])
                    pos += n
                    done += n
                    task.progress(0.3 * done / (2 * edge), "Clearing old partition data")
        dev.flush()
    except DeviceIOError as exc:
        raise _explain_write_failure(exc) from exc

    # flash prefers partitions aligned to its erase blocks; disks to 1 MiB
    if removable:
        align = (4 if usable <= 32 * GIB else 16) * MIB
    else:
        align = MIB
    if usable < 256 * MIB:
        align = MIB
    start = align // ss
    use_gpt = dev.sectors >= 2 ** 32 and not limit_bytes
    if usable // ss >= 2 ** 32:
        use_gpt = True
        if limit_bytes:
            raise RepairError("A capacity limit above 2 TiB is not supported.")
    end = usable // ss - (34 if use_gpt else 0)
    count = (end - start) // (MIB // ss) * (MIB // ss)
    if count <= 0:
        raise RepairError("No room for a partition on this device.")

    if use_gpt:
        if fs == "FAT32":
            raise RepairError("FAT32 cannot be used above 2 TiB; choose exFAT or NTFS.")
        blocks = layout.build_gpt(dev.sectors, ss, [(start, count, label)])
        scheme = "GPT"
    else:
        blocks = {0: layout.build_mbr([(start, count, layout.mbr_type_for(fs))])}
        scheme = "MBR"
    task.progress(0.92 if full_wipe else 0.35, f"Writing {scheme} partition table")
    for lba, data in blocks.items():
        _write_checked(dev, lba, data, "partition table")

    formatted = False
    if fs == "FAT32" and (force_own_fat32 or count * ss > 32 * GIB):
        try:
            fat32fmt.format_fat32(dev, start, count, label, task)
        except DeviceIOError as exc:
            raise _explain_write_failure(exc) from exc
        check = layout.inspect_fs(dev, start, count)
        if check is None or not check.healthy:
            raise RepairError("The new FAT32 filesystem did not validate after writing: "
                              + ("; ".join(check.problems) if check else "boot sector unreadable"))
        formatted = True
    return {"fs": fs, "scheme": scheme, "start_lba": start, "sectors": count, "formatted": formatted}


def _guard_ps(number, size):
    """PowerShell-side repeat of the safety check, placed in front of every storage cmdlet."""
    return (f"$ErrorActionPreference='Stop'\n"
            f"$d = Get-Disk -Number {int(number)}\n"
            "if (@('USB','SD','MMC','1394') -notcontains \"$($d.BusType)\") "
            "{ throw 'SAFETY: disk is not on an external bus' }\n"
            "if ($d.IsBoot -or $d.IsSystem) { throw 'SAFETY: disk is a boot/system disk' }\n"
            f"if ($d.Size -ne {int(size)}) {{ throw 'SAFETY: disk size changed' }}\n")


def _windows_format(ident, fs, label, do_format, task):
    """Let Windows detect the new partition, format it if needed, and give it a drive letter."""
    safe_label = "".join(c for c in (label or "") if c.isalnum() or c in " _-")[:11].strip()
    label_arg = f"-NewFileSystemLabel '{safe_label}'" if safe_label else ""
    script = _guard_ps(ident.number, ident.size) + f"""
Update-HostStorageCache
$p = $null
for ($i = 0; $i -lt 30 -and -not $p; $i++) {{
    $p = Get-Partition -DiskNumber {ident.number} -ErrorAction SilentlyContinue |
         Where-Object {{ $_.Size -gt 1MB -and "$($_.Type)" -ne 'Reserved' }} | Select-Object -First 1
    if (-not $p) {{ Start-Sleep -Milliseconds 500; Update-HostStorageCache }}
}}
if (-not $p) {{ throw 'Windows did not detect the new partition' }}
if ({'$true' if do_format else '$false'}) {{
    Format-Volume -Partition $p -FileSystem {fs} {label_arg} -Force -Confirm:$false | Out-Null
}}
$p = Get-Partition -DiskNumber {ident.number} -PartitionNumber $p.PartitionNumber
if (-not $p.DriveLetter -or [int][char]$p.DriveLetter -eq 0) {{
    try {{ $p | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction Stop }} catch {{ }}
    Start-Sleep -Milliseconds 800
    $p = Get-Partition -DiskNumber {ident.number} -PartitionNumber $p.PartitionNumber
}}
"LETTER=$("$($p.DriveLetter)".Trim([char]0))"
"""
    task.progress(0.96, "Formatting with Windows" if do_format else "Waiting for Windows to mount")
    rc, out, err = run_ps(script, timeout=600)
    letter = ""
    for line in out.splitlines():
        if line.startswith("LETTER="):
            letter = line[7:].strip()
    if rc != 0 or (err and not letter and "LETTER=" not in out):
        raise RepairError("Windows could not finish: " + (err or out or f"exit code {rc}"))
    return letter + ":" if letter else ""


def wipe_and_format(number, fingerprint, fs="auto", label="", full_wipe=False, task=None,
                    limit_bytes=None):
    """Erase the device, create one partition and format it. Destroys all data on the device."""
    task = task or Task()
    with PhysicalDevice(number, write=True, expected_fingerprint=fingerprint, log=task.log) as dev:
        ident = dev.identity
        task.log(f"Erasing {ident.model} ({human_size(ident.size)}), disk {number}."
                 + (f" Using only the first {human_size(limit_bytes)}." if limit_bytes else ""))
        result = prepare_disk(dev, fs, label, full_wipe, task, removable=ident.removable,
                              limit_bytes=limit_bytes)
    task.log(f"Created a {result['scheme']} partition table; partition starts at sector "
             f"{result['start_lba']}, {human_size(result['sectors'] * ident.sector_size)}.")
    time.sleep(1.5)  # let Windows notice the new table
    safety.verify_number(number, fingerprint, for_write=True)
    try:
        letter = _windows_format(ident, result["fs"], label, not result["formatted"], task)
    except RepairError as exc:
        if result["fs"] != "FAT32" or result["formatted"]:
            raise
        task.log(f"Windows format failed ({exc}); using the built-in FAT32 formatter instead.")
        with PhysicalDevice(number, write=True, expected_fingerprint=fingerprint,
                            log=task.log) as dev:
            fat32fmt.format_fat32(dev, result["start_lba"], result["sectors"], label, task)
        time.sleep(1.5)
        letter = _windows_format(ident, "FAT32", label, False, task)
    result["letter"] = letter
    if letter:
        task.log(f"Formatted as {result['fs']} and mounted at {letter}")
        result["verified"] = verify_volume(letter, task)
    else:
        task.log(f"Formatted as {result['fs']}; Windows has not assigned a drive letter yet - "
                 "unplug and re-insert the device.")
        result["verified"] = False
    task.progress(1.0, "Format complete", force=True)
    return result


def verify_volume(letter, task=None):
    """Write a file to the volume, read it back uncached and compare."""
    task = task or Task()
    path = os.path.join(letter + "\\", "diskrepair_write_test.tmp")
    payload = os.urandom(MIB)
    try:
        with open(path, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        handle = winapi.open_path(path, winapi.GENERIC_READ, 0x20000000)  # FILE_FLAG_NO_BUFFERING
        try:
            back = winapi.read_at(handle, 0, MIB)
        finally:
            winapi.close(handle)
        ok = back == payload
    except OSError as exc:
        task.log(f"Write test on {letter} failed: {exc}")
        return False
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    task.log(f"Write test on {letter}: " + ("passed - data written and read back correctly."
                                             if ok else "FAILED - data read back differs."))
    return ok


# ------------------------------------------------------------------ Windows-level fixes

def clear_readonly(number, fingerprint, task=None):
    """Clear the read-only and offline flags Windows holds for the disk and its volumes."""
    task = task or Task()
    ident = safety.verify_number(number, fingerprint, for_write=True)
    script = _guard_ps(number, ident.size) + f"""
$ErrorActionPreference='Continue'
Set-Disk -Number {number} -IsOffline $false -ErrorAction SilentlyContinue
Set-Disk -Number {number} -IsReadOnly $false -ErrorAction SilentlyContinue
$policy = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies' -ErrorAction SilentlyContinue).WriteProtect
$d = Get-Disk -Number {number}
"READONLY=$($d.IsReadOnly);OFFLINE=$($d.IsOffline);POLICY=$policy"
"""
    rc, out, err = run_ps(script)
    if rc != 0 and "SAFETY" in err:
        raise safety.SafetyError(err)
    letters = [l for v in volumes_on_disk(number) for l in v["letters"]]
    lines = [f"select disk {number}", "attributes disk clear readonly"]
    for letter in letters:
        lines += [f"select volume {letter[0]}", "attributes volume clear readonly"]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(lines) + "\n")
        script_path = f.name
    try:
        safety.verify_number(number, fingerprint, for_write=True)
        proc = subprocess.run(["diskpart", "/s", script_path], capture_output=True, timeout=120,
                              creationflags=CREATE_NO_WINDOW)
        for line in proc.stdout.decode("oem", "replace").splitlines():
            if line.strip() and "Microsoft" not in line and "Copyright" not in line \
                    and "On computer" not in line:
                task.log("diskpart: " + line.strip())
    except (OSError, subprocess.SubprocessError) as exc:
        task.log(f"diskpart could not run: {exc}")
    finally:
        os.remove(script_path)
    rc, out2, _ = run_ps(_guard_ps(number, ident.size)
                         + f"$d = Get-Disk -Number {number}\n\"READONLY=$($d.IsReadOnly);OFFLINE=$($d.IsOffline)\"")
    status = out2 or out
    still = "READONLY=True" in status
    if "POLICY=1" in out:
        task.log("Note: this PC has a system-wide USB write-protect policy enabled "
                 "(StorageDevicePolicies\\WriteProtect = 1). DiskRepair does not change system "
                 "settings; an administrator must set that value to 0.")
    if still:
        task.log("The disk is still read-only. Check the physical lock switch (SD adapters have "
                 "one). If there is none, the flash controller has locked itself read-only for "
                 "good - copy the data off and replace the device.")
    else:
        task.log("Read-only and offline flags are clear.")
    return not still


def run_chkdsk(number, fingerprint, letter, task=None, fix=True, surface=False):
    """Run Windows CHKDSK on a volume that belongs to the selected external disk."""
    task = task or Task()
    letter = letter.rstrip("\\").upper()
    safety.verify_number(number, fingerprint, for_write=fix)
    owned = {l.upper() for v in volumes_on_disk(number) for l in v["letters"]}
    if letter not in owned:
        raise safety.SafetyError(f"Refused: {letter} is not a volume on disk {number}.")
    args = ["chkdsk", letter] + (["/f", "/x"] if fix else []) + (["/r"] if surface else [])
    task.log("Running: " + " ".join(args))
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, creationflags=CREATE_NO_WINDOW)
    try:
        proc.stdin.write(b"N\r\n")
        proc.stdin.close()
    except OSError:
        pass
    pending = b""
    last = ""
    while True:
        chunk = proc.stdout.read(256)
        if not chunk:
            break
        pending += chunk
        *lines, pending = pending.replace(b"\r", b"\n").split(b"\n")
        for raw in lines:
            line = raw.decode("oem", "replace").strip()
            if not line or line == last:
                continue
            last = line
            if "percent" in line.lower() or line.endswith("%"):
                task.progress(0.5, "CHKDSK: " + line[:90])
            else:
                task.log(line)
    code = proc.wait()
    meaning = {0: "no errors found", 1: "errors were found and fixed",
               2: "cleanup performed or skipped (run again with fix)",
               3: "could not check or could not fix all errors"}.get(code, f"exit code {code}")
    task.log(f"CHKDSK finished: {meaning}.")
    return code
