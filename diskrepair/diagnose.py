"""Read-only diagnosis: turns raw structure checks into findings and recommended repairs."""

from dataclasses import asdict, dataclass, field

from . import layout, scan
from .task import Task, human_size

SEVERITY_ORDER = {"critical": 0, "error": 1, "warn": 2, "info": 3, "ok": 4}

FIX_TITLES = {
    "clear_readonly": "Clear write protection / bring disk online",
    "chkdsk": "Repair the filesystem with CHKDSK",
    "restore_boot": "Restore the boot sector from its backup copy",
    "rebuild_table": "Rebuild the partition table from the filesystems found",
    "extract_files": "Copy files out with the built-in filesystem reader",
    "rescue_image": "Save a sector-by-sector rescue image",
    "carve": "Recover files by signature (photos, videos, documents)",
    "surface_scan": "Full surface scan for unreadable areas",
    "capacity_test": "Test real capacity and whether writes are stored",
    "deep_search": "Deep search for lost partitions",
    "format": "Erase, re-partition and format (destroys data)",
}


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str = ""
    fixes: list = field(default_factory=list)


@dataclass
class Report:
    device: str = ""
    size: int = 0
    sector_size: int = 512
    scheme: str = "unknown"           # MBR / GPT / superfloppy / none
    sector0: str = ""
    partitions: list = field(default_factory=list)    # [layout.Partition]
    filesystems: list = field(default_factory=list)   # [layout.FsInfo] reachable via the table
    found: list = field(default_factory=list)         # [layout.FsInfo] found by searching
    findings: list = field(default_factory=list)
    surface: object = None
    verdict: str = ""
    recommended: list = field(default_factory=list)

    def add(self, severity, code, title, detail="", fixes=()):
        self.findings.append(Finding(severity, code, title, detail, list(fixes)))

    def has(self, code):
        return any(f.code == code for f in self.findings)

    def to_dict(self):
        data = asdict(self)
        data["surface"] = asdict(self.surface) if self.surface else None
        return data

    def to_text(self):
        lines = [f"Device: {self.device}",
                 f"Size: {human_size(self.size)} ({self.size // self.sector_size} sectors of "
                 f"{self.sector_size} bytes)",
                 f"Layout: {self.scheme} - {self.sector0}", ""]
        if self.partitions:
            lines.append("Partition table:")
            for p in self.partitions:
                lines.append(f"  #{p.index} {p.type_name}: start sector {p.start_lba}, "
                             f"{human_size(p.sectors * self.sector_size)}"
                             + (f"  [{'; '.join(p.problems)}]" if p.problems else ""))
            lines.append("")
        for title, items in (("Filesystems", self.filesystems),
                             ("Filesystems found by searching", self.found)):
            if items:
                lines.append(title + ":")
                for f in items:
                    state = "OK" if f.healthy else "; ".join(f.problems)
                    lines.append(f"  {f.fs} at sector {f.start_lba}, "
                                 f"{human_size(f.total_sectors * self.sector_size)}"
                                 + (f", label '{f.label}'" if f.label else "") + f" - {state}")
                lines.append("")
        if self.surface:
            lines += [self.surface.summary(), ""]
        lines.append("Findings:")
        for f in sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9)):
            lines.append(f"  [{f.severity.upper()}] {f.title}")
            if f.detail:
                lines.append(f"      {f.detail}")
        lines += ["", "Verdict: " + self.verdict]
        if self.recommended:
            lines.append("Recommended steps, in order:")
            for i, fix in enumerate(self.recommended, 1):
                lines.append(f"  {i}. {FIX_TITLES.get(fix, fix)}")
        return "\n".join(lines)


def diagnose(dev, os_info=None, task=None, search=True):
    """Analyse a block device without writing to it."""
    task = task or Task()
    os_info = os_info or {}
    ss = dev.sector_size
    rep = Report(device=dev.name, size=dev.size, sector_size=ss)

    # ---- what Windows itself reports
    if os_info.get("is_read_only"):
        rep.add("warn", "readonly", "Windows marks this disk read-only",
                "A software read-only flag is set. If clearing it does not stick, the card's lock "
                "switch is on or the flash controller has locked itself permanently.",
                ["clear_readonly"])
    if os_info.get("is_offline"):
        rep.add("warn", "offline", "The disk is offline in Windows", "", ["clear_readonly"])
    health = os_info.get("health") or ""
    if health and health not in ("Healthy", "0"):
        rep.add("error", "os_health", f"Windows reports the disk health as '{health}'")

    if dev.size == 0:
        rep.add("critical", "no_media", "The reader reports no media / zero capacity",
                "The card reader is detected but the card inside does not answer. Re-seat the "
                "card, clean its contacts, and try another reader. If it stays at zero the "
                "card's controller has failed - software cannot repair that.")
        rep.verdict = "No usable media detected. This is a hardware-level failure."
        return rep
    if dev.size < 64 * 1024 * 1024:
        rep.add("error", "tiny", f"Device reports only {human_size(dev.size)}",
                "Flash controllers that lose their firmware tables fall back to a tiny capacity. "
                "This usually means the controller has failed.", ["capacity_test"])

    # ---- sector 0
    task.progress(0.02, "Reading the first sectors")
    head = None
    try:
        head = dev.read_sectors(0, min(8, dev.sectors))
    except OSError as exc:
        rep.sector0 = "unreadable"
        rep.add("critical", "sector0_unreadable", "The first sector cannot be read",
                f"{exc}. The partition table lives here. The media is failing or the controller "
                "is not responding.", ["rescue_image", "surface_scan", "format"])

    superfloppy = None
    if head is not None:
        sector0 = head[:ss]
        superfloppy = layout.parse_boot(head, 0)
        mbr = layout.parse_mbr(sector0, dev.sectors)
        if superfloppy is not None:
            rep.scheme, rep.sector0 = "superfloppy", f"{superfloppy.fs} boot sector (no partition table)"
            rep.partitions = [layout.Partition(1, "superfloppy", 0, dev.sectors, superfloppy.fs)]
        elif mbr.signature_ok and mbr.protective:
            rep.scheme, rep.sector0 = "GPT", "protective MBR"
            gpt = layout.parse_gpt(dev)
            rep.partitions = gpt.entries
            if not gpt.primary_ok and not gpt.backup_ok:
                rep.add("error", "gpt_destroyed", "GPT partition table is destroyed",
                        "Both the primary and the backup GPT headers fail validation.",
                        ["rebuild_table", "deep_search"])
            elif not gpt.primary_ok or not gpt.backup_ok:
                which = "primary" if not gpt.primary_ok else "backup"
                rep.add("warn", "gpt_damaged", f"The {which} GPT header is damaged",
                        "The other copy is intact. Windows repairs this on its own once the disk "
                        "is writable.")
        elif mbr.signature_ok and any(not p.problems for p in mbr.entries):
            rep.scheme, rep.sector0 = "MBR", "master boot record"
            rep.partitions = mbr.entries
            for p in mbr.entries:
                if p.problems:
                    rep.add("error", "bad_partition_entry",
                            f"Partition {p.index} entry is invalid: {'; '.join(p.problems)}",
                            "", ["rebuild_table", "deep_search"])
        elif layout.is_blank(sector0):
            rep.scheme = "none"
            rep.sector0 = "blank (all zeros)" if not sector0.strip(b"\x00") else "blank (all 0xFF)"
            rep.add("error", "no_table", "The first sector is blank - there is no partition table",
                    "This is why Windows shows the device as unallocated / RAW or asks to format it.")
        elif mbr.signature_ok and mbr.entries:
            rep.scheme, rep.sector0 = "MBR", "master boot record with invalid entries"
            rep.partitions = mbr.entries
            for p in mbr.entries:
                oversize = any("past the end" in x for x in p.problems)
                rep.add("error", "bad_partition_entry",
                        f"Partition {p.index} entry is invalid: {'; '.join(p.problems)}",
                        f"The entry describes {human_size(p.sectors * ss)} starting at sector "
                        f"{p.start_lba}, but the device reports {human_size(dev.size)}. "
                        + ("The device is now smaller than when it was partitioned - typical of "
                           "a failing flash controller or a counterfeit card." if oversize else ""),
                        ["capacity_test", "deep_search"] if oversize else ["deep_search"])
        elif mbr.signature_ok:
            rep.scheme, rep.sector0 = "none", "boot signature present but the partition table is empty"
            rep.add("error", "empty_table", "The partition table is empty",
                    "The boot signature is there but no partition is listed, so Windows shows an "
                    "empty, unformatted device.")
        else:
            rep.scheme, rep.sector0 = "none", "unrecognised data (corrupted)"
            rep.add("error", "corrupt_sector0", "The first sector holds unrecognised data",
                    "The partition table / boot sector has been overwritten or corrupted.")

    # ---- a bootable installer image written straight onto the device (Rufus DD mode, Etcher, dd)
    if head is not None:
        try:
            if dev.read_bytes(32768, 2048)[1:6] == b"CD001":
                rep.add("info", "iso_image", "The device holds a bootable ISO / installer image",
                        "It was written with a tool such as Rufus (DD mode), balenaEtcher or dd. "
                        "Windows cannot read that layout, shows a tiny or unreadable volume and "
                        "offers to format it. That is expected, not damage. To use the device "
                        "for normal storage again, erase and format it.", ["format"])
        except OSError:
            pass

    # ---- filesystems reachable through the partition table
    task.progress(0.08, "Checking filesystems")
    def inspectable(p):
        if p.type_code in (0x05, 0x0F, 0xEE) or p.type_name == "Microsoft reserved":
            return False
        if any("past the end" not in x for x in p.problems):
            return False  # an oversized partition is still worth a look; other faults are not
        return p.scheme == "superfloppy" or 0 < p.start_lba < dev.sectors

    for p in filter(inspectable, rep.partitions):
        try:
            info = layout.inspect_fs(dev, p.start_lba, p.sectors)
        except OSError as exc:
            rep.add("error", "fs_unreadable", f"Partition {p.index}: filesystem area unreadable",
                    str(exc), ["rescue_image", "surface_scan"])
            continue
        if info is None:
            rep.add("error", "no_fs", f"Partition {p.index}: no recognisable filesystem",
                    "The boot sector and its backups are gone. Windows reports this as RAW.",
                    ["carve", "format"])
            continue
        rep.filesystems.append(info)
        _judge_fs(rep, p, info)

    # ---- nothing usable: go looking
    usable = [f for f in rep.filesystems if f.windows_readable]
    if search and head is not None and not usable:
        task.log("No usable filesystem via the partition table - searching standard locations.")
        rep.found = [f for f in scan.find_partitions(dev, task, deep=False)
                     if not any(f.start_lba == g.start_lba for g in rep.filesystems)]
        good = [f for f in rep.found if f.windows_readable and f.total_sectors]
        if good:
            desc = ", ".join(f"{f.fs} {human_size(f.total_sectors * ss)} at sector {f.start_lba}"
                             for f in good)
            fixes = ["rebuild_table"]
            if any(f.from_backup for f in good):
                fixes.append("restore_boot")
            rep.add("error", "lost_partition", "Found filesystem(s) missing from the partition table",
                    f"{desc}. The data is still there; the table that points to it is not.", fixes)
        else:
            rep.add("info", "nothing_found", "No filesystem found at the standard locations",
                    "A deep search checks every 1 MiB boundary and can still find one.",
                    ["deep_search"])

    # ---- surface sample
    task.progress(0.5, "Sampling the surface")
    try:
        rep.surface = scan.sample_surface(dev, task)
    except OSError:
        rep.surface = None
    s = rep.surface
    if s and s.blocks_tested:
        if s.bad_ranges:
            share = len(s.bad_ranges) / s.blocks_tested
            sev = "critical" if share > 0.25 else "error"
            rep.add(sev, "read_errors",
                    f"{len(s.bad_ranges)} of {s.blocks_tested} sampled areas are unreadable",
                    "The media has physical read errors. Save a rescue image before any other "
                    "work - every extra read can make a failing device worse.",
                    ["rescue_image", "surface_scan"])
        if s.slow_blocks:
            rep.add("warn", "slow", f"{s.slow_blocks} sampled areas took over 2 seconds to read",
                    "Slow reads are an early sign of failing flash or a weak connection.",
                    ["rescue_image", "surface_scan"])
        if not s.bad_ranges and s.blank_blocks == s.blocks_tested:
            rep.add("warn", "all_blank", "Every sampled area is empty",
                    "The device returns only blank data. Either it was fully erased, or the flash "
                    "controller has lost its mapping and no longer returns the stored data. "
                    "Files cannot be recovered by software; formatting may still make it usable.",
                    ["capacity_test", "format"])
        elif not s.bad_ranges:
            rep.add("ok", "surface_ok", "All sampled areas read correctly",
                    f"{s.blocks_tested - s.blank_blocks} of {s.blocks_tested} samples contain data.")

    _conclude(rep, os_info)
    task.progress(1.0, "Diagnosis complete", force=True)
    return rep


def _judge_fs(rep, part, info):
    who = f"Partition {part.index} ({info.fs})"
    if not info.windows_readable:
        rep.add("info", "foreign_fs", f"{who}: Windows cannot read this filesystem",
                "It belongs to Linux or macOS. That is not damage - but Windows will offer to "
                "format it. Formatting erases it.", ["format"])
        return
    if info.fs == "BitLocker":
        rep.add("info", "bitlocker", f"{who}: the volume is BitLocker-encrypted",
                "Unlock it with its password or recovery key in File Explorer.")
        return
    if info.from_backup:
        rep.add("error", "boot_damaged", f"{who}: primary boot sector is damaged, backup is intact",
                "Windows shows the volume as RAW. Copying the backup boot sector over the primary "
                "normally restores access to all files.", ["restore_boot"])
        return
    if info.problems:
        rep.add("error", "fs_damaged", f"{who}: " + "; ".join(info.problems),
                "", ["extract_files", "chkdsk", "format"])
    else:
        rep.add("ok", "fs_ok", f"{who}: boot structures are valid",
                f"{human_size(info.total_sectors * rep.sector_size)}"
                + (f", label '{info.label}'" if info.label else ""))
    if info.details.get("dirty"):
        rep.add("warn", "dirty", f"{who}: volume was not cleanly removed",
                "The dirty flag is set. A filesystem check clears it.", ["chkdsk"])
    if info.details.get("io_error_flag"):
        rep.add("warn", "io_flag", f"{who}: a previous I/O error is recorded in the filesystem",
                "", ["chkdsk", "surface_scan"])
    if info.backup_lba >= 0 and not info.from_backup and not info.problems and not info.backup_ok:
        rep.add("info", "backup_boot_bad", f"{who}: backup boot sector is missing or invalid",
                "Not a fault by itself; a filesystem check rewrites it.", ["chkdsk"])


def _conclude(rep, os_info):
    order = ["clear_readonly", "rescue_image", "restore_boot", "rebuild_table", "extract_files",
             "chkdsk", "deep_search", "carve", "surface_scan", "capacity_test", "format"]
    wanted = {fix for f in rep.findings for fix in f.fixes}
    volumes = os_info.get("volumes") or []
    mounted = [v for v in volumes if v.get("fs") and v.get("letters")]
    healthy_fs = [f for f in rep.filesystems if f.windows_readable and f.healthy and not f.from_backup]

    if healthy_fs and volumes and not mounted and not rep.has("read_errors"):
        rep.add("error", "not_mounted",
                "Boot structures look valid but Windows does not mount the volume",
                "The damage is deeper in the filesystem (allocation table or directories), or the "
                "volume has no drive letter.", ["extract_files", "chkdsk", "format"])
        wanted |= {"extract_files", "chkdsk", "format"}
    if healthy_fs and mounted:
        wanted.add("chkdsk")
    if not healthy_fs and not rep.has("all_blank") and not rep.has("no_media"):
        wanted |= {"carve", "format"}
    if "format" in wanted or rep.has("read_errors"):
        wanted.add("capacity_test")
    if "chkdsk" in wanted and not any(v.get("letters") for v in volumes):
        wanted.discard("chkdsk")
    rep.recommended = [fix for fix in order if fix in wanted]

    worst = min((SEVERITY_ORDER.get(f.severity, 9) for f in rep.findings), default=4)
    if rep.has("read_errors"):
        rep.verdict = ("The media has unreadable areas (failing hardware). Rescue the data first; "
                       "the device should not be trusted afterwards even if a format succeeds.")
    elif rep.has("iso_image"):
        rep.verdict = ("The device is not damaged - it holds a bootable installer image that "
                       "Windows cannot read. Erase and format it to use it for normal storage.")
    elif rep.has("boot_damaged"):
        rep.verdict = ("Boot sector corruption with an intact backup - a small, reversible repair "
                       "should bring the volume and its files back.")
    elif rep.has("lost_partition"):
        rep.verdict = ("The partition table is lost but the filesystem is still on the device - "
                       "rebuilding the table should bring the files back without formatting.")
    elif rep.has("all_blank"):
        rep.verdict = ("The device reads as completely empty. There is nothing to recover; test "
                       "that it stores writes, then format it.")
    elif rep.has("fs_damaged") or rep.has("not_mounted"):
        rep.verdict = ("The filesystem is damaged. Copy out what can be read, then repair with "
                       "CHKDSK or re-format.")
    elif not healthy_fs:
        rep.verdict = ("No working filesystem. Recover files by signature if you need them, test "
                       "the capacity, then erase and format to make the device usable.")
    elif worst >= SEVERITY_ORDER["info"]:
        rep.verdict = "No structural damage found. A filesystem check is a safe next step."
    else:
        rep.verdict = "Minor issues found - see the recommended steps."
