"""On-disk structures: MBR, GPT and FAT / exFAT / NTFS boot sectors (parse, validate, build)."""

import struct
import uuid
import zlib
from dataclasses import dataclass, field

MBR_TYPES = {0x01: "FAT12", 0x04: "FAT16", 0x06: "FAT16", 0x0E: "FAT16 (LBA)",
             0x0B: "FAT32", 0x0C: "FAT32 (LBA)", 0x07: "NTFS/exFAT", 0x05: "Extended",
             0x0F: "Extended (LBA)", 0x82: "Linux swap", 0x83: "Linux", 0xEE: "GPT protective",
             0xEF: "EFI system", 0xAF: "macOS HFS+", 0x27: "Windows recovery"}

GPT_BASIC_DATA = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")
GPT_TYPES = {GPT_BASIC_DATA: "Basic data",
             uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"): "EFI system",
             uuid.UUID("E3C9E316-0B5C-4DB8-817D-F92DF00215AE"): "Microsoft reserved",
             uuid.UUID("0FC63DAF-8483-4772-8E79-3D69D8477DE4"): "Linux filesystem",
             uuid.UUID("48465300-0000-11AA-AA11-00306543ECAC"): "macOS HFS+",
             uuid.UUID("7C3457EF-0000-11AA-AA11-00306543ECAC"): "macOS APFS"}


@dataclass
class Partition:
    index: int
    scheme: str            # 'MBR', 'GPT', 'superfloppy' or 'found'
    start_lba: int
    sectors: int
    type_name: str = ""
    type_code: int = 0
    bootable: bool = False
    name: str = ""
    problems: list = field(default_factory=list)


@dataclass
class FsInfo:
    fs: str                          # FAT12/FAT16/FAT32/exFAT/NTFS or a foreign fs name
    start_lba: int
    total_sectors: int = 0
    bytes_per_sector: int = 512
    cluster_size: int = 0
    label: str = ""
    windows_readable: bool = True
    problems: list = field(default_factory=list)   # things wrong with the primary structures
    backup_lba: int = -1             # where the backup boot sector should be
    backup_ok: bool = False
    backup_matches: bool = False
    from_backup: bool = False        # this info was parsed from the backup boot sector
    details: dict = field(default_factory=dict)

    @property
    def healthy(self):
        return not self.problems


# ------------------------------------------------------------------ sector classification

def is_blank(buf):
    return not buf.strip(b"\x00") or not buf.strip(b"\xff")


def detect_fs(buf):
    """Filesystem whose boot sector / superblock starts at buf[0]. buf should be >= 2048 bytes."""
    if len(buf) < 512:
        return None
    if buf[3:11] == b"NTFS    " and buf[510:512] == b"\x55\xaa":
        return "NTFS"
    if buf[3:11] == b"EXFAT   " and buf[510:512] == b"\x55\xaa":
        return "exFAT"
    if buf[3:11] == b"-FVE-FS-":
        return "BitLocker"
    if buf[510:512] == b"\x55\xaa" and buf[0] in (0xEB, 0xE9):
        bps = struct.unpack_from("<H", buf, 11)[0]
        spc = buf[13]
        nfats = buf[16]
        if bps in (512, 1024, 2048, 4096) and spc and spc & (spc - 1) == 0 and nfats in (1, 2):
            if buf[82:87] == b"FAT32":
                return "FAT32"
            if buf[54:57] == b"FAT":
                return _fat_kind(buf)
            if struct.unpack_from("<H", buf, 14)[0] and buf[21] >= 0xF0:
                return _fat_kind(buf)
    if buf[:6] == b"LUKS\xba\xbe":
        return "LUKS encrypted"
    if len(buf) >= 1024 + 58 and buf[1024 + 56:1024 + 58] == b"\x53\xef":
        return "Linux ext2/3/4"
    if len(buf) >= 1026 and buf[1024:1026] in (b"H+", b"HX"):
        return "macOS HFS+"
    if buf[32:36] == b"NXSB":
        return "macOS APFS"
    return None


def _fat_geometry(buf):
    bps = struct.unpack_from("<H", buf, 11)[0]
    spc = buf[13]
    reserved = struct.unpack_from("<H", buf, 14)[0]
    nfats = buf[16]
    root_entries = struct.unpack_from("<H", buf, 17)[0]
    total = struct.unpack_from("<H", buf, 19)[0] or struct.unpack_from("<I", buf, 32)[0]
    fat_size = struct.unpack_from("<H", buf, 22)[0] or struct.unpack_from("<I", buf, 36)[0]
    root_sectors = (root_entries * 32 + bps - 1) // bps
    data_start = reserved + nfats * fat_size + root_sectors
    clusters = max(0, total - data_start) // spc if spc else 0
    return {"bps": bps, "spc": spc, "reserved": reserved, "nfats": nfats,
            "root_entries": root_entries, "total": total, "fat_size": fat_size,
            "root_sectors": root_sectors, "data_start": data_start, "clusters": clusters}


def _fat_kind(buf):
    clusters = _fat_geometry(buf)["clusters"]
    if clusters < 4085:
        return "FAT12"
    if clusters < 65525:
        return "FAT16"
    return "FAT32"


# ------------------------------------------------------------------ MBR

@dataclass
class Mbr:
    signature_ok: bool
    entries: list
    protective: bool
    disk_signature: int


def parse_mbr(sector, total_sectors=None):
    sig_ok = sector[510:512] == b"\x55\xaa"
    entries = []
    for i in range(4):
        raw = sector[446 + 16 * i:462 + 16 * i]
        status, ptype = raw[0], raw[4]
        start, count = struct.unpack_from("<II", raw, 8)
        if ptype == 0 and start == 0 and count == 0:
            continue
        part = Partition(i + 1, "MBR", start, count, MBR_TYPES.get(ptype, f"type 0x{ptype:02X}"),
                         ptype, status == 0x80)
        if status not in (0x00, 0x80):
            part.problems.append("invalid boot flag")
        if ptype == 0 or count == 0 or start == 0:
            part.problems.append("empty or zero-length entry")
        if total_sectors and ptype != 0xEE and start + count > total_sectors:
            part.problems.append("extends past the end of the device")
        entries.append(part)
    for a in entries:
        for b in entries:
            if a.index < b.index and a.start_lba < b.start_lba + b.sectors \
                    and b.start_lba < a.start_lba + a.sectors:
                a.problems.append(f"overlaps partition {b.index}")
    protective = any(e.type_code == 0xEE for e in entries)
    return Mbr(sig_ok, entries, protective, struct.unpack_from("<I", sector, 440)[0])


def build_mbr(partitions, disk_signature=None):
    """partitions: [(start_lba, sectors, type_code)] -> 512-byte MBR."""
    if len(partitions) > 4:
        raise ValueError("an MBR holds at most 4 primary partitions")
    mbr = bytearray(512)
    if disk_signature is None:
        disk_signature = uuid.uuid4().int & 0xFFFFFFFF
    struct.pack_into("<I", mbr, 440, disk_signature or 1)
    for i, (start, count, ptype) in enumerate(partitions):
        if start >= 2 ** 32 or count >= 2 ** 32:
            raise ValueError("partition does not fit an MBR (needs GPT)")
        chs = b"\xfe\xff\xff"
        struct.pack_into("<B3sB3sII", mbr, 446 + 16 * i, 0, chs, ptype, chs, start, count)
    mbr[510:512] = b"\x55\xaa"
    return bytes(mbr)


def mbr_type_for(fs):
    return {"FAT12": 0x01, "FAT16": 0x0E, "FAT32": 0x0C}.get(fs, 0x07)


# ------------------------------------------------------------------ GPT

@dataclass
class Gpt:
    primary_ok: bool
    backup_ok: bool
    entries: list
    problems: list


def _parse_gpt_header(dev, lba):
    ss = dev.sector_size
    hdr = dev.read_sectors(lba, 1)
    if hdr[:8] != b"EFI PART":
        return None
    hsize = struct.unpack_from("<I", hdr, 12)[0]
    if not 92 <= hsize <= ss:
        return None
    crc = struct.unpack_from("<I", hdr, 16)[0]
    check = bytearray(hdr[:hsize])
    check[16:20] = b"\x00" * 4
    if zlib.crc32(bytes(check)) & 0xFFFFFFFF != crc:
        return None
    entries_lba, count, esize, entries_crc = struct.unpack_from("<QIII", hdr, 72)
    if esize < 128 or count > 1024 or entries_lba >= dev.sectors:
        return None
    raw = dev.read_bytes(entries_lba * ss, count * esize)
    if zlib.crc32(raw) & 0xFFFFFFFF != entries_crc:
        return None
    parts = []
    for i in range(count):
        e = raw[i * esize:(i + 1) * esize]
        if e[:16] == b"\x00" * 16:
            continue
        type_guid = uuid.UUID(bytes_le=e[:16])
        first, last = struct.unpack_from("<QQ", e, 32)
        name = e[56:128].decode("utf-16-le", "replace").rstrip("\x00")
        part = Partition(i + 1, "GPT", first, last - first + 1,
                         GPT_TYPES.get(type_guid, str(type_guid)), 0, False, name)
        if last < first or last >= dev.sectors:
            part.problems.append("extends past the end of the device")
        parts.append(part)
    return parts


def parse_gpt(dev):
    problems = []
    try:
        primary = _parse_gpt_header(dev, 1)
    except OSError as exc:
        primary = None
        problems.append(f"primary GPT unreadable: {exc}")
    try:
        backup = _parse_gpt_header(dev, dev.sectors - 1)
    except OSError as exc:
        backup = None
        problems.append(f"backup GPT unreadable: {exc}")
    if primary is None:
        problems.append("primary GPT header is missing or fails its checksum")
    if backup is None:
        problems.append("backup GPT header is missing or fails its checksum")
    return Gpt(primary is not None, backup is not None,
               primary if primary is not None else (backup or []), problems)


def build_gpt(dev_sectors, sector_size, partitions):
    """partitions: [(start_lba, sectors, name)] -> {lba: bytes} covering protective MBR,
    primary header + entries, backup entries + header."""
    entry_count, entry_size = 128, 128
    table_sectors = entry_count * entry_size // sector_size
    first_usable = 2 + table_sectors
    last_usable = dev_sectors - 2 - table_sectors
    table = bytearray(entry_count * entry_size)
    for i, (start, count, name) in enumerate(partitions):
        if start < first_usable or start + count - 1 > last_usable:
            raise ValueError("partition outside the GPT usable area")
        e = bytearray(entry_size)
        e[0:16] = GPT_BASIC_DATA.bytes_le
        e[16:32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQQ", e, 32, start, start + count - 1, 0)
        encoded = (name or "Basic data partition").encode("utf-16-le")[:70]
        e[56:56 + len(encoded)] = encoded
        table[i * entry_size:(i + 1) * entry_size] = e
    table_crc = zlib.crc32(bytes(table)) & 0xFFFFFFFF
    disk_guid = uuid.uuid4().bytes_le

    def header(my_lba, alt_lba, entries_lba):
        h = bytearray(sector_size)
        struct.pack_into("<8sIIIIQQQQ16sQIII", h, 0, b"EFI PART", 0x00010000, 92, 0, 0,
                         my_lba, alt_lba, first_usable, last_usable, disk_guid,
                         entries_lba, entry_count, entry_size, table_crc)
        struct.pack_into("<I", h, 16, zlib.crc32(bytes(h[:92])) & 0xFFFFFFFF)
        return bytes(h)

    pmbr = bytearray(sector_size)
    struct.pack_into("<B3sB3sII", pmbr, 446, 0, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1,
                     min(dev_sectors - 1, 0xFFFFFFFF))
    pmbr[510:512] = b"\x55\xaa"
    backup_table_lba = dev_sectors - 1 - table_sectors
    return {0: bytes(pmbr),
            1: header(1, dev_sectors - 1, 2),
            2: bytes(table),
            backup_table_lba: bytes(table),
            dev_sectors - 1: header(dev_sectors - 1, 1, backup_table_lba)}


# ------------------------------------------------------------------ filesystem boot sectors

def exfat_boot_checksum(region, sector_size):
    """Checksum over the first 11 sectors of an exFAT boot region."""
    checksum = 0
    data = region[:11 * sector_size]
    for i, byte in enumerate(data):
        if i in (106, 107, 112):
            continue
        checksum = (((checksum & 1) << 31) | (checksum >> 1)) + byte & 0xFFFFFFFF
    return checksum


def _parse_fat(buf, lba, kind):
    g = _fat_geometry(buf)
    info = FsInfo(kind, lba, g["total"], g["bps"], g["bps"] * g["spc"], details=dict(g))
    if kind == "FAT32":
        info.label = buf[71:82].decode("ascii", "replace").strip()
        info.details.update(root_cluster=struct.unpack_from("<I", buf, 44)[0],
                            fsinfo=struct.unpack_from("<H", buf, 48)[0],
                            backup_boot=struct.unpack_from("<H", buf, 50)[0])
        if g["root_entries"] != 0:
            info.problems.append("FAT32 boot sector has a non-zero root entry count")
        if not 2 <= info.details["root_cluster"] < g["clusters"] + 2:
            info.problems.append("root directory cluster is out of range")
    else:
        info.label = buf[43:54].decode("ascii", "replace").strip()
    if info.label == "NO NAME":
        info.label = ""
    if g["total"] == 0 or g["fat_size"] == 0 or g["reserved"] == 0:
        info.problems.append("boot sector has zero-sized fields")
    elif g["fat_size"] * g["bps"] < (g["clusters"] + 2) * {"FAT12": 1.5, "FAT16": 2, "FAT32": 4}[kind]:
        info.problems.append("FAT is too small for the volume size")
    info.details["hidden"] = struct.unpack_from("<I", buf, 28)[0]
    return info


def _parse_exfat(buf, lba):
    part_offset, vol_len, fat_off, fat_len, heap_off, clusters, root = \
        struct.unpack_from("<QQIIIII", buf, 64)
    bps_shift, spc_shift, nfats = buf[108], buf[109], buf[110]
    info = FsInfo("exFAT", lba, vol_len)
    if not 9 <= bps_shift <= 12 or spc_shift > 25 - bps_shift:
        info.problems.append("invalid sector or cluster size")
        return info
    info.bytes_per_sector = 1 << bps_shift
    info.cluster_size = 1 << (bps_shift + spc_shift)
    info.details = {"partition_offset": part_offset, "fat_offset": fat_off, "fat_length": fat_len,
                    "heap_offset": heap_off, "clusters": clusters, "root_cluster": root,
                    "spc": 1 << spc_shift, "nfats": nfats,
                    "volume_flags": struct.unpack_from("<H", buf, 106)[0]}
    if nfats not in (1, 2) or fat_off < 24 or heap_off < fat_off + fat_len * nfats:
        info.problems.append("inconsistent FAT / cluster heap offsets")
    if clusters == 0 or heap_off + clusters * (1 << spc_shift) > vol_len:
        info.problems.append("cluster heap does not fit the volume")
    if not 2 <= root < clusters + 2:
        info.problems.append("root directory cluster is out of range")
    return info


def _parse_ntfs(buf, lba):
    bps = struct.unpack_from("<H", buf, 11)[0]
    spc_raw = buf[13]
    spc = spc_raw if spc_raw <= 0x80 else 1 << (256 - spc_raw)
    total, mft, mftmirr = struct.unpack_from("<QQQ", buf, 40)
    info = FsInfo("NTFS", lba, total + 1, bps or 512, (bps or 512) * spc)
    info.details = {"mft_cluster": mft, "mftmirr_cluster": mftmirr, "spc": spc,
                    "hidden": struct.unpack_from("<I", buf, 28)[0]}
    if bps not in (512, 1024, 2048, 4096) or spc == 0 or total == 0:
        info.problems.append("boot sector has invalid geometry")
    elif mft * spc >= total or mftmirr * spc >= total:
        info.problems.append("MFT location is outside the volume")
    return info


def parse_boot(buf, lba):
    """FsInfo from a boot sector buffer, or None if it is not a recognised filesystem."""
    kind = detect_fs(buf)
    if kind is None:
        return None
    if kind in ("FAT12", "FAT16", "FAT32"):
        return _parse_fat(buf, lba, kind)
    if kind == "exFAT":
        return _parse_exfat(buf, lba)
    if kind == "NTFS":
        return _parse_ntfs(buf, lba)
    info = FsInfo(kind, lba, windows_readable=(kind == "BitLocker"))
    return info


def inspect_fs(dev, start_lba, part_sectors=0, expected=None):
    """Examine the filesystem at start_lba including its backup boot sector and key structures.

    Returns FsInfo, or None when neither the primary nor any backup boot sector is recognisable.
    `expected` narrows where to look for a backup when the primary is destroyed.
    """
    ss = dev.sector_size
    limit = dev.sectors - start_lba
    if limit <= 0:
        return None
    try:
        head = dev.read_sectors(start_lba, min(24, limit))
        read_error = None
    except OSError as exc:
        head, read_error = b"", str(exc)
    info = parse_boot(head, start_lba) if head else None

    if info is None:
        info = _fs_from_backup(dev, start_lba, part_sectors, head, expected)
        if info is None:
            return None
        info.problems.insert(0, "primary boot sector is unreadable" if read_error
                             else "primary boot sector is damaged or erased")
        return info

    if info.fs == "FAT32":
        bk = info.details.get("backup_boot") or 6
        info.backup_lba = start_lba + bk
        if len(head) >= (bk + 1) * ss:
            backup = head[bk * ss:(bk + 1) * ss]
            info.backup_ok = detect_fs(backup) == "FAT32"
            info.backup_matches = backup[:90] == head[:90]
        fsinfo = info.details.get("fsinfo") or 1
        fsi = head[fsinfo * ss:(fsinfo + 1) * ss]
        if len(fsi) == ss and (fsi[:4] != b"RRaA" or fsi[484:488] != b"rrAa"):
            info.problems.append("FSInfo sector signature is damaged")
        _check_fat_tables(dev, info)
    elif info.fs in ("FAT12", "FAT16"):
        _check_fat_tables(dev, info)
    elif info.fs == "exFAT":
        info.backup_lba = start_lba + 12
        bss = info.bytes_per_sector
        if not info.problems and len(head) >= 24 * bss:
            def region_ok(region):
                want = struct.pack("<I", exfat_boot_checksum(region, bss)) * (bss // 4)
                return region[11 * bss:12 * bss] == want
            if not region_ok(head[:12 * bss]):
                info.problems.append("exFAT boot region checksum mismatch")
            backup = head[12 * bss:24 * bss]
            info.backup_ok = detect_fs(backup) == "exFAT" and region_ok(backup)
            info.backup_matches = backup[:11 * bss] == head[:11 * bss]
    elif info.fs == "NTFS":
        info.backup_lba = start_lba + info.total_sectors - 1
        if not info.problems:
            try:
                backup = dev.read_sectors(info.backup_lba, 1)
                info.backup_ok = detect_fs(backup) == "NTFS"
                info.backup_matches = backup[:84] == head[:84]
            except (OSError, ValueError):
                pass
            try:
                mft_lba = start_lba + info.details["mft_cluster"] * info.details["spc"] \
                    * (info.bytes_per_sector // ss)
                if dev.read_sectors(mft_lba, 1)[:4] != b"FILE":
                    info.problems.append("Master File Table (MFT) start is damaged")
            except (OSError, ValueError) as exc:
                info.problems.append(f"Master File Table (MFT) is unreadable: {exc}")
    if part_sectors and info.total_sectors > part_sectors + 1 and info.windows_readable:
        info.problems.append("filesystem is larger than its partition")
    if start_lba + info.total_sectors > dev.sectors + 1 and info.total_sectors:
        info.problems.append("filesystem extends past the end of the device")
    return info


def _check_fat_tables(dev, info):
    """Compare the start of FAT1 and FAT2 and check the media / dirty markers."""
    if info.problems:
        return
    g = info.details
    scale = g["bps"] // dev.sector_size or 1
    try:
        fat1 = dev.read_sectors(info.start_lba + g["reserved"] * scale, 8)
        if info.fs == "FAT32":
            e0, e1 = struct.unpack_from("<II", fat1, 0)
            if e0 & 0x0FFFFF00 != 0x0FFFFF00:
                info.problems.append("first FAT entry (media marker) is corrupted")
            elif not e1 & 0x08000000:
                info.details["dirty"] = True
            if e1 & 0x0FFFFFFF >= 0x0FFFFFF8 and not e1 & 0x04000000:
                info.details["io_error_flag"] = True
        elif fat1[0] < 0xF0 or fat1[1] != 0xFF:
            info.problems.append("first FAT entry (media marker) is corrupted")
        if g["nfats"] == 2:
            fat2 = dev.read_sectors(info.start_lba + (g["reserved"] + g["fat_size"]) * scale, 8)
            if fat1 != fat2:
                info.problems.append("the two FAT copies differ")
    except (OSError, ValueError) as exc:
        info.problems.append(f"file allocation table is unreadable: {exc}")


def _fs_from_backup(dev, start_lba, part_sectors, head, expected=None):
    """Primary boot sector is gone - try the standard backup locations."""
    ss = dev.sector_size
    candidates = []
    if len(head) >= 7 * ss:
        candidates.append(("FAT32", start_lba + 6, head[6 * ss:7 * ss]))
    if len(head) >= 24 * ss:
        candidates.append(("exFAT", start_lba + 12, head[12 * ss:24 * ss]))
    if not head:  # primary area unreadable: fetch backups individually
        for kind, off, count in (("FAT32", 6, 1), ("exFAT", 12, 12)):
            try:
                candidates.append((kind, start_lba + off, dev.read_sectors(start_lba + off, count)))
            except (OSError, ValueError):
                pass
    if part_sectors:
        try:
            last = start_lba + part_sectors - 1
            candidates.append(("NTFS", last, dev.read_sectors(last, 1)))
        except (OSError, ValueError):
            pass
    for kind, lba, buf in candidates:
        if expected and expected != kind:
            continue
        info = parse_boot(buf, start_lba)
        if info is None or info.fs != kind or info.problems:
            continue
        if kind == "exFAT":
            bss = info.bytes_per_sector
            want = struct.pack("<I", exfat_boot_checksum(buf, bss)) * (bss // 4)
            if buf[11 * bss:12 * bss] != want:
                continue
        info.from_backup = True
        info.backup_lba = lba
        info.backup_ok = True
        return info
    return None
