"""A FAT32 formatter that works on any size up to 2 TiB.

Windows refuses to create FAT32 above 32 GB, yet cameras, car stereos, consoles and
printers often need it. Layout follows Microsoft's FAT specification.
"""

import struct
import time

from .task import Task

MIB = 1024 * 1024


def _cluster_sectors(total_bytes, bps):
    gib = 1024 * MIB
    if total_bytes <= 64 * MIB:
        size = 512
    elif total_bytes <= 128 * MIB:
        size = 1024
    elif total_bytes <= 256 * MIB:
        size = 2048
    elif total_bytes <= 8 * gib:
        size = 4096
    elif total_bytes <= 16 * gib:
        size = 8192
    elif total_bytes <= 32 * gib:
        size = 16384
    elif total_bytes <= 2048 * gib:
        size = 32768
    else:
        size = 65536
    return max(1, size // bps)


def plan(part_sectors, bps=512):
    """Geometry for a FAT32 volume of part_sectors sectors."""
    if part_sectors >= 2 ** 32:
        raise ValueError("FAT32 cannot exceed 2^32 sectors (2 TiB at 512 bytes/sector)")
    spc = _cluster_sectors(part_sectors * bps, bps)
    reserved = 32
    fat_size = (4 * (part_sectors - reserved)) // (spc * bps + 8) + 1
    # push the data area onto a cluster boundary (flash-friendly alignment)
    reserved += -(reserved + 2 * fat_size) % spc
    data_start = reserved + 2 * fat_size
    clusters = (part_sectors - data_start) // spc
    if clusters < 65525:
        raise ValueError("volume is too small for FAT32")
    if clusters >= 0x0FFFFFF5 or fat_size * bps // 4 < clusters + 2:
        raise ValueError("volume geometry does not fit FAT32")
    return {"bps": bps, "spc": spc, "reserved": reserved, "fat_size": fat_size,
            "data_start": data_start, "clusters": clusters, "total": part_sectors}


def _label_bytes(label):
    clean = "".join(c for c in (label or "").upper() if c.isalnum() or c in " _-")[:11]
    return clean.encode("ascii", "replace").ljust(11) if clean.strip() else b"NO NAME    "


def boot_sector(geo, start_lba, label="", volume_id=None):
    b = bytearray(geo["bps"])
    b[0:3] = b"\xeb\x58\x90"
    b[3:11] = b"MSWIN4.1"
    struct.pack_into("<HBHBHHBHHHII", b, 11, geo["bps"], geo["spc"], geo["reserved"], 2, 0, 0,
                     0xF8, 0, 63, 255, start_lba & 0xFFFFFFFF, geo["total"])
    struct.pack_into("<IHHIHH", b, 36, geo["fat_size"], 0, 0, 2, 1, 6)
    b[64] = 0x80
    b[66] = 0x29
    struct.pack_into("<I", b, 67, volume_id if volume_id is not None else int(time.time()) & 0xFFFFFFFF)
    b[71:82] = _label_bytes(label)
    b[82:90] = b"FAT32   "
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def format_fat32(dev, start_lba, part_sectors, label="", task=None):
    """Write a fresh, empty FAT32 filesystem into [start_lba, start_lba + part_sectors)."""
    task = task or Task()
    bps = dev.sector_size
    geo = plan(part_sectors, bps)
    if start_lba + part_sectors > dev.sectors:
        raise ValueError("partition extends past the end of the device")

    boot = boot_sector(geo, start_lba, label)
    fsinfo = bytearray(bps)
    fsinfo[0:4] = b"RRaA"
    fsinfo[484:488] = b"rrAa"
    struct.pack_into("<II", fsinfo, 488, geo["clusters"] - 1, 3)  # free count, next free
    fsinfo[510:512] = b"\x55\xaa"
    third = bytearray(bps)
    third[510:512] = b"\x55\xaa"

    reserved = bytearray(geo["reserved"] * bps)
    for base in (0, 6):
        reserved[base * bps:(base + 1) * bps] = boot
        reserved[(base + 1) * bps:(base + 2) * bps] = fsinfo
        reserved[(base + 2) * bps:(base + 3) * bps] = third

    def offset(sector):
        return (start_lba + sector) * bps

    task.progress(0.0, "Writing FAT32 boot region")
    dev.write(offset(0), bytes(reserved))

    # two FATs: zero-filled except the three reserved entries at the start
    fat_head = struct.pack("<III", 0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFFF)
    chunk_sectors = max(1, MIB // bps)
    zero = bytes(chunk_sectors * bps)
    total = 2 * geo["fat_size"]
    done = 0
    for fat in range(2):
        first = geo["reserved"] + fat * geo["fat_size"]
        pos = 0
        while pos < geo["fat_size"]:
            n = min(chunk_sectors, geo["fat_size"] - pos)
            block = zero[:n * bps]
            if pos == 0:
                block = fat_head + block[len(fat_head):]
            dev.write(offset(first + pos), block)
            pos += n
            done += n
            task.progress(done / total * 0.98, f"Writing file allocation table {fat + 1} of 2")

    # root directory: one zeroed cluster, optionally holding the volume label entry
    root = bytearray(geo["spc"] * bps)
    name = _label_bytes(label)
    if name != b"NO NAME    ":
        root[0:11] = name
        root[11] = 0x08
    dev.write(offset(geo["data_start"]), bytes(root))
    dev.flush()
    task.progress(1.0, "FAT32 filesystem written", force=True)
    return geo
