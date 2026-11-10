"""Read-only scans: lost-partition search and surface (bad sector) scan."""

import time
from dataclasses import dataclass, field

from . import layout
from .task import Task, human_size

MIB = 1024 * 1024
QUICK_LBAS_512 = (0, 63, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 264192)


def _resolve_start(dev, lba, info):
    """A valid boot sector was seen at `lba`. Work out whether it is a primary or a backup copy
    and return the LBA where the filesystem really starts."""
    hidden = info.details.get("hidden")
    if info.fs == "FAT32":
        bk = info.details.get("backup_boot") or 6
        if lba >= bk and hidden == lba - bk:
            return lba - bk
    elif info.fs == "exFAT":
        if lba >= 12 and info.details.get("partition_offset") == lba - 12:
            return lba - 12
    elif info.fs == "NTFS":
        span = info.total_sectors - 1  # the backup sits right after the last volume sector
        if span and lba >= span and hidden == lba - span:
            return lba - span
    return lba


def _probe(dev, lba):
    """Look for a filesystem starting at (or backed up around) lba. Returns FsInfo or None."""
    ss = dev.sector_size
    first = max(lba - 1, 0)
    count = min(25 + (lba - first), dev.sectors - first)
    if count <= 0:
        return None
    try:
        window = dev.read_sectors(first, count)
    except (OSError, ValueError):
        return None
    rel = (lba - first) * ss
    hit = None
    for sector_off in (0, 6, 12):
        chunk = window[rel + sector_off * ss:rel + sector_off * ss + 4096]
        if len(chunk) >= 512 and layout.detect_fs(chunk):
            hit = lba
            break
    if hit is None and lba > 0:
        tail = layout.parse_boot(window[:ss], first)
        if tail and tail.fs == "NTFS" and not tail.problems:
            start = first - (tail.total_sectors - 1)
            if start >= 0:
                return layout.inspect_fs(dev, start, tail.total_sectors, expected="NTFS")
        return None
    if hit is None:
        return None
    info = layout.inspect_fs(dev, lba)
    if info is None:
        return None
    if not info.from_backup:
        start = _resolve_start(dev, lba, info)
        if start != lba:
            return layout.inspect_fs(dev, start, info.total_sectors)
    return info


def find_partitions(dev, task=None, deep=False):
    """Search the device for filesystems that are not (or wrongly) listed in the partition table.

    Quick mode checks the standard start offsets. Deep mode checks every 1 MiB boundary.
    Returns a list of FsInfo sorted by start, without overlaps.
    """
    task = task or Task()
    ss = dev.sector_size
    step = MIB // ss
    candidates = sorted({l * 512 // ss for l in QUICK_LBAS_512 if l * 512 % ss == 0})
    if deep:
        candidates = sorted(set(candidates) | set(range(0, dev.sectors, step)))
    found = []
    skip_until = -1
    total = len(candidates)
    started = time.monotonic()
    for i, lba in enumerate(candidates):
        if lba >= dev.sectors:
            break
        if i % 64 == 0:
            done = i / max(total, 1)
            eta = ""
            if deep and done > 0.01:
                eta = f", about {int((time.monotonic() - started) * (1 - done) / done)}s left"
            task.progress(done, f"Searching for lost partitions at {human_size(lba * ss)}"
                                f" - {len(found)} found{eta}")
        if lba < skip_until:
            continue
        info = _probe(dev, lba)
        if info is None:
            continue
        if any(f.start_lba == info.start_lba for f in found):
            continue
        if info.total_sectors and info.start_lba + info.total_sectors > dev.sectors + 1:
            info.problems.append("filesystem extends past the end of the device")
        found.append(info)
        task.log(f"Found {info.fs} filesystem at sector {info.start_lba} "
                 f"({human_size(info.total_sectors * ss)})"
                 + (" - recovered from its backup boot sector" if info.from_backup else ""))
        if info.total_sectors:
            skip_until = info.start_lba + info.total_sectors
    task.progress(1.0, f"Partition search finished - {len(found)} found", force=True)
    found.sort(key=lambda f: f.start_lba)
    result, end = [], -1
    for info in found:
        if info.start_lba >= end:
            result.append(info)
            end = info.start_lba + max(info.total_sectors, 1)
    return result


# ------------------------------------------------------------------ surface scan

@dataclass
class SurfaceResult:
    bytes_tested: int = 0
    blocks_tested: int = 0
    bad_ranges: list = field(default_factory=list)    # [(offset, length)]
    slow_blocks: int = 0
    blank_blocks: int = 0
    seconds: float = 0.0
    sampled: bool = False
    stopped_early: bool = False

    @property
    def bad_bytes(self):
        return sum(length for _o, length in self.bad_ranges)

    @property
    def speed(self):
        return self.bytes_tested / self.seconds if self.seconds > 0 else 0

    def summary(self):
        kind = "Sampled" if self.sampled else "Scanned"
        text = (f"{kind} {human_size(self.bytes_tested)} in {self.seconds:.1f}s "
                f"({human_size(self.speed)}/s): ")
        if not self.bad_ranges:
            text += "no unreadable areas"
        else:
            text += f"{len(self.bad_ranges)} unreadable area(s), {human_size(self.bad_bytes)} total"
        if self.slow_blocks:
            text += f", {self.slow_blocks} slow block(s)"
        return text


def sample_surface(dev, task=None, samples=96, block=64 * 1024):
    """Read evenly spread blocks across the device - a fast health indicator."""
    task = task or Task()
    ss = dev.sector_size
    block -= block % ss
    result = SurfaceResult(sampled=True)
    if dev.size < block * 4:
        return result
    span = dev.size - block
    offsets = sorted({(span * i // (samples - 1)) // ss * ss for i in range(samples)})
    start = time.monotonic()
    consecutive_bad = 0
    for i, offset in enumerate(offsets):
        task.progress(i / len(offsets), f"Sampling surface at {human_size(offset)}")
        t0 = time.monotonic()
        try:
            data = dev.read(offset, block)
            consecutive_bad = 0
            if layout.is_blank(data):
                result.blank_blocks += 1
        except OSError:
            result.bad_ranges.append((offset, block))
            consecutive_bad += 1
        if time.monotonic() - t0 > 2.0:
            result.slow_blocks += 1
        result.blocks_tested += 1
        result.bytes_tested += block
        if consecutive_bad >= 12:  # device is not answering; do not hang for minutes
            result.stopped_early = True
            break
    result.seconds = time.monotonic() - start
    return result


def surface_scan(dev, task=None, block=MIB, start=0, end=None):
    """Read every block of the device and map the unreadable areas (read-only)."""
    task = task or Task()
    ss = dev.sector_size
    end = dev.size if end is None else min(end, dev.size)
    result = SurfaceResult()
    began = time.monotonic()
    offset = start
    fine = 64 * 1024
    refined = 0
    while offset < end:
        length = min(block, end - offset)
        length -= length % ss
        if length <= 0:
            break
        elapsed = time.monotonic() - began
        done = (offset - start) / max(end - start, 1)
        eta = f", {int(elapsed * (1 - done) / done)}s left" if done > 0.005 else ""
        task.progress(done, f"Surface scan {human_size(offset)} / {human_size(end)} - "
                            f"{len(result.bad_ranges)} bad area(s){eta}")
        t0 = time.monotonic()
        try:
            data = dev.read(offset, length)
            if layout.is_blank(data):
                result.blank_blocks += 1
        except OSError:
            if refined < 256 and length > fine:  # localise the damage inside this block
                refined += 1
                for sub in range(offset, offset + length, fine):
                    sub_len = min(fine, offset + length - sub)
                    try:
                        dev.read(sub, sub_len)
                    except OSError:
                        _add_range(result.bad_ranges, sub, sub_len)
                    task.check()
            else:
                _add_range(result.bad_ranges, offset, length)
        if time.monotonic() - t0 > 2.0:
            result.slow_blocks += 1
        result.blocks_tested += 1
        result.bytes_tested += length
        offset += length
    result.seconds = time.monotonic() - began
    task.progress(1.0, result.summary(), force=True)
    return result


def _add_range(ranges, offset, length):
    if ranges and ranges[-1][0] + ranges[-1][1] == offset:
        ranges[-1] = (ranges[-1][0], ranges[-1][1] + length)
    else:
        ranges.append((offset, length))
