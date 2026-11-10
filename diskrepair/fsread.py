"""Built-in read-only FAT12/16/32 and exFAT readers.

They copy files off a volume that Windows refuses to mount ("RAW", "needs formatting"),
tolerate damaged allocation tables, and can also pull out deleted files.
"""

import os
import struct
from dataclasses import dataclass

from .task import Task, human_size

MIB = 1024 * 1024
_BAD_CHARS = '<>:"/\\|?*'
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} \
    | {f"LPT{i}" for i in range(1, 10)}


@dataclass
class Entry:
    name: str
    is_dir: bool
    size: int
    first_cluster: int
    contiguous: bool = False
    deleted: bool = False


def safe_name(name):
    clean = "".join("_" if c in _BAD_CHARS or ord(c) < 32 else c for c in name).rstrip(". ")
    if not clean:
        clean = "_unnamed"
    if clean.split(".")[0].upper() in _RESERVED:
        clean = "_" + clean
    return clean[:200]


class _Reader:
    cluster_size = 0
    clusters = 0

    def __init__(self, dev):
        self.dev = dev
        self._fat_block = (-1, b"")

    def _fat_bytes(self, offset, length):
        block = offset // 65536
        if self._fat_block[0] != block:
            self._fat_block = (block, self.dev.read_bytes(self.fat_off + block * 65536, 65536 + 8))
        start = offset - block * 65536
        return self._fat_block[1][start:start + length]

    def valid(self, cluster):
        return 2 <= cluster < self.clusters + 2

    def cluster_offset(self, cluster):
        return self.data_off + (cluster - 2) * self.cluster_size

    def next_cluster(self, cluster):
        raise NotImplementedError

    def clusters_for(self, entry):
        """(cluster list, suspect) for an entry. Falls back to assuming the data is contiguous
        when the allocation table is broken or the file is deleted."""
        needed = max(1, -(-entry.size // self.cluster_size)) if not entry.is_dir else None
        first = entry.first_cluster
        if not self.valid(first):
            return [], True
        if entry.contiguous or entry.deleted:
            count = needed or 1
            return list(range(first, min(first + count, self.clusters + 2))), entry.deleted
        chain, seen, cluster = [], set(), first
        limit = needed if needed is not None else 65536
        while self.valid(cluster) and cluster not in seen and len(chain) < limit:
            chain.append(cluster)
            seen.add(cluster)
            try:
                cluster = self.next_cluster(cluster)
            except OSError:
                break
        suspect = False
        if needed is not None and len(chain) < needed:
            suspect = True  # chain ended early: assume the rest follows on
            nxt = chain[-1] + 1
            while len(chain) < needed and self.valid(nxt):
                chain.append(nxt)
                nxt += 1
        return chain, suspect

    def runs(self, clusters):
        """Merge a cluster list into (byte offset, byte length) runs."""
        out = []
        for c in clusters:
            off = self.cluster_offset(c)
            if out and out[-1][0] + out[-1][1] == off and out[-1][1] < 8 * MIB:
                out[-1][1] += self.cluster_size
            else:
                out.append([off, self.cluster_size])
        return out

    def read_dir_bytes(self, entry, limit=8 * MIB):
        clusters, _ = self.clusters_for(entry)
        data = bytearray()
        for off, length in self.runs(clusters):
            try:
                data += self.dev.read_bytes(off, length)
            except OSError:
                break
            if len(data) >= limit:
                break
        return bytes(data)


class FatReader(_Reader):
    def __init__(self, dev, info):
        super().__init__(dev)
        g = info.details
        self.kind = info.fs
        bps = g["bps"]
        base = info.start_lba * dev.sector_size
        self.cluster_size = bps * g["spc"]
        self.clusters = g["clusters"]
        self.fat_off = base + g["reserved"] * bps
        self.root_off = base + (g["reserved"] + g["nfats"] * g["fat_size"]) * bps
        self.root_len = g["root_sectors"] * bps
        self.data_off = base + g["data_start"] * bps
        self.root_cluster = g.get("root_cluster", 0)

    def next_cluster(self, cluster):
        if self.kind == "FAT32":
            value = struct.unpack("<I", self._fat_bytes(cluster * 4, 4))[0] & 0x0FFFFFFF
            return value if value < 0x0FFFFFF7 else -1
        if self.kind == "FAT16":
            value = struct.unpack("<H", self._fat_bytes(cluster * 2, 2))[0]
            return value if value < 0xFFF7 else -1
        raw = struct.unpack("<H", self._fat_bytes(cluster * 3 // 2, 2))[0]
        value = raw >> 4 if cluster & 1 else raw & 0xFFF
        return value if value < 0xFF7 else -1

    def root(self):
        return Entry("", True, 0, self.root_cluster)

    def list_dir(self, entry, include_deleted=False):
        if entry.name == "" and self.kind != "FAT32":
            raw = self.dev.read_bytes(self.root_off, self.root_len)
        else:
            raw = self.read_dir_bytes(entry)
        out, lfn = [], []
        for i in range(0, len(raw) - 31, 32):
            e = raw[i:i + 32]
            if e[0] == 0x00:
                break
            attr = e[11]
            deleted = e[0] == 0xE5
            if attr & 0x3F == 0x0F:
                if deleted:
                    lfn = []
                    continue
                if e[0] & 0x40:
                    lfn = []
                lfn.append((e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le", "replace"))
                continue
            long_name = "".join(reversed(lfn)).split("\x00")[0].rstrip("￿")
            lfn = []
            if attr & 0x08:
                continue
            base = e[0:8]
            if base[0] == 0x05:
                base = b"\xe5" + base[1:]
            stem = base.decode("cp437", "replace").rstrip()
            ext = e[8:11].decode("cp437", "replace").rstrip()
            if e[12] & 0x08:
                stem = stem.lower()
            if e[12] & 0x10:
                ext = ext.lower()
            if deleted:
                stem = "_" + stem[1:]
            name = long_name if long_name and not deleted else (stem + ("." + ext if ext else ""))
            if name in (".", ".."):
                continue
            if deleted and not include_deleted:
                continue
            cluster = struct.unpack_from("<H", e, 26)[0]
            if self.kind == "FAT32":
                cluster |= struct.unpack_from("<H", e, 20)[0] << 16
            size = struct.unpack_from("<I", e, 28)[0]
            is_dir = bool(attr & 0x10)
            if deleted and is_dir:
                continue
            out.append(Entry(name, is_dir, 0 if is_dir else size, cluster, deleted=deleted))
        return out


class ExFatReader(_Reader):
    def __init__(self, dev, info):
        super().__init__(dev)
        d = info.details
        bps = info.bytes_per_sector
        base = info.start_lba * dev.sector_size
        self.cluster_size = info.cluster_size
        self.clusters = d["clusters"]
        self.fat_off = base + d["fat_offset"] * bps
        self.data_off = base + d["heap_offset"] * bps
        self.root_cluster = d["root_cluster"]

    def next_cluster(self, cluster):
        value = struct.unpack("<I", self._fat_bytes(cluster * 4, 4))[0]
        return value if value < 0xFFFFFFF7 else -1

    def root(self):
        return Entry("", True, 0, self.root_cluster)

    def list_dir(self, entry, include_deleted=False):
        raw = self.read_dir_bytes(entry)
        out = []
        i = 0
        while i + 32 <= len(raw):
            kind = raw[i]
            if kind == 0x00:
                break
            if kind & 0x7F != 0x05:
                i += 32
                continue
            deleted = not kind & 0x80
            count = raw[i + 1]
            attrs = struct.unpack_from("<H", raw, i + 4)[0]
            group = raw[i + 32:i + 32 * (count + 1)]
            i += 32 * (count + 1)
            if len(group) < 64 or group[0] & 0x7F != 0x40:
                continue
            flags, name_len = group[1], group[3]
            first = struct.unpack_from("<I", group, 20)[0]
            size = struct.unpack_from("<Q", group, 24)[0]
            name = ""
            for j in range(32, len(group), 32):
                if group[j] & 0x7F == 0x41:
                    name += group[j + 2:j + 32].decode("utf-16-le", "replace")
            name = name[:name_len]
            if not name or (deleted and not include_deleted):
                continue
            is_dir = bool(attrs & 0x10)
            if deleted and is_dir:
                continue
            item = Entry(name, is_dir, size, first, contiguous=bool(flags & 0x02), deleted=deleted)
            if is_dir:
                item.dir_bytes = size
            out.append(item)
        return out

    def clusters_for(self, entry):
        if entry.is_dir and entry.contiguous:
            count = max(1, -(-getattr(entry, "dir_bytes", self.cluster_size) // self.cluster_size))
            first = entry.first_cluster
            if not self.valid(first):
                return [], True
            return list(range(first, min(first + count, self.clusters + 2))), False
        return super().clusters_for(entry)


def open_reader(dev, info):
    """A reader for the filesystem described by a layout.FsInfo, or None if unsupported."""
    if info is None or info.problems and not info.cluster_size:
        return None
    if info.fs in ("FAT12", "FAT16", "FAT32") and info.details.get("spc"):
        return FatReader(dev, info)
    if info.fs == "exFAT" and info.details.get("clusters"):
        return ExFatReader(dev, info)
    return None


def list_tree(reader, task=None, include_deleted=False, max_entries=500000):
    """Walk the whole directory tree -> [(relative path parts, Entry)]."""
    task = task or Task()
    result = []
    stack = [((), reader.root())]
    visited = set()
    while stack and len(result) < max_entries:
        parts, directory = stack.pop()
        if directory.first_cluster in visited or len(parts) > 40:
            continue
        visited.add(directory.first_cluster)
        task.progress(0.0, f"Reading directories - {len(result)} item(s) found")
        try:
            entries = reader.list_dir(directory, include_deleted)
        except (OSError, struct.error):
            continue
        for e in entries:
            path = parts + (safe_name(e.name),)
            if e.is_dir:
                stack.append((path, e))
            result.append((path, e))
    return result


def extract_all(reader, out_dir, task=None, include_deleted=False):
    """Copy every file to out_dir. Returns stats including files that may be damaged."""
    task = task or Task()
    tree = list_tree(reader, task, include_deleted)
    files = [(p, e) for p, e in tree if not e.is_dir]
    total = sum(e.size for _p, e in files) or 1
    stats = {"files": 0, "bytes": 0, "failed": 0, "suspect": 0, "deleted": 0,
             "dirs": sum(1 for _p, e in tree if e.is_dir), "total_bytes": total, "problems": []}
    task.log(f"Found {len(files)} file(s) in {stats['dirs']} folder(s), {human_size(total)}.")
    done = 0
    for parts, entry in files:
        rel = os.path.join("_deleted", *parts) if entry.deleted else os.path.join(*parts)
        target = os.path.join(out_dir, rel)
        task.progress(done / total, f"Copying {rel[-70:]} ({stats['files']}/{len(files)})")
        clusters, suspect = reader.clusters_for(entry)
        if entry.size and not clusters:
            stats["failed"] += 1
            stats["problems"].append(f"{rel}: no valid data location")
            done += entry.size
            continue
        try:
            os.makedirs(os.path.dirname(target) or out_dir, exist_ok=True)
            remaining = entry.size
            errors = 0
            with open(target, "wb") as out:
                for off, length in reader.runs(clusters):
                    if remaining <= 0:
                        break
                    n = min(length, remaining)
                    try:
                        out.write(reader.dev.read_bytes(off, n))
                    except OSError:
                        out.write(bytes(n))
                        errors += 1
                    remaining -= n
                    done += n
                    task.progress(done / total, f"Copying {rel[-70:]} "
                                                f"({stats['files']}/{len(files)})")
        except OSError as exc:
            stats["failed"] += 1
            stats["problems"].append(f"{rel}: {exc}")
            continue
        stats["files"] += 1
        stats["bytes"] += entry.size
        if entry.deleted:
            stats["deleted"] += 1
        if suspect or errors or remaining > 0:
            stats["suspect"] += 1
            why = "unreadable sectors" if errors else "allocation chain damaged"
            if entry.deleted:
                why = "deleted file, layout guessed"
            stats["problems"].append(f"{rel}: may be incomplete ({why})")
    task.progress(1.0, f"Copied {stats['files']} file(s)", force=True)
    task.log(f"Copied {stats['files']} file(s), {human_size(stats['bytes'])}. "
             f"{stats['suspect']} may be damaged, {stats['failed']} could not be copied.")
    return stats
