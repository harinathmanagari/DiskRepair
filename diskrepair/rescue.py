"""Data rescue: sector-by-sector imaging that survives bad sectors, and signature-based file carving."""

import json
import os
import re
import shutil
import struct
import time

from . import winapi
from .task import Task, human_size

MIB = 1024 * 1024


class RescueError(Exception):
    pass


def check_destination(folder, source_disk_number=None, needed=0):
    """Make sure output goes to a different disk than the one being rescued, with enough room."""
    os.makedirs(folder, exist_ok=True)
    if source_disk_number is not None:
        if source_disk_number in winapi.disk_numbers_for_path(os.path.abspath(folder)):
            raise RescueError("The destination folder is on the device being rescued. "
                              "Choose a folder on another disk.")
    free = shutil.disk_usage(folder).free
    if needed and free < needed:
        raise RescueError(f"Not enough free space in {folder}: {human_size(needed)} needed, "
                          f"{human_size(free)} available.")
    return free


# ------------------------------------------------------------------ imaging

def image_device(dev, out_path, task=None, block=MIB, max_bytes=None):
    """Copy the device to an image file. Unreadable areas are skipped first, retried in small
    pieces afterwards, and left as zeros if they stay unreadable. Returns a summary dict."""
    task = task or Task()
    ss = dev.sector_size
    total = dev.size if max_bytes is None else min(dev.size, max_bytes)
    total -= total % ss
    pending = []                      # [(offset, length)] blocks that failed in pass 1
    started = time.monotonic()
    copied = 0
    with open(out_path, "wb") as out:
        out.truncate(total)
        pos = 0
        skip = block
        while pos < total:
            n = min(block, total - pos)
            done = pos / total
            rate = copied / max(time.monotonic() - started, 0.001)
            eta = f", {int((total - pos) / rate)}s left" if rate > 0 else ""
            task.progress(done * 0.9, f"Imaging {human_size(pos)} / {human_size(total)} at "
                                      f"{human_size(rate)}/s - {len(pending)} bad block(s){eta}")
            try:
                data = dev.read(pos, n)
                out.seek(pos)
                out.write(data)
                copied += n
                pos += n
                skip = block
            except OSError:
                # jump ahead further each time so a dead region does not stall the whole rescue
                jump = min(skip, total - pos)
                pending.append((pos, jump))
                pos += jump
                skip = min(skip * 2, 64 * MIB)

        # pass 2: go back through the skipped areas in small pieces
        bad = []
        fine = max(ss, 4096 - 4096 % ss)
        todo = sum(length for _o, length in pending)
        worked = 0
        deadline = time.monotonic() + 30 * 60
        for offset, length in pending:
            for sub in range(offset, offset + length, fine):
                n = min(fine, offset + length - sub)
                worked += n
                task.progress(0.9 + 0.1 * worked / max(todo, 1),
                              f"Retrying damaged areas: {human_size(worked)} / {human_size(todo)}")
                if time.monotonic() > deadline:
                    _merge(bad, sub, offset + length - sub)
                    break
                try:
                    data = dev.read(sub, n)
                    out.seek(sub)
                    out.write(data)
                    copied += n
                except OSError:
                    _merge(bad, sub, n)
    summary = {"image": out_path, "size": total, "copied": copied,
               "bad_ranges": bad, "bad_bytes": sum(l for _o, l in bad),
               "seconds": round(time.monotonic() - started, 1), "sector_size": ss}
    with open(out_path + ".map.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    task.progress(1.0, "Imaging finished", force=True)
    task.log(f"Image saved: {out_path} ({human_size(total)}). "
             + (f"{human_size(summary['bad_bytes'])} could not be read and is zero-filled."
                if bad else "Every sector was read."))
    return summary


def _merge(ranges, offset, length):
    if ranges and ranges[-1][0] + ranges[-1][1] == offset:
        ranges[-1] = [ranges[-1][0], ranges[-1][1] + length]
    else:
        ranges.append([offset, length])


# ------------------------------------------------------------------ carving

class _Window:
    """Random-access reads over a device with a small cache, tolerant of read errors."""

    def __init__(self, dev):
        self.dev = dev
        self.base = -1
        self.buf = b""

    def get(self, offset, length):
        if offset >= self.dev.size:
            return b""
        length = min(length, self.dev.size - offset)
        if not (self.base <= offset and offset + length <= self.base + len(self.buf)):
            span = max(length, 4 * MIB)
            try:
                self.buf = self.dev.read_bytes(offset, span)
            except OSError:
                try:
                    self.buf = self.dev.read_bytes(offset, length)
                except OSError:
                    return b""
            self.base = offset
        start = offset - self.base
        return self.buf[start:start + length]


def _jpeg_length(win, start, limit):
    pos = start + 2
    end = start + limit
    while pos < end:
        head = win.get(pos, 4)
        if head[:2] == b"\xff\xd9":
            return pos + 2 - start
        if len(head) < 4 or head[0] != 0xFF:
            return None
        marker = head[1]
        if marker == 0xFF:                       # fill byte
            pos += 1
            continue
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker in (0x00, 0xD8):
            return None
        seg = struct.unpack(">H", head[2:4])[0]
        if seg < 2:
            return None
        pos += 2 + seg
        if marker == 0xDA:                       # entropy-coded data follows the scan header
            pos = _jpeg_next_marker(win, pos, end)
            if pos is None:
                return None
    return None


def _jpeg_next_marker(win, pos, end):
    """Position of the next real marker after entropy-coded data (skips FF00 and restart markers)."""
    while pos < end:
        chunk = win.get(pos, 256 * 1024)
        if len(chunk) < 2:
            return None
        i = 0
        while True:
            i = chunk.find(b"\xff", i)
            if i == -1:
                pos += len(chunk)
                break
            if i + 1 >= len(chunk):
                pos += i
                break
            nxt = chunk[i + 1]
            if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                i += 2
            elif nxt == 0xFF:
                i += 1
            else:
                return pos + i
    return None


def _png_length(win, start, limit):
    pos = start + 8
    while pos < start + limit:
        head = win.get(pos, 8)
        if len(head) < 8:
            return None
        length = struct.unpack(">I", head[:4])[0]
        kind = head[4:8]
        if length > 0x7FFFFFFF or not kind.isalpha():
            return None
        pos += 12 + length
        if kind == b"IEND":
            return pos - start
    return None


_MP4_BOXES = {b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"moof",
              b"mfra", b"pnot", b"udta", b"sidx", b"styp", b"PICT", b"pdin", b"bloc", b"junk",
              b"thum", b"prvw", b"mpvd"}


def _mp4_length(win, start, limit):
    pos = start
    seen = set()
    while pos < start + limit:
        head = win.get(pos, 16)
        if len(head) < 8:
            break
        size = struct.unpack(">I", head[:4])[0]
        kind = head[4:8]
        if kind not in _MP4_BOXES:
            break
        if size == 1:
            if len(head) < 16:
                break
            size = struct.unpack(">Q", head[8:16])[0]
        elif size == 0:
            return None
        if size < 8:
            break
        seen.add(kind)
        pos += size
    if b"ftyp" in seen and (b"moov" in seen or b"meta" in seen or b"mdat" in seen) \
            and pos - start <= limit:
        return pos - start
    return None


def _riff_length(win, start, limit):
    head = win.get(start, 12)
    if len(head) < 12 or head[8:12] not in (b"AVI ", b"WAVE", b"WEBP"):
        return None
    size = struct.unpack("<I", head[4:8])[0] + 8
    return size if 12 < size <= limit else None


def _zip_length(win, start, limit):
    pos = start
    step = 4 * MIB
    while pos < start + limit:
        chunk = win.get(pos, step + 22)
        if len(chunk) < 22:
            return None
        i = chunk.find(b"PK\x05\x06")
        if i != -1 and i + 22 <= len(chunk):
            comment = struct.unpack("<H", chunk[i + 20:i + 22])[0]
            return pos + i + 22 + comment - start
        pos += step
    return None


def _pdf_length(win, start, limit):
    limit = min(limit, 64 * MIB)
    last = None
    pos = start
    step = 4 * MIB
    while pos < start + limit:
        chunk = win.get(pos, step + 8)
        if not chunk:
            break
        i = chunk.rfind(b"%%EOF")
        if i != -1:
            last = pos + i + 5 - start
        elif last is not None:
            break
        if len(chunk) < step:
            break
        pos += step
    return last


def _zip_ext(win, start):
    head = win.get(start, 4096)
    if b"word/" in head:
        return "docx"
    if b"xl/" in head:
        return "xlsx"
    if b"ppt/" in head:
        return "pptx"
    return "zip"


def _mp4_ext(win, start):
    brand = win.get(start + 8, 4)
    if brand.startswith(b"qt"):
        return "mov"
    if brand in (b"heic", b"heix", b"mif1", b"msf1"):
        return "heic"
    if brand.startswith(b"3g"):
        return "3gp"
    if brand in (b"M4A ", b"M4B "):
        return "m4a"
    if brand == b"crx ":
        return "cr3"
    return "mp4"


_SIGNATURES = re.compile(rb"\xff\xd8\xff|\x89PNG\r\n\x1a\n|%PDF-|PK\x03\x04|RIFF|ftyp")

# kind -> (measure function, default extension, max size, offset of signature inside the file)
_KINDS = {
    b"\xff\xd8\xff": ("jpg", _jpeg_length, 64 * MIB, 0),
    b"\x89PNG\r\n\x1a\n": ("png", _png_length, 128 * MIB, 0),
    b"%PDF-": ("pdf", _pdf_length, 64 * MIB, 0),
    b"PK\x03\x04": ("zip", _zip_length, 512 * MIB, 0),
    b"RIFF": ("riff", _riff_length, 4096 * MIB, 0),
    b"ftyp": ("mp4", _mp4_length, 64 * 1024 * MIB, 4),
}


def carve_files(dev, out_dir, task=None, start=0, end=None, min_size=2048):
    """Recover files by their signatures, without using the filesystem. Works on the raw device
    or on a rescue image. Fragmented files come out truncated or damaged - a known limit of
    carving. Returns {'files': n, 'bytes': n, 'by_type': {...}}."""
    task = task or Task()
    os.makedirs(out_dir, exist_ok=True)
    ss = 512
    end = dev.size if end is None else min(end, dev.size)
    win = _Window(dev)
    chunk = 4 * MIB
    stats = {"files": 0, "bytes": 0, "by_type": {}, "read_errors": 0}
    pos = start - start % ss
    resume_at = 0
    zip_cooldown = 0
    began = time.monotonic()
    while pos < end:
        done = (pos - start) / max(end - start, 1)
        rate = (pos - start) / max(time.monotonic() - began, 0.001)
        eta = f", {int((end - pos) / rate)}s left" if rate > 0 and done > 0.002 else ""
        task.progress(done, f"Scanning {human_size(pos)} / {human_size(end)} - "
                            f"{stats['files']} file(s) recovered{eta}")
        n = min(chunk, end - pos)
        try:
            data = dev.read_bytes(pos, n)
        except OSError:
            stats["read_errors"] += 1
            pos += n
            continue
        for match in _SIGNATURES.finditer(data):
            sig = match.group()
            ext, measure, limit, sig_off = _KINDS[sig]
            file_start = pos + match.start() - sig_off
            if file_start % ss or file_start < resume_at or file_start < 0:
                continue
            if ext == "zip" and file_start < zip_cooldown:
                continue
            task.check()
            length = measure(win, file_start, min(limit, end - file_start))
            if not length or length < min_size:
                if ext == "zip":  # an unterminated archive: do not rescan from each inner header
                    zip_cooldown = file_start + 16 * MIB
                continue
            if ext == "zip":
                ext = _zip_ext(win, file_start)
            elif ext == "mp4":
                ext = _mp4_ext(win, file_start)
            elif ext == "riff":
                ext = {b"AVI ": "avi", b"WAVE": "wav", b"WEBP": "webp"}[win.get(file_start + 8, 4)]
            stats["files"] += 1
            name = os.path.join(out_dir, f"recovered_{stats['files']:05d}_at{file_start // ss}.{ext}")
            _copy_range(dev, file_start, length, name, task)
            stats["bytes"] += length
            stats["by_type"][ext] = stats["by_type"].get(ext, 0) + 1
            resume_at = file_start + length
        pos += n
    task.progress(1.0, f"Carving finished - {stats['files']} file(s) recovered", force=True)
    task.log(f"Recovered {stats['files']} file(s), {human_size(stats['bytes'])}: "
             + (", ".join(f"{v} {k}" for k, v in sorted(stats["by_type"].items())) or "none"))
    return stats


def _copy_range(dev, offset, length, path, task):
    with open(path, "wb") as out:
        pos = offset
        end = offset + length
        while pos < end:
            n = min(4 * MIB, end - pos)
            try:
                out.write(dev.read_bytes(pos, n))
            except OSError:
                out.write(bytes(n))
            pos += n
            task.check()
