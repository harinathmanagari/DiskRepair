"""Block devices: a guarded physical disk and a file-backed image (used for rescued images and tests)."""

import os
import time

from . import safety, winapi


class DeviceIOError(OSError):
    def __init__(self, op, offset, length, cause):
        self.op, self.offset, self.length = op, offset, length
        self.winerror_code = getattr(cause, "winerror", None)
        super().__init__(f"{op} failed at offset {offset} (+{length}): {cause}")


class BlockDevice:
    name = "device"
    size = 0
    sector_size = 512
    writable = False

    def read(self, offset, length):
        raise NotImplementedError

    def write(self, offset, data):
        raise NotImplementedError

    def flush(self):
        pass

    def close(self):
        pass

    @property
    def sectors(self):
        return self.size // self.sector_size

    def read_sectors(self, lba, count=1):
        return self.read(lba * self.sector_size, count * self.sector_size)

    def write_sectors(self, lba, data):
        self.write(lba * self.sector_size, data)

    def read_bytes(self, offset, length):
        """Read an arbitrary byte range (aligns to sectors internally, clamps to device end)."""
        if length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        ss = self.sector_size
        start = offset - offset % ss
        end = -(-(offset + length) // ss) * ss
        data = self.read(start, min(end, self.size) - start)
        return data[offset - start:offset - start + length]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class ImageDevice(BlockDevice):
    """A disk image file treated as a block device."""

    def __init__(self, path, writable=False, sector_size=512):
        self.name = os.path.basename(path)
        self.path = path
        self.writable = writable
        self.sector_size = sector_size
        self._f = open(path, "r+b" if writable else "rb")
        self.size = os.path.getsize(path)

    def read(self, offset, length):
        self._f.seek(offset)
        return self._f.read(length)

    def write(self, offset, data):
        if not self.writable:
            raise PermissionError("image opened read-only")
        self._f.seek(offset)
        self._f.write(data)

    def flush(self):
        if self.writable:
            self._f.flush()

    def close(self):
        self._f.close()


class PhysicalDevice(BlockDevice):
    """A physical disk, opened only after the safety guard approves the handle itself."""

    def __init__(self, number, write=False, expected_fingerprint=None, log=None):
        self.number = int(number)
        self.name = f"Disk {self.number}"
        self.writable = bool(write)
        self._locks = []
        self._handle = None
        self._log = log or (lambda msg: None)

        # Pre-check on a query-only handle so a refused disk is never opened for data access.
        safety.verify_number(self.number, expected_fingerprint, for_write=write)

        access = winapi.GENERIC_READ | (winapi.GENERIC_WRITE if write else 0)
        handle = winapi.open_path(rf"\\.\PhysicalDrive{self.number}", access)
        try:
            # Authoritative check on the handle that will actually be used.
            self.identity = safety.verify(safety.identity_from_handle(handle, self.number),
                                          expected_fingerprint, for_write=write)
        except Exception:
            winapi.close(handle)
            raise
        self._handle = handle
        self.size = self.identity.size
        self.sector_size = self.identity.sector_size
        if write:
            self._locks = _lock_volumes(self.number, self._log)

    def read(self, offset, length):
        ss = self.sector_size
        if offset % ss or length % ss:
            raise ValueError("raw reads must be sector aligned")
        try:
            data = winapi.read_at(self._handle, offset, length)
        except OSError as exc:
            raise DeviceIOError("read", offset, length, exc) from exc
        if len(data) != length:
            raise DeviceIOError("read", offset, length,
                                OSError(f"short read ({len(data)} bytes)"))
        return data

    def write(self, offset, data):
        if not self.writable:
            raise PermissionError("device opened read-only")
        ss = self.sector_size
        if offset % ss or len(data) % ss:
            raise ValueError("raw writes must be sector aligned")
        if offset < 0 or offset + len(data) > self.size:
            raise ValueError("write outside device bounds")
        try:
            winapi.write_at(self._handle, offset, data)
        except OSError as exc:
            raise DeviceIOError("write", offset, len(data), exc) from exc

    def flush(self):
        if self._handle is not None and self.writable:
            winapi.flush(self._handle)

    def close(self):
        if self._handle is None:
            return
        if self.writable:
            winapi.flush(self._handle)
            try:  # make Windows re-read the partition table
                winapi.ioctl(self._handle, winapi.IOCTL_DISK_UPDATE_PROPERTIES)
            except OSError:
                pass
        for lock in self._locks:
            try:
                winapi.ioctl(lock, winapi.FSCTL_UNLOCK_VOLUME)
            except OSError:
                pass
            winapi.close(lock)
        self._locks = []
        winapi.close(self._handle)
        self._handle = None


def volumes_on_disk(number):
    """Volumes that live on the given disk. Volumes spanning other disks raise SafetyError."""
    result = []
    for vol in winapi.list_volumes():
        disks = {d for d, _s, _l in vol["extents"]}
        if number not in disks:
            continue
        if disks != {number}:
            raise safety.SafetyError(
                f"Refused: a volume on disk {number} also spans disk(s) "
                f"{sorted(disks - {number})}")
        result.append(vol)
    return result


def _lock_volumes(number, log):
    """Lock and dismount every volume on the disk so raw writes are permitted and nothing is cached."""
    handles = []
    for vol in volumes_on_disk(number):
        path = vol["guid_path"].rstrip("\\")
        label = ", ".join(vol["letters"]) or path
        try:
            handle = winapi.open_path(path, winapi.GENERIC_READ | winapi.GENERIC_WRITE)
        except OSError as exc:
            log(f"Could not open volume {label} for locking: {exc}")
            continue
        locked = False
        for _ in range(10):
            try:
                winapi.ioctl(handle, winapi.FSCTL_LOCK_VOLUME)
                locked = True
                break
            except OSError:
                time.sleep(0.3)
        if not locked:
            log(f"Volume {label} is in use by another program; forcing dismount.")
        try:
            winapi.ioctl(handle, winapi.FSCTL_DISMOUNT_VOLUME)
        except OSError as exc:
            log(f"Dismount of {label} failed: {exc}")
        handles.append(handle)
    return handles
