"""Thin ctypes layer over the Win32 calls DiskRepair needs."""

import ctypes
import struct
from ctypes import wintypes as wt

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
FILE_BEGIN = 0
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
IOCTL_STORAGE_GET_DEVICE_NUMBER = 0x002D1080
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
IOCTL_DISK_UPDATE_PROPERTIES = 0x00070140
IOCTL_DISK_IS_WRITABLE = 0x00070024
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
FSCTL_LOCK_VOLUME = 0x00090018
FSCTL_UNLOCK_VOLUME = 0x0009001C
FSCTL_DISMOUNT_VOLUME = 0x00090020

ERROR_MORE_DATA = 234
ERROR_NO_MORE_FILES = 18
ERROR_WRITE_PROTECT = 19

kernel32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                 wt.DWORD, wt.DWORD, wt.HANDLE]
kernel32.CreateFileW.restype = wt.HANDLE
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL
kernel32.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                              ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.ReadFile.restype = wt.BOOL
kernel32.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                               ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.WriteFile.restype = wt.BOOL
kernel32.SetFilePointerEx.argtypes = [wt.HANDLE, ctypes.c_longlong,
                                      ctypes.POINTER(ctypes.c_longlong), wt.DWORD]
kernel32.SetFilePointerEx.restype = wt.BOOL
kernel32.FlushFileBuffers.argtypes = [wt.HANDLE]
kernel32.FlushFileBuffers.restype = wt.BOOL
kernel32.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                     ctypes.c_void_p, wt.DWORD,
                                     ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
kernel32.DeviceIoControl.restype = wt.BOOL
kernel32.FindFirstVolumeW.argtypes = [wt.LPWSTR, wt.DWORD]
kernel32.FindFirstVolumeW.restype = wt.HANDLE
kernel32.FindNextVolumeW.argtypes = [wt.HANDLE, wt.LPWSTR, wt.DWORD]
kernel32.FindNextVolumeW.restype = wt.BOOL
kernel32.FindVolumeClose.argtypes = [wt.HANDLE]
kernel32.FindVolumeClose.restype = wt.BOOL
kernel32.GetVolumePathNamesForVolumeNameW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD,
                                                      ctypes.POINTER(wt.DWORD)]
kernel32.GetVolumePathNamesForVolumeNameW.restype = wt.BOOL


def _last_error():
    return ctypes.WinError(ctypes.get_last_error())


def open_path(path, access, flags=0):
    """Open a device path. access=0 gives a query-only handle that cannot read or write data."""
    handle = kernel32.CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  None, OPEN_EXISTING, flags, None)
    if handle is None or handle == INVALID_HANDLE_VALUE:
        raise _last_error()
    return handle


def close(handle):
    if handle is not None:
        kernel32.CloseHandle(handle)


def ioctl(handle, code, in_bytes=b"", out_size=0):
    inbuf = ctypes.create_string_buffer(in_bytes, len(in_bytes)) if in_bytes else None
    outbuf = ctypes.create_string_buffer(out_size) if out_size else None
    returned = wt.DWORD(0)
    ok = kernel32.DeviceIoControl(handle, code, inbuf, len(in_bytes), outbuf, out_size,
                                  ctypes.byref(returned), None)
    if not ok:
        raise _last_error()
    return outbuf.raw[:returned.value] if outbuf else b""


def read_at(handle, offset, length):
    if not kernel32.SetFilePointerEx(handle, offset, None, FILE_BEGIN):
        raise _last_error()
    buf = ctypes.create_string_buffer(length)
    got = wt.DWORD(0)
    if not kernel32.ReadFile(handle, buf, length, ctypes.byref(got), None):
        raise _last_error()
    return buf.raw[:got.value]


def write_at(handle, offset, data):
    if not kernel32.SetFilePointerEx(handle, offset, None, FILE_BEGIN):
        raise _last_error()
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    done = wt.DWORD(0)
    if not kernel32.WriteFile(handle, buf, len(data), ctypes.byref(done), None):
        raise _last_error()
    if done.value != len(data):
        raise OSError(f"short write at offset {offset}: {done.value} of {len(data)} bytes")


def flush(handle):
    kernel32.FlushFileBuffers(handle)


# ---------------------------------------------------------------- device queries

def storage_descriptor(handle):
    """STORAGE_DEVICE_DESCRIPTOR for a disk handle -> dict(bus_type, removable, vendor, product, serial)."""
    query = struct.pack("<IIB3x", 0, 0, 0)  # StorageDeviceProperty, PropertyStandardQuery
    raw = ioctl(handle, IOCTL_STORAGE_QUERY_PROPERTY, query, 1024)
    if len(raw) < 36:
        raise OSError("storage descriptor too short")
    removable = raw[10] != 0
    vendor_off, product_off, _rev_off, serial_off, bus_type = struct.unpack_from("<IIIII", raw, 12)

    def text(off):
        if not off or off >= len(raw):
            return ""
        end = raw.find(b"\x00", off)
        return raw[off:end if end != -1 else len(raw)].decode("ascii", "replace").strip()

    return {"bus_type": bus_type, "removable": removable, "vendor": text(vendor_off),
            "product": text(product_off), "serial": text(serial_off)}


def device_number(handle):
    """Physical disk number behind a disk handle."""
    raw = ioctl(handle, IOCTL_STORAGE_GET_DEVICE_NUMBER, b"", 12)
    _dev_type, number, _part = struct.unpack("<III", raw)
    return number


def geometry(handle):
    """(size_bytes, bytes_per_sector) for a disk handle."""
    raw = ioctl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, b"", 256)
    bytes_per_sector = struct.unpack_from("<I", raw, 20)[0]
    size = struct.unpack_from("<q", raw, 24)[0]
    return size, bytes_per_sector


def volume_extents(handle):
    """[(disk_number, start_offset, length)] for a volume handle."""
    raw = ioctl(handle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, b"", 8 + 24 * 32)
    count = struct.unpack_from("<I", raw, 0)[0]
    out = []
    for i in range(count):
        disk, start, length = struct.unpack_from("<I4xqq", raw, 8 + 24 * i)
        out.append((disk, start, length))
    return out


def list_volumes():
    """All volumes: [{'guid_path': '\\\\?\\Volume{..}\\', 'letters': ['E:'], 'extents': [...]}]."""
    volumes = []
    buf = ctypes.create_unicode_buffer(512)
    find = kernel32.FindFirstVolumeW(buf, 512)
    if find is None or find == INVALID_HANDLE_VALUE:
        return volumes
    try:
        while True:
            guid_path = buf.value
            info = {"guid_path": guid_path, "letters": [], "extents": []}
            names = ctypes.create_unicode_buffer(1024)
            needed = wt.DWORD(0)
            if kernel32.GetVolumePathNamesForVolumeNameW(guid_path, names, 1024,
                                                         ctypes.byref(needed)):
                parts = names[:needed.value].split("\x00")
                info["letters"] = [p.rstrip("\\") for p in parts
                                   if len(p) == 3 and p[1] == ":"]
            try:
                handle = open_path(guid_path.rstrip("\\"), 0)
                try:
                    info["extents"] = volume_extents(handle)
                finally:
                    close(handle)
            except OSError:
                pass  # no media, optical drive, etc.
            volumes.append(info)
            if not kernel32.FindNextVolumeW(find, buf, 512):
                break
    finally:
        kernel32.FindVolumeClose(find)
    return volumes


def disk_numbers_for_path(path):
    """Physical disk numbers that hold the volume containing a filesystem path (e.g. 'C:\\Windows')."""
    drive = path[:2]
    if len(drive) != 2 or drive[1] != ":":
        return set()
    try:
        handle = open_path("\\\\.\\" + drive, 0)
    except OSError:
        return set()
    try:
        return {disk for disk, _s, _l in volume_extents(handle)}
    except OSError:
        return set()
    finally:
        close(handle)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False
