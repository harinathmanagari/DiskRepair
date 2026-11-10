"""The external-only guard.

Rules, all enforced on the device handle itself (not on cached enumeration data):

1. The disk's bus type must be an external one: USB, SD, MMC or FireWire.
   SATA, NVMe, RAID, SAS, virtual disks and anything unknown are refused.
2. The disk must not hold the Windows volume, the user profile, the temp folder,
   or the folder this program runs from - even if it is on USB (e.g. Windows To Go).
3. Opening for write additionally requires the fingerprint (model + serial + size)
   of the disk the user selected, so a re-plugged device that took the same disk
   number is never written by mistake.

There is deliberately no override switch.
"""

import os
import sys
from dataclasses import dataclass

from . import winapi

BUS_NAMES = {0: "Unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "FireWire", 5: "SSA",
             6: "Fibre Channel", 7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA",
             12: "SD", 13: "MMC", 14: "Virtual", 15: "File-backed virtual",
             16: "Storage Spaces", 17: "NVMe", 18: "SCM", 19: "UFS"}

ALLOWED_BUS_TYPES = frozenset({4, 7, 12, 13})  # FireWire, USB, SD, MMC

MAX_DISKS = 64


class SafetyError(Exception):
    """Raised when an operation would touch a disk that is not a permitted external disk."""


@dataclass(frozen=True)
class DriveIdentity:
    number: int
    bus_type: int
    removable: bool
    vendor: str
    product: str
    serial: str
    size: int
    sector_size: int

    @property
    def bus_name(self):
        return BUS_NAMES.get(self.bus_type, f"bus {self.bus_type}")

    @property
    def model(self):
        return " ".join(p for p in (self.vendor, self.product) if p) or "Unknown device"

    @property
    def fingerprint(self):
        return f"{self.vendor}|{self.product}|{self.serial}|{self.size}"


def identity_from_handle(handle, number=None):
    desc = winapi.storage_descriptor(handle)
    actual = winapi.device_number(handle)
    if number is not None and actual != number:
        raise SafetyError(f"handle for disk {number} resolved to disk {actual}")
    try:
        size, sector = winapi.geometry(handle)
    except OSError:
        size, sector = 0, 512  # no media in the reader
    return DriveIdentity(actual, desc["bus_type"], desc["removable"], desc["vendor"],
                         desc["product"], desc["serial"], size, sector or 512)


def identify_drive(number):
    """Identity of physical disk N using a query-only handle (no data access)."""
    handle = winapi.open_path(rf"\\.\PhysicalDrive{int(number)}", 0)
    try:
        return identity_from_handle(handle, int(number))
    finally:
        winapi.close(handle)


def protected_disk_numbers():
    """Disks that hold the running system or this program. Never touched, whatever their bus."""
    paths = [os.environ.get("SystemRoot", r"C:\Windows"),
             os.environ.get("SystemDrive", "C:") + "\\",
             os.path.expanduser("~"),
             os.environ.get("TEMP", ""),
             os.path.abspath(sys.argv[0] or "."),
             os.path.abspath(__file__),
             os.getcwd()]
    protected = set()
    for path in paths:
        if path:
            protected |= winapi.disk_numbers_for_path(os.path.abspath(path))
    return protected


def refusal_reason(identity, protected=None):
    """None if the disk is a permitted external disk, otherwise why it is refused."""
    if identity.bus_type not in ALLOWED_BUS_TYPES:
        return (f"disk {identity.number} ({identity.model}) is on the {identity.bus_name} bus - "
                "only USB, SD, MMC and FireWire disks may be accessed")
    if protected is None:
        protected = protected_disk_numbers()
    if identity.number in protected:
        return (f"disk {identity.number} ({identity.model}) holds Windows, your user profile "
                "or this program and is protected")
    return None


def verify(identity, expected_fingerprint=None, for_write=False):
    """Raise SafetyError unless this disk may be accessed (and matches the selected device)."""
    reason = refusal_reason(identity)
    if reason:
        raise SafetyError("Refused: " + reason)
    if for_write and not expected_fingerprint:
        raise SafetyError("Refused: write access needs the fingerprint of the selected device")
    if expected_fingerprint and identity.fingerprint != expected_fingerprint:
        raise SafetyError(
            f"Refused: disk {identity.number} is no longer the device that was selected "
            "(it was unplugged or replaced). Refresh the device list and try again.")
    return identity


def verify_number(number, expected_fingerprint=None, for_write=False):
    return verify(identify_drive(number), expected_fingerprint, for_write)


def scan_drives():
    """[(DriveIdentity, refusal_reason_or_None)] for every physical disk present."""
    protected = protected_disk_numbers()
    found = []
    for number in range(MAX_DISKS):
        try:
            ident = identify_drive(number)
        except OSError:
            continue
        found.append((ident, refusal_reason(ident, protected)))
    return found
