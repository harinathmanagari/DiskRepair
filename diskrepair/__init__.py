"""DiskRepair - diagnose, rescue and repair external storage (USB disks, flash drives, SD cards).

Every raw access goes through diskrepair.safety, which refuses any disk that is
not attached over an external bus or that hosts the running system.
"""

__version__ = "1.0.0"
