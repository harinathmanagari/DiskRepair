"""Engine tests on simulated disk images. Run:  python -m unittest discover tests -v

No physical disk is written by these tests. The only real-hardware checks are query-only
(they confirm the safety guard refuses the system disk).
"""

import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from diskrepair import (captest, diagnose, fat32fmt, fsread, layout, repair, rescue, safety,  # noqa: E402
                        scan)
from diskrepair.blockdev import BlockDevice, ImageDevice, PhysicalDevice  # noqa: E402

MIB = 1024 * 1024
JPEG = (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00\x43\x00" + bytes(64)
        + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + b"\x12\x34\xff\x00\x56" * 900 + b"\xff\xd9")
PNG = (b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + bytes(13) + bytes(4)
       + struct.pack(">I", 3000) + b"IDAT" + bytes(range(256)) * 11 + bytes(184) + bytes(4)
       + struct.pack(">I", 0) + b"IEND" + bytes(4))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="diskrepair-test-")
        self.backups = os.path.join(self.tmp, "backups")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def image(self, size_mib=80, name="disk.img"):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.truncate(size_mib * MIB)
        return path

    def fat32_disk(self, size_mib=80):
        """A healthy MBR + FAT32 image with two files and a sub-folder."""
        path = self.image(size_mib)
        with ImageDevice(path, writable=True) as dev:
            res = repair.prepare_disk(dev, "fat32", "TESTVOL", task=None, removable=False,
                                      force_own_fat32=True)
            info = layout.inspect_fs(dev, res["start_lba"], res["sectors"])
            _fat_add(dev, info, [("HELLO.TXT", b"hello world\n" * 500, None),
                                 ("PHOTO.JPG", JPEG, None),
                                 ("DOCS", None, [("NOTE.TXT", b"nested file", None),
                                                 ("IMAGE.PNG", PNG, None)])])
        return path, res


def _fat_add(dev, info, items):
    """Minimal FAT32 writer for test fixtures (contiguous files, 8.3 names)."""
    g = info.details
    bps, spc = g["bps"], g["spc"]
    base = info.start_lba * dev.sector_size
    csize = bps * spc
    state = {"next": 3}

    def set_fat(cluster, value):
        for copy in range(2):
            off = base + (g["reserved"] + copy * g["fat_size"]) * bps + cluster * 4
            dev.write(off, struct.pack("<I", value))

    def alloc(data):
        count = max(1, -(-len(data) // csize))
        first = state["next"]
        state["next"] += count
        for i in range(count):
            set_fat(first + i, first + i + 1 if i < count - 1 else 0x0FFFFFFF)
        dev.write(base + (g["data_start"] + (first - 2) * spc) * bps,
                  data + bytes(count * csize - len(data)))
        return first

    def entry(name, attr, cluster, size):
        stem, _, ext = name.partition(".")
        raw = bytearray(32)
        raw[0:11] = stem.ljust(8).encode() + ext.ljust(3).encode()
        raw[11] = attr
        struct.pack_into("<H", raw, 20, cluster >> 16)
        struct.pack_into("<H", raw, 26, cluster & 0xFFFF)
        struct.pack_into("<I", raw, 28, size)
        return bytes(raw)

    def build(children):
        out = b""
        for name, data, sub in children:
            if sub is None:
                out += entry(name, 0x20, alloc(data), len(data))
            else:
                out += entry(name, 0x10, alloc(build(sub)), 0)
        return out

    root_off = base + (g["data_start"] + (g["root_cluster"] - 2) * spc) * bps
    existing = dev.read(root_off, 32)
    listing = build(items)
    dev.write(root_off + (32 if existing[0] else 0), listing)


def _exfat_image(path, start_lba=2048, size_mib=64):
    """Hand-built exFAT volume: one fragmented file, one contiguous file, one folder."""
    bps, spc = 512, 8
    csize = bps * spc
    with open(path, "wb") as f:
        f.truncate(size_mib * MIB)
    dev = ImageDevice(path, writable=True)
    vol_sectors = dev.sectors - start_lba
    fat_off, fat_len = 128, 64
    heap_off = 256
    clusters = (vol_sectors - heap_off) // spc
    boot = bytearray(bps)
    boot[0:3] = b"\xeb\x76\x90"
    boot[3:11] = b"EXFAT   "
    struct.pack_into("<QQIIIIIIHH", boot, 64, start_lba, vol_sectors, fat_off, fat_len, heap_off,
                     clusters, 4, 0x12345678, 0x0100, 0)
    boot[108], boot[109], boot[110], boot[111] = 9, 3, 1, 0x80
    boot[510:512] = b"\x55\xaa"
    region = bytearray(12 * bps)
    region[0:bps] = boot
    for i in range(1, 9):
        region[i * bps + 510:i * bps + 512] = b"\x55\xaa"
    checksum = layout.exfat_boot_checksum(bytes(region), bps)
    region[11 * bps:12 * bps] = struct.pack("<I", checksum) * (bps // 4)
    base = start_lba * bps
    dev.write(base, bytes(region))
    dev.write(base + 12 * bps, bytes(region))

    fat = bytearray(fat_len * bps)

    def set_fat(c, v):
        struct.pack_into("<I", fat, c * 4, v)

    set_fat(0, 0xFFFFFFF8)
    set_fat(1, 0xFFFFFFFF)
    set_fat(4, 0xFFFFFFFF)                       # root dir

    def put(cluster, data):
        dev.write(base + (heap_off + (cluster - 2) * spc) * bps, data)

    frag = bytes(range(256)) * 16 + b"B" * csize + b"tail-of-fragmented-file"
    # fragmented file: clusters 10 -> 20 -> 11
    for c, nxt, part in ((10, 20, frag[:csize]), (20, 11, frag[csize:2 * csize]),
                         (11, 0xFFFFFFFF, frag[2 * csize:].ljust(csize, b"\x00"))):
        set_fat(c, nxt)
        put(c, part)
    contig = JPEG
    for i in range(-(-len(contig) // csize)):
        put(30 + i, contig[i * csize:(i + 1) * csize].ljust(csize, b"\x00"))
    put(40, b"inside folder".ljust(csize, b"\x00"))

    def entry_set(name, attrs, first, size, flags):
        units = name.encode("utf-16-le")
        names = [units[i:i + 30] for i in range(0, len(units), 30)]
        primary = bytearray(32)
        primary[0], primary[1] = 0x85, 1 + len(names)
        struct.pack_into("<H", primary, 4, attrs)
        stream = bytearray(32)
        stream[0], stream[1], stream[3] = 0xC0, flags, len(name)
        struct.pack_into("<Q", stream, 8, size)
        struct.pack_into("<I", stream, 20, first)
        struct.pack_into("<Q", stream, 24, size)
        out = bytes(primary) + bytes(stream)
        for n in names:
            out += b"\xc1\x00" + n.ljust(30, b"\x00")
        return out

    sub = entry_set("inner note.txt", 0x20, 40, 13, 0x03)
    put(41, sub.ljust(csize, b"\x00"))
    set_fat(41, 0xFFFFFFFF)
    root = (b"\x83\x04" + "EXFT".encode("utf-16-le")).ljust(32, b"\x00")
    root += entry_set("fragmented data file.bin", 0x20, 10, len(frag), 0x01)
    root += entry_set("holiday photo.jpg", 0x20, 30, len(contig), 0x03)
    root += entry_set("My Folder", 0x10, 41, csize, 0x01)
    put(4, root.ljust(csize, b"\x00"))
    dev.write(base + fat_off * bps, bytes(fat))
    dev.write(0, layout.build_mbr([(start_lba, vol_sectors, 0x07)]))
    dev.close()
    return frag, contig


class FlakyDevice(BlockDevice):
    """Wraps an image and makes chosen byte ranges unreadable."""

    def __init__(self, inner, bad):
        self.inner, self.bad = inner, bad
        self.size, self.sector_size, self.name = inner.size, inner.sector_size, "flaky"

    def read(self, offset, length):
        for start, n in self.bad:
            if offset < start + n and start < offset + length:
                raise OSError("simulated unreadable sector")
        return self.inner.read(offset, length)


class FakeCapacityDevice(BlockDevice):
    """Claims `size` bytes but only the first `real` bytes store data; the rest wraps around."""
    writable = True

    def __init__(self, size, real, wrap=True):
        self.size, self.real, self.wrap = size, real, wrap
        self.sector_size, self.name = 512, "fake"
        self.store = bytearray(real)

    def read(self, offset, length):
        if offset + length <= self.real:
            return bytes(self.store[offset:offset + length])
        if self.wrap:
            pos = offset % self.real
            return bytes((self.store + self.store)[pos:pos + length])
        return b"\xff" * length

    def write(self, offset, data):
        if offset + len(data) <= self.real:
            self.store[offset:offset + len(data)] = data
        elif self.wrap:
            pos = offset % self.real
            n = min(len(data), self.real - pos)
            self.store[pos:pos + n] = data[:n]


class StuckDevice(FakeCapacityDevice):
    """Accepts writes and silently discards them (a controller locked read-only)."""

    def write(self, offset, data):
        pass


# ---------------------------------------------------------------------------------------------

class SafetyTests(unittest.TestCase):
    def test_internal_buses_are_refused(self):
        for bus in (0, 1, 2, 3, 8, 10, 11, 14, 15, 16, 17):
            ident = safety.DriveIdentity(5, bus, False, "V", "P", "S", 10 ** 9, 512)
            self.assertIsNotNone(safety.refusal_reason(ident, protected=set()), bus)

    def test_external_buses_allowed_unless_protected(self):
        for bus in (4, 7, 12, 13):
            ident = safety.DriveIdentity(5, bus, True, "V", "P", "S", 10 ** 9, 512)
            self.assertIsNone(safety.refusal_reason(ident, protected=set()))
            self.assertIsNotNone(safety.refusal_reason(ident, protected={5}))

    def test_write_needs_matching_fingerprint(self):
        ident = safety.DriveIdentity(5, 7, True, "V", "P", "S", 10 ** 9, 512)
        with self.assertRaises(safety.SafetyError):
            safety.verify(ident, None, for_write=True)
        with self.assertRaises(safety.SafetyError):
            safety.verify(ident, "V|P|OTHER|1", for_write=True)

    @unittest.skipUnless(sys.platform == "win32", "Windows only")
    def test_real_system_disk_is_refused(self):
        protected = safety.protected_disk_numbers()
        self.assertTrue(protected, "could not locate the system disk")
        for number in protected:
            ident = safety.identify_drive(number)          # query-only handle
            self.assertIsNotNone(safety.refusal_reason(ident))
            with self.assertRaises(safety.SafetyError):
                PhysicalDevice(number)
            with self.assertRaises(safety.SafetyError):
                PhysicalDevice(number, write=True, expected_fingerprint=ident.fingerprint)

    @unittest.skipUnless(sys.platform == "win32", "Windows only")
    def test_every_non_external_disk_is_refused(self):
        for ident, reason in safety.scan_drives():
            if ident.bus_type not in safety.ALLOWED_BUS_TYPES:
                self.assertIsNotNone(reason)
                with self.assertRaises(safety.SafetyError):
                    PhysicalDevice(ident.number)


class FormatAndDiagnoseTests(Base):
    def test_fresh_fat32_is_healthy(self):
        path, res = self.fat32_disk()
        with ImageDevice(path) as dev:
            rep = diagnose.diagnose(dev)
            self.assertEqual(rep.scheme, "MBR")
            self.assertEqual(len(rep.filesystems), 1)
            fs = rep.filesystems[0]
            self.assertEqual((fs.fs, fs.label, fs.healthy, fs.backup_ok, fs.backup_matches),
                             ("FAT32", "TESTVOL", True, True, True))
            self.assertFalse([f for f in rep.findings if f.severity in ("error", "critical")])

    def test_fat32_geometry_is_consistent(self):
        for sectors in (200_000, 4_000_000, 62_000_000, 500_000_000, 4_000_000_000):
            geo = fat32fmt.plan(sectors)
            self.assertGreaterEqual(geo["fat_size"] * 512 // 4, geo["clusters"] + 2)
            self.assertLessEqual(geo["data_start"] + geo["clusters"] * geo["spc"], sectors)
            self.assertEqual(geo["data_start"] % geo["spc"], 0)
            self.assertGreaterEqual(geo["clusters"], 65525)

    def test_blank_device(self):
        with ImageDevice(self.image(16)) as dev:
            rep = diagnose.diagnose(dev)
            self.assertEqual(rep.scheme, "none")
            self.assertTrue(rep.has("no_table") and rep.has("all_blank"))
            self.assertIn("format", rep.recommended)

    def test_installer_image_is_recognised_as_not_damaged(self):
        path = self.image(16)
        with ImageDevice(path, writable=True) as dev:
            dev.write(0, layout.build_mbr([(64, 8192, 0x17)]))
            dev.write(32768, b"\x01CD001\x01" + bytes(505))
            rep = diagnose.diagnose(dev)
            self.assertTrue(rep.has("iso_image"))
            self.assertIn("not damaged", rep.verdict)
            self.assertIn("format", rep.recommended)

    def test_signature_with_empty_table(self):
        path = self.image(16)
        with ImageDevice(path, writable=True) as dev:
            dev.write(0, bytes(510) + b"\x55\xaa")
            rep = diagnose.diagnose(dev)
            self.assertTrue(rep.has("empty_table"))
            self.assertIn("format", rep.recommended)

    def test_device_smaller_than_its_partition(self):
        path, res = self.fat32_disk(80)
        with open(path, "r+b") as f:
            f.truncate(40 * MIB)                      # the "device" shrank under its partition
        with ImageDevice(path) as dev:
            rep = diagnose.diagnose(dev)
            self.assertTrue(rep.has("bad_partition_entry"))
            self.assertIn("capacity_test", rep.recommended)
            self.assertTrue(any("past the end" in p for f in rep.filesystems for p in f.problems))

    def test_gpt_roundtrip(self):
        path = self.image(64)
        with ImageDevice(path, writable=True) as dev:
            for lba, data in layout.build_gpt(dev.sectors, 512, [(2048, 100000, "Data")]).items():
                dev.write_sectors(lba, data)
            gpt = layout.parse_gpt(dev)
            self.assertTrue(gpt.primary_ok and gpt.backup_ok)
            self.assertEqual([(p.start_lba, p.sectors, p.name) for p in gpt.entries],
                             [(2048, 100000, "Data")])
            dev.write_sectors(1, bytes(512))            # destroy the primary header
            gpt = layout.parse_gpt(dev)
            self.assertTrue(not gpt.primary_ok and gpt.backup_ok and len(gpt.entries) == 1)


class RepairTests(Base):
    def test_lost_partition_table_is_rebuilt(self):
        path, res = self.fat32_disk()
        with ImageDevice(path, writable=True) as dev:
            dev.write(0, bytes(512))                                    # wipe the MBR
            rep = diagnose.diagnose(dev)
            self.assertTrue(rep.has("lost_partition"))
            self.assertEqual(rep.recommended[0], "rebuild_table")
            scheme = repair.rebuild_partition_table(dev, rep.found, backup_dir=self.backups)
            self.assertEqual(scheme, "MBR")
            rep = diagnose.diagnose(dev)
            self.assertEqual(rep.scheme, "MBR")
            self.assertEqual(rep.partitions[0].start_lba, res["start_lba"])
            self.assertTrue(rep.filesystems[0].healthy)

    def test_damaged_boot_sector_restored_and_undone(self):
        path, res = self.fat32_disk()
        start = res["start_lba"]
        with ImageDevice(path, writable=True) as dev:
            good = dev.read_sectors(start, 1)
            dev.write_sectors(start, os.urandom(512))
            rep = diagnose.diagnose(dev)
            self.assertTrue(rep.has("boot_damaged"))
            self.assertIn("restore_boot", rep.recommended)
            repair.restore_boot_sector(dev, start, res["sectors"], backup_dir=self.backups,
                                       fingerprint="fp")
            self.assertEqual(dev.read_sectors(start, 1), good)
            self.assertTrue(diagnose.diagnose(dev).filesystems[0].healthy)
            backups = repair.list_backups("fp", self.backups)
            self.assertEqual(len(backups), 1)
            repair.undo_backup(dev, backups[0])                         # undo puts damage back
            self.assertNotEqual(dev.read_sectors(start, 1), good)

    def test_lost_table_and_boot_sector_together(self):
        path, res = self.fat32_disk()
        start = res["start_lba"]
        with ImageDevice(path, writable=True) as dev:
            dev.write(0, bytes(512))
            dev.write_sectors(start, bytes(512))
            found = scan.find_partitions(dev)
            self.assertEqual([(f.start_lba, f.fs, f.from_backup) for f in found],
                             [(start, "FAT32", True)])
            repair.rebuild_partition_table(dev, found, backup_dir=self.backups)
            repair.restore_boot_sector(dev, start, res["sectors"], backup_dir=self.backups)
            rep = diagnose.diagnose(dev)
            self.assertTrue(rep.filesystems and rep.filesystems[0].healthy)

    def test_deep_search_finds_oddly_placed_partition(self):
        path, res = self.fat32_disk(120)
        moved = self.image(160, "moved.img")
        offset = 37 * MIB                                   # not one of the quick-scan offsets
        with open(path, "rb") as src, open(moved, "r+b") as dst:
            src.seek(res["start_lba"] * 512)
            dst.seek(offset)
            dst.write(src.read(res["sectors"] * 512))
        with ImageDevice(moved) as dev:
            self.assertEqual(scan.find_partitions(dev, deep=False), [])
            found = scan.find_partitions(dev, deep=True)
            self.assertEqual([(f.start_lba, f.fs) for f in found], [(offset // 512, "FAT32")])

    def test_write_that_does_not_stick_is_detected(self):
        dev = StuckDevice(64 * MIB, 64 * MIB)
        with self.assertRaises(repair.RepairError) as ctx:
            repair.prepare_disk(dev, "fat32", "X", removable=True, force_own_fat32=True)
        self.assertIn("not storing writes", str(ctx.exception))

    def test_ntfs_backup_boot_detection(self):
        path = self.image(64)
        start, total = 2048, 100000
        boot = bytearray(512)
        boot[0:3] = b"\xeb\x52\x90"
        boot[3:11] = b"NTFS    "
        struct.pack_into("<HB", boot, 11, 512, 8)
        struct.pack_into("<I", boot, 28, start)
        struct.pack_into("<QQQ", boot, 40, total - 1, 4, 8)
        boot[510:512] = b"\x55\xaa"
        with ImageDevice(path, writable=True) as dev:
            dev.write(0, layout.build_mbr([(start, total, 0x07)]))
            dev.write_sectors(start + total - 1, bytes(boot))          # only the backup survives
            dev.write_sectors(start + 4 * 8, b"FILE" + bytes(508))
            rep = diagnose.diagnose(dev)
            self.assertTrue(rep.has("boot_damaged"))
            repair.restore_boot_sector(dev, start, total, backup_dir=self.backups)
            fs = diagnose.diagnose(dev).filesystems[0]
            self.assertEqual((fs.fs, fs.healthy, fs.backup_ok), ("NTFS", True, True))


class RecoveryTests(Base):
    def test_fat32_extraction(self):
        path, res = self.fat32_disk()
        out = os.path.join(self.tmp, "out")
        with ImageDevice(path) as dev:
            info = layout.inspect_fs(dev, res["start_lba"], res["sectors"])
            stats = fsread.extract_all(fsread.open_reader(dev, info), out)
        self.assertEqual((stats["files"], stats["failed"], stats["suspect"]), (4, 0, 0))
        with open(os.path.join(out, "PHOTO.JPG"), "rb") as f:
            self.assertEqual(f.read(), JPEG)
        with open(os.path.join(out, "DOCS", "IMAGE.PNG"), "rb") as f:
            self.assertEqual(f.read(), PNG)
        with open(os.path.join(out, "HELLO.TXT"), "rb") as f:
            self.assertEqual(f.read(), b"hello world\n" * 500)

    def test_fat32_extraction_with_destroyed_fat(self):
        path, res = self.fat32_disk()
        out = os.path.join(self.tmp, "out")
        with ImageDevice(path, writable=True) as dev:
            info = layout.inspect_fs(dev, res["start_lba"], res["sectors"])
            g = info.details
            fat = (res["start_lba"] + g["reserved"]) * 512
            dev.write(fat + 12, bytes(4096))            # zero the chains, keep the root entry
            stats = fsread.extract_all(fsread.open_reader(dev, info), out)
        self.assertEqual(stats["files"], 4)
        self.assertGreater(stats["suspect"], 0)
        with open(os.path.join(out, "HELLO.TXT"), "rb") as f:   # contiguous fallback still correct
            self.assertEqual(f.read(), b"hello world\n" * 500)

    def test_exfat_diagnose_and_extract(self):
        path = os.path.join(self.tmp, "exfat.img")
        frag, contig = _exfat_image(path)
        out = os.path.join(self.tmp, "out")
        with ImageDevice(path) as dev:
            rep = diagnose.diagnose(dev)
            fs = rep.filesystems[0]
            self.assertEqual((fs.fs, fs.healthy, fs.backup_ok, fs.backup_matches),
                             ("exFAT", True, True, True), fs.problems)
            stats = fsread.extract_all(fsread.open_reader(dev, fs), out)
        self.assertEqual((stats["files"], stats["failed"], stats["suspect"]), (3, 0, 0))
        with open(os.path.join(out, "fragmented data file.bin"), "rb") as f:
            self.assertEqual(f.read(), frag)
        with open(os.path.join(out, "holiday photo.jpg"), "rb") as f:
            self.assertEqual(f.read(), contig)
        with open(os.path.join(out, "My Folder", "inner note.txt"), "rb") as f:
            self.assertEqual(f.read(), b"inside folder")

    def test_exfat_boot_restore(self):
        path = os.path.join(self.tmp, "exfat.img")
        _exfat_image(path)
        with ImageDevice(path, writable=True) as dev:
            dev.write_sectors(2048, bytes(512 * 3))
            rep = diagnose.diagnose(dev)
            self.assertTrue(rep.has("boot_damaged"))
            repair.restore_boot_sector(dev, 2048, dev.sectors - 2048, backup_dir=self.backups)
            self.assertTrue(diagnose.diagnose(dev).filesystems[0].healthy)

    def test_carving_without_filesystem(self):
        path = self.image(32)
        with ImageDevice(path, writable=True) as dev:
            dev.write(5 * MIB, JPEG)
            dev.write(9 * MIB + 512 * 7, PNG)
            dev.write(20 * MIB, JPEG)
        out = os.path.join(self.tmp, "carved")
        with ImageDevice(path) as dev:
            stats = rescue.carve_files(dev, out, min_size=100)
        self.assertEqual(stats["by_type"], {"jpg": 2, "png": 1})
        sizes = sorted(os.path.getsize(os.path.join(out, n)) for n in os.listdir(out))
        self.assertEqual(sizes, sorted([len(JPEG), len(JPEG), len(PNG)]))

    def test_imaging_skips_bad_areas(self):
        path, _ = self.fat32_disk(40)
        out = os.path.join(self.tmp, "rescue.img")
        with ImageDevice(path) as inner:
            bad = [(10 * MIB + 4096, 8192)]
            summary = rescue.image_device(FlakyDevice(inner, bad), out)
            self.assertEqual(summary["bad_ranges"], [[10 * MIB + 4096, 8192]])
            with open(out, "rb") as f:
                copy = f.read()
            original = inner.read(0, inner.size)
        self.assertEqual(len(copy), len(original))
        self.assertEqual(copy[:10 * MIB + 4096], original[:10 * MIB + 4096])
        self.assertEqual(copy[10 * MIB + 12288:], original[10 * MIB + 12288:])

    def test_surface_scan_maps_bad_ranges(self):
        with ImageDevice(self.image(24)) as inner:
            result = scan.surface_scan(FlakyDevice(inner, [(7 * MIB + 65536, 65536)]))
        self.assertEqual(result.bad_ranges, [(7 * MIB + 65536, 65536)])

    def test_destination_on_same_disk_is_refused(self):
        here = winapi_disk = None
        from diskrepair import winapi
        disks = winapi.disk_numbers_for_path(self.tmp)
        if not disks:
            self.skipTest("cannot map temp folder to a disk")
        with self.assertRaises(rescue.RescueError):
            rescue.check_destination(self.tmp, next(iter(disks)))


class CapacityTests(Base):
    def test_genuine_device_passes_and_is_restored(self):
        dev = FakeCapacityDevice(512 * MIB, 512 * MIB)
        dev.store[:] = os.urandom(1024) * (512 * 1024)
        before = bytes(dev.store)
        result = captest.capacity_test(dev, backup_dir=self.backups, quick=True)
        self.assertEqual(result["verdict"], "genuine")
        self.assertEqual(bytes(dev.store), before)

    def test_wraparound_fake_is_detected(self):
        dev = FakeCapacityDevice(2048 * MIB, 256 * MIB, wrap=True)
        result = captest.capacity_test(dev, quick=True)
        self.assertEqual(result["verdict"], "fake_capacity")

    def test_discarding_fake_is_detected(self):
        dev = FakeCapacityDevice(2048 * MIB, 256 * MIB, wrap=False)
        result = captest.capacity_test(dev, quick=True)
        self.assertEqual(result["verdict"], "fake_capacity")
        self.assertLessEqual(result["real_capacity"], 320 * MIB)

    def test_fake_device_formatted_to_real_capacity(self):
        dev = FakeCapacityDevice(2048 * MIB, 300 * MIB, wrap=False)
        result = captest.capacity_test(dev, quick=True)
        self.assertEqual((result["verdict"], result["kind"]), ("fake_capacity", "limbo"))
        self.assertLessEqual(result["usable_bytes"], 300 * MIB)
        self.assertGreater(result["usable_bytes"], 280 * MIB)        # edge located precisely
        res = repair.prepare_disk(dev, "fat32", "REAL", removable=True, force_own_fat32=True,
                                  limit_bytes=result["usable_bytes"])
        self.assertLessEqual((res["start_lba"] + res["sectors"]) * 512, result["usable_bytes"])
        fs = diagnose.diagnose(dev, search=False).filesystems[0]
        self.assertEqual((fs.fs, fs.healthy, fs.label), ("FAT32", True, "REAL"))

    def test_stuck_controller_is_detected(self):
        result = captest.capacity_test(StuckDevice(256 * MIB, 256 * MIB), quick=True)
        self.assertEqual(result["verdict"], "not_storing_writes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
