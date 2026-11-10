"""Command-line front end (the GUI is the main interface; this is for scripting and support).

  python -m diskrepair list
  python -m diskrepair diagnose <disk-number | image-file> [--json FILE] [--deep]
"""

import argparse
import json
import sys

from . import devices, diagnose, scan
from .blockdev import ImageDevice, PhysicalDevice
from .task import Task


def _open(target):
    if target.isdigit():
        info = devices.find_disk(int(target))
        if info is None:
            raise SystemExit(f"Disk {target} is not an accessible external disk.")
        return PhysicalDevice(info.number, expected_fingerprint=info.fingerprint), info.os_summary()
    return ImageDevice(target), None


def cmd_list(_args):
    inv = devices.enumerate_devices()
    print("External disks (accessible):")
    for d in inv.external:
        print("  " + d.title)
        for v in d.volumes:
            print(f"      volume {', '.join(v['letters']) or '(no letter)'}: "
                  f"{v['fs'] or 'RAW / unrecognised'} {v['label']}")
    if not inv.external:
        print("  (none)")
    print("Internal disks (protected, never opened):")
    for ident, reason in inv.protected:
        print(f"  Disk {ident.number}: {ident.model} ({ident.bus_name})")
    for p in inv.pnp_problems:
        print(f"Device problem: {p.get('Name')} [{p.get('Class')}] - {p.get('Status')} {p.get('Problem')}")
    if inv.warning:
        print("Warning:", inv.warning)


def cmd_diagnose(args):
    task = Task(on_log=lambda m: print("  " + m, file=sys.stderr))
    try:
        dev, os_info = _open(args.target)
    except Exception as exc:  # report to the output file too: elevated runs have no visible console
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump({"error": f"{type(exc).__name__}: {exc}"}, f)
        raise
    with dev:
        report = diagnose.diagnose(dev, os_info, task)
        if args.deep:
            report.found = scan.find_partitions(dev, task, deep=True)
        text = report.to_text()
        if args.hexdump:
            try:
                text += "\n\nFirst sector:\n" + _hexdump(dev.read_sectors(0, 1))
            except OSError as exc:
                text += f"\n\nFirst sector unreadable: {exc}"
    print(text)
    if args.json:
        data = report.to_dict()
        data["text"] = text
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)


def _write_target(args):
    """A disk selected for writing must be named by number AND serial, so it cannot be mistaken."""
    info = devices.find_disk(int(args.disk))
    if info is None:
        raise SystemExit(f"Disk {args.disk} is not an accessible external disk.")
    if info.identity.serial != args.serial:
        raise SystemExit(f"Serial mismatch: disk {args.disk} has serial "
                         f"'{info.identity.serial}'. Nothing was written.")
    return info


def _dump(args, data):
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)


def cmd_captest(args):
    from . import captest, repair
    info = _write_target(args)
    task = Task(on_log=print)
    with PhysicalDevice(info.number, write=True, expected_fingerprint=info.fingerprint,
                        log=print) as dev:
        result = captest.capacity_test(dev, task, repair.BACKUP_DIR, quick=not args.thorough)
    print(f"Verdict: {result['verdict']} - usable {result['usable_bytes']} bytes")
    _dump(args, result)


def cmd_format(args):
    from . import repair
    if not args.erase_all_data:
        raise SystemExit("Refusing to format without --erase-all-data.")
    info = _write_target(args)
    result = repair.wipe_and_format(info.number, info.fingerprint, args.fs, args.label,
                                    args.zero_fill, Task(on_log=print),
                                    limit_bytes=args.limit_bytes)
    print(f"Formatted {result['fs']} at {result.get('letter') or '(no letter yet)'}; "
          f"write test {'passed' if result.get('verified') else 'not passed'}")
    _dump(args, result)


def _hexdump(data):
    lines = []
    for i in range(0, len(data), 16):
        row = data[i:i + 16]
        lines.append(f"{i:04x}  {row.hex(' '):<47}  "
                     + "".join(chr(b) if 32 <= b < 127 else "." for b in row))
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="diskrepair", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="list external disks")
    p = sub.add_parser("diagnose", help="read-only diagnosis of a disk or image file")
    p.add_argument("target")
    p.add_argument("--json")
    p.add_argument("--deep", action="store_true", help="also deep-search for lost partitions")
    p.add_argument("--hexdump", action="store_true", help="include a dump of the first sector")
    p = sub.add_parser("captest", help="capacity / write test (writes test blocks, restores them)")
    p.add_argument("disk")
    p.add_argument("--serial", required=True, help="serial of the device, as shown by 'list'")
    p.add_argument("--thorough", action="store_true")
    p.add_argument("--json")
    p = sub.add_parser("format", help="erase and format an external disk")
    p.add_argument("disk")
    p.add_argument("--serial", required=True)
    p.add_argument("--erase-all-data", action="store_true", help="required confirmation")
    p.add_argument("--fs", default="auto", choices=["auto", "fat32", "exfat", "ntfs"])
    p.add_argument("--label", default="")
    p.add_argument("--zero-fill", action="store_true")
    p.add_argument("--limit-bytes", type=int, help="use only the first N bytes (fake-capacity cards)")
    p.add_argument("--json")
    sub.add_parser("gui", help="start the graphical interface (default)")
    args = parser.parse_args(argv)
    if args.command == "list":
        cmd_list(args)
    elif args.command == "diagnose":
        cmd_diagnose(args)
    elif args.command == "captest":
        cmd_captest(args)
    elif args.command == "format":
        cmd_format(args)
    else:
        from . import gui
        gui.main()


if __name__ == "__main__":
    main()
