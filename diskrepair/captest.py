"""Capacity / write-retention test.

Counterfeit cards report far more space than they have, and worn-out flash controllers
accept writes without storing them. Both look like "corruption" and no format fixes them.
This test writes small marker blocks spread across the whole device, reads them all back,
and (by default) puts the original contents back afterwards.

Fake controllers come in two kinds, and both are caught:
- "limbo": writes past the real capacity are dropped; reads return blank or stale data.
- "wraparound": high address bits are ignored, so the address space repeats with a
  power-of-two period. Probes sit on a power-of-two grid, which guarantees that two of them
  land on the same real block and one marker overwrites the other.
"""

import json
import os
import struct
import time

from . import winapi
from .task import Task, human_size

MIB = 1024 * 1024
PROBE = 64 * 1024


class _WriteProtected(Exception):
    pass


def _pattern(nonce, offset, ss, length):
    out = bytearray()
    for lba in range(offset // ss, (offset + length) // ss):
        unit = nonce + struct.pack("<Q", lba)
        out += (unit * (ss // len(unit) + 1))[:ss]
    return bytes(out)


def _power_of_two_at_most(n):
    return 1 << (max(int(n), 1).bit_length() - 1)


def _round(dev, offsets, probe, task, label, lo, hi, backup, restore):
    """Save originals, write markers, verify, restore. Returns ({offset: status}, alias_spans, restored_ok)."""
    ss = dev.sector_size
    nonce = os.urandom(16)
    n = max(len(offsets), 1)
    span = hi - lo
    originals, status = {}, {}

    for i, off in enumerate(offsets):
        task.progress(lo + span * 0.25 * i / n, f"{label}: saving original contents ({i}/{n})")
        try:
            originals[off] = dev.read(off, probe)
            if backup:
                backup.write(struct.pack("<Q", off) + originals[off])
        except OSError:
            status[off] = "unreadable"
    if backup:
        backup.flush()

    written = []
    for i, off in enumerate(offsets):
        if off not in originals:
            continue
        task.progress(lo + span * (0.25 + 0.25 * i / n), f"{label}: writing test markers ({i}/{n})")
        try:
            dev.write(off, _pattern(nonce, off, ss, probe))
            written.append(off)
        except OSError as exc:
            if getattr(exc, "winerror_code", None) == winapi.ERROR_WRITE_PROTECT and not written:
                raise _WriteProtected() from exc
            status[off] = "write_error"
    dev.flush()

    alias_spans = []
    for i, off in enumerate(written):
        task.progress(lo + span * (0.5 + 0.25 * i / n), f"{label}: verifying markers ({i}/{n})")
        try:
            data = dev.read(off, probe)
        except OSError:
            status[off] = "read_error"
            continue
        if data == _pattern(nonce, off, ss, probe):
            status[off] = "ok"
        elif data == originals[off]:
            status[off] = "stale"
        elif data[:16] == nonce and struct.unpack_from("<Q", data, 16)[0] != off // ss:
            status[off] = "aliased"
            alias_spans.append(abs(struct.unpack_from("<Q", data, 16)[0] * ss - off))
        else:
            status[off] = "garbage"

    restored_ok = None
    if restore:
        failed = 0
        for i, off in enumerate(written):
            task.progress(lo + span * (0.75 + 0.25 * i / n),
                          f"{label}: restoring original contents ({i}/{n})")
            try:
                dev.write(off, originals[off])
            except OSError:
                failed += 1
        dev.flush()
        restored_ok = failed == 0
    return status, alias_spans, restored_ok


def capacity_test(dev, task=None, backup_dir=None, quick=False, restore=True):
    """Returns a dict with 'verdict' in: genuine, fake_capacity, not_storing_writes,
    write_protected, unreliable. For fake_capacity, 'usable_bytes' is the size that was
    verified to store data (use it to format only the real part)."""
    task = task or Task()
    ss = dev.sector_size
    probe = PROBE - PROBE % ss
    if dev.size < probe * 8:
        raise ValueError("device too small to test")
    step = _power_of_two_at_most(dev.size // 32) if quick else 256 * MIB
    step = max(step, probe)
    offsets = sorted(set(range(0, dev.size - probe, step)) | {(dev.size - probe) // ss * ss})

    result = {"probes": len(offsets), "probe_bytes": probe, "size": dev.size, "step": step,
              "real_capacity": dev.size, "usable_bytes": dev.size, "backup": None,
              "restored": None, "counts": {}}
    backup = None
    if backup_dir:
        os.makedirs(backup_dir, exist_ok=True)
        result["backup"] = os.path.join(backup_dir, time.strftime("captest-%Y%m%d-%H%M%S.bin"))
        backup = open(result["backup"], "wb")
    try:
        try:
            status, spans, restored = _round(dev, offsets, probe, task, "Capacity test",
                                             0.0, 0.7, backup, restore)
        except _WriteProtected:
            result["verdict"] = "write_protected"
            result["summary"] = ("The device rejects writes (write-protected). Check the lock "
                                 "switch; if there is none the controller is locked read-only.")
            task.log(result["summary"])
            return result
        result["restored"] = restored
        counts = {}
        for value in status.values():
            counts[value] = counts.get(value, 0) + 1
        result["counts"] = counts
        tested = [o for o in offsets if status.get(o) not in ("unreadable", "write_error")]
        good = [o for o in tested if status[o] == "ok"]
        bad = [o for o in tested if status[o] != "ok"]
        trouble = len(offsets) - len(tested)

        if not tested:
            result["verdict"] = "unreliable"
            result["summary"] = "No test block could be written or read - the device is failing."
        elif not bad and not trouble:
            result["verdict"] = "genuine"
            result["summary"] = (f"All {len(tested)} test blocks across {human_size(dev.size)} "
                                 "were stored and read back correctly. The capacity is real and "
                                 "the device retains writes.")
        elif len(bad) == len(tested) and all(status[o] == "stale" for o in bad):
            result["verdict"] = "not_storing_writes"
            result["real_capacity"] = result["usable_bytes"] = 0
            result["summary"] = ("The device reported every write as successful but kept its old "
                                 "contents. The flash controller has locked itself read-only "
                                 "(worn out). It cannot be formatted or repaired - copy the data "
                                 "off and replace it.")
        elif spans:
            period = min(spans)
            result["verdict"] = "fake_capacity"
            result["kind"] = "wraparound"
            result["real_capacity"] = period
            result["usable_bytes"] = period // MIB * MIB
        elif good and bad and max(good) < min(bad) and not trouble:
            # clean cut: everything below works, everything above does not -> find the edge
            last_good, first_bad = max(good), min(bad)
            fine_step = max(probe, _power_of_two_at_most((first_bad - last_good) // 64))
            fine = list(range(last_good + fine_step, first_bad, fine_step))
            if fine:
                status2, _s, restored2 = _round(dev, fine, probe, task, "Locating real capacity",
                                                0.7, 1.0, backup, restore)
                if restore:
                    result["restored"] = bool(restored and restored2)
                for off in fine:
                    if status2.get(off) == "ok":
                        last_good = off
                    else:
                        first_bad = off
                        break
            result["verdict"] = "fake_capacity"
            result["kind"] = "limbo"
            result["real_capacity"] = first_bad
            result["usable_bytes"] = (last_good + probe) // MIB * MIB
        else:
            result["verdict"] = "unreliable"
            result["summary"] = (f"{len(bad) + trouble} of {len(offsets)} test blocks failed "
                                 f"({counts}). The failures are scattered rather than starting at "
                                 "one point, so the media itself is failing.")
        if result["verdict"] == "fake_capacity":
            result["summary"] = (
                f"The device claims {human_size(dev.size)} but only about "
                f"{human_size(result['real_capacity'])} actually stores data - a counterfeit / "
                "fake-capacity device. Anything written past that point is silently lost, which "
                "is what corrupted it. It can be made usable by formatting only the real "
                f"capacity ({human_size(result['usable_bytes'])}), but do not trust it with "
                "important data.")
    finally:
        if backup:
            backup.close()
    task.progress(1.0, "Capacity test finished", force=True)
    task.log(result["summary"])
    if result["backup"]:
        with open(result["backup"] + ".json", "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    return result
