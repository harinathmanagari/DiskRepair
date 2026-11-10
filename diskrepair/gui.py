"""Desktop interface (tkinter). All disk work runs on a worker thread; the UI only renders."""

import ctypes
import os
import queue
import sys
import threading
import time
import tkinter as tk
import traceback
from tkinter import filedialog, messagebox, ttk

from . import __version__, captest, devices, diagnose, fsread, repair, rescue, safety, scan, winapi
from .blockdev import ImageDevice, PhysicalDevice
from .task import Cancelled, Task, human_size

LOG_DIR = os.path.join(repair.DATA_DIR, "logs")
SEV_LABEL = {"critical": "CRITICAL", "error": "PROBLEM", "warn": "WARNING", "info": "NOTE", "ok": "OK"}
SEV_COLOR = {"critical": "#b00020", "error": "#c2410c", "warn": "#a16207", "info": "#1d4ed8",
             "ok": "#15803d"}

# id, tab, title, risk, description
ACTIONS = [
    ("clear_readonly", "Repair", "Clear write protection", "Changes disk flags",
     "Clears the read-only and offline flags Windows holds for the disk and its volumes."),
    ("chkdsk", "Repair", "Repair filesystem (CHKDSK)", "Modifies the filesystem",
     "Runs Windows CHKDSK on the volume to fix directory and allocation errors."),
    ("restore_boot", "Repair", "Restore boot sector from backup", "Small write, undoable",
     "Copies the intact backup boot sector over a damaged primary one. Fixes most 'RAW' / "
     "'needs formatting' volumes without losing files."),
    ("deep_search", "Repair", "Deep search for lost partitions", "Read-only",
     "Checks every 1 MiB boundary of the device for filesystems missing from the partition table."),
    ("rebuild_table", "Repair", "Rebuild partition table", "Small write, undoable",
     "Writes a new partition table pointing at the filesystems found. Files are not touched."),
    ("undo", "Repair", "Undo last boot-sector / table change", "Small write",
     "Puts back the sectors saved before the most recent metadata repair on this device."),
    ("format", "Repair", "Erase and format", "ERASES ALL DATA",
     "Wipes old structures, creates a fresh partition and filesystem, then verifies the device "
     "stores data. Includes FAT32 for cards above 32 GB, which Windows itself refuses to create."),
    ("rescue_image", "Recover data", "Save rescue image", "Read-only",
     "Copies every readable sector to an image file on another disk, skipping and retrying bad "
     "areas. Do this first on a failing device."),
    ("extract_files", "Recover data", "Copy files out (built-in reader)", "Read-only",
     "Reads FAT / exFAT directly and copies your files with their names and folders - works when "
     "Windows cannot mount the volume. Can include deleted files."),
    ("carve", "Recover data", "Recover files by signature", "Read-only",
     "Scans raw sectors for photos, videos, PDFs and Office files when no filesystem survives. "
     "Names are lost; fragmented files may come out damaged."),
    ("surface_scan", "Test", "Full surface scan", "Read-only",
     "Reads the whole device and maps unreadable areas."),
    ("capacity_test", "Test", "Capacity and write test", "Writes test blocks, then restores them",
     "Detects counterfeit (fake-capacity) cards and controllers that accept writes without "
     "storing them - faults that no format can fix."),
]
ACTION_TITLE = {a[0]: a[2] for a in ACTIONS}


def _relaunch_elevated():
    exe = sys.executable
    pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(pythonw):
        exe = pythonw
    launcher = os.path.join(repair.APP_DIR, "DiskRepair.pyw")
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, f'"{launcher}"',
                                             repair.APP_DIR, 1)
    return rc > 32


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"DiskRepair {__version__} - external drives only")
        self.geometry("1180x780")
        self.minsize(980, 640)
        self.events = queue.Queue()
        self.job = None            # (thread, Task, title)
        self.inventory = None
        self.selected = None       # devices.DiskInfo
        self.reports = {}          # fingerprint -> diagnose.Report
        self.capacity = {}         # fingerprint -> last capacity test result
        self.action_buttons = []
        self.admin = winapi.is_admin()
        self._refreshing = False
        self._build()
        self.after(80, self._pump)
        self.after(150, self.refresh)

    # ------------------------------------------------------------------ layout
    def _build(self):
        style = ttk.Style(self)
        style.configure("Title.TLabel", font=("Segoe UI", 13, "bold"))
        style.configure("Card.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("Risk.TLabel", foreground="#6b7280")
        style.configure("Danger.TLabel", foreground="#b00020", font=("Segoe UI", 9, "bold"))
        style.configure("Verdict.TLabel", font=("Segoe UI", 10, "bold"), wraplength=760)

        top = ttk.Frame(self, padding=(12, 10, 12, 4))
        top.pack(fill="x")
        ttk.Label(top, text="DiskRepair", style="Title.TLabel").pack(side="left")
        self.guard_label = ttk.Label(top, text="", foreground="#15803d")
        self.guard_label.pack(side="left", padx=16)
        if not self.admin:
            ttk.Label(top, text="Not running as administrator - disk access is unavailable",
                      foreground="#b00020").pack(side="right")

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=12, pady=4)

        left = ttk.Frame(body)
        body.add(left, weight=1)
        ttk.Label(left, text="External devices", style="Card.TLabel").pack(anchor="w")
        self.device_list = tk.Listbox(left, height=8, exportselection=False, activestyle="none",
                                      font=("Segoe UI", 10))
        self.device_list.pack(fill="x", pady=(4, 4))
        self.device_list.bind("<<ListboxSelect>>", lambda _e: self._on_select())
        ttk.Button(left, text="Refresh device list", command=self.refresh).pack(fill="x")
        ttk.Label(left, text="Device details", style="Card.TLabel").pack(anchor="w", pady=(12, 0))
        self.details = tk.Text(left, height=14, width=44, wrap="word", relief="flat",
                               background=self.cget("background"), font=("Segoe UI", 9))
        self.details.pack(fill="both", expand=True, pady=(4, 0))
        self.details.configure(state="disabled")

        right = ttk.Frame(body)
        body.add(right, weight=3)
        self.tabs = ttk.Notebook(right)
        self.tabs.pack(fill="both", expand=True)
        self._build_diagnosis_tab()
        for tab in ("Repair", "Recover data", "Test"):
            self._build_action_tab(tab)

        bottom = ttk.Frame(self, padding=(12, 4, 12, 10))
        bottom.pack(fill="x")
        row = ttk.Frame(bottom)
        row.pack(fill="x")
        self.progress = ttk.Progressbar(row, maximum=1000)
        self.progress.pack(side="left", fill="x", expand=True)
        self.cancel_button = ttk.Button(row, text="Cancel", command=self._cancel, state="disabled")
        self.cancel_button.pack(side="left", padx=(8, 0))
        self.status = ttk.Label(bottom, text="Ready")
        self.status.pack(anchor="w", pady=(2, 4))
        self.log = tk.Text(bottom, height=9, wrap="word", font=("Consolas", 9), state="disabled")
        self.log.pack(fill="x")

    def _build_diagnosis_tab(self):
        tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(tab, text="Diagnosis")
        head = ttk.Frame(tab)
        head.pack(fill="x")
        btn = ttk.Button(head, text="Run diagnosis (read-only)", command=self.act_diagnose)
        btn.pack(side="left")
        self.action_buttons.append(btn)
        ttk.Label(head, text="Reads the device without changing anything on it.",
                  style="Risk.TLabel").pack(side="left", padx=10)
        self.verdict = ttk.Label(tab, text="Select a device and run the diagnosis.",
                                 style="Verdict.TLabel")
        self.verdict.pack(anchor="w", pady=(10, 6))
        self.findings = ttk.Treeview(tab, columns=("sev", "title"), show="headings", height=9)
        self.findings.heading("sev", text="Level")
        self.findings.heading("title", text="Finding")
        self.findings.column("sev", width=90, stretch=False)
        self.findings.column("title", width=640)
        for sev, color in SEV_COLOR.items():
            self.findings.tag_configure(sev, foreground=color)
        self.findings.pack(fill="both", expand=True)
        self.findings.bind("<<TreeviewSelect>>", lambda _e: self._show_finding())
        self.finding_detail = tk.Text(tab, height=5, wrap="word", font=("Segoe UI", 9),
                                      state="disabled")
        self.finding_detail.pack(fill="x", pady=(6, 6))
        ttk.Label(tab, text="Recommended steps, in order", style="Card.TLabel").pack(anchor="w")
        self.recommend_frame = ttk.Frame(tab)
        self.recommend_frame.pack(fill="x", pady=(4, 0))
        ttk.Button(tab, text="Show full technical report",
                   command=self._show_report).pack(anchor="e", pady=(6, 0))

    def _build_action_tab(self, name):
        tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(tab, text=name)
        for action_id, group, title, risk, text in ACTIONS:
            if group != name:
                continue
            card = ttk.Frame(tab, padding=(0, 5))
            card.pack(fill="x")
            btn = ttk.Button(card, text=title, width=36,
                             command=lambda a=action_id: self.run_action(a))
            btn.pack(side="left", anchor="n")
            self.action_buttons.append(btn)
            info = ttk.Frame(card)
            info.pack(side="left", fill="x", expand=True, padx=10)
            ttk.Label(info, text=risk,
                      style="Danger.TLabel" if "ERASE" in risk else "Risk.TLabel").pack(anchor="w")
            ttk.Label(info, text=text, wraplength=520, justify="left").pack(anchor="w")
        if name == "Recover data":
            self.include_deleted = tk.BooleanVar(value=False)
            ttk.Checkbutton(tab, text="Also recover deleted files when copying files out",
                            variable=self.include_deleted).pack(anchor="w", pady=(10, 0))
            self.image_source = tk.StringVar(value="")
            row = ttk.Frame(tab)
            row.pack(fill="x", pady=(8, 0))
            ttk.Label(row, text="Recover from a saved rescue image instead of the device:").pack(
                anchor="w")
            ttk.Entry(row, textvariable=self.image_source).pack(side="left", fill="x", expand=True)
            ttk.Button(row, text="Browse...", command=self._pick_image).pack(side="left", padx=4)
            ttk.Button(row, text="Clear", command=lambda: self.image_source.set("")).pack(side="left")
        if name == "Test":
            self.full_captest = tk.BooleanVar(value=False)
            ttk.Checkbutton(tab, text="Thorough capacity test (one probe every 256 MB instead of "
                                      "32 probes in total)",
                            variable=self.full_captest).pack(anchor="w", pady=(10, 0))

    # ------------------------------------------------------------------ plumbing
    def _log(self, message):
        stamp = time.strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"{stamp}  {message}\n")
        self.log.see("end")
        self.log.configure(state="disabled")
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            with open(os.path.join(LOG_DIR, time.strftime("diskrepair-%Y%m%d.log")), "a",
                      encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d')} {stamp}  {message}\n")
        except OSError:
            pass

    def _set_text(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _pump(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "progress":
                    self.progress["value"] = int(event[1] * 1000)
                    if event[2]:
                        self.status.configure(text=event[2])
                elif kind == "log":
                    self._log(event[1])
                elif kind == "finished":
                    self._job_finished(*event[1:])
                elif kind == "inventory":
                    self._apply_inventory(*event[1:])
        except queue.Empty:
            pass
        self.after(80, self._pump)

    def run_job(self, title, func, on_done=None):
        """Run func(task) on a worker thread. on_done(result) runs on the UI thread on success."""
        if self.job:
            messagebox.showinfo("Busy", "Another operation is still running.")
            return
        task = Task(on_progress=lambda f, m: self.events.put(("progress", f, m)),
                    on_log=lambda m: self.events.put(("log", m)))

        def worker():
            try:
                result = func(task)
                self.events.put(("finished", title, "ok", result, on_done))
            except Cancelled:
                self.events.put(("finished", title, "cancelled", None, None))
            except (safety.SafetyError, repair.RepairError, rescue.RescueError) as exc:
                self.events.put(("finished", title, "error", str(exc), None))
            except PermissionError as exc:
                self.events.put(("finished", title, "error",
                                 f"Access denied ({exc}). DiskRepair must run as administrator, "
                                 "and no other program may be using the device.", None))
            except Exception as exc:  # surfaced to the user; details go to the log
                self.events.put(("log", traceback.format_exc()))
                self.events.put(("finished", title, "error", f"{type(exc).__name__}: {exc}", None))

        self._log(f"--- {title} ---")
        self.status.configure(text=title + "...")
        self.progress["value"] = 0
        for b in self.action_buttons:
            b.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        thread = threading.Thread(target=worker, daemon=True)
        self.job = (thread, task, title)
        thread.start()

    def _job_finished(self, title, outcome, result, on_done):
        self.job = None
        for b in self.action_buttons:
            b.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        if outcome == "ok":
            self.progress["value"] = 1000
            self.status.configure(text=f"{title}: done")
            if on_done:
                on_done(result)
        elif outcome == "cancelled":
            self.status.configure(text=f"{title}: cancelled")
            self._log(f"{title} was cancelled.")
        else:
            self.status.configure(text=f"{title}: failed")
            self._log(f"{title} FAILED: {result}")
            messagebox.showerror(title, result)

    def _cancel(self):
        if self.job:
            self.job[1].cancel()
            self.status.configure(text="Cancelling...")

    # ------------------------------------------------------------------ devices
    def refresh(self, then=None):
        """Re-enumerate devices on a background thread; `then()` runs once the list is updated."""
        if self._refreshing:
            return
        self._refreshing = True
        previous = self.selected.fingerprint if self.selected else None
        self.status.configure(text="Looking for external devices...")

        def worker():
            try:
                inv = devices.enumerate_devices()
            except Exception as exc:
                inv = f"Device enumeration failed: {exc}"
            self.events.put(("inventory", inv, previous, then))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_inventory(self, inv, previous, then):
        self._refreshing = False
        if isinstance(inv, str):
            self._log(inv)
            return
        self.inventory = inv
        if not self.job:
            self.status.configure(text="Ready")
        self.device_list.delete(0, "end")
        for d in inv.external:
            self.device_list.insert("end", "  " + d.title)
        hidden = len(inv.protected)
        self.guard_label.configure(
            text=f"Safety guard active: {hidden} internal disk(s) hidden and locked out")
        self.selected = None
        for i, d in enumerate(inv.external):
            if d.fingerprint == previous or (previous is None and len(inv.external) == 1):
                self.device_list.selection_set(i)
                self.selected = d
        if not inv.external:
            text = "No external storage device with media was found.\n\n"
            if inv.pnp_problems:
                text += "Windows reports problems with these devices:\n" + "\n".join(
                    f"  - {p.get('Name') or p.get('InstanceId')} ({p.get('Status')}, "
                    f"{p.get('Problem')})" for p in inv.pnp_problems)
                text += ("\n\nA device that fails at this level is not answering on the USB bus. "
                         "Try another port, cable or card reader. If it never appears in this "
                         "list, its controller is dead and software cannot reach it.")
            else:
                text += ("If a device is plugged in but missing here, it is not answering on the "
                         "bus at all. Try another USB port, cable, or card reader.")
            self._set_text(self.details, text)
        self._on_select()
        if inv.warning:
            self._log(inv.warning)
        if then:
            then()

    def _on_select(self):
        sel = self.device_list.curselection()
        if sel and self.inventory:
            self.selected = self.inventory.external[sel[0]]
        d = self.selected
        if not d:
            self._render_report(None)
            return
        ident = d.identity
        lines = [ident.model, f"Disk number: {d.number}", f"Connection: {ident.bus_name}"
                 f"{' (removable media)' if ident.removable else ''}",
                 f"Capacity: {human_size(ident.size) if ident.size else 'no media'}",
                 f"Serial: {ident.serial or 'n/a'}",
                 f"Windows status: {d.os.get('OperationalStatus', '?')}, "
                 f"health {d.os.get('HealthStatus', '?')}",
                 f"Partition style: {d.os.get('PartitionStyle', '?')}",
                 f"Read-only: {'yes' if d.os.get('IsReadOnly') else 'no'}", "", "Volumes:"]
        for v in d.volumes:
            lines.append(f"  {', '.join(v['letters']) or '(no drive letter)'}: "
                         f"{v['fs'] or 'RAW / unreadable'}"
                         + (f" '{v['label']}'" if v["label"] else "")
                         + (f", {human_size(v['size'])}" if v["size"] else ""))
        if not d.volumes:
            lines.append("  none")
        self._set_text(self.details, "\n".join(lines))
        self._render_report(self.reports.get(d.fingerprint))

    def _need_device(self):
        if not self.selected:
            messagebox.showinfo("No device", "Select an external device first.")
            return None
        if not self.admin:
            messagebox.showwarning("Administrator needed",
                                   "Close DiskRepair and start it again, accepting the Windows "
                                   "administrator prompt. Raw disk access is not possible without it.")
            return None
        return self.selected

    def _open(self, d, task, write=False):
        return PhysicalDevice(d.number, write=write, expected_fingerprint=d.fingerprint,
                              log=task.log)

    # ------------------------------------------------------------------ diagnosis
    def act_diagnose(self):
        d = self._need_device()
        if not d:
            return

        def work(task):
            fresh = devices.find_disk(d.number) or d
            with self._open(d, task) as dev:
                return diagnose.diagnose(dev, fresh.os_summary(), task)

        def done(report):
            report.device = d.title
            self.reports[d.fingerprint] = report
            self._render_report(report)
            self._log("Verdict: " + report.verdict)
            self.tabs.select(0)

        self.run_job("Diagnosis", work, done)

    def _render_report(self, report):
        self.findings.delete(*self.findings.get_children())
        for child in self.recommend_frame.winfo_children():
            if child in self.action_buttons:
                self.action_buttons.remove(child)
            child.destroy()
        self._set_text(self.finding_detail, "")
        if report is None:
            self.verdict.configure(text="Select a device and run the diagnosis."
                                   if self.selected else "No external device selected.")
            return
        self.verdict.configure(text=report.verdict)
        ordered = sorted(report.findings, key=lambda f: diagnose.SEVERITY_ORDER.get(f.severity, 9))
        self._finding_rows = {}
        for f in ordered:
            row = self.findings.insert("", "end", values=(SEV_LABEL.get(f.severity, f.severity),
                                                          f.title), tags=(f.severity,))
            self._finding_rows[row] = f
        rows = self.findings.get_children()
        if rows:
            self.findings.selection_set(rows[0])
        for i, fix in enumerate(report.recommended, 1):
            btn = ttk.Button(self.recommend_frame,
                             text=f"{i}. {diagnose.FIX_TITLES.get(fix, fix)}",
                             command=lambda a=fix: self.run_action(a))
            btn.grid(row=(i - 1) // 2, column=(i - 1) % 2, sticky="ew", padx=(0, 6), pady=2)
            if self.job:
                btn.configure(state="disabled")
            self.action_buttons.append(btn)
        self.recommend_frame.columnconfigure(0, weight=1)
        self.recommend_frame.columnconfigure(1, weight=1)

    def _show_finding(self):
        sel = self.findings.selection()
        f = getattr(self, "_finding_rows", {}).get(sel[0]) if sel else None
        if f:
            fixes = ", ".join(diagnose.FIX_TITLES.get(x, x) for x in f.fixes)
            self._set_text(self.finding_detail,
                           f.title + ("\n\n" + f.detail if f.detail else "")
                           + ("\n\nWhat helps: " + fixes if fixes else ""))

    def _show_report(self):
        report = self.reports.get(self.selected.fingerprint) if self.selected else None
        if not report:
            messagebox.showinfo("Report", "Run the diagnosis first.")
            return
        win = tk.Toplevel(self)
        win.title("Technical report")
        win.geometry("820x600")
        text = tk.Text(win, wrap="word", font=("Consolas", 9))
        text.pack(fill="both", expand=True)
        text.insert("1.0", report.to_text())
        text.configure(state="disabled")

    def _report_or_warn(self):
        report = self.reports.get(self.selected.fingerprint) if self.selected else None
        if not report:
            messagebox.showinfo("Diagnosis needed", "Run the diagnosis first so DiskRepair knows "
                                                    "what is on the device.")
        return report

    # ------------------------------------------------------------------ actions
    def run_action(self, action):
        handler = getattr(self, "act_" + action, None)
        if handler:
            handler()

    def _after_write(self, _result=None):
        """Re-read the device after anything changed it."""
        if self.selected:
            self.reports.pop(self.selected.fingerprint, None)

        def rediagnose():
            if self.selected and self.selected.identity.size and not self.job:
                self.act_diagnose()

        self.refresh(then=rediagnose)

    def act_clear_readonly(self):
        d = self._need_device()
        if d:
            self.run_job("Clear write protection",
                         lambda task: repair.clear_readonly(d.number, d.fingerprint, task),
                         self._after_write)

    def act_chkdsk(self):
        d = self._need_device()
        if not d:
            return
        letters = d.letters
        if not letters:
            messagebox.showinfo("CHKDSK", "This device has no drive letter, so Windows CHKDSK "
                                          "cannot run on it. Use the other repairs first.")
            return
        letter = letters[0]
        if not messagebox.askyesno("CHKDSK", f"Run CHKDSK /F on {letter} ({d.identity.model})?\n\n"
                                             "CHKDSK repairs the filesystem in place. If the files "
                                             "matter and the device is failing, save a rescue image "
                                             "first."):
            return
        surface = messagebox.askyesno("CHKDSK", "Also scan for bad sectors (/R)?\n"
                                                "This reads the whole volume and can take hours.")
        self.run_job(f"CHKDSK {letter}",
                     lambda task: repair.run_chkdsk(d.number, d.fingerprint, letter, task,
                                                    fix=True, surface=surface),
                     self._after_write)

    def _damaged_boot_targets(self, report):
        targets = []
        for info in list(report.filesystems) + list(report.found):
            if info.from_backup:
                size = next((p.sectors for p in report.partitions
                             if p.start_lba == info.start_lba), info.total_sectors)
                targets.append((info, size))
        return targets

    def act_restore_boot(self):
        d = self._need_device()
        report = d and self._report_or_warn()
        if not report:
            return
        targets = self._damaged_boot_targets(report)
        if not targets:
            messagebox.showinfo("Restore boot sector", "The diagnosis found no volume with a "
                                                       "damaged primary boot sector and an intact backup.")
            return
        desc = "\n".join(f"  - {i.fs} volume at sector {i.start_lba}" for i, _s in targets)
        if not messagebox.askyesno("Restore boot sector",
                                   f"Copy the backup boot sector over the damaged one for:\n{desc}\n\n"
                                   "Only the boot sectors are written. The replaced sectors are "
                                   "saved first and can be put back with 'Undo'. Continue?"):
            return

        def work(task):
            with self._open(d, task, write=True) as dev:
                for info, size in targets:
                    repair.restore_boot_sector(dev, info.start_lba, size, task, d.fingerprint)

        self.run_job("Restore boot sector", work, self._after_write)

    def act_deep_search(self):
        d = self._need_device()
        if not d:
            return

        def work(task):
            with self._open(d, task) as dev:
                return scan.find_partitions(dev, task, deep=True)

        def done(found):
            report = self.reports.get(d.fingerprint)
            if report is not None:
                report.found = found
            ss = d.identity.sector_size
            if found:
                text = "\n".join(f"  - {f.fs} at sector {f.start_lba}, "
                                 f"{human_size(f.total_sectors * ss)}"
                                 + (f", label '{f.label}'" if f.label else "")
                                 + (" (boot sector damaged, backup intact)" if f.from_backup else "")
                                 for f in found)
                messagebox.showinfo("Deep search", f"Found {len(found)} filesystem(s):\n{text}\n\n"
                                                   "Use 'Rebuild partition table' to make them "
                                                   "visible to Windows again, or 'Copy files out' "
                                                   "to rescue the files first.")
            else:
                messagebox.showinfo("Deep search", "No filesystem was found anywhere on the device. "
                                                   "Use 'Recover files by signature' if you need "
                                                   "the data, then 'Erase and format'.")

        self.run_job("Deep search for lost partitions", work, done)

    def act_rebuild_table(self):
        d = self._need_device()
        report = d and self._report_or_warn()
        if not report:
            return
        found = [f for f in report.found if f.windows_readable and f.total_sectors]
        if not found:
            messagebox.showinfo("Rebuild partition table",
                                "No lost filesystem is known yet. Run 'Deep search for lost "
                                "partitions' first.")
            return
        ss = d.identity.sector_size
        desc = "\n".join(f"  - {f.fs}, {human_size(f.total_sectors * ss)}, starting at sector "
                         f"{f.start_lba}" for f in found)
        if not messagebox.askyesno("Rebuild partition table",
                                   f"Write a new partition table on {d.identity.model} listing:\n"
                                   f"{desc}\n\nOnly the partition table sectors are written; they "
                                   "are saved first and can be restored with 'Undo'. Continue?"):
            return

        def work(task):
            with self._open(d, task, write=True) as dev:
                repair.rebuild_partition_table(dev, found, task, d.fingerprint)
                for info in found:
                    if info.from_backup:
                        repair.restore_boot_sector(dev, info.start_lba, info.total_sectors, task,
                                                   d.fingerprint)

        self.run_job("Rebuild partition table", work, self._after_write)

    def act_undo(self):
        d = self._need_device()
        if not d:
            return
        backups = [b for b in repair.list_backups(d.fingerprint) if b.get("data_file")]
        if not backups:
            messagebox.showinfo("Undo", "No saved sectors exist for this device.")
            return
        last = backups[0]
        if not messagebox.askyesno("Undo", f"Put back {last['sectors']} sector(s) at sector "
                                           f"{last['lba']} saved on {last['time']}?\n\n"
                                           f"({last['note']})"):
            return

        def work(task):
            with self._open(d, task, write=True) as dev:
                repair.undo_backup(dev, last, task)
            os.replace(last["path"], last["path"] + ".undone")

        self.run_job("Undo last change", work, self._after_write)

    def act_format(self):
        d = self._need_device()
        if d:
            FormatDialog(self, d)

    def start_format(self, d, fs, label, full, limit=None):
        self.run_job("Erase and format",
                     lambda task: repair.wipe_and_format(d.number, d.fingerprint, fs, label, full,
                                                         task, limit_bytes=limit),
                     self._format_done)

    def _format_done(self, result):
        if result.get("letter") and result.get("verified"):
            messagebox.showinfo("Erase and format",
                                f"The device is formatted as {result['fs']} and mounted at "
                                f"{result['letter']}\nA write-and-read-back test passed.")
        elif result.get("letter"):
            messagebox.showwarning("Erase and format",
                                   f"Formatted as {result['fs']} at {result['letter']}, but the "
                                   "write test failed. Run the capacity test - the device may not "
                                   "be storing data reliably.")
        else:
            messagebox.showinfo("Erase and format",
                                f"Formatted as {result['fs']}. Unplug and re-insert the device "
                                "so Windows assigns a drive letter.")
        self._after_write()

    # ---- recovery
    def _source(self, d, task):
        """(device, os_info) for recovery: the saved image if one is chosen, else the disk."""
        path = self.image_source.get().strip()
        if path:
            return ImageDevice(path), None
        return self._open(d, task), None

    def _pick_image(self):
        path = filedialog.askopenfilename(title="Choose a rescue image",
                                          filetypes=[("Disk images", "*.img *.bin *.dd"),
                                                     ("All files", "*.*")])
        if path:
            self.image_source.set(path)

    def _pick_folder(self, title, sub):
        initial = os.path.join(repair.DATA_DIR, sub)
        os.makedirs(initial, exist_ok=True)
        folder = filedialog.askdirectory(title=title, initialdir=initial, mustexist=False)
        return os.path.join(folder, time.strftime("%Y%m%d-%H%M%S")) if folder else None

    def _device_or_image(self):
        if self.image_source.get().strip():
            if not os.path.isfile(self.image_source.get().strip()):
                messagebox.showerror("Rescue image", "The chosen image file does not exist.")
                return None
            return self.selected or True
        return self._need_device()

    def act_rescue_image(self):
        d = self._need_device()
        if not d:
            return
        initial = os.path.join(repair.DATA_DIR, "images")
        os.makedirs(initial, exist_ok=True)
        path = filedialog.asksaveasfilename(
            title="Save rescue image as", initialdir=initial, defaultextension=".img",
            initialfile=f"disk{d.number}-{time.strftime('%Y%m%d-%H%M%S')}.img",
            filetypes=[("Disk image", "*.img")])
        if not path:
            return

        def work(task):
            rescue.check_destination(os.path.dirname(path), d.number, d.identity.size)
            with self._open(d, task) as dev:
                return rescue.image_device(dev, path, task)

        def done(summary):
            messagebox.showinfo("Rescue image",
                                f"Image saved to:\n{summary['image']}\n\n"
                                + (f"{human_size(summary['bad_bytes'])} could not be read."
                                   if summary["bad_ranges"] else "Every sector was read.")
                                + "\n\nYou can now recover files from this image instead of "
                                  "stressing the device.")
            self.image_source.set(summary["image"])

        self.run_job("Save rescue image", work, done)

    def act_extract_files(self):
        d = self._device_or_image()
        if not d:
            return
        out = self._pick_folder("Folder to copy the recovered files into", "recovered")
        if not out:
            return
        deleted = self.include_deleted.get()
        number = None if self.image_source.get().strip() else d.number

        def work(task):
            rescue.check_destination(out, number)
            dev, _ = self._source(d, task)
            with dev:
                report = diagnose.diagnose(dev, None, task)
                candidates = [f for f in list(report.filesystems) + list(report.found)
                              if fsread.open_reader(dev, f)]
                if not candidates:
                    task.log("No FAT/exFAT filesystem at the usual places - deep searching.")
                    candidates = [f for f in scan.find_partitions(dev, task, deep=True)
                                  if fsread.open_reader(dev, f)]
                if not candidates:
                    raise rescue.RescueError(
                        "No readable FAT or exFAT filesystem was found. Use 'Recover files by "
                        "signature' instead (NTFS volumes: use CHKDSK or signature recovery).")
                total = {"files": 0, "suspect": 0, "failed": 0, "out": out}
                for n, info in enumerate(candidates, 1):
                    target = out if len(candidates) == 1 else os.path.join(out, f"volume{n}")
                    task.log(f"Reading {info.fs} volume at sector {info.start_lba}.")
                    stats = fsread.extract_all(fsread.open_reader(dev, info), target, task, deleted)
                    for key in ("files", "suspect", "failed"):
                        total[key] += stats[key]
                    if stats["problems"]:
                        os.makedirs(target, exist_ok=True)
                        with open(os.path.join(target, "_recovery_problems.txt"), "w",
                                  encoding="utf-8") as f:
                            f.write("\n".join(stats["problems"]))
                return total

        def done(total):
            messagebox.showinfo("Copy files out",
                                f"{total['files']} file(s) copied to:\n{total['out']}\n\n"
                                f"{total['suspect']} may be incomplete, {total['failed']} could not "
                                "be copied (see _recovery_problems.txt).")

        self.run_job("Copy files out", work, done)

    def act_carve(self):
        d = self._device_or_image()
        if not d:
            return
        out = self._pick_folder("Folder to put the recovered files into", "recovered")
        if not out:
            return
        number = None if self.image_source.get().strip() else d.number

        def work(task):
            rescue.check_destination(out, number)
            dev, _ = self._source(d, task)
            with dev:
                stats = rescue.carve_files(dev, out, task)
            stats["out"] = out
            return stats

        def done(stats):
            kinds = ", ".join(f"{v} {k}" for k, v in sorted(stats["by_type"].items())) or "none"
            messagebox.showinfo("Recover files by signature",
                                f"{stats['files']} file(s) recovered ({kinds}) to:\n{stats['out']}")

        self.run_job("Recover files by signature", work, done)

    # ---- tests
    def act_surface_scan(self):
        d = self._need_device()
        if not d:
            return

        def work(task):
            with self._open(d, task) as dev:
                return scan.surface_scan(dev, task)

        def done(result):
            self._log(result.summary())
            for off, length in result.bad_ranges[:50]:
                self._log(f"  unreadable: offset {off} ({human_size(off)}), {human_size(length)}")
            if result.bad_ranges:
                messagebox.showwarning("Surface scan", result.summary() + "\n\nThe media is "
                                       "physically failing. Rescue your data and replace it.")
            else:
                messagebox.showinfo("Surface scan", result.summary())

        self.run_job("Full surface scan", work, done)

    def act_capacity_test(self):
        d = self._need_device()
        if not d:
            return
        if not messagebox.askyesno(
                "Capacity and write test",
                f"This writes small test blocks across {d.identity.model} "
                f"({human_size(d.identity.size)}), reads them back, then restores the original "
                "contents.\n\nOn a healthy device nothing is lost. On a counterfeit or failing "
                "device the restore itself can fail - if the files matter, save a rescue image "
                "first.\n\nContinue?"):
            return
        quick = not self.full_captest.get()

        def work(task):
            with self._open(d, task, write=True) as dev:
                return captest.capacity_test(dev, task, repair.BACKUP_DIR, quick=quick)

        def done(result):
            self.capacity[d.fingerprint] = result
            if result["verdict"] == "fake_capacity" and result["usable_bytes"] >= 64 * 1024 * 1024:
                if messagebox.askyesno("Capacity and write test", result["summary"]
                                       + "\n\nOpen 'Erase and format' limited to the real capacity?"):
                    FormatDialog(self, d)
                return
            box = messagebox.showinfo if result["verdict"] == "genuine" else messagebox.showwarning
            box("Capacity and write test", result["summary"])

        self.run_job("Capacity and write test", work, done)


class FormatDialog(tk.Toplevel):
    def __init__(self, app, d):
        super().__init__(app)
        self.app, self.d = app, d
        self.title("Erase and format")
        self.resizable(False, False)
        self.transient(app)
        self.grab_set()
        pad = ttk.Frame(self, padding=16)
        pad.pack(fill="both", expand=True)
        ident = d.identity
        ttk.Label(pad, text="Everything on this device will be erased:",
                  style="Danger.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(pad, text=f"{ident.model}\nDisk {d.number}, {human_size(ident.size)}, "
                            f"{ident.bus_name}"
                            + (f", drive {', '.join(d.letters)}" if d.letters else ""),
                  font=("Segoe UI", 10, "bold")).grid(row=1, column=0, columnspan=2, sticky="w",
                                                      pady=(4, 12))
        test = app.capacity.get(d.fingerprint) or {}
        self.limit_bytes = test.get("usable_bytes") if test.get("verdict") == "fake_capacity" else None
        self.use_limit = tk.BooleanVar(value=bool(self.limit_bytes))
        if self.limit_bytes:
            ttk.Checkbutton(pad, variable=self.use_limit,
                            text=f"Use only the verified real capacity "
                                 f"({human_size(self.limit_bytes)}) - recommended for this "
                                 "fake-capacity device").grid(row=8, column=0, columnspan=2,
                                                              sticky="w", pady=(10, 0))
        default = repair.choose_fs(self.limit_bytes or ident.size)
        ttk.Label(pad, text="Filesystem").grid(row=2, column=0, sticky="w")
        self.fs = tk.StringVar(value=f"Auto ({default})")
        choices = [f"Auto ({default})", "FAT32", "exFAT", "NTFS"]
        ttk.Combobox(pad, textvariable=self.fs, values=choices, state="readonly",
                     width=24).grid(row=2, column=1, sticky="w", pady=2)
        ttk.Label(pad, text="FAT32: cameras, consoles, car stereos (files up to 4 GB)\n"
                            "exFAT: large cards and big files\nNTFS: Windows-only hard disks",
                  style="Risk.TLabel").grid(row=3, column=1, sticky="w")
        ttk.Label(pad, text="Volume label").grid(row=4, column=0, sticky="w", pady=(8, 0))
        self.label = tk.StringVar(value="")
        ttk.Entry(pad, textvariable=self.label, width=27).grid(row=4, column=1, sticky="w",
                                                               pady=(8, 0))
        self.full = tk.BooleanVar(value=False)
        ttk.Checkbutton(pad, text="Zero-fill the whole device first (slow; can revive flash that "
                                  "fails a quick format)",
                        variable=self.full).grid(row=5, column=0, columnspan=2, sticky="w",
                                                 pady=(10, 0))
        ttk.Label(pad, text="Type ERASE to confirm").grid(row=6, column=0, sticky="w", pady=(14, 0))
        self.confirm = tk.StringVar()
        self.confirm.trace_add("write", lambda *_a: self.ok.configure(
            state="normal" if self.confirm.get().strip() == "ERASE" else "disabled"))
        entry = ttk.Entry(pad, textvariable=self.confirm, width=27)
        entry.grid(row=6, column=1, sticky="w", pady=(14, 0))
        buttons = ttk.Frame(pad)
        buttons.grid(row=9, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right")
        self.ok = ttk.Button(buttons, text="Erase and format", state="disabled", command=self._go)
        self.ok.pack(side="right", padx=8)
        entry.focus_set()

    def _go(self):
        fs = self.fs.get()
        fs = "auto" if fs.startswith("Auto") else fs
        label, full = self.label.get().strip(), self.full.get()
        limit = self.limit_bytes if self.use_limit.get() else None
        self.destroy()
        self.app.start_format(self.d, fs, label, full, limit)


def main():
    if not winapi.is_admin() and not os.environ.get("DISKREPAIR_NO_ELEVATE"):
        if _relaunch_elevated():
            return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
    App().mainloop()


if __name__ == "__main__":
    main()
