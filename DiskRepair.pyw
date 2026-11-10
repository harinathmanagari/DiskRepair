"""DiskRepair launcher. Double-click this file (or DiskRepair.bat). Windows asks for administrator rights."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from diskrepair import gui
    gui.main()
except Exception:  # pythonw has no console: show the crash instead of vanishing
    import traceback
    from tkinter import messagebox
    messagebox.showerror("DiskRepair failed to start", traceback.format_exc())
