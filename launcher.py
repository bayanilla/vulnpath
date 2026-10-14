#!/usr/bin/env python3
"""Point-and-click launcher for the workbench (standard-library tkinter, no installs).

Windows: double-click "Run Workbench.bat".  Linux: ./run_workbench.sh  (needs the python3-tk OS package).
"""
import os
import queue
import subprocess
import sys
import threading
import webbrowser
from datetime import datetime
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover
    sys.exit("tkinter is not available in this Python. Use the command line instead:\n"
             "  python investigate.py --input <case> --output <results>\n"
             "(On Linux, install the OS package python3-tk / python3-tkinter to use the launcher.)")

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench.correlate import DEFAULT_INTERNAL, Settings  # noqa: E402
from workbench.pipeline import InputError, run  # noqa: E402

PAD = {"padx": 8, "pady": 4}


def open_path(p: Path) -> None:
    if sys.platform.startswith("win"):
        os.startfile(str(p))  # noqa: S606 - opens the local report/folder with the default app
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(p)])
    else:
        subprocess.Popen(["xdg-open", str(p)])


class Launcher(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vulnerability Investigation Workbench")
        self.minsize(760, 560)
        self.msgs: queue.Queue = queue.Queue()
        self.out_dir: Path | None = None

        self.case = tk.StringVar()
        self.out = tk.StringVar()
        self.internal = tk.StringVar(value=" ".join(DEFAULT_INTERNAL[:3]))
        self.offset = tk.StringVar(value="0")
        self.tmap = tk.StringVar()
        self.stale = tk.StringVar(value="30")
        self.scan = tk.StringVar(value="20")

        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)

        ttk.Label(root, text="Correlate raw Zeek / Palo Alto logs with a Nessus scan. Runs fully offline; "
                             "input files are never modified.", foreground="#4b5563").grid(
            row=0, column=0, columnspan=3, sticky="w", **PAD)

        self._row(root, 1, "Case folder (raw files)", self.case, self._pick_case)
        self._row(root, 2, "Results folder", self.out, self._pick_out)

        adv = ttk.LabelFrame(root, text="Options", padding=8)
        adv.grid(row=3, column=0, columnspan=3, sticky="ew", **PAD)
        adv.columnconfigure(1, weight=1)
        ttk.Label(adv, text="Internal networks (CIDR, space separated)").grid(row=0, column=0, sticky="w", **PAD)
        ttk.Entry(adv, textvariable=self.internal).grid(row=0, column=1, columnspan=2, sticky="ew", **PAD)
        ttk.Label(adv, text="Palo Alto log time zone (hours from UTC)").grid(row=1, column=0, sticky="w", **PAD)
        ttk.Spinbox(adv, from_=-12, to=14, increment=0.5, width=6, textvariable=self.offset).grid(
            row=1, column=1, sticky="w", **PAD)
        ttk.Label(adv, text="Threat ID → CVE map (optional CSV)").grid(row=2, column=0, sticky="w", **PAD)
        ttk.Entry(adv, textvariable=self.tmap).grid(row=2, column=1, sticky="ew", **PAD)
        ttk.Button(adv, text="Browse…", command=self._pick_tmap).grid(row=2, column=2, **PAD)
        ttk.Label(adv, text="Flag scan as stale after (days)").grid(row=3, column=0, sticky="w", **PAD)
        ttk.Spinbox(adv, from_=1, to=3650, width=6, textvariable=self.stale).grid(row=3, column=1, sticky="w", **PAD)
        ttk.Label(adv, text="Probing threshold (distinct host:port per source)").grid(row=4, column=0, sticky="w", **PAD)
        ttk.Spinbox(adv, from_=2, to=100000, width=6, textvariable=self.scan).grid(row=4, column=1, sticky="w", **PAD)

        bar = ttk.Frame(root)
        bar.grid(row=4, column=0, columnspan=3, sticky="ew", **PAD)
        self.run_btn = ttk.Button(bar, text="Run analysis", command=self._run)
        self.run_btn.pack(side="left")
        self.report_btn = ttk.Button(bar, text="Open report", command=self._open_report, state="disabled")
        self.report_btn.pack(side="left", padx=8)
        self.folder_btn = ttk.Button(bar, text="Open results folder", command=self._open_folder, state="disabled")
        self.folder_btn.pack(side="left")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=160)
        self.progress.pack(side="right")

        self.summary = ttk.Label(root, text="", font=("TkDefaultFont", 11, "bold"))
        self.summary.grid(row=5, column=0, columnspan=3, sticky="w", **PAD)

        logf = ttk.Frame(root)
        logf.grid(row=6, column=0, columnspan=3, sticky="nsew", **PAD)
        root.rowconfigure(6, weight=1)
        self.log = tk.Text(logf, height=12, wrap="word", state="disabled", font=("TkFixedFont", 9),
                           background="#f9fafb", relief="flat")
        sb = ttk.Scrollbar(logf, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.after(100, self._drain)

    def _row(self, parent, r, label, var, cmd):
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", **PAD)
        ttk.Entry(parent, textvariable=var).grid(row=r, column=1, sticky="ew", **PAD)
        ttk.Button(parent, text="Browse…", command=cmd).grid(row=r, column=2, **PAD)

    def _pick_case(self):
        d = filedialog.askdirectory(title="Choose the case folder with the raw files")
        if d:
            self.case.set(d)
            if not self.out.get():
                stamp = datetime.now().strftime("%Y%m%d-%H%M")
                self.out.set(str(Path(d).parent / f"{Path(d).name}_results_{stamp}"))

    def _pick_out(self):
        d = filedialog.askdirectory(title="Choose where to write results")
        if d:
            self.out.set(d)

    def _pick_tmap(self):
        f = filedialog.askopenfilename(title="Threat ID to CVE map", filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if f:
            self.tmap.set(f)

    def _write(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _settings(self) -> Settings:
        try:
            return Settings(self.internal.get().split() or DEFAULT_INTERNAL, int(self.scan.get()),
                            int(self.stale.get()), float(self.offset.get()), self.tmap.get().strip())
        except ValueError as e:
            raise InputError(f"check the options: {e}") from e

    def _run(self):
        case, out = self.case.get().strip(), self.out.get().strip()
        if not case or not out:
            messagebox.showwarning("Missing folder", "Choose a case folder and a results folder.")
            return
        try:
            settings = self._settings()
        except InputError as e:
            messagebox.showerror("Invalid option", str(e))
            return
        self.run_btn.configure(state="disabled")
        self.report_btn.configure(state="disabled")
        self.folder_btn.configure(state="disabled")
        self.summary.configure(text="Running…", foreground="#111827")
        self.progress.start(12)
        self.out_dir = Path(out)

        def work():
            try:
                ctx = run(Path(case), Path(out), settings, log=lambda m: self.msgs.put(("log", m)))
                self.msgs.put(("done", ctx))
            except InputError as e:
                self.msgs.put(("error", str(e)))
            except Exception as e:  # show anything unexpected instead of failing silently
                self.msgs.put(("error", f"{type(e).__name__}: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def _drain(self):
        try:
            while True:
                kind, val = self.msgs.get_nowait()
                if kind == "log":
                    self._write(val)
                elif kind == "done":
                    self._finish(val)
                else:
                    self._fail(val)
        except queue.Empty:
            pass
        self.after(100, self._drain)

    def _finish(self, ctx):
        self.progress.stop()
        self.progress["value"] = 0
        self.run_btn.configure(state="normal")
        self.report_btn.configure(state="normal")
        self.folder_btn.configure(state="normal")
        F = ctx["findings"]
        unblocked = sum(1 for f in F if f["ips"]["not_blocked"])
        self.summary.configure(
            text=f"{len(F)} findings · {unblocked} unblocked IPS detections · {len(ctx['paths'])} attack paths · "
                 f"{len(ctx['chains'])} same-host chains", foreground="#166534")
        for n in ctx["notices"]:
            self._write("NOTE: " + n)

    def _fail(self, msg):
        self.progress.stop()
        self.progress["value"] = 0
        self.run_btn.configure(state="normal")
        self.summary.configure(text="Run failed", foreground="#b91c1c")
        self._write("ERROR: " + msg)
        messagebox.showerror("Run failed", msg)

    def _open_report(self):
        if self.out_dir:
            webbrowser.open((self.out_dir / "report.html").resolve().as_uri())

    def _open_folder(self):
        if self.out_dir:
            open_path(self.out_dir)


if __name__ == "__main__":
    Launcher().mainloop()
