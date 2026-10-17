
import csv
import hashlib
import json
import os
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_DIR = Path.home() / "FileIntegrityMonitor"
BASELINE_FILE = APP_DIR / "baseline.json"
REPORT_DIR = APP_DIR / "reports"

APP_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_folder(folder):
    results = {}
    errors = []

    for root, dirs, files in os.walk(folder):
        dirs[:] = [
            d for d in dirs
            if not (Path(root) / d).is_symlink()
        ]

        for filename in files:
            path = Path(root) / filename

            if path.is_symlink() or not path.is_file():
                continue

            relative = str(path.relative_to(folder))

            try:
                results[relative] = sha256_file(path)
            except (OSError, PermissionError) as error:
                errors.append(f"{relative}: {error}")

    return results, errors


class FileIntegrityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sentinel | File Integrity Monitor")
        self.root.geometry("1050x680")
        self.root.minsize(800, 520)

        self.folder = None
        self.baseline = {}
        self.events = []

        self.setup_style()
        self.build_ui()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            rowheight=29,
            background="#17212F",
            fieldbackground="#17212F",
            foreground="#E7EDF5"
        )
        style.configure(
            "Treeview.Heading",
            background="#253449",
            foreground="white",
            padding=8
        )
        style.map(
            "Treeview",
            background=[("selected", "#285D78")]
        )

    def build_ui(self):
        self.root.configure(bg="#0D1420")

        header = tk.Frame(self.root, bg="#111C2B", padx=22, pady=18)
        header.pack(fill="x")

        tk.Label(
            header, text="SENTINEL",
            font=("Segoe UI", 22, "bold"),
            fg="#58D6A3", bg="#111C2B"
        ).pack(anchor="w")

        tk.Label(
            header,
            text="FILE INTEGRITY MONITOR  /  SHA-256",
            font=("Segoe UI", 10),
            fg="#A9B8CA", bg="#111C2B"
        ).pack(anchor="w", pady=(3, 0))

        body = tk.Frame(self.root, bg="#0D1420", padx=20, pady=16)
        body.pack(fill="both", expand=True)

        controls = tk.Frame(body, bg="#0D1420")
        controls.pack(fill="x", pady=(0, 12))

        self.folder_label = tk.Label(
            controls, text="No folder selected",
            bg="#0D1420", fg="#D5DFEA",
            anchor="w", font=("Segoe UI", 10)
        )
        self.folder_label.pack(fill="x", pady=(0, 10))

        buttons = tk.Frame(controls, bg="#0D1420")
        buttons.pack(fill="x")

        self.add_button(buttons, "Select Folder", self.select_folder)
        self.add_button(buttons, "Create Baseline", self.create_baseline)
        self.add_button(buttons, "Scan for Changes", self.scan_changes)
        self.add_button(buttons, "Export CSV", self.export_csv)

        stats = tk.Frame(body, bg="#0D1420")
        stats.pack(fill="x", pady=(0, 14))

        self.stat_labels = {}
        for key, title in [
            ("files", "FILES SCANNED"),
            ("added", "ADDED"),
            ("modified", "MODIFIED"),
            ("deleted", "DELETED"),
        ]:
            card = tk.Frame(
                stats, bg="#172638", padx=14, pady=12
            )
            card.pack(side="left", fill="x", expand=True, padx=(0, 8))

            tk.Label(
                card, text=title, bg="#172638", fg="#9CB0C6",
                font=("Segoe UI", 9)
            ).pack(anchor="w")

            value = tk.Label(
                card, text="0", bg="#172638", fg="#FFFFFF",
                font=("Segoe UI", 22, "bold")
            )
            value.pack(anchor="w", pady=(4, 0))
            self.stat_labels[key] = value

        tk.Label(
            body, text="SECURITY EVENTS",
            bg="#0D1420", fg="#D5DFEA",
            font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", pady=(0, 8))

        columns = ("time", "status", "file", "details")
        self.table = ttk.Treeview(
            body, columns=columns, show="headings"
        )

        for column, title, width in [
            ("time", "TIME", 155),
            ("status", "EVENT", 105),
            ("file", "FILE", 300),
            ("details", "DETAILS", 270),
        ]:
            self.table.heading(column, text=title)
            self.table.column(column, width=width, anchor="w")

        self.table.tag_configure("ADDED", foreground="#58D6A3")
        self.table.tag_configure("MODIFIED", foreground="#F6C66B")
        self.table.tag_configure("DELETED", foreground="#FF8585")
        self.table.pack(fill="both", expand=True)

        self.status = tk.Label(
            self.root,
            text="Ready | Select a folder to begin",
            bg="#111C2B", fg="#A9B8CA",
            anchor="w", padx=20, pady=9
        )
        self.status.pack(fill="x", side="bottom")

    def add_button(self, parent, label, command):
        tk.Button(
            parent, text=label, command=command,
            bg="#20374A", fg="#FFFFFF",
            activebackground="#31536B",
            activeforeground="#FFFFFF",
            relief="flat", padx=12, pady=8,
            cursor="hand2"
        ).pack(side="left", padx=(0, 8))

    def select_folder(self):
        chosen = filedialog.askdirectory(
            title="Choose a folder to monitor"
        )
        if not chosen:
            return

        self.folder = Path(chosen).resolve()
        self.folder_label.config(text=f"Monitoring target: {self.folder}")
        self.events.clear()
        self.refresh_table()
        self.status.config(text="Folder selected | Create a baseline first")

    def create_baseline(self):
        if not self.folder:
            messagebox.showwarning(
                "Select a folder", "Choose a folder first."
            )
            return

        if not messagebox.askyesno(
            "Create baseline",
            "Record the current SHA-256 hashes for this folder?"
        ):
            return

        try:
            hashes, errors = scan_folder(self.folder)
        except OSError as error:
            messagebox.showerror("Scan failed", str(error))
            return

        self.baseline = hashes
        data = {
            "folder": str(self.folder),
            "created_at": datetime.now().isoformat(timespec="seconds"),
            "hashes": hashes,
        }

        try:
            BASELINE_FILE.write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
        except OSError as error:
            messagebox.showerror(
                "Save failed", f"Could not save baseline: {error}"
            )
            return

        self.events.clear()
        self.refresh_table()
        self.stat_labels["files"].config(text=str(len(hashes)))
        self.status.config(
            text=f"Baseline created | {len(hashes)} files | "
                 f"{len(errors)} read errors"
        )

    def scan_changes(self):
        if not self.folder:
            messagebox.showwarning(
                "Select a folder", "Choose a folder first."
            )
            return

        if not BASELINE_FILE.exists():
            messagebox.showwarning(
                "No baseline", "Create a baseline before scanning."
            )
            return

        try:
            data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            messagebox.showerror("Baseline error", str(error))
            return

        if Path(data.get("folder", "")).resolve() != self.folder:
            messagebox.showwarning(
                "Wrong baseline",
                "The saved baseline belongs to a different folder. "
                "Create a new baseline for this folder."
            )
            return

        self.baseline = data.get("hashes", {})

        try:
            current, errors = scan_folder(self.folder)
        except OSError as error:
            messagebox.showerror("Scan failed", str(error))
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        events = []

        for name in sorted(current.keys() - self.baseline.keys()):
            events.append((now, "ADDED", name, "New file detected"))

        for name in sorted(self.baseline.keys() - current.keys()):
            events.append((now, "DELETED", name, "File missing"))

        for name in sorted(current.keys() & self.baseline.keys()):
            if current[name] != self.baseline[name]:
                events.append(
                    (now, "MODIFIED", name, "SHA-256 mismatch")
                )

        self.events = events
        self.refresh_table()

        self.stat_labels["files"].config(text=str(len(current)))
        for key, event_name in [
            ("added", "ADDED"),
            ("modified", "MODIFIED"),
            ("deleted", "DELETED"),
        ]:
            count = sum(e[1] == event_name for e in events)
            self.stat_labels[key].config(text=str(count))

        self.status.config(
            text=f"Scan complete | {len(events)} changes detected | "
                 f"{len(errors)} read errors"
        )

        if errors:
            messagebox.showwarning(
                "Some files could not be read",
                f"{len(errors)} file(s) could not be hashed. "
                "Check file permissions before relying on the results."
            )

    def refresh_table(self):
        for item in self.table.get_children():
            self.table.delete(item)

        for event in self.events:
            self.table.insert(
                "", "end", values=event, tags=(event[1],)
            )

    def export_csv(self):
        if not self.events:
            messagebox.showinfo(
                "No events", "Run a scan with detected changes first."
            )
            return

        default_name = (
            "file_integrity_report_"
            + datetime.now().strftime("%Y%m%d_%H%M%S")
            + ".csv"
        )

        path = filedialog.asksaveasfilename(
            title="Export security report",
            initialdir=str(REPORT_DIR),
            initialfile=default_name,
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as file:
                writer = csv.writer(file)
                writer.writerow(
                    ["Timestamp", "Event", "File", "Details"]
                )
                writer.writerows(self.events)
        except OSError as error:
            messagebox.showerror("Export failed", str(error))
            return

        messagebox.showinfo("Export complete", f"Report saved to:\n{path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityApp(root)
    root.mainloop()
