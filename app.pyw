
import csv
import hashlib
import json
import os
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = None
    Observer = None

try:
    from winotify import Notification, audio
except ImportError:
    Notification = None
    audio = None


APP_DIR = Path.home() / "FileIntegrityMonitor"
BASELINE_FILE = APP_DIR / "baseline.json"
HISTORY_FILE = APP_DIR / "scan_history.json"
REPORT_DIR = APP_DIR / "reports"

APP_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

BG = "#0A101B"
PANEL = "#111C2B"
CARD = "#162438"
CARD_ALT = "#1B2B40"
TEXT = "#EDF4FC"
MUTED = "#91A4BA"
GREEN = "#55E0AE"
YELLOW = "#FFC66D"
RED = "#FF7D91"
BLUE = "#315D82"
BORDER = "#263950"


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def display_time(value=None):
    if value is None:
        return datetime.now().astimezone().strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        )

    try:
        return datetime.fromisoformat(value).astimezone().strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        )
    except (ValueError, TypeError):
        return str(value)


def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        for chunk in iter(
            lambda: file.read(1024 * 1024), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def scan_folder(folder):
    """Return file hashes, read errors, and skipped-item count."""

    folder = Path(folder).resolve()
    results = {}
    errors = []
    skipped = 0

    for root, dirs, files in os.walk(
        folder, followlinks=False
    ):
        root_path = Path(root)
        kept_dirs = []

        for dirname in dirs:
            directory = root_path / dirname

            if directory.is_symlink():
                skipped += 1
            else:
                kept_dirs.append(dirname)

        dirs[:] = kept_dirs

        for filename in files:
            path = root_path / filename

            if path.is_symlink():
                skipped += 1
                continue

            try:
                if not path.is_file():
                    skipped += 1
                    continue

                relative = path.relative_to(folder).as_posix()
                results[relative] = sha256_file(path)

            except OSError as error:
                errors.append({
                    "path": str(path),
                    "error": str(error)
                })

    return results, errors, skipped


def load_json_list(path):
    if not path.exists():
        return []

    try:
        value = json.loads(
            path.read_text(encoding="utf-8")
        )
        return value if isinstance(value, list) else []

    except (OSError, json.JSONDecodeError):
        return []


def save_json_atomic(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")

    temporary.write_text(
        json.dumps(value, indent=2),
        encoding="utf-8"
    )

    temporary.replace(path)


if FileSystemEventHandler is None:
    class WatchdogBase:
        pass
else:
    WatchdogBase = FileSystemEventHandler


class WatchHandler(WatchdogBase):
    """Send filesystem activity to the application's UI thread."""

    def __init__(self, event_queue):
        super().__init__()
        self.event_queue = event_queue

    def on_any_event(self, event):
        if event.is_directory:
            return

        if event.event_type not in (
            "created", "modified", "deleted", "moved"
        ):
            return

        self.event_queue.put((
            "filesystem_event",
            {
                "event_type": event.event_type,
                "src_path": event.src_path,
                "dest_path": getattr(event, "dest_path", ""),
                "time": now_iso()
            }
        ))


class FileIntegrityApp:

    def __init__(self, root):
        self.root = root

        self.root.title(
            "SENTINEL | File Integrity Monitor"
        )
        self.root.geometry("1280x820")
        self.root.minsize(980, 650)
        self.root.configure(bg=BG)

        self.folder = None
        self.baseline = {}
        self.current_hashes = {}
        self.events = []

        self.scan_history = load_json_list(HISTORY_FILE)
        self.event_queue = queue.Queue()

        self.observer = None
        self.monitoring = False
        self.last_event_by_path = {}
        self.scan_running = False

        self.last_scan = (
            self.scan_history[-1]
            if self.scan_history else None
        )

        self.last_scan_errors = []
        self.last_scan_skipped = 0

        self.setup_style()
        self.build_ui()
        self.update_scan_summary(self.last_scan)

        self.root.after(150, self.process_queue)
        self.root.protocol(
            "WM_DELETE_WINDOW", self.on_close
        )

    # --------------------------------------------------
    # UI DESIGN
    # --------------------------------------------------

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            rowheight=31,
            background=CARD,
            fieldbackground=CARD,
            foreground=TEXT,
            borderwidth=0,
            font=("Segoe UI", 9)
        )

        style.configure(
            "Treeview.Heading",
            background=CARD_ALT,
            foreground=TEXT,
            padding=9,
            relief="flat",
            font=("Segoe UI", 9, "bold")
        )

        style.map(
            "Treeview",
            background=[("selected", "#294C6C")]
        )

        style.configure(
            "TCombobox",
            fieldbackground=CARD,
            background=CARD,
            foreground=TEXT,
            arrowcolor=TEXT,
            padding=6
        )

    def label(
        self, parent, text, size=10,
        color=TEXT, bold=False, bg=None
    ):
        return tk.Label(
            parent,
            text=text,
            font=(
                "Segoe UI", size,
                "bold" if bold else "normal"
            ),
            fg=color,
            bg=bg or parent.cget("bg")
        )

    def build_ui(self):

        header = tk.Frame(
            self.root,
            bg=PANEL,
            padx=24,
            pady=18,
            highlightbackground=BORDER,
            highlightthickness=1
        )
        header.pack(
            fill="x", padx=14, pady=(14, 8)
        )

        head_row = tk.Frame(header, bg=PANEL)
        head_row.pack(fill="x")

        brand = tk.Frame(head_row, bg=PANEL)
        brand.pack(side="left", fill="x", expand=True)

        self.label(
            brand, "◈  SENTINEL",
            size=24, color=GREEN, bold=True
        ).pack(anchor="w")

        self.label(
            brand,
            "FILE INTEGRITY MONITOR  /  SHA-256  /  DEFENSIVE SECURITY",
            size=9, color=MUTED
        ).pack(anchor="w", pady=(3, 0))

        self.monitor_badge = tk.Label(
            head_row,
            text="●  MONITORING OFF",
            bg="#2A3545",
            fg=MUTED,
            font=("Segoe UI", 9, "bold"),
            padx=13,
            pady=8
        )
        self.monitor_badge.pack(
            side="right", padx=(10, 0)
        )

        body = tk.Frame(
            self.root, bg=BG, padx=14, pady=8
        )
        body.pack(fill="both", expand=True)

        # Monitored folder panel
        folder_card = tk.Frame(
            body,
            bg=CARD,
            padx=15,
            pady=12,
            highlightbackground=BORDER,
            highlightthickness=1
        )
        folder_card.pack(fill="x", pady=(0, 10))

        self.label(
            folder_card,
            "MONITORED DIRECTORY",
            size=9, color=MUTED, bold=True
        ).pack(anchor="w")

        self.folder_label = self.label(
            folder_card, "No folder selected",
            size=10, color=TEXT
        )
        self.folder_label.pack(
            anchor="w", pady=(4, 10), fill="x"
        )

        controls = tk.Frame(folder_card, bg=CARD)
        controls.pack(fill="x")

        self.add_button(
            controls, "Choose Folder",
            self.select_folder
        )
        self.add_button(
            controls, "Create Baseline",
            self.create_baseline
        )
        self.add_button(
            controls, "Scan Now", self.scan_now
        )

        self.start_button = self.add_button(
            controls, "▶  Start Monitoring",
            self.start_monitoring, kind="primary"
        )

        self.stop_button = self.add_button(
            controls, "■  Stop",
            self.stop_monitoring, kind="danger"
        )
        self.stop_button.config(state="disabled")

        self.add_button(
            controls, "Export Report CSV",
            self.export_csv
        )

        # Dashboard statistic cards
        stats = tk.Frame(body, bg=BG)
        stats.pack(fill="x", pady=(0, 10))

        self.stat_labels = {}

        stat_specs = [
            ("files", "FILES SCANNED", "#68B8FF"),
            ("added", "ADDED", GREEN),
            ("modified", "MODIFIED", YELLOW),
            ("deleted", "DELETED", RED)
        ]

        for key, title, accent in stat_specs:
            card = tk.Frame(
                stats,
                bg=CARD,
                padx=16,
                pady=12,
                highlightbackground=BORDER,
                highlightthickness=1
            )
            card.pack(
                side="left", fill="x",
                expand=True, padx=(0, 8)
            )

            self.label(
                card, title, size=9,
                color=MUTED, bold=True
            ).pack(anchor="w")

            value = self.label(
                card, "0", size=23,
                color=accent, bold=True
            )
            value.pack(anchor="w", pady=(4, 0))

            self.stat_labels[key] = value

        # Latest scan summary
        summary = tk.Frame(
            body,
            bg=CARD,
            padx=15,
            pady=10,
            highlightbackground=BORDER,
            highlightthickness=1
        )
        summary.pack(fill="x", pady=(0, 10))

        self.label(
            summary, "LATEST SCAN SUMMARY",
            size=9, color=MUTED, bold=True
        ).pack(anchor="w")

        self.scan_summary_label = self.label(
            summary, "No scans recorded yet.",
            size=9, color=TEXT
        )
        self.scan_summary_label.pack(
            anchor="w", pady=(5, 0), fill="x"
        )

        # Search and event filter
        filters = tk.Frame(body, bg=BG)
        filters.pack(fill="x", pady=(0, 8))

        self.label(
            filters, "SECURITY EVENTS",
            size=11, color=TEXT, bold=True
        ).pack(side="left", padx=(0, 16))

        self.label(
            filters, "Search",
            size=9, color=MUTED
        ).pack(side="left", padx=(0, 6))

        self.search_var = tk.StringVar()

        search = tk.Entry(
            filters,
            textvariable=self.search_var,
            bg=CARD,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Segoe UI", 10),
            width=28
        )
        search.pack(
            side="left", ipady=6, padx=(0, 14)
        )

        self.search_var.trace_add(
            "write", lambda *_: self.refresh_table()
        )

        self.label(
            filters, "Event type",
            size=9, color=MUTED
        ).pack(side="left", padx=(0, 6))

        self.filter_var = tk.StringVar(value="ALL")

        filter_box = ttk.Combobox(
            filters,
            textvariable=self.filter_var,
            state="readonly",
            values=(
                "ALL", "ADDED", "MODIFIED",
                "DELETED", "ERROR"
            ),
            width=12
        )
        filter_box.pack(side="left")

        filter_box.bind(
            "<<ComboboxSelected>>",
            lambda _e: self.refresh_table()
        )

        self.label(
            filters,
            "Double-click a row for hash details",
            size=9, color=MUTED
        ).pack(side="right")

        # Events table
        table_frame = tk.Frame(
            body,
            bg=CARD,
            highlightbackground=BORDER,
            highlightthickness=1
        )
        table_frame.pack(fill="both", expand=True)

        columns = ("time", "status", "file", "details")

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        for col, title, width in [
            ("time", "TIMESTAMP", 185),
            ("status", "EVENT", 105),
            ("file", "FILE / RELATIVE PATH", 380),
            ("details", "DETAILS", 390)
        ]:
            self.table.heading(col, text=title)
            self.table.column(
                col, width=width, anchor="w"
            )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.table.yview
        )

        self.table.configure(
            yscrollcommand=scrollbar.set
        )

        self.table.pack(
            side="left", fill="both", expand=True
        )
        scrollbar.pack(side="right", fill="y")

        self.table.tag_configure(
            "ADDED", foreground=GREEN
        )
        self.table.tag_configure(
            "MODIFIED", foreground=YELLOW
        )
        self.table.tag_configure(
            "DELETED", foreground=RED
        )
        self.table.tag_configure(
            "ERROR", foreground=RED
        )

        self.table.bind(
            "<Double-1>", self.show_event_details
        )

        self.status = tk.Label(
            self.root,
            text="Ready  •  Choose a folder to begin",
            bg=PANEL,
            fg=MUTED,
            anchor="w",
            padx=18,
            pady=9,
            font=("Segoe UI", 9)
        )
        self.status.pack(fill="x", side="bottom")

    def add_button(
        self, parent, text, command, kind="normal"
    ):
        styles = {
            "normal": (
                "#23364C", TEXT, "#304A65"
            ),
            "primary": (
                "#146A55", "#FFFFFF", "#1C8A6D"
            ),
            "danger": (
                "#492637", "#FFDDE4", "#663449"
            )
        }

        bg, fg, active = styles[kind]

        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active,
            activeforeground="white",
            disabledforeground="#68788B",
            relief="flat",
            padx=12,
            pady=8,
            cursor="hand2",
            font=("Segoe UI", 9, "bold")
        )
        button.pack(side="left", padx=(0, 7))

        return button

    # --------------------------------------------------
    # FOLDER AND BASELINE
    # --------------------------------------------------

    def select_folder(self):
        if self.monitoring:
            messagebox.showwarning(
                "Monitoring active",
                "Stop monitoring before changing folders."
            )
            return

        chosen = filedialog.askdirectory(
            title="Choose a folder to monitor"
        )

        if not chosen:
            return

        self.folder = Path(chosen).resolve()
        self.folder_label.config(text=str(""))

        self.baseline = {}
        self.current_hashes = {}
        self.events.clear()

        self.refresh_table()
        self.update_stats()

        self.status.config(
            text="Folder selected  •  Create a baseline before scanning"
        )

    def create_baseline(self):
        if not self.folder:
            messagebox.showwarning(
                "Select a folder",
                "Choose a folder first."
            )
            return

        if self.monitoring:
            messagebox.showwarning(
                "Monitoring active",
                "Stop monitoring before replacing the baseline."
            )
            return

        confirmed = messagebox.askyesno(
            "Create baseline",
            "Hash all accessible files in this folder "
            "and replace the saved baseline?"
        )

        if not confirmed:
            return

        self.status.config(
            text="Creating baseline... please wait"
        )
        self.root.update_idletasks()

        try:
            hashes, errors, skipped = scan_folder(
                self.folder
            )

            data = {
                "folder": str(self.folder),
                "created_at": now_iso(),
                "hashes": hashes
            }

            save_json_atomic(BASELINE_FILE, data)

        except OSError as error:
            messagebox.showerror(
                "Baseline failed", str(error)
            )
            self.status.config(
                text="Baseline creation failed"
            )
            return

        self.baseline = hashes
        self.current_hashes = dict(hashes)
        self.events.clear()

        self.refresh_table()
        self.update_stats()

        self.last_scan_errors = errors
        self.last_scan_skipped = skipped

        self.status.config(
            text=f"Baseline created  •  {len(hashes)} files  •  "
                 f"{len(errors)} errors  •  {skipped} skipped"
        )

        self.record_scan(
            "BASELINE", len(hashes), [], errors, skipped
        )

        if errors:
            messagebox.showwarning(
                "Some files could not be read",
                f"{len(errors)} file(s) had read errors. "
                "They may not be included in the baseline."
            )

    def load_baseline(self):
        if not BASELINE_FILE.exists():
            raise FileNotFoundError(
                "No saved baseline. Click Create Baseline first."
            )

        data = json.loads(
            BASELINE_FILE.read_text(encoding="utf-8")
        )

        if Path(data.get("folder", "")).resolve() != self.folder:
            raise ValueError(
                "The saved baseline belongs to another folder. "
                "Create a baseline for this folder."
            )

        hashes = data.get("hashes")

        if (
            not isinstance(hashes, dict)
            or not all(
                isinstance(k, str) and isinstance(v, str)
                for k, v in hashes.items()
            )
        ):
            raise ValueError(
                "The baseline file has an invalid format."
            )

        return hashes

    # --------------------------------------------------
    # SCANNING AND SCAN HISTORY
    # --------------------------------------------------

    def scan_now(self):
        if not self.folder:
            messagebox.showwarning(
                "Select a folder", "Choose a folder first."
            )
            return

        if self.scan_running:
            self.status.config(
                text="A scan is already running..."
            )
            return

        try:
            baseline = self.load_baseline()
        except (
            OSError, ValueError, json.JSONDecodeError
        ) as error:
            messagebox.showerror(
                "Baseline error", str(error)
            )
            return

        self.scan_running = True

        self.status.config(
            text="Scanning files and calculating SHA-256 hashes..."
        )

        threading.Thread(
            target=self._scan_worker,
            args=(baseline, str(self.folder)),
            daemon=True
        ).start()

    def _scan_worker(self, baseline, folder_string):
        started = time.monotonic()

        try:
            current, errors, skipped = scan_folder(
                Path(folder_string)
            )

            duration = round(
                time.monotonic() - started, 2
            )

            self.event_queue.put((
                "scan_complete",
                (
                    baseline, current, errors,
                    skipped, duration
                )
            ))

        except Exception as error:
            self.event_queue.put((
                "scan_failed", str(error)
            ))

    def apply_scan(
        self, baseline, current, errors,
        skipped, duration
    ):
        scan_time = now_iso()

        previous = (
            self.current_hashes
            if self.current_hashes
            else baseline
        )

        new_events = []

        for name in sorted(current.keys() - previous.keys()):
            new_events.append(
                self.make_event(
                    scan_time, "ADDED", name,
                    "File appeared since previous scan",
                    previous.get(name), current[name], "SCAN"
                )
            )

        for name in sorted(previous.keys() - current.keys()):
            new_events.append(
                self.make_event(
                    scan_time, "DELETED", name,
                    "File missing since previous scan",
                    previous[name], None, "SCAN"
                )
            )

        for name in sorted(current.keys() & previous.keys()):
            if current[name] != previous[name]:
                new_events.append(
                    self.make_event(
                        scan_time, "MODIFIED", name,
                        "SHA-256 changed",
                        previous[name], current[name], "SCAN"
                    )
                )

        # When the application first scans after opening,
        # compare the current folder against the baseline.
        if not self.current_hashes:
            new_events = []

            for name in sorted(current.keys() - baseline.keys()):
                new_events.append(
                    self.make_event(
                        scan_time, "ADDED", name,
                        "File added since baseline",
                        None, current[name], "SCAN"
                    )
                )

            for name in sorted(baseline.keys() - current.keys()):
                new_events.append(
                    self.make_event(
                        scan_time, "DELETED", name,
                        "File missing since baseline",
                        baseline[name], None, "SCAN"
                    )
                )

            for name in sorted(current.keys() & baseline.keys()):
                if current[name] != baseline[name]:
                    new_events.append(
                        self.make_event(
                            scan_time, "MODIFIED", name,
                            "SHA-256 changed since baseline",
                            baseline[name], current[name], "SCAN"
                        )
                    )

        self.events.extend(new_events)
        self.current_hashes = current
        self.baseline = baseline

        self.last_scan_errors = errors
        self.last_scan_skipped = skipped

        self.refresh_table()
        self.update_stats()

        summary = {
            "timestamp": scan_time,
            "scan_type": "MANUAL_SCAN",
            "folder": str(self.folder),
            "files_scanned": len(current),
            "changes_detected": len(new_events),
            "error_count": len(errors),
            "skipped_count": skipped,
            "duration_seconds": duration,
            "errors": errors
        }

        self.record_scan_record(summary)
        self.update_scan_summary(summary)

        self.status.config(
            text=f"Scan complete  •  {len(current)} files  •  "
                 f"{len(new_events)} changes  •  "
                 f"{len(errors)} errors  •  {skipped} skipped  •  "
                 f"{duration}s"
        )

        if new_events:
            self.notify(
                "File integrity changes detected",
                f"{len(new_events)} change(s) found during scan."
            )

        if errors:
            messagebox.showwarning(
                "Scan completed with errors",
                f"{len(errors)} file(s) could not be read.\n"
                f"{skipped} item(s) were skipped.\n\n"
                "See the scan summary or exported report for details."
            )

    def make_event(
        self, when, kind, name, details,
        old_hash=None, new_hash=None, source="REALTIME"
    ):
        return {
            "time": when,
            "status": kind,
            "file": name,
            "details": details,
            "old_hash": old_hash or "",
            "new_hash": new_hash or "",
            "source": source
        }

    def record_scan(
        self, scan_type, files_scanned,
        events, errors, skipped
    ):
        record = {
            "timestamp": now_iso(),
            "scan_type": scan_type,
            "folder": str(self.folder),
            "files_scanned": files_scanned,
            "changes_detected": len(events),
            "error_count": len(errors),
            "skipped_count": skipped,
            "duration_seconds": 0,
            "errors": errors
        }

        self.record_scan_record(record)
        self.update_scan_summary(record)

    def record_scan_record(self, record):
        self.scan_history.append(record)

        # Keep the latest 5,000 scan records.
        self.scan_history = self.scan_history[-5000:]

        try:
            save_json_atomic(
                HISTORY_FILE, self.scan_history
            )
        except OSError as error:
            self.status.config(
                text=f"Warning: scan history could not be saved: {error}"
            )

        self.last_scan = record

    def update_scan_summary(self, record):
        if not record:
            self.scan_summary_label.config(
                text="No scans recorded yet."
            )
            return

        text = (
            f"Last scan: {display_time(record.get('timestamp'))}   |   "
            f"Type: {record.get('scan_type', 'SCAN')}   |   "
            f"Files: {record.get('files_scanned', 0)}   |   "
            f"Changes: {record.get('changes_detected', 0)}   |   "
            f"Read errors: {record.get('error_count', 0)}   |   "
            f"Skipped: {record.get('skipped_count', 0)}   |   "
            f"Duration: {record.get('duration_seconds', 0)}s"
        )

        self.scan_summary_label.config(text=text)

    # --------------------------------------------------
    # REAL-TIME MONITORING AND NOTIFICATIONS
    # --------------------------------------------------

    def start_monitoring(self):
        if FileSystemEventHandler is None or Observer is None:
            messagebox.showerror(
                "Missing dependency",
                "Real-time monitoring requires watchdog.\n\n"
                "Install with:\n"
                "py -m pip install watchdog winotify"
            )
            return

        if not self.folder:
            messagebox.showwarning(
                "Select a folder", "Choose a folder first."
            )
            return

        try:
            baseline = self.load_baseline()
        except (
            OSError, ValueError, json.JSONDecodeError
        ) as error:
            messagebox.showerror(
                "Baseline error", str(error)
            )
            return

        if self.observer:
            return

        self.observer = Observer()

        try:
            self.observer.schedule(
                WatchHandler(self.event_queue),
                str(self.folder),
                recursive=True
            )
            self.observer.start()

        except Exception as error:
            self.observer = None
            messagebox.showerror(
                "Monitor failed", str(error)
            )
            return

        self.current_hashes = (
            self.current_hashes or dict(baseline)
        )
        self.baseline = baseline
        self.monitoring = True

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.monitor_badge.config(
            text="●  MONITORING ACTIVE",
            bg="#124D40",
            fg=GREEN
        )

        self.status.config(
            text="Real-time monitoring active  •  "
                 "Changes can trigger Windows notifications"
        )

        self.notify(
            "Sentinel monitoring started",
            self.folder.name
        )

    def stop_monitoring(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=3)
            except Exception:
                pass

            self.observer = None

        self.monitoring = False

        if hasattr(self, "start_button"):
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")

        if hasattr(self, "monitor_badge"):
            self.monitor_badge.config(
                text="●  MONITORING OFF",
                bg="#2A3545",
                fg=MUTED
            )

        if hasattr(self, "status"):
            self.status.config(text="Monitoring stopped")

    def process_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()

                if kind == "filesystem_event":
                    self.handle_filesystem_event(payload)

                elif kind == "scan_complete":
                    self.scan_running = False
                    self.apply_scan(*payload)

                elif kind == "scan_failed":
                    self.scan_running = False
                    self.status.config(text="Scan failed")
                    messagebox.showerror(
                        "Scan failed", payload
                    )

        except queue.Empty:
            pass

        self.root.after(150, self.process_queue)

    def handle_filesystem_event(self, item):
        if not self.monitoring or not self.folder:
            return

        raw_path = (
            item.get("dest_path")
            if item.get("event_type") == "moved"
            and item.get("dest_path")
            else item.get("src_path", "")
        )

        try:
            path = Path(raw_path).resolve(strict=False)
            relative = path.relative_to(
                self.folder
            ).as_posix()

        except (ValueError, OSError):
            return

        self.last_event_by_path[relative] = time.monotonic()

        self.root.after(
            500,
            lambda name=relative: self.reconcile_path(name)
        )

        # A move can mean the old path was deleted as well.
        if (
            item.get("event_type") == "moved"
            and item.get("src_path")
        ):
            try:
                old_rel = (
                    Path(item["src_path"])
                    .resolve(strict=False)
                    .relative_to(self.folder)
                    .as_posix()
                )

                if old_rel != relative:
                    self.last_event_by_path[old_rel] = time.monotonic()

                    self.root.after(
                        550,
                        lambda name=old_rel: self.reconcile_path(name)
                    )

            except (ValueError, OSError):
                pass

    def reconcile_path(self, relative):
        if not self.monitoring or not self.folder:
            return

        last = self.last_event_by_path.get(relative)

        if (
            last is not None
            and time.monotonic() - last < 0.42
        ):
            self.root.after(
                250,
                lambda: self.reconcile_path(relative)
            )
            return

        path = self.folder / Path(relative)

        old_hash = self.current_hashes.get(
            relative, self.baseline.get(relative)
        )

        new_hash = None
        read_error = None

        try:
            if (
                path.exists()
                and path.is_file()
                and not path.is_symlink()
            ):
                new_hash = sha256_file(path)

        except OSError as error:
            read_error = str(error)

        if read_error:
            event = self.make_event(
                now_iso(), "ERROR", relative,
                f"Could not read file: {read_error}",
                old_hash, None
            )
            self.events.append(event)

            self.notify(
                "Sentinel could not read a file", relative
            )

        elif old_hash is None and new_hash is not None:
            event = self.make_event(
                now_iso(), "ADDED", relative,
                "New file detected", None, new_hash
            )
            self.current_hashes[relative] = new_hash
            self.events.append(event)

            self.notify("File added", relative)

        elif old_hash is not None and new_hash is None:
            event = self.make_event(
                now_iso(), "DELETED", relative,
                "File deleted or no longer accessible",
                old_hash, None
            )
            self.current_hashes.pop(relative, None)
            self.events.append(event)

            self.notify("File deleted", relative)

        elif (
            old_hash is not None
            and new_hash is not None
            and old_hash != new_hash
        ):
            event = self.make_event(
                now_iso(), "MODIFIED", relative,
                "SHA-256 changed", old_hash, new_hash
            )
            self.current_hashes[relative] = new_hash
            self.events.append(event)

            self.notify("File modified", relative)

        else:
            return

        self.refresh_table()
        self.update_stats()

        self.status.config(
            text=f"Monitoring active  •  "
                 f"{event['status']}: {relative}"
        )

    def notify(self, title, message):
        if Notification is None:
            self.status.config(
                text=f"ALERT: {title} — {message}"
            )
            return

        try:
            toast = Notification(
                app_id="Sentinel File Integrity Monitor",
                title=title,
                msg=message[:240],
                duration="short"
            )

            if audio is not None:
                toast.set_audio(audio.Default, loop=False)

            toast.show()

        except Exception:
            self.status.config(
                text=f"ALERT: {title} — {message}"
            )

    # --------------------------------------------------
    # EVENT DASHBOARD AND DETAILS
    # --------------------------------------------------

    def update_stats(self):
        self.stat_labels["files"].config(
            text=str(len(self.current_hashes))
        )

        for key, event_type in [
            ("added", "ADDED"),
            ("modified", "MODIFIED"),
            ("deleted", "DELETED")
        ]:
            count = sum(
                event["status"] == event_type
                for event in self.events
            )
            self.stat_labels[key].config(text=str(count))

    def refresh_table(self):
        for item in self.table.get_children():
            self.table.delete(item)

        query = self.search_var.get().strip().casefold()
        selected_type = self.filter_var.get()

        # Newest events appear first.
        for index in range(len(self.events) - 1, -1, -1):
            event = self.events[index]

            searchable = (
                f"{event['file']} "
                f"{event['details']} "
                f"{event['status']}"
            ).casefold()

            if query and query not in searchable:
                continue

            if (
                selected_type != "ALL"
                and event["status"] != selected_type
            ):
                continue

            self.table.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    display_time(event["time"]),
                    event["status"],
                    event["file"],
                    event["details"]
                ),
                tags=(event["status"],)
            )

    def show_event_details(self, _event=None):
        selection = self.table.selection()

        if not selection:
            return

        event = self.events[int(selection[0])]

        window = tk.Toplevel(self.root)
        window.title("Sentinel | Event Details")
        window.configure(bg=BG)
        window.geometry("820x570")
        window.minsize(680, 450)
        window.transient(self.root)

        frame = tk.Frame(
            window,
            bg=CARD,
            padx=20,
            pady=18,
            highlightbackground=BORDER,
            highlightthickness=1
        )
        frame.pack(
            fill="both", expand=True, padx=14, pady=14
        )

        event_color = (
            RED
            if event["status"] in ("DELETED", "ERROR")
            else GREEN
        )

        self.label(
            frame,
            f"{event['status']}  /  EVENT DETAILS",
            size=15,
            color=event_color,
            bold=True
        ).pack(anchor="w")

        self.label(
            frame, f"File: {event['file']}",
            size=10, color=TEXT
        ).pack(anchor="w", pady=(12, 4))

        self.label(
            frame,
            f"Timestamp: {display_time(event['time'])}",
            size=9, color=MUTED
        ).pack(anchor="w")

        self.label(
            frame,
            f"Source: {event.get('source', 'REALTIME')}   |   "
            f"Details: {event['details']}",
            size=9, color=MUTED
        ).pack(anchor="w", pady=(4, 14))

        for title, value in [
            (
                "PREVIOUS SHA-256",
                event.get("old_hash") or "Not available"
            ),
            (
                "CURRENT SHA-256",
                event.get("new_hash") or "Not available"
            )
        ]:
            self.label(
                frame, title, size=9,
                color=MUTED, bold=True
            ).pack(anchor="w", pady=(5, 4))

            box = tk.Text(
                frame,
                height=3,
                wrap="word",
                bg=BG,
                fg=TEXT,
                insertbackground=TEXT,
                relief="flat",
                font=("Consolas", 9),
                padx=8,
                pady=7
            )
            box.pack(fill="x")
            box.insert("1.0", value)
            box.config(state="disabled")

        tk.Button(
            frame,
            text="Close",
            command=window.destroy,
            bg=BLUE,
            fg="white",
            activebackground="#477AA5",
            relief="flat",
            padx=18,
            pady=8
        ).pack(anchor="e", pady=(14, 0))

    # --------------------------------------------------
    # CSV REPORTING
    # --------------------------------------------------

    def export_csv(self):
        if not self.scan_history and not self.events:
            messagebox.showinfo(
                "Nothing to export",
                "No scan history or security events have been recorded yet."
            )
            return

        default_name = (
            "sentinel_report_"
            + datetime.now().strftime("%Y%m%d_%H%M%S")
            + ".csv"
        )

        path = filedialog.asksaveasfilename(
            title="Export Sentinel report",
            initialdir=str(REPORT_DIR),
            initialfile=default_name,
            defaultextension=".csv",
            filetypes=[("CSV report", "*.csv")]
        )

        if not path:
            return

        fields = [
            "record_type",
            "timestamp",
            "scan_type",
            "folder",
            "files_scanned",
            "changes_detected",
            "error_count",
            "skipped_count",
            "duration_seconds",
            "event_type",
            "file",
            "details",
            "old_sha256",
            "new_sha256",
            "error"
        ]

        try:
            with open(
                path, "w", newline="", encoding="utf-8-sig"
            ) as output:
                writer = csv.DictWriter(
                    output, fieldnames=fields
                )
                writer.writeheader()

                # Export each scan summary.
                for scan in self.scan_history:
                    writer.writerow({
                        "record_type": "SCAN_SUMMARY",
                        "timestamp": scan.get("timestamp", ""),
                        "scan_type": scan.get("scan_type", ""),
                        "folder": scan.get("folder", ""),
                        "files_scanned": scan.get("files_scanned", 0),
                        "changes_detected": scan.get("changes_detected", 0),
                        "error_count": scan.get("error_count", 0),
                        "skipped_count": scan.get("skipped_count", 0),
                        "duration_seconds": scan.get("duration_seconds", 0)
                    })

                    # Export individual file-read errors.
                    for error in scan.get("errors", []):
                        writer.writerow({
                            "record_type": "SCAN_ERROR",
                            "timestamp": scan.get("timestamp", ""),
                            "scan_type": scan.get("scan_type", ""),
                            "folder": scan.get("folder", ""),
                            "error": (
                                f"{error.get('path', '')}: "
                                f"{error.get('error', '')}"
                            )
                        })

                # Export security events with old/new hashes.
                for event in self.events:
                    writer.writerow({
                        "record_type": "SECURITY_EVENT",
                        "timestamp": event.get("time", ""),
                        "folder": str(self.folder or ""),
                        "event_type": event.get("status", ""),
                        "file": event.get("file", ""),
                        "details": event.get("details", ""),
                        "old_sha256": event.get("old_hash", ""),
                        "new_sha256": event.get("new_hash", "")
                    })

        except OSError as error:
            messagebox.showerror(
                "Export failed", str(error)
            )
            return

        messagebox.showinfo(
            "Report exported",
            f"Sentinel report saved to:\n{path}\n\n"
            "Includes scan summaries, read errors, skipped-item counts, "
            "and security events with SHA-256 hashes."
        )

    def on_close(self):
        self.stop_monitoring()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityApp(root)
    root.mainloop()
