#!/usr/bin/env python3
import argparse
import json
import os
import queue
import shutil
import sys
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import winreg  # type: ignore
except Exception:  # pragma: no cover - non-Windows environments
    winreg = None


@dataclass
class ScanItem:
    category: str
    label: str
    path: str
    size_bytes: int
    file_count: int
    safe_to_delete: bool
    reason: str


@dataclass
class TreeNode:
    name: str
    path: str
    size_bytes: int
    children: List["TreeNode"]


SAFE_DELETE_CATEGORIES = {
    "temp_system",
    "temp_user",
    "teams_classic_cache",
    "teams_new_cache",
    "outlook_secure_temp",
}


DEFAULT_SKIP_DIRS = [
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
    "C:\\$Recycle.Bin",
    "C:\\System Volume Information",
]


def app_data_dir() -> str:
    root = os.environ.get("LOCALAPPDATA", ".")
    path = os.path.join(root, "CDriveCleaner")
    os.makedirs(path, exist_ok=True)
    return path


def log_path() -> str:
    return os.path.join(app_data_dir(), "cleaner.log")


def log_event(message: str) -> None:
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path(), "a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message}\n")
    except Exception:
        return


def config_path() -> str:
    return os.path.join(app_data_dir(), "settings.json")


def load_config() -> Dict[str, object]:
    defaults = {
        "min_full_scan_mb": 100,
        "skip_dirs": DEFAULT_SKIP_DIRS,
        "aggressive_full_scan": False,
    }
    try:
        with open(config_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            defaults.update(data)
    except Exception:
        pass
    return defaults


def save_config(config: Dict[str, object]) -> None:
    try:
        with open(config_path(), "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
    except Exception:
        return


def human_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def safe_exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except Exception:
        return False


def dir_size(path: str) -> Tuple[int, int]:
    total = 0
    count = 0
    try:
        for root, _, files in os.walk(path):
            for name in files:
                file_path = os.path.join(root, name)
                try:
                    total += os.path.getsize(file_path)
                    count += 1
                except Exception:
                    continue
    except Exception:
        return 0, 0
    return total, count


def is_reparse_point(path: str) -> bool:
    try:
        return os.path.islink(path)
    except Exception:
        return False


def scan_tree(
    root: str,
    max_depth: int,
    min_size_mb: int,
    skip_dirs: Optional[List[str]] = None,
    progress: Optional[queue.Queue] = None,
) -> TreeNode:
    skip_dir_set = {p.lower() for p in (skip_dirs or DEFAULT_SKIP_DIRS)}
    min_size_bytes = max(0, min_size_mb) * 1024 * 1024

    def walk(path: str, depth: int) -> TreeNode:
        total_size = 0
        children: List[TreeNode] = []
        try:
            if progress is not None:
                progress.put(("path", path))
            with os.scandir(path) as it:
                for entry in it:
                    entry_path = entry.path
                    entry_lower = entry_path.lower()
                    if skip_dir_set and any(entry_lower.startswith(p) for p in skip_dir_set):
                        continue
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if depth < max_depth:
                            node = walk(entry_path, depth + 1)
                            total_size += node.size_bytes
                            if node.size_bytes >= min_size_bytes:
                                children.append(node)
                        else:
                            size, _ = dir_size(entry_path)
                            total_size += size
                            if size >= min_size_bytes:
                                children.append(
                                    TreeNode(
                                        name=entry.name,
                                        path=entry_path,
                                        size_bytes=size,
                                        children=[],
                                    )
                                )
                    else:
                        try:
                            size = entry.stat(follow_symlinks=False).st_size
                        except Exception:
                            size = 0
                        total_size += size
                        if size >= min_size_bytes:
                            children.append(
                                TreeNode(
                                    name=entry.name,
                                    path=entry_path,
                                    size_bytes=size,
                                    children=[],
                                )
                            )
        except Exception:
            return TreeNode(
                name=os.path.basename(path) or path,
                path=path,
                size_bytes=0,
                children=[],
            )
        children.sort(key=lambda n: n.size_bytes, reverse=True)
        return TreeNode(
            name=os.path.basename(path) or path,
            path=path,
            size_bytes=total_size,
            children=children,
        )

    return walk(root, 0)


def squarify(sizes: List[int], x: float, y: float, width: float, height: float) -> List[Tuple[float, float, float, float]]:
    if not sizes:
        return []

    def normalize(values: List[int], area: float) -> List[float]:
        total = sum(values)
        if total == 0:
            return [0 for _ in values]
        return [value * area / total for value in values]

    def worst_ratio(row: List[float], w: float) -> float:
        if not row or min(row) == 0:
            return float("inf")
        total = sum(row)
        max_val = max(row)
        min_val = min(row)
        return max((w * w * max_val) / (total * total), (total * total) / (w * w * min_val))

    sizes_norm = normalize(sizes, width * height)
    rects: List[Tuple[float, float, float, float]] = []
    row: List[float] = []
    remaining = sizes_norm[:]
    x0, y0, w, h = x, y, width, height

    while remaining:
        row.append(remaining[0])
        new_row = row[:]
        if w >= h:
            if len(row) == 1 or worst_ratio(new_row, h) <= worst_ratio(row[:-1], h):
                remaining.pop(0)
            else:
                row.pop()
                total = sum(row)
                row_height = total / w if w else 0
                offset = 0
                for size in row:
                    rect_width = size / row_height if row_height else 0
                    rects.append((x0 + offset, y0, rect_width, row_height))
                    offset += rect_width
                y0 += row_height
                h -= row_height
                row = []
        else:
            if len(row) == 1 or worst_ratio(new_row, w) <= worst_ratio(row[:-1], w):
                remaining.pop(0)
            else:
                row.pop()
                total = sum(row)
                row_width = total / h if h else 0
                offset = 0
                for size in row:
                    rect_height = size / row_width if row_width else 0
                    rects.append((x0, y0 + offset, row_width, rect_height))
                    offset += rect_height
                x0 += row_width
                w -= row_width
                row = []

    if row:
        total = sum(row)
        if w >= h:
            row_height = total / w if w else 0
            offset = 0
            for size in row:
                rect_width = size / row_height if row_height else 0
                rects.append((x0 + offset, y0, rect_width, row_height))
                offset += rect_width
        else:
            row_width = total / h if h else 0
            offset = 0
            for size in row:
                rect_height = size / row_width if row_width else 0
                rects.append((x0, y0 + offset, row_width, rect_height))
                offset += rect_height

    return rects


def color_for_name(name: str) -> str:
    seed = abs(hash(name)) % 360
    return hsl_to_hex(seed, 0.55, 0.62)


def hsl_to_hex(h: float, s: float, l: float) -> str:
    h = h % 360
    c = (1 - abs(2 * l - 1)) * s
    x = c * (1 - abs((h / 60) % 2 - 1))
    m = l - c / 2
    if h < 60:
        r, g, b = c, x, 0
    elif h < 120:
        r, g, b = x, c, 0
    elif h < 180:
        r, g, b = 0, c, x
    elif h < 240:
        r, g, b = 0, x, c
    elif h < 300:
        r, g, b = x, 0, c
    else:
        r, g, b = c, 0, x
    r_i = int((r + m) * 255)
    g_i = int((g + m) * 255)
    b_i = int((b + m) * 255)
    return f"#{r_i:02x}{g_i:02x}{b_i:02x}"


def file_size(path: str) -> Tuple[int, int]:
    try:
        return os.path.getsize(path), 1
    except Exception:
        return 0, 0


def get_outlook_secure_temp_paths() -> List[str]:
    paths: List[str] = []
    if winreg is None:
        return paths

    versions = ["16.0", "15.0", "14.0", "12.0"]
    for version in versions:
        key_path = f"Software\\Microsoft\\Office\\{version}\\Outlook\\Security"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                value, _ = winreg.QueryValueEx(key, "OutlookSecureTempFolder")
                if isinstance(value, str) and value:
                    paths.append(value)
        except Exception:
            continue

    # Fallback default location (if Outlook created it but registry lookup failed)
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    fallback = os.path.join(
        local_app_data, "Microsoft", "Windows", "INetCache", "Content.Outlook"
    )
    if fallback and safe_exists(fallback):
        paths.append(fallback)

    unique_paths: List[str] = []
    for path in paths:
        if path not in unique_paths:
            unique_paths.append(path)
    return unique_paths


def resolve_rule_paths() -> Dict[str, List[Tuple[str, str, str]]]:
    env = os.environ
    local_app = env.get("LOCALAPPDATA", "")
    app_data = env.get("APPDATA", "")
    system_root = env.get("SystemRoot", "C:\\Windows")

    rules: Dict[str, List[Tuple[str, str, str]]] = {
        "temp_system": [
            ("Windows Temp", os.path.join(system_root, "Temp"), "System temp files."),
        ],
        "temp_user": [
            ("User Temp", env.get("TEMP", ""), "Per-user temp files."),
            ("Local Temp", os.path.join(local_app, "Temp"), "Per-user local temp files."),
        ],
        "teams_classic_cache": [
            (
                "Teams (Classic) Cache",
                os.path.join(app_data, "Microsoft", "Teams"),
                "Teams classic cache and local data.",
            )
        ],
        "teams_new_cache": [
            (
                "Teams (New) Cache",
                os.path.join(
                    local_app,
                    "Packages",
                    "MSTeams_8wekyb3d8bbwe",
                    "LocalCache",
                    "Microsoft",
                    "MSTeams",
                ),
                "New Teams cache (UWP/Store app).",
            )
        ],
        "outlook_secure_temp": [],
        "windows_search_index": [
            (
                "Windows Search Index",
                "C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows",
                "Windows Search index store (Windows.edb).",
            )
        ],
    }

    for path in get_outlook_secure_temp_paths():
        rules["outlook_secure_temp"].append(
            ("Outlook Secure Temp", path, "Outlook attachment temp cache.")
        )

    return rules


def scan_rules() -> List[ScanItem]:
    rules = resolve_rule_paths()
    items: List[ScanItem] = []
    for category, entries in rules.items():
        for label, path, reason in entries:
            if not path:
                continue
            if not safe_exists(path):
                continue
            if os.path.isdir(path):
                size, count = dir_size(path)
            else:
                size, count = file_size(path)
            items.append(
                ScanItem(
                    category=category,
                    label=label,
                    path=path,
                    size_bytes=size,
                    file_count=count,
                    safe_to_delete=category in SAFE_DELETE_CATEGORIES,
                    reason=reason,
                )
            )
    return items


def full_scan(
    root: str,
    aggressive: bool = False,
    min_mb: int = 100,
    skip_dirs: Optional[List[str]] = None,
    progress: Optional[queue.Queue] = None,
) -> List[ScanItem]:
    items: List[ScanItem] = []
    skip_dir_set: set = set()
    if not aggressive:
        skip_dir_set = {p.lower() for p in (skip_dirs or DEFAULT_SKIP_DIRS)}

    for current_root, dirs, files in os.walk(root):
        current_root_lower = current_root.lower()
        if skip_dir_set and any(current_root_lower.startswith(p) for p in skip_dir_set):
            dirs[:] = []
            continue
        folder_size = 0
        file_count = 0
        for name in files:
            try:
                file_path = os.path.join(current_root, name)
                folder_size += os.path.getsize(file_path)
                file_count += 1
            except Exception:
                continue
        if progress is not None:
            progress.put(("path", current_root))
        if folder_size >= min_mb * 1024 * 1024:
            items.append(
                ScanItem(
                    category="full_scan",
                    label=os.path.basename(current_root) or current_root,
                    path=current_root,
                    size_bytes=folder_size,
                    file_count=file_count,
                    safe_to_delete=False,
                    reason="Large folder discovered by full scan.",
                )
            )
    return items


def format_report(items: List[ScanItem]) -> str:
    lines = []
    total = sum(item.size_bytes for item in items)
    lines.append(f"Found {len(items)} targets totaling {human_bytes(total)}")
    lines.append("")
    for item in sorted(items, key=lambda i: i.size_bytes, reverse=True):
        safe_marker = "SAFE" if item.safe_to_delete else "REVIEW"
        lines.append(
            f"[{safe_marker}] {item.label} | {human_bytes(item.size_bytes)} | "
            f"{item.file_count} files | {item.path}"
        )
    return "\n".join(lines)


def delete_contents(path: str) -> Tuple[int, int, List[str]]:
    deleted_bytes = 0
    deleted_files = 0
    failures: List[str] = []
    if not os.path.isdir(path):
        try:
            deleted_bytes += os.path.getsize(path)
            os.remove(path)
            deleted_files += 1
        except Exception as exc:
            failures.append(f"{path} ({exc})")
        return deleted_bytes, deleted_files, failures

    try:
        for name in os.listdir(path):
            entry = os.path.join(path, name)
            try:
                if os.path.isdir(entry):
                    size, _ = dir_size(entry)
                    shutil.rmtree(entry, ignore_errors=False)
                    deleted_bytes += size
                    deleted_files += 1
                else:
                    size, _ = file_size(entry)
                    os.remove(entry)
                    deleted_bytes += size
                    deleted_files += 1
            except Exception as exc:
                failures.append(f"{entry} ({exc})")
    except Exception as exc:
        failures.append(f"{path} ({exc})")

    return deleted_bytes, deleted_files, failures


def clean_items(
    items: List[ScanItem], allow_dangerous: bool = False
) -> Tuple[int, int, List[str]]:
    deleted_bytes = 0
    deleted_files = 0
    failures: List[str] = []
    for item in items:
        if not item.safe_to_delete and not allow_dangerous:
            failures.append(f"{item.path} (blocked: review required)")
            continue
        db, df, errs = delete_contents(item.path)
        deleted_bytes += db
        deleted_files += df
        failures.extend(errs)
    return deleted_bytes, deleted_files, failures


def save_scan_cache(items: List[ScanItem]) -> None:
    try:
        payload = [asdict(item) for item in items]
        with open(os.path.join(app_data_dir(), "last_scan.json"), "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
    except Exception:
        return


def load_scan_cache() -> List[ScanItem]:
    try:
        with open(os.path.join(app_data_dir(), "last_scan.json"), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, list):
            return [ScanItem(**item) for item in data if isinstance(item, dict)]
    except Exception:
        pass
    return []


def launch_gui() -> None:
    import tkinter as tk
    from tkinter import messagebox, ttk

    root = tk.Tk()
    root.title("C Drive Cleaner")
    root.geometry("980x640")

    config = load_config()
    items: List[ScanItem] = load_scan_cache()
    progress_queue: "queue.Queue" = queue.Queue()

    header = tk.Label(
        root,
        text="C Drive Cleaner",
        font=("Segoe UI", 16, "bold"),
    )
    header.pack(pady=6)

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

    scanner_tab = tk.Frame(notebook)
    results_tab = tk.Frame(notebook)
    settings_tab = tk.Frame(notebook)
    treemap_tab = tk.Frame(notebook)

    notebook.add(scanner_tab, text="Scanner")
    notebook.add(results_tab, text="Results")
    notebook.add(settings_tab, text="Settings")
    notebook.add(treemap_tab, text="Tree Map")

    summary_var = tk.StringVar(value="Ready to scan.")
    progress_var = tk.StringVar(value="")
    treemap_summary_var = tk.StringVar(value="Run a tree scan to visualize disk usage.")
    treemap_progress_var = tk.StringVar(value="")

    scanner_header = tk.Label(
        scanner_tab,
        text="Run a scan and review results before cleaning.",
        font=("Segoe UI", 10),
    )
    scanner_header.pack(anchor="w", padx=8, pady=4)

    full_scan_var = tk.BooleanVar(value=False)
    aggressive_var = tk.BooleanVar(value=bool(config.get("aggressive_full_scan")))
    min_mb_var = tk.StringVar(value=str(config.get("min_full_scan_mb", 100)))

    options_frame = tk.Frame(scanner_tab)
    options_frame.pack(fill=tk.X, padx=8, pady=6)
    tk.Checkbutton(
        options_frame,
        text="Include full drive scan (slow)",
        variable=full_scan_var,
    ).pack(side=tk.LEFT)
    tk.Checkbutton(
        options_frame,
        text="Aggressive full scan (includes system folders)",
        variable=aggressive_var,
    ).pack(side=tk.LEFT, padx=12)
    tk.Label(options_frame, text="Min size (MB):").pack(side=tk.LEFT, padx=8)
    tk.Entry(options_frame, textvariable=min_mb_var, width=6).pack(side=tk.LEFT)

    status_frame = tk.Frame(scanner_tab)
    status_frame.pack(fill=tk.X, padx=8, pady=4)
    tk.Label(status_frame, textvariable=summary_var).pack(anchor="w")
    tk.Label(status_frame, textvariable=progress_var, fg="#555").pack(anchor="w")

    columns = ("category", "size", "files", "path", "safe")
    tree = ttk.Treeview(results_tab, columns=columns, show="headings", height=16)
    tree.heading("category", text="Category")
    tree.heading("size", text="Size")
    tree.heading("files", text="Files")
    tree.heading("path", text="Path")
    tree.heading("safe", text="Safety")
    tree.column("category", width=180)
    tree.column("size", width=90, anchor=tk.E)
    tree.column("files", width=70, anchor=tk.E)
    tree.column("path", width=520)
    tree.column("safe", width=90)
    tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

    settings_label = tk.Label(
        settings_tab,
        text="Folders to skip during full scan (one per line):",
        font=("Segoe UI", 10),
    )
    settings_label.pack(anchor="w", padx=8, pady=4)
    skip_text = tk.Text(settings_tab, height=10)
    skip_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
    skip_text.insert("1.0", "\n".join(config.get("skip_dirs", DEFAULT_SKIP_DIRS)))

    treemap_header = tk.Label(
        treemap_tab,
        text="Tree Map View (beginner friendly): scan a drive and click rectangles to drill down.",
        font=("Segoe UI", 10),
    )
    treemap_header.pack(anchor="w", padx=8, pady=4)

    treemap_controls = tk.Frame(treemap_tab)
    treemap_controls.pack(fill=tk.X, padx=8, pady=4)
    tk.Label(treemap_controls, text="Root path:").pack(side=tk.LEFT)
    treemap_root_var = tk.StringVar(value="C:\\")
    tk.Entry(treemap_controls, textvariable=treemap_root_var, width=12).pack(
        side=tk.LEFT, padx=6
    )
    tk.Label(treemap_controls, text="Max depth:").pack(side=tk.LEFT)
    treemap_depth_var = tk.StringVar(value="2")
    tk.Entry(treemap_controls, textvariable=treemap_depth_var, width=4).pack(
        side=tk.LEFT, padx=6
    )
    tk.Label(treemap_controls, text="Min size (MB):").pack(side=tk.LEFT)
    treemap_min_var = tk.StringVar(value="50")
    tk.Entry(treemap_controls, textvariable=treemap_min_var, width=6).pack(
        side=tk.LEFT, padx=6
    )
    treemap_scan_button = tk.Button(treemap_controls, text="Scan")
    treemap_scan_button.pack(side=tk.LEFT, padx=6)
    treemap_back_button = tk.Button(treemap_controls, text="Back", state=tk.DISABLED)
    treemap_back_button.pack(side=tk.LEFT)

    treemap_status = tk.Frame(treemap_tab)
    treemap_status.pack(fill=tk.X, padx=8, pady=4)
    tk.Label(treemap_status, textvariable=treemap_summary_var).pack(anchor="w")
    tk.Label(treemap_status, textvariable=treemap_progress_var, fg="#555").pack(
        anchor="w"
    )

    treemap_canvas = tk.Canvas(treemap_tab, background="#f7f7f7", highlightthickness=0)
    treemap_canvas.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

    treemap_legend = tk.Label(
        treemap_tab,
        text="Tip: click a rectangle to zoom in; use Back to go up.",
        font=("Segoe UI", 9),
        fg="#555",
    )
    treemap_legend.pack(anchor="w", padx=8, pady=(0, 6))

    treemap_root: Optional[TreeNode] = None
    treemap_stack: List[TreeNode] = []
    treemap_rects: List[Tuple[int, TreeNode]] = []

    def refresh_view() -> None:
        tree.delete(*tree.get_children())
        for item in items:
            safety = "SAFE" if item.safe_to_delete else "REVIEW"
            tree.insert(
                "",
                tk.END,
                iid=item.path,
                values=(
                    item.label,
                    human_bytes(item.size_bytes),
                    item.file_count,
                    item.path,
                    safety,
                ),
            )

    def export_report() -> None:
        from tkinter import filedialog

        path = filedialog.asksaveasfilename(
            title="Save report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
        )
        if not path:
            return
        report = format_report(items)
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(report)
            messagebox.showinfo("Cleaner", f"Report saved to {path}")
        except Exception as exc:
            messagebox.showerror("Cleaner", f"Failed to save report: {exc}")

    def open_selected_path() -> None:
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Cleaner", "Select an item first.")
            return
        path = selected[0]
        try:
            os.startfile(path)
        except Exception as exc:
            messagebox.showerror("Cleaner", f"Could not open: {exc}")

    def run_scan_in_background() -> None:
        def worker() -> None:
            nonlocal items
            summary_var.set("Scanning...")
            progress_var.set("")
            log_event("Scan started")
            scan_items = scan_rules()
            if full_scan_var.get():
                try:
                    min_mb_value = int(min_mb_var.get())
                except Exception:
                    min_mb_value = 100
                skip_dirs = [
                    line.strip()
                    for line in skip_text.get("1.0", tk.END).splitlines()
                    if line.strip()
                ]
                scan_items.extend(
                    full_scan(
                        "C:\\",
                        aggressive=aggressive_var.get(),
                        min_mb=min_mb_value,
                        skip_dirs=skip_dirs,
                        progress=progress_queue,
                    )
                )
            items = scan_items
            save_scan_cache(items)
            summary_var.set(
                f"Scan complete: {len(items)} targets, {human_bytes(sum(i.size_bytes for i in items))} total."
            )
            progress_var.set("")
            log_event("Scan completed")
            refresh_view()

        threading.Thread(target=worker, daemon=True).start()

    def draw_treemap(node: TreeNode) -> None:
        treemap_canvas.delete("all")
        treemap_rects.clear()
        if not node.children:
            treemap_canvas.create_text(
                12,
                12,
                anchor="nw",
                text="No children to display.",
                fill="#444",
            )
            return
        width = max(1, treemap_canvas.winfo_width() - 10)
        height = max(1, treemap_canvas.winfo_height() - 10)
        sizes = [child.size_bytes for child in node.children]
        rects = squarify(sizes, 5, 5, width, height)
        for rect, child in zip(rects, node.children):
            x, y, w, h = rect
            fill = color_for_name(child.name)
            rect_id = treemap_canvas.create_rectangle(x, y, x + w, y + h, fill=fill, outline="#ffffff")
            label = f"{child.name}\n{human_bytes(child.size_bytes)}"
            treemap_canvas.create_text(
                x + 6,
                y + 6,
                anchor="nw",
                text=label,
                fill="#1a1a1a",
                font=("Segoe UI", 9),
            )
            treemap_rects.append((rect_id, child))

        treemap_summary_var.set(
            f"{node.path} - {len(node.children)} items, {human_bytes(node.size_bytes)} total"
        )

    def run_treemap_scan() -> None:
        nonlocal treemap_root, treemap_stack

        def worker() -> None:
            treemap_scan_button.config(state=tk.DISABLED)
            treemap_back_button.config(state=tk.DISABLED)
            treemap_summary_var.set("Tree scan running...")
            treemap_progress_var.set("")
            root_path = treemap_root_var.get().strip() or "C:\\"
            try:
                depth_value = int(treemap_depth_var.get())
            except Exception:
                depth_value = 2
            try:
                min_value = int(treemap_min_var.get())
            except Exception:
                min_value = 50
            skip_dirs = [
                line.strip()
                for line in skip_text.get("1.0", tk.END).splitlines()
                if line.strip()
            ]
            treemap_node = scan_tree(
                root=root_path,
                max_depth=max(0, depth_value),
                min_size_mb=max(0, min_value),
                skip_dirs=skip_dirs,
                progress=progress_queue,
            )
            treemap_root = treemap_node
            treemap_stack = []
            treemap_summary_var.set("Tree scan complete.")
            treemap_progress_var.set("")
            treemap_canvas.after(0, lambda: draw_treemap(treemap_node))
            treemap_scan_button.config(state=tk.NORMAL)

        threading.Thread(target=worker, daemon=True).start()

    def treemap_on_click(event: tk.Event) -> None:
        nonlocal treemap_root, treemap_stack
        clicked = treemap_canvas.find_closest(event.x, event.y)
        if not clicked:
            return
        for rect_id, child in treemap_rects:
            if rect_id == clicked[0]:
                if child.children:
                    if treemap_root is not None:
                        treemap_stack.append(treemap_root)
                    treemap_root = child
                    draw_treemap(child)
                    treemap_back_button.config(state=tk.NORMAL)
                break

    def treemap_back() -> None:
        nonlocal treemap_root, treemap_stack
        if not treemap_stack:
            treemap_back_button.config(state=tk.DISABLED)
            return
        treemap_root = treemap_stack.pop()
        if treemap_root is not None:
            draw_treemap(treemap_root)
        if not treemap_stack:
            treemap_back_button.config(state=tk.DISABLED)

    treemap_scan_button.config(command=run_treemap_scan)
    treemap_back_button.config(command=treemap_back)
    treemap_canvas.bind("<Button-1>", treemap_on_click)

    def poll_progress() -> None:
        try:
            while True:
                msg_type, payload = progress_queue.get_nowait()
                if msg_type == "path":
                    progress_var.set(f"Scanning: {payload}")
                    treemap_progress_var.set(f"Scanning: {payload}")
        except queue.Empty:
            pass
        root.after(200, poll_progress)

    def clean_selected() -> None:
        selected = tree.selection()
        if not selected:
            messagebox.showinfo("Cleaner", "Select at least one item.")
            return
        chosen = [item for item in items if item.path in selected]
        blocked = [item for item in chosen if not item.safe_to_delete]
        if blocked:
            messagebox.showwarning(
                "Cleaner",
                "Some selected items require review and won't be deleted.",
            )
        ok = messagebox.askyesno(
            "Cleaner",
            "Delete contents for selected SAFE items?",
        )
        if not ok:
            return
        deleted_bytes, deleted_files, failures = clean_items(chosen)
        log_event(
            f"Cleaned {deleted_files} entries totaling {deleted_bytes} bytes; failures={len(failures)}"
        )
        message = (
            f"Deleted {deleted_files} entries totaling {human_bytes(deleted_bytes)}."
        )
        if failures:
            message += "\nSome items could not be removed."
        messagebox.showinfo("Cleaner", message)
        refresh_view()

    def save_settings() -> None:
        try:
            min_mb_value = int(min_mb_var.get())
        except Exception:
            min_mb_value = 100
        config_update = {
            "min_full_scan_mb": min_mb_value,
            "skip_dirs": [
                line.strip()
                for line in skip_text.get("1.0", tk.END).splitlines()
                if line.strip()
            ],
            "aggressive_full_scan": aggressive_var.get(),
        }
        save_config(config_update)
        messagebox.showinfo("Cleaner", "Settings saved.")

    scanner_buttons = tk.Frame(scanner_tab)
    scanner_buttons.pack(fill=tk.X, padx=8, pady=8)
    tk.Button(scanner_buttons, text="Scan Now", command=run_scan_in_background).pack(
        side=tk.LEFT
    )
    tk.Button(scanner_buttons, text="Save Settings", command=save_settings).pack(
        side=tk.LEFT, padx=8
    )
    tk.Button(scanner_buttons, text="Exit", command=root.destroy).pack(side=tk.RIGHT)

    results_buttons = tk.Frame(results_tab)
    results_buttons.pack(fill=tk.X, padx=8, pady=8)
    tk.Button(results_buttons, text="Open Folder", command=open_selected_path).pack(
        side=tk.LEFT
    )
    tk.Button(results_buttons, text="Export Report", command=export_report).pack(
        side=tk.LEFT, padx=8
    )
    tk.Button(results_buttons, text="Clean Selected", command=clean_selected).pack(
        side=tk.RIGHT
    )

    summary_var.set(
        f"Loaded last scan: {len(items)} targets, {human_bytes(sum(i.size_bytes for i in items))} total."
        if items
        else "Ready to scan."
    )
    refresh_view()
    poll_progress()
    root.mainloop()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan and clean common cache/temp locations on C drive."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="Run a scan and print results.")
    scan_cmd.add_argument("--full", action="store_true", help="Include full drive scan.")
    scan_cmd.add_argument(
        "--aggressive",
        action="store_true",
        help="Include system folders in full scan.",
    )
    scan_cmd.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of text.",
    )
    scan_cmd.add_argument(
        "--save-report",
        help="Save a human-readable report to a file.",
    )
    scan_cmd.add_argument(
        "--min-mb",
        type=int,
        default=None,
        help="Minimum folder size (MB) for full scan.",
    )

    clean_cmd = sub.add_parser("clean", help="Delete contents of safe locations.")
    clean_cmd.add_argument(
        "--category",
        action="append",
        default=[],
        help="Limit to specific category (repeatable).",
    )
    clean_cmd.add_argument(
        "--confirm",
        action="store_true",
        help="Required to perform deletion.",
    )
    clean_cmd.add_argument(
        "--dangerous",
        action="store_true",
        help="Allow cleaning review-only items.",
    )
    clean_cmd.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without removing anything.",
    )
    clean_cmd.add_argument(
        "--use-last-scan",
        action="store_true",
        help="Use cached scan results instead of rescanning.",
    )

    report_cmd = sub.add_parser("report", help="Write a report to a file.")
    report_cmd.add_argument("--path", required=True, help="Output file path.")
    report_cmd.add_argument("--full", action="store_true", help="Include full drive scan.")
    report_cmd.add_argument(
        "--aggressive",
        action="store_true",
        help="Include system folders in full scan.",
    )

    sub.add_parser("gui", help="Launch the UI.")

    args = parser.parse_args(argv)

    if args.command == "gui":
        launch_gui()
        return 0

    config = load_config()
    items = scan_rules()
    if args.command in {"scan", "report"} and args.full:
        min_mb = args.min_mb if args.min_mb is not None else int(
            config.get("min_full_scan_mb", 100)
        )
        skip_dirs = config.get("skip_dirs", DEFAULT_SKIP_DIRS)
        if not isinstance(skip_dirs, list):
            skip_dirs = DEFAULT_SKIP_DIRS
        items.extend(
            full_scan(
                "C:\\",
                aggressive=args.aggressive,
                min_mb=min_mb,
                skip_dirs=skip_dirs,
            )
        )

    if args.command == "scan":
        if args.json:
            payload = [asdict(item) for item in items]
            print(json.dumps(payload, indent=2))
        else:
            print(format_report(items))
        save_scan_cache(items)
        if args.save_report:
            with open(args.save_report, "w", encoding="utf-8") as handle:
                handle.write(format_report(items))
            print(f"Report saved to {args.save_report}")
        return 0

    if args.command == "report":
        report = format_report(items)
        with open(args.path, "w", encoding="utf-8") as handle:
            handle.write(report)
        print(f"Report written to {args.path}")
        return 0

    if args.command == "clean":
        if args.use_last_scan:
            cached = load_scan_cache()
            if cached:
                items = cached
        if not args.confirm:
            print("Refusing to delete without --confirm.")
            return 2
        if args.category:
            items = [item for item in items if item.category in args.category]
        if args.dry_run:
            print(format_report(items))
            return 0
        deleted_bytes, deleted_files, failures = clean_items(
            items, allow_dangerous=args.dangerous
        )
        print(
            f"Deleted {deleted_files} entries totaling {human_bytes(deleted_bytes)}."
        )
        if failures:
            print("Failures:")
            for fail in failures:
                print(f"- {fail}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
