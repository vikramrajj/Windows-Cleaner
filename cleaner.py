#!/usr/bin/env python3
import argparse
import csv
import getpass
import json
import os
import platform
import queue
import shutil
import sys
import threading
import time
import uuid
from dataclasses import dataclass, asdict, field
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
    requires_admin: bool = False
    services_to_stop: List[str] = field(default_factory=list)


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
    "office_document_cache",
    "windows_update_cache",
    "delivery_optimization_cache",
}

APP_VERSION = "1.2.0"

ADMIN_REQUIRED_CATEGORIES = {
    "windows_update_cache",
    "delivery_optimization_cache",
}

SERVICE_DEPENDENCIES = {
    "windows_update_cache": ["wuauserv", "bits"],
    "delivery_optimization_cache": ["dosvc"],
}

ONE_CLICK_CATEGORIES = {
    "temp_system",
    "temp_user",
    "teams_classic_cache",
    "teams_new_cache",
    "outlook_secure_temp",
    "office_document_cache",
    "windows_update_cache",
    "delivery_optimization_cache",
}

BUILTIN_PROFILES: Dict[str, Dict[str, object]] = {
    "standard": {
        "label": "Standard",
        "description": "Temp + Teams + Outlook secure temp.",
        "categories": [
            "temp_system",
            "temp_user",
            "teams_classic_cache",
            "teams_new_cache",
            "outlook_secure_temp",
        ],
        "allow_dangerous": False,
    },
    "enterprise": {
        "label": "Enterprise",
        "description": "Temp + Teams + Outlook + Office + Windows Update + Delivery Optimization.",
        "categories": [
            "temp_system",
            "temp_user",
            "teams_classic_cache",
            "teams_new_cache",
            "outlook_secure_temp",
            "office_document_cache",
            "windows_update_cache",
            "delivery_optimization_cache",
        ],
        "allow_dangerous": False,
    },
    "aggressive": {
        "label": "Aggressive",
        "description": "Enterprise profile plus Windows Search Index.",
        "categories": [
            "temp_system",
            "temp_user",
            "teams_classic_cache",
            "teams_new_cache",
            "outlook_secure_temp",
            "office_document_cache",
            "windows_update_cache",
            "delivery_optimization_cache",
            "windows_search_index",
        ],
        "allow_dangerous": True,
    },
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
        "policy_profile": "enterprise",
        "audit_enabled": True,
        "audit_sink_path": "",
        "audit_http_endpoint": "",
    }
    try:
        with open(config_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            defaults.update(data)
    except Exception:
        pass
    return defaults


def load_profiles() -> Dict[str, Dict[str, object]]:
    profiles = {name: dict(value) for name, value in BUILTIN_PROFILES.items()}
    custom_path = os.environ.get("CLEANER_PROFILES_PATH", "")
    if not custom_path:
        custom_path = os.path.join(app_data_dir(), "profiles.json")
    if os.path.isfile(custom_path):
        try:
            with open(custom_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                for name, profile in data.items():
                    if isinstance(profile, dict):
                        profiles[name] = profile
        except Exception:
            pass
    return profiles


def get_profile(name: str, profiles: Dict[str, Dict[str, object]]) -> Dict[str, object]:
    if name in profiles:
        return profiles[name]
    return profiles.get("enterprise", BUILTIN_PROFILES["enterprise"])


def profile_categories(profile: Dict[str, object]) -> List[str]:
    categories = profile.get("categories", [])
    if isinstance(categories, list):
        return [str(item) for item in categories]
    return []


def save_config(config: Dict[str, object]) -> None:
    try:
        with open(config_path(), "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2)
    except Exception:
        return


def audit_log_path() -> str:
    return os.path.join(app_data_dir(), "audit.jsonl")


def is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def service_is_running(name: str) -> bool:
    try:
        result = subprocess_run(["sc", "query", name])
        output = (result or "").upper()
        return "RUNNING" in output
    except Exception:
        return False


def stop_services(services: List[str]) -> List[str]:
    stopped = []
    for service in services:
        if service_is_running(service):
            subprocess_run(["sc", "stop", service])
            stopped.append(service)
    return stopped


def start_services(services: List[str]) -> None:
    for service in services:
        subprocess_run(["sc", "start", service])


def subprocess_run(command: List[str]) -> str:
    try:
        import subprocess

        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return (result.stdout or "") + (result.stderr or "")
    except Exception:
        return ""


def quote_arg(value: str) -> str:
    if any(ch in value for ch in [" ", "\""]):
        escaped = value.replace("\"", "\\\"")
        return f"\"{escaped}\""
    return value


def build_task_command(args: List[str]) -> str:
    if getattr(sys, "frozen", False):
        exe = sys.executable
        return " ".join([quote_arg(exe)] + [quote_arg(arg) for arg in args])
    script = os.path.abspath(__file__)
    return " ".join([quote_arg(sys.executable), quote_arg(script)] + [quote_arg(arg) for arg in args])


def schedule_create(
    name: str,
    profile: str,
    frequency: str,
    time_of_day: str,
    days: Optional[List[str]] = None,
    run_level: str = "LIMITED",
) -> str:
    command = build_task_command(["clean", "--confirm", "--profile", profile])
    args = [
        "schtasks",
        "/Create",
        "/TN",
        name,
        "/TR",
        command,
        "/SC",
        frequency.upper(),
        "/ST",
        time_of_day,
        "/F",
        "/RL",
        run_level.upper(),
    ]
    if frequency.upper() == "WEEKLY" and days:
        args.extend(["/D", ",".join(days)])
    return subprocess_run(args)


def schedule_delete(name: str) -> str:
    return subprocess_run(["schtasks", "/Delete", "/TN", name, "/F"])


def schedule_run(name: str) -> str:
    return subprocess_run(["schtasks", "/Run", "/TN", name])


def schedule_query(name: str) -> str:
    return subprocess_run(["schtasks", "/Query", "/TN", name, "/V", "/FO", "LIST"])


def schedule_list(prefix: str = "CDriveCleaner") -> List[str]:
    output = subprocess_run(["schtasks", "/Query", "/FO", "LIST"])
    tasks: List[str] = []
    for line in output.splitlines():
        if line.startswith("TaskName:"):
            task_name = line.split(":", 1)[-1].strip()
            if prefix in task_name:
                tasks.append(task_name)
    return tasks


def get_audit_config(
    overrides: Optional[Dict[str, Optional[str]]] = None,
) -> Dict[str, Optional[str]]:
    config = load_config()
    sink = os.environ.get("CLEANER_AUDIT_SINK") or str(
        config.get("audit_sink_path", "")
    )
    endpoint = os.environ.get("CLEANER_AUDIT_ENDPOINT") or str(
        config.get("audit_http_endpoint", "")
    )
    enabled = bool(config.get("audit_enabled", True))
    if overrides:
        sink = overrides.get("sink", sink) or sink
        endpoint = overrides.get("endpoint", endpoint) or endpoint
        enabled = overrides.get("enabled", enabled) if overrides.get("enabled") is not None else enabled
    return {"sink": sink, "endpoint": endpoint, "enabled": enabled}


def build_audit_event(
    action: str,
    profile: str,
    categories: List[str],
    deleted_bytes: int,
    deleted_files: int,
    failures: List[str],
    skipped: List[str],
) -> Dict[str, object]:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "host": platform.node(),
        "user": getpass.getuser(),
        "admin": is_admin(),
        "app_version": APP_VERSION,
        "action": action,
        "profile": profile,
        "categories": categories,
        "deleted_bytes": deleted_bytes,
        "deleted_files": deleted_files,
        "failures": failures[:50],
        "skipped": skipped[:50],
    }


def write_audit_event(event: Dict[str, object], sink: str = "", endpoint: str = "") -> None:
    try:
        with open(audit_log_path(), "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event) + "\n")
    except Exception:
        pass

    if sink:
        try:
            os.makedirs(os.path.dirname(sink), exist_ok=True)
            with open(sink, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event) + "\n")
        except Exception as exc:
            log_event(f"Audit sink write failed: {exc}")

    if endpoint:
        try:
            import urllib.request

            data = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:
            log_event(f"Audit endpoint send failed: {exc}")


def read_audit_events() -> List[Dict[str, object]]:
    events: List[Dict[str, object]] = []
    try:
        with open(audit_log_path(), "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        events.append(event)
                except Exception:
                    continue
    except Exception:
        return events
    return events


def emit_audit_event(
    action: str,
    profile: str,
    categories: List[str],
    deleted_bytes: int,
    deleted_files: int,
    failures: List[str],
    skipped: List[str],
    audit_overrides: Optional[Dict[str, Optional[str]]] = None,
) -> None:
    audit_config = get_audit_config(audit_overrides)
    if not audit_config.get("enabled", True):
        return
    event = build_audit_event(
        action=action,
        profile=profile,
        categories=categories,
        deleted_bytes=deleted_bytes,
        deleted_files=deleted_files,
        failures=failures,
        skipped=skipped,
    )
    write_audit_event(
        event,
        sink=audit_config.get("sink") or "",
        endpoint=audit_config.get("endpoint") or "",
    )


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
        "office_document_cache": [],
        "windows_update_cache": [
            (
                "Windows Update Download Cache",
                os.path.join(system_root, "SoftwareDistribution", "Download"),
                "Downloaded Windows Update payloads.",
            )
        ],
        "delivery_optimization_cache": [
            (
                "Delivery Optimization Cache",
                os.path.join(
                    system_root,
                    "ServiceProfiles",
                    "NetworkService",
                    "AppData",
                    "Local",
                    "Microsoft",
                    "DeliveryOptimization",
                    "Cache",
                ),
                "Delivery Optimization cache (downloaded update content).",
            )
        ],
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

    for version in ["16.0", "15.0"]:
        cache_path = os.path.join(
            local_app, "Microsoft", "Office", version, "OfficeFileCache"
        )
        rules["office_document_cache"].append(
            (
                f"Office Document Cache {version}",
                cache_path,
                "Office document cache (OneDrive/SharePoint sync).",
            )
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
            requires_admin = category in ADMIN_REQUIRED_CATEGORIES
            services = SERVICE_DEPENDENCIES.get(category, [])
            items.append(
                ScanItem(
                    category=category,
                    label=label,
                    path=path,
                    size_bytes=size,
                    file_count=count,
                    safe_to_delete=category in SAFE_DELETE_CATEGORIES,
                    reason=reason,
                    requires_admin=requires_admin,
                    services_to_stop=services,
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
        admin_marker = "ADMIN" if item.requires_admin else ""
        marker = "|".join([m for m in [safe_marker, admin_marker] if m])
        lines.append(
            f"[{marker}] {item.label} | {human_bytes(item.size_bytes)} | "
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
    admin = is_admin()
    for item in items:
        if item.requires_admin and not admin:
            failures.append(f"{item.path} (blocked: admin required)")
            continue
        if not item.safe_to_delete and not allow_dangerous:
            failures.append(f"{item.path} (blocked: review required)")
            continue
        db, df, errs = delete_contents(item.path)
        deleted_bytes += db
        deleted_files += df
        failures.extend(errs)
    return deleted_bytes, deleted_files, failures


def clean_by_categories(
    items: List[ScanItem],
    categories: List[str],
    allow_dangerous: bool = False,
) -> Tuple[int, int, List[str], List[str]]:
    skipped: List[str] = []
    candidates = [item for item in items if item.category in categories]
    admin = is_admin()

    services = []
    for item in candidates:
        if item.requires_admin and not admin:
            skipped.append(f"{item.label} (admin required)")
            continue
        services.extend(item.services_to_stop)

    services = list(dict.fromkeys(services))
    stopped = stop_services(services) if admin and services else []

    cleanable = [
        item
        for item in candidates
        if (not item.requires_admin) or (item.requires_admin and admin)
    ]
    deleted_bytes, deleted_files, failures = clean_items(
        cleanable, allow_dangerous=allow_dangerous
    )

    if stopped:
        start_services(stopped)

    return deleted_bytes, deleted_files, failures, skipped


def one_click_clean(items: List[ScanItem]) -> Tuple[int, int, List[str], List[str]]:
    return clean_by_categories(items, list(ONE_CLICK_CATEGORIES))


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
    root.geometry("1100x720")
    root.configure(bg="#f6f7fb")

    config = load_config()
    profiles = load_profiles()
    items: List[ScanItem] = load_scan_cache()
    progress_queue: "queue.Queue" = queue.Queue()

    style = ttk.Style()
    style.theme_use("clam")

    brand_bg = "#0f172a"
    brand_fg = "#f8fafc"
    accent = "#f97316"
    text_primary = "#0f172a"
    text_muted = "#64748b"
    panel_bg = "#ffffff"
    border = "#e2e8f0"

    style.configure("TFrame", background=panel_bg)
    style.configure("TLabel", background=panel_bg, foreground=text_primary, font=("Segoe UI", 10))
    style.configure("Muted.TLabel", background=panel_bg, foreground=text_muted, font=("Segoe UI", 9))
    style.configure("Title.TLabel", background=brand_bg, foreground=brand_fg, font=("Segoe UI Semibold", 18))
    style.configure("Subtitle.TLabel", background=brand_bg, foreground="#cbd5f5", font=("Segoe UI", 10))
    style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(10, 6))
    style.map("TButton", background=[("active", "#f1f5f9")])
    style.configure("Primary.TButton", background=accent, foreground="#ffffff")
    style.map("Primary.TButton", background=[("active", "#ea580c")])
    style.configure("TNotebook", background=panel_bg, borderwidth=0)
    style.configure("TNotebook.Tab", padding=(16, 8), font=("Segoe UI Semibold", 10))
    style.map("TNotebook.Tab", background=[("selected", panel_bg)], foreground=[("selected", text_primary)])
    style.configure(
        "Treeview",
        font=("Segoe UI", 10),
        rowheight=28,
        background=panel_bg,
        fieldbackground=panel_bg,
        bordercolor=border,
    )
    style.configure("Treeview.Heading", font=("Segoe UI Semibold", 10), background="#f1f5f9")

    header_frame = tk.Frame(root, bg=brand_bg, height=86)
    header_frame.pack(fill=tk.X, pady=(0, 8))
    header_frame.pack_propagate(False)

    header_left = tk.Frame(header_frame, bg=brand_bg)
    header_left.pack(side=tk.LEFT, padx=20, pady=16)
    tk.Label(
        header_left,
        text="C Drive Cleaner",
        font=("Segoe UI Semibold", 20),
        fg=brand_fg,
        bg=brand_bg,
    ).pack(anchor="w")
    tk.Label(
        header_left,
        text="Minimal, safe, and fast cleanup for Windows",
        font=("Segoe UI", 10),
        fg="#cbd5f5",
        bg=brand_bg,
    ).pack(anchor="w")

    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 12))

    scanner_tab = ttk.Frame(notebook)
    results_tab = ttk.Frame(notebook)
    settings_tab = ttk.Frame(notebook)
    treemap_tab = ttk.Frame(notebook)

    notebook.add(scanner_tab, text="Scanner")
    notebook.add(results_tab, text="Results")
    notebook.add(settings_tab, text="Settings")
    notebook.add(treemap_tab, text="Tree Map")

    summary_var = tk.StringVar(value="Ready to scan.")
    progress_var = tk.StringVar(value="")
    treemap_summary_var = tk.StringVar(value="Run a tree scan to visualize disk usage.")
    treemap_progress_var = tk.StringVar(value="")

    scanner_header = ttk.Label(
        scanner_tab,
        text="Scan your drive and review results before cleaning.",
        style="Muted.TLabel",
    )
    scanner_header.pack(anchor="w", padx=16, pady=(16, 6))

    full_scan_var = tk.BooleanVar(value=False)
    aggressive_var = tk.BooleanVar(value=bool(config.get("aggressive_full_scan")))
    min_mb_var = tk.StringVar(value=str(config.get("min_full_scan_mb", 100)))

    profile_names = sorted(profiles.keys())
    default_profile = str(config.get("policy_profile", "enterprise"))
    if default_profile not in profiles:
        default_profile = "enterprise"
    profile_var = tk.StringVar(value=default_profile)
    profile_desc_var = tk.StringVar(
        value=str(profiles.get(default_profile, {}).get("description", ""))
    )

    options_frame = ttk.Frame(scanner_tab)
    options_frame.pack(fill=tk.X, padx=16, pady=6)
    tk.Checkbutton(
        options_frame,
        text="Include full drive scan (slow)",
        variable=full_scan_var,
        bg=panel_bg,
    ).pack(side=tk.LEFT)
    tk.Checkbutton(
        options_frame,
        text="Aggressive full scan (includes system folders)",
        variable=aggressive_var,
        bg=panel_bg,
    ).pack(side=tk.LEFT, padx=12)
    ttk.Label(options_frame, text="Min size (MB):").pack(side=tk.LEFT, padx=(12, 6))
    tk.Entry(options_frame, textvariable=min_mb_var, width=6).pack(side=tk.LEFT)

    profile_frame = ttk.Frame(scanner_tab)
    profile_frame.pack(fill=tk.X, padx=16, pady=(4, 10))
    ttk.Label(profile_frame, text="Policy profile:").pack(side=tk.LEFT)
    profile_combo = ttk.Combobox(
        profile_frame,
        textvariable=profile_var,
        values=profile_names,
        state="readonly",
        width=18,
    )
    profile_combo.pack(side=tk.LEFT, padx=8)
    profile_desc = ttk.Label(profile_frame, textvariable=profile_desc_var, style="Muted.TLabel")
    profile_desc.pack(side=tk.LEFT, padx=8)

    def on_profile_change(event: Optional[tk.Event] = None) -> None:
        name = profile_var.get()
        profile = get_profile(name, profiles)
        profile_desc_var.set(str(profile.get("description", "")))

    profile_combo.bind("<<ComboboxSelected>>", on_profile_change)

    status_frame = ttk.Frame(scanner_tab)
    status_frame.pack(fill=tk.X, padx=16, pady=(0, 10))
    ttk.Label(status_frame, textvariable=summary_var).pack(anchor="w")
    ttk.Label(status_frame, textvariable=progress_var, style="Muted.TLabel").pack(anchor="w")

    columns = ("category", "size", "files", "path", "safe")
    tree = ttk.Treeview(results_tab, columns=columns, show="headings", height=18)
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
    tree.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)

    settings_label = ttk.Label(
        settings_tab,
        text="Folders to skip during full scan (one per line):",
        style="Muted.TLabel",
    )
    settings_label.pack(anchor="w", padx=16, pady=(16, 6))
    skip_text = tk.Text(settings_tab, height=10)
    skip_text.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 12))
    skip_text.insert("1.0", "\n".join(config.get("skip_dirs", DEFAULT_SKIP_DIRS)))

    audit_frame = ttk.Frame(settings_tab)
    audit_frame.pack(fill=tk.X, padx=16, pady=(0, 12))
    audit_enabled_var = tk.BooleanVar(value=bool(config.get("audit_enabled", True)))
    tk.Checkbutton(
        audit_frame,
        text="Enable audit logging",
        variable=audit_enabled_var,
        bg=panel_bg,
    ).pack(anchor="w")
    ttk.Label(audit_frame, text="Audit sink path (optional):").pack(anchor="w", pady=(6, 2))
    audit_sink_var = tk.StringVar(value=str(config.get("audit_sink_path", "")))
    tk.Entry(audit_frame, textvariable=audit_sink_var, width=70).pack(anchor="w")
    ttk.Label(audit_frame, text="Audit HTTP endpoint (optional):").pack(anchor="w", pady=(6, 2))
    audit_endpoint_var = tk.StringVar(value=str(config.get("audit_http_endpoint", "")))
    tk.Entry(audit_frame, textvariable=audit_endpoint_var, width=70).pack(anchor="w")

    treemap_header = ttk.Label(
        treemap_tab,
        text="Tree Map View (beginner friendly): scan a drive and click rectangles to drill down.",
        style="Muted.TLabel",
    )
    treemap_header.pack(anchor="w", padx=16, pady=(16, 6))

    treemap_controls = ttk.Frame(treemap_tab)
    treemap_controls.pack(fill=tk.X, padx=16, pady=4)
    ttk.Label(treemap_controls, text="Root path:").pack(side=tk.LEFT)
    treemap_root_var = tk.StringVar(value="C:\\")
    tk.Entry(treemap_controls, textvariable=treemap_root_var, width=12).pack(
        side=tk.LEFT, padx=6
    )
    ttk.Label(treemap_controls, text="Max depth:").pack(side=tk.LEFT)
    treemap_depth_var = tk.StringVar(value="2")
    tk.Entry(treemap_controls, textvariable=treemap_depth_var, width=4).pack(
        side=tk.LEFT, padx=6
    )
    ttk.Label(treemap_controls, text="Min size (MB):").pack(side=tk.LEFT)
    treemap_min_var = tk.StringVar(value="50")
    tk.Entry(treemap_controls, textvariable=treemap_min_var, width=6).pack(
        side=tk.LEFT, padx=6
    )
    treemap_scan_button = ttk.Button(treemap_controls, text="Scan")
    treemap_scan_button.pack(side=tk.LEFT, padx=6)
    treemap_back_button = ttk.Button(treemap_controls, text="Back", state=tk.DISABLED)
    treemap_back_button.pack(side=tk.LEFT)

    treemap_status = ttk.Frame(treemap_tab)
    treemap_status.pack(fill=tk.X, padx=16, pady=4)
    ttk.Label(treemap_status, textvariable=treemap_summary_var).pack(anchor="w")
    ttk.Label(treemap_status, textvariable=treemap_progress_var, style="Muted.TLabel").pack(
        anchor="w"
    )

    treemap_canvas = tk.Canvas(treemap_tab, background="#f8fafc", highlightthickness=0)
    treemap_canvas.pack(fill=tk.BOTH, expand=True, padx=16, pady=10)

    treemap_legend = ttk.Label(
        treemap_tab,
        text="Tip: click a rectangle to zoom in; use Back to go up.",
        style="Muted.TLabel",
    )
    treemap_legend.pack(anchor="w", padx=16, pady=(0, 12))

    treemap_root: Optional[TreeNode] = None
    treemap_stack: List[TreeNode] = []
    treemap_rects: List[Tuple[int, TreeNode]] = []
    tree_item_map: Dict[str, ScanItem] = {}

    def refresh_view() -> None:
        tree.delete(*tree.get_children())
        tree_item_map.clear()
        for item in items:
            safety = "SAFE" if item.safe_to_delete else "REVIEW"
            tree_id = tree.insert(
                "",
                tk.END,
                values=(
                    item.label,
                    human_bytes(item.size_bytes),
                    item.file_count,
                    item.path,
                    safety,
                ),
            )
            tree_item_map[tree_id] = item

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
        item = tree_item_map.get(selected[0])
        if not item:
            return
        path = item.path
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

    def run_one_click() -> None:
        def worker() -> None:
            nonlocal items
            profile_name = profile_var.get() or "enterprise"
            profile = get_profile(profile_name, profiles)
            categories = profile_categories(profile) or list(ONE_CLICK_CATEGORIES)
            allow_dangerous = bool(profile.get("allow_dangerous", False))
            ok = messagebox.askyesno(
                "One Click Clean",
                f"Run the '{profile_name}' policy profile?",
            )
            if not ok:
                return
            summary_var.set("Running one-click cleanup...")
            progress_var.set("")
            items = scan_rules()
            deleted_bytes, deleted_files, failures, skipped = clean_by_categories(
                items, categories, allow_dangerous=allow_dangerous
            )
            emit_audit_event(
                action="profile_clean",
                profile=profile_name,
                categories=categories,
                deleted_bytes=deleted_bytes,
                deleted_files=deleted_files,
                failures=failures,
                skipped=skipped,
            )
            summary = (
                f"Profile '{profile_name}' removed {deleted_files} items ({human_bytes(deleted_bytes)})."
            )
            if skipped:
                summary += "\nSome items require admin rights."
            if failures:
                summary += "\nSome items could not be removed."
            messagebox.showinfo("One Click Clean", summary)
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
        chosen = [tree_item_map[item_id] for item_id in selected if item_id in tree_item_map]
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
        emit_audit_event(
            action="manual_clean",
            profile="manual",
            categories=[item.category for item in chosen],
            deleted_bytes=deleted_bytes,
            deleted_files=deleted_files,
            failures=failures,
            skipped=[],
        )
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
            "policy_profile": profile_var.get(),
            "audit_enabled": audit_enabled_var.get(),
            "audit_sink_path": audit_sink_var.get(),
            "audit_http_endpoint": audit_endpoint_var.get(),
        }
        save_config(config_update)
        messagebox.showinfo("Cleaner", "Settings saved.")

    scanner_buttons = ttk.Frame(scanner_tab)
    scanner_buttons.pack(fill=tk.X, padx=16, pady=12)
    ttk.Button(
        scanner_buttons,
        text="Scan Now",
        command=run_scan_in_background,
        style="Primary.TButton",
    ).pack(side=tk.LEFT)
    ttk.Button(
        scanner_buttons,
        text="One Click Clean",
        command=run_one_click,
    ).pack(side=tk.LEFT, padx=8)
    ttk.Button(scanner_buttons, text="Save Settings", command=save_settings).pack(
        side=tk.LEFT, padx=8
    )
    ttk.Button(scanner_buttons, text="Exit", command=root.destroy).pack(side=tk.RIGHT)

    results_buttons = ttk.Frame(results_tab)
    results_buttons.pack(fill=tk.X, padx=16, pady=12)
    ttk.Button(results_buttons, text="Open Folder", command=open_selected_path).pack(
        side=tk.LEFT
    )
    ttk.Button(results_buttons, text="Export Report", command=export_report).pack(
        side=tk.LEFT, padx=8
    )
    ttk.Button(results_buttons, text="Clean Selected", command=clean_selected, style="Primary.TButton").pack(
        side=tk.RIGHT
    )

    start_tab = os.environ.get("CLEANER_START_TAB", "").strip().lower()
    if start_tab == "results":
        notebook.select(results_tab)
    elif start_tab == "settings":
        notebook.select(settings_tab)
    elif start_tab in {"treemap", "tree", "tree map"}:
        notebook.select(treemap_tab)
    else:
        notebook.select(scanner_tab)

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
        "--profile",
        help="Use a policy profile (see profiles list).",
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
        "--one-click",
        action="store_true",
        help="Run the one-click cleanup set.",
    )
    clean_cmd.add_argument(
        "--audit-sink",
        help="Write audit events to an additional JSONL path (e.g., UNC share).",
    )
    clean_cmd.add_argument(
        "--audit-endpoint",
        help="Send audit events to an HTTP endpoint.",
    )
    clean_cmd.add_argument(
        "--audit-disable",
        action="store_true",
        help="Disable audit events for this run.",
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

    profiles_cmd = sub.add_parser("profiles", help="List or export policy profiles.")
    profiles_cmd.add_argument("--list", action="store_true", help="List profiles.")
    profiles_cmd.add_argument("--show", help="Show a profile by name.")
    profiles_cmd.add_argument("--export", help="Export profiles to JSON.")

    schedule_cmd = sub.add_parser("schedule", help="Manage scheduled cleanups.")
    schedule_cmd.add_argument("--create", action="store_true", help="Create a schedule.")
    schedule_cmd.add_argument("--delete", action="store_true", help="Delete a schedule.")
    schedule_cmd.add_argument("--run-now", action="store_true", help="Run a schedule now.")
    schedule_cmd.add_argument("--list", action="store_true", help="List schedules.")
    schedule_cmd.add_argument("--name", help="Task name (default uses profile).")
    schedule_cmd.add_argument("--profile", default="enterprise", help="Profile to run.")
    schedule_cmd.add_argument("--freq", default="DAILY", help="DAILY or WEEKLY.")
    schedule_cmd.add_argument("--time", default="02:00", help="Start time (HH:MM).")
    schedule_cmd.add_argument("--days", help="Weekly days, e.g. MON,TUE.")
    schedule_cmd.add_argument(
        "--run-level", default="LIMITED", help="LIMITED or HIGHEST."
    )

    audit_cmd = sub.add_parser("audit", help="Export or push audit logs.")
    audit_cmd.add_argument("--export", help="Export audit log to a file.")
    audit_cmd.add_argument(
        "--format",
        default="jsonl",
        choices=["jsonl", "json", "csv"],
        help="Export format.",
    )
    audit_cmd.add_argument("--push", help="Push audit log to an HTTP endpoint.")

    args = parser.parse_args(argv)

    if args.command == "gui":
        launch_gui()
        return 0

    config = load_config()
    profiles = load_profiles()

    if args.command == "profiles":
        if args.export:
            with open(args.export, "w", encoding="utf-8") as handle:
                json.dump(profiles, handle, indent=2)
            print(f"Profiles exported to {args.export}")
            return 0
        if args.show:
            profile = get_profile(args.show, profiles)
            print(json.dumps(profile, indent=2))
            return 0
        for name in sorted(profiles.keys()):
            profile = profiles[name]
            label = profile.get("label", name)
            desc = profile.get("description", "")
            print(f"- {name}: {label} {('- ' + desc) if desc else ''}")
        return 0

    if args.command == "schedule":
        profile_name = args.profile or "enterprise"
        task_name = args.name or f"CDriveCleaner - {profile_name}"
        if args.list:
            tasks = schedule_list()
            if tasks:
                for task in tasks:
                    print(task)
            else:
                print("No schedules found.")
            return 0
        if args.delete:
            print(schedule_delete(task_name))
            return 0
        if args.run_now:
            print(schedule_run(task_name))
            return 0
        if args.create:
            days = [d.strip().upper() for d in (args.days or "").split(",") if d.strip()]
            output = schedule_create(
                name=task_name,
                profile=profile_name,
                frequency=str(args.freq).upper(),
                time_of_day=args.time,
                days=days or None,
                run_level=str(args.run_level).upper(),
            )
            print(output)
            return 0
        print(schedule_query(task_name))
        return 0

    if args.command == "audit":
        events = read_audit_events()
        if args.export:
            if args.format == "jsonl":
                with open(args.export, "w", encoding="utf-8") as handle:
                    for event in events:
                        handle.write(json.dumps(event) + "\n")
            elif args.format == "json":
                with open(args.export, "w", encoding="utf-8") as handle:
                    json.dump(events, handle, indent=2)
            else:
                if events:
                    with open(args.export, "w", encoding="utf-8", newline="") as handle:
                        writer = csv.DictWriter(handle, fieldnames=sorted(events[0].keys()))
                        writer.writeheader()
                        writer.writerows(events)
            print(f"Audit exported to {args.export}")
            return 0
        if args.push:
            for event in events:
                write_audit_event(event, sink="", endpoint=args.push)
            print(f"Audit pushed to {args.push}")
            return 0
        print(f"{len(events)} audit events found.")
        return 0

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
        audit_overrides = {
            "sink": args.audit_sink,
            "endpoint": args.audit_endpoint,
            "enabled": False if args.audit_disable else None,
        }
        if args.profile:
            profile = get_profile(args.profile, profiles)
            categories = profile_categories(profile)
            allow_dangerous = bool(profile.get("allow_dangerous", False)) or args.dangerous
            deleted_bytes, deleted_files, failures, skipped = clean_by_categories(
                items, categories, allow_dangerous=allow_dangerous
            )
            emit_audit_event(
                action="profile_clean",
                profile=args.profile,
                categories=categories,
                deleted_bytes=deleted_bytes,
                deleted_files=deleted_files,
                failures=failures,
                skipped=skipped,
                audit_overrides=audit_overrides,
            )
            print(
                f"Profile '{args.profile}' removed {deleted_files} entries totaling {human_bytes(deleted_bytes)}."
            )
            if skipped:
                print("Skipped (admin required):")
                for item in skipped:
                    print(f"- {item}")
            if failures:
                print("Failures:")
                for fail in failures:
                    print(f"- {fail}")
            return 0
        if args.one_click:
            deleted_bytes, deleted_files, failures, skipped = one_click_clean(items)
            emit_audit_event(
                action="one_click",
                profile="one_click",
                categories=list(ONE_CLICK_CATEGORIES),
                deleted_bytes=deleted_bytes,
                deleted_files=deleted_files,
                failures=failures,
                skipped=skipped,
                audit_overrides=audit_overrides,
            )
            print(
                f"One-click cleanup removed {deleted_files} entries totaling {human_bytes(deleted_bytes)}."
            )
            if skipped:
                print("Skipped (admin required):")
                for item in skipped:
                    print(f"- {item}")
            if failures:
                print("Failures:")
                for fail in failures:
                    print(f"- {fail}")
            return 0
        if args.category:
            items = [item for item in items if item.category in args.category]
        if args.dry_run:
            print(format_report(items))
            return 0
        deleted_bytes, deleted_files, failures = clean_items(
            items, allow_dangerous=args.dangerous
        )
        emit_audit_event(
            action="manual_clean",
            profile="manual",
            categories=[item.category for item in items],
            deleted_bytes=deleted_bytes,
            deleted_files=deleted_files,
            failures=failures,
            skipped=[],
            audit_overrides=audit_overrides,
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
