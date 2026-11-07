from __future__ import annotations

import os
from pathlib import Path

from security_audit.config import Config


ROOT_OUTPUT_DIRS = {
    "security_reports",
    "reports",
    "alerts",
    "history",
    "knowledge_base",
    "vulnerability_patterns",
    "trend_analysis",
    "logs",
}

TEXT_EXTENSIONS = {
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".py",
    ".json",
    ".yml",
    ".yaml",
    ".html",
    ".css",
    ".toml",
    ".txt",
    ".xml",
    ".gradle",
    ".php",
    ".rb",
    ".go",
    ".rs",
    ".tf",
    ".sh",
    ".ps1",
    ".md",
    ".env",
    ".example",
    ".ini",
    ".cfg",
    ".sql",
    ".dockerfile",
}

BINARY_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".pdf",
    ".docx",
    ".doc",
    ".zip",
    ".gz",
    ".woff",
    ".woff2",
    ".ico",
    ".mp4",
    ".mp3",
}


def is_within(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return path.name


def location(root: Path, path: Path, line: int | None = None) -> str:
    rel = relative(root, path)
    if line is None:
        return rel
    return f"{rel}:{line}"


def _skipped(root: Path, path: Path, config: Config) -> bool:
    if not is_within(root, path):
        return True
    rel = relative(root, path)
    return any(rel.startswith(prefix) for prefix in config.skip_prefixes)


def iter_files(root: Path, config: Config, *, include_binary: bool = False):
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        if not is_within(root, current):
            dirnames[:] = []
            continue
        pruned: list[str] = []
        for name in dirnames:
            if name in config.exclude_dir_names:
                continue
            if current == root and name in ROOT_OUTPUT_DIRS:
                continue
            candidate = current / name
            if candidate.is_symlink() or not is_within(root, candidate):
                continue
            if _skipped(root, candidate, config):
                continue
            pruned.append(name)
        dirnames[:] = pruned
        if _skipped(root, current, config):
            continue
        for name in filenames:
            if name in config.exclude_file_names:
                continue
            path = current / name
            if path.is_symlink() or not path.is_file():
                continue
            if not include_binary and path.suffix.lower() in BINARY_EXTENSIONS:
                continue
            if _skipped(root, path, config):
                continue
            yield path


def read_text(path: Path, limit: int) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > limit:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:1024]:
        return None
    return data.decode("utf-8", errors="replace")
