from __future__ import annotations

import json
import os
from pathlib import Path

from security_audit.config import Config
from security_audit.files import iter_files

MANIFESTS = (
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
)

FRAMEWORK_PACKAGES = {
    "vite": "Vite",
    "react": "React",
    "next": "Next.js",
    "express": "Express",
    "firebase": "Firebase",
    "gsap": "GSAP",
    "vue": "Vue",
    "svelte": "Svelte",
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
}

LANGUAGE_BY_EXTENSION = {
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".py": "Python",
    ".html": "HTML",
    ".css": "CSS",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".java": "Java",
    ".tf": "Terraform",
}


def _package_names(root: Path) -> set[str]:
    path = root / "package.json"
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    names: set[str] = set()
    if isinstance(data, dict):
        for key in ("dependencies", "devDependencies"):
            block = data.get(key)
            if isinstance(block, dict):
                names.update(str(name) for name in block)
    return names


def inventory_repository(root: Path, config: Config) -> dict[str, object]:
    root = root.resolve()
    languages: dict[str, int] = {}
    manifests: list[str] = []
    for path in iter_files(root, config, include_binary=True):
        if path.name in MANIFESTS:
            manifests.append(path.relative_to(root).as_posix())
        language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
        if language:
            languages[language] = languages.get(language, 0) + 1
    frameworks = sorted(
        label for package, label in FRAMEWORK_PACKAGES.items() if package in _package_names(root)
    )
    if (root / "firebase.json").is_file() and "Firebase Hosting" not in frameworks:
        frameworks.append("Firebase Hosting")
    if (root / "Dockerfile").is_file():
        frameworks.append("Docker")
    env_example = (root / ".env.example").is_file()
    env_file = (root / ".env").is_file()
    gitignore = ""
    gitignore_path = root / ".gitignore"
    if gitignore_path.is_file():
        try:
            gitignore = gitignore_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            gitignore = ""
    package_name = root.name
    package_path = root / "package.json"
    if package_path.is_file():
        try:
            package_data = json.loads(package_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            package_data = {}
        if isinstance(package_data, dict) and isinstance(package_data.get("name"), str):
            package_name = package_data["name"]
    return {
        "name": package_name,
        "path": str(root),
        "languages": sorted(languages, key=lambda name: (-languages[name], name)),
        "language_counts": languages,
        "frameworks": frameworks,
        "manifests": sorted(manifests),
        "env_example_present": env_example,
        "env_file_present": env_file,
        "env_gitignored": ".env" in gitignore.splitlines() or any(
            line.strip() == ".env" for line in gitignore.splitlines()
        ),
    }


def _classify(path: str) -> str:
    normalized = path.replace("\\", "/")
    if (
        "/.cursor/" in normalized
        or normalized.endswith("/.cursor")
        or "/plugins/cache/" in normalized
    ):
        return "editor_plugin_cache"
    if "/.nvm" in normalized or "/.npm" in normalized:
        return "runtime_manager"
    return "other"


def machine_git_counts(home: Path | None) -> dict[str, object]:
    counts = {"editor_plugin_cache": 0, "runtime_manager": 0, "other": 0}
    if home is None or not home.is_dir():
        return {"counts": counts, "status": "home directory unavailable"}
    start_depth = len(home.resolve().parts)
    try:
        for dirpath, dirnames, _filenames in os.walk(home, followlinks=False):
            current = Path(dirpath)
            depth = len(current.parts) - start_depth
            if depth > 10:
                dirnames[:] = []
                continue
            if ".git" in dirnames:
                counts[_classify(str(current))] += 1
                dirnames[:] = []
                continue
            dirnames[:] = [
                name
                for name in dirnames
                if name not in {"node_modules", "dist", "proc", "sys", "dev"}
            ]
    except OSError as exc:
        return {"counts": counts, "status": f"incomplete ({exc.__class__.__name__})"}
    return {"counts": counts, "status": "counted without reading file contents"}
