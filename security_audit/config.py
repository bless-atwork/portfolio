from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    exclude_dir_names: set[str] = field(default_factory=set)
    exclude_file_names: set[str] = field(default_factory=set)
    skip_prefixes: tuple[str, ...] = ()
    max_file_bytes: int = 800_000
    dependency_penalty_cap: int = 35
    downgrade_development_severities: bool = True
    alert_severities: set[str] = field(default_factory=lambda: {"critical"})
    alert_exposures: set[str] = field(
        default_factory=lambda: {
            "application",
            "production-runtime",
            "secret",
            "database",
            "ci",
        }
    )
    database_host: str = "127.0.0.1"
    npm_audit: bool = True
    external_scanners: bool = True
    snyk: bool = False
    machine_inventory: bool = True
    weights: dict[str, int] = field(
        default_factory=lambda: {"critical": 25, "high": 12, "medium": 5, "low": 2}
    )


def _as_set(value: object, fallback: set[str]) -> set[str]:
    if isinstance(value, list):
        return {str(item) for item in value}
    return set(fallback)


def load_config(root: Path) -> Config:
    packaged = Path(__file__).with_name("config.json")
    project = root / "security_audit" / "config.json"
    path = project if project.is_file() else packaged
    data: dict[str, object] = {}
    if path.is_file():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            data = loaded
    network = data.get("network") if isinstance(data.get("network"), dict) else {}
    weights = data.get("weights") if isinstance(data.get("weights"), dict) else {}
    config = Config(
        exclude_dir_names=_as_set(
            data.get("exclude_dir_names"),
            {
                ".git",
                "node_modules",
                "dist",
                "dist-ssr",
                ".firebase",
                "coverage",
                ".tools",
                "__pycache__",
            },
        ),
        exclude_file_names=_as_set(
            data.get("exclude_file_names"),
            {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
        ),
        skip_prefixes=tuple(
            str(item)
            for item in data.get(
                "skip_prefixes",
                [
                    "security_audit/rules/",
                    "security_audit/.tools/",
                    "security_audit/tests/",
                ],
            )
            if isinstance(data.get("skip_prefixes", []), list)
        ),
        max_file_bytes=int(data.get("max_file_bytes", 800_000)),
        dependency_penalty_cap=int(data.get("dependency_penalty_cap", 35)),
        downgrade_development_severities=bool(
            data.get("downgrade_development_severities", True)
        ),
        alert_severities=_as_set(data.get("alert_severities"), {"critical"}),
        alert_exposures=_as_set(
            data.get("alert_exposures"),
            {"application", "production-runtime", "secret", "database", "ci"},
        ),
        database_host=str(data.get("database_host", "127.0.0.1")),
        npm_audit=bool(network.get("npm_audit", True)),
        external_scanners=bool(network.get("external_scanners", True)),
        snyk=bool(network.get("snyk", False)),
        machine_inventory=bool(data.get("machine_inventory", True)),
    )
    for name, value in weights.items():
        if name in config.weights:
            config.weights[name] = int(value)
    return config
