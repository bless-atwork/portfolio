from __future__ import annotations

import shutil
import socket
from pathlib import Path

from security_audit.config import Config
from security_audit.files import iter_files, location
from security_audit.models import Finding

_ENGINES = (
    ("postgresql", 5432, "psql"),
    ("mysql", 3306, "mysql"),
    ("mariadb", 3306, "mariadb"),
    ("sqlserver", 1433, "sqlcmd"),
    ("mongodb", 27017, "mongosh"),
    ("redis", 6379, "redis-cli"),
    ("elasticsearch", 9200, "curl"),
)
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
_SQLITE_SUFFIXES = {".sqlite", ".sqlite3", ".db"}


def _listening(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET if ":" not in host else socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(0.3)
    try:
        sock.connect((host, port))
    except OSError:
        return False
    else:
        return True
    finally:
        sock.close()


def scan_databases(
    root: Path, config: Config
) -> tuple[list[Finding], list[dict[str, object]]]:
    findings: list[Finding] = []
    rows: list[dict[str, object]] = []
    host = config.database_host
    local = host in _LOCAL_HOSTS
    checked_ports: dict[int, bool] = {}
    reported_ports: set[int] = set()
    if not local:
        rows.append(
            {
                "engine": "configured-host",
                "status": "not_contacted",
                "detail": "The configured database host is not local, so it was not contacted.",
            }
        )
    for engine, port, client in _ENGINES:
        listening = False
        if local:
            if port not in checked_ports:
                checked_ports[port] = _listening(host, port)
            listening = checked_ports[port]
        client_found = shutil.which(client) is not None
        status = "listening" if listening else "not_listening"
        rows.append(
            {
                "engine": engine,
                "port": port,
                "status": status,
                "client_installed": client_found,
                "authenticated": False,
                "detail": (
                    "Local port accepted a TCP connection. No login, query, or password test was sent."
                    if listening
                    else "No local listener. Passwords, grants, backups, and indexes were not inspected."
                ),
            }
        )
        if listening and port not in reported_ports:
            reported_ports.add(port)
            label = "mysql/mariadb" if port == 3306 else engine
            findings.append(
                Finding(
                    rule_id="database-port-open",
                    title=f"{label} accepts local connections",
                    severity="medium",
                    upstream_severity="medium",
                    exposure="database",
                    category="database",
                    location=f"{host}:{port}",
                    summary=(
                        f"{label} is reachable on the loopback port. "
                        "Authentication, encryption, and privileges were not tested."
                    ),
                    recommendation=(
                        "Confirm the listener is bound to loopback, requires authentication, "
                        "and does not use a default password. Keep backups and encryption enabled."
                    ),
                    likelihood="low",
                    impact="medium",
                    likelihood_score=2,
                    impact_score=3,
                    source="builtin",
                )
            )

    for path in iter_files(root, config, include_binary=True):
        if path.suffix.lower() not in _SQLITE_SUFFIXES:
            continue
        where = location(root, path)
        rows.append(
            {
                "engine": "sqlite",
                "status": "file_present",
                "detail": where,
            }
        )
        findings.append(
            Finding(
                rule_id="sqlite-file-present",
                title="SQLite database file is in the repository tree",
                severity="medium",
                upstream_severity="medium",
                exposure="database",
                category="database",
                location=where,
                summary="The file was not opened and its rows were not read.",
                recommendation="Keep database files out of git. If the file contains personal data, restrict its permissions and encrypt the volume.",
                likelihood="medium",
                impact="medium",
                likelihood_score=3,
                impact_score=3,
                source="builtin",
            )
        )
    if not any(row["engine"] == "sqlite" for row in rows):
        rows.append(
            {
                "engine": "sqlite",
                "status": "not_found",
                "detail": "No SQLite files were found in the scanned tree.",
            }
        )
    return findings, rows
