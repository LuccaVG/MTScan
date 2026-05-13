"""Durable scan summary storage for MTScan graphs.

The web app keeps live scan logs in memory, but graph data should survive
restarts. Cassandra is used when available; a local JSONL store is used as a
zero-setup fallback so the interface stays seamless while Cassandra is being
installed or started.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
import threading
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:  # Optional dependency: installed through config/requirements.txt.
    from cassandra.cluster import Cluster  # type: ignore
except Exception:  # pragma: no cover - exercised when dependency is absent.
    Cluster = None  # type: ignore


DEFAULT_KEYSPACE = "mtscan"
DEFAULT_HISTORY_FILE = Path(__file__).resolve().parents[1] / "data" / "scan_history.jsonl"
DEFAULT_SCHEDULE_FILE = Path(__file__).resolve().parents[1] / "data" / "schedules.json"
DEFAULT_AUTH_FILE = Path(__file__).resolve().parents[1] / "data" / "auth.json"
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,47}$")


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_datetime(value: object) -> Optional[_dt.datetime]:
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=_dt.timezone.utc)
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=_dt.timezone.utc)


def _format_datetime(value: object) -> Optional[str]:
    parsed = _parse_datetime(value)
    if not parsed:
        return None
    return parsed.astimezone().isoformat(timespec="seconds")


def _json_dumps(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def _json_loads(value: object, fallback: object) -> object:
    if not value:
        return fallback
    try:
        return json.loads(str(value))
    except (TypeError, ValueError):
        return fallback


def _cql_identifier(value: str) -> str:
    if not IDENTIFIER_PATTERN.match(value):
        raise RuntimeError("Cassandra keyspace must start with a letter and contain only letters, numbers, or underscores")
    return value


def _history_sort_key(record: Dict[str, object]) -> str:
    return str(record.get("finished_at") or record.get("started_at") or record.get("created_at") or "")


def normalize_scan_record(record: Dict[str, object]) -> Dict[str, object]:
    """Return an app-compatible scan record suitable for API responses."""
    scan_id = str(record.get("id") or record.get("scan_id") or "")
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    results = record.get("results") if isinstance(record.get("results"), list) else []
    return {
        "id": scan_id,
        "target": str(record.get("target") or ""),
        "mode": str(record.get("mode") or "chain"),
        "status": str(record.get("status") or "completed"),
        "created_at": _format_datetime(record.get("created_at")) or str(record.get("created_at") or ""),
        "started_at": _format_datetime(record.get("started_at")),
        "finished_at": _format_datetime(record.get("finished_at")) or _format_datetime(_utc_now()),
        "dry_run": bool(record.get("dry_run", False)),
        "json_output": bool(record.get("json_output", True)),
        "output_dir": str(record.get("output_dir") or "") or None,
        "error": str(record.get("error") or "") or None,
        "lines": [],
        "results": results,
        "summary": summary,
        "report_file": str(record.get("report_file") or "") or None,
        "storage": str(record.get("storage") or ""),
    }


def normalize_schedule_record(record: Dict[str, object]) -> Dict[str, object]:
    """Return an app-compatible recurring scan schedule record."""
    schedule_id = str(record.get("id") or record.get("schedule_id") or "")
    options = record.get("options") if isinstance(record.get("options"), dict) else {}
    return {
        "id": schedule_id,
        "name": str(record.get("name") or ""),
        "target": str(record.get("target") or ""),
        "mode": str(record.get("mode") or "chain"),
        "profile": str(record.get("profile") or "default"),
        "options": options,
        "interval_hours": int(record.get("interval_hours") or 1),
        "enabled": bool(record.get("enabled", True)),
        "dry_run": bool(record.get("dry_run", False)),
        "json_output": bool(record.get("json_output", True)),
        "created_at": _format_datetime(record.get("created_at")) or _format_datetime(_utc_now()),
        "updated_at": _format_datetime(record.get("updated_at")) or _format_datetime(_utc_now()),
        "last_run_at": _format_datetime(record.get("last_run_at")),
        "next_run_at": _format_datetime(record.get("next_run_at")),
        "last_scan_id": str(record.get("last_scan_id") or "") or None,
        "last_status": str(record.get("last_status") or "") or None,
    }


def _schedule_sort_key(record: Dict[str, object]) -> str:
    return str(record.get("next_run_at") or record.get("updated_at") or record.get("created_at") or "")


class DisabledScanStore:
    backend = "off"

    def __init__(self, reason: str = "disabled") -> None:
        self.reason = reason
        self.auth_record: Optional[Dict[str, object]] = None

    def save_scan(self, record: Dict[str, object]) -> None:
        return None

    def list_scans(self, limit: int = 100, target: Optional[str] = None) -> List[Dict[str, object]]:
        return []

    def get_scan(self, scan_id: str) -> Optional[Dict[str, object]]:
        return None

    def save_schedule(self, record: Dict[str, object]) -> None:
        return None

    def list_schedules(self, limit: int = 100) -> List[Dict[str, object]]:
        return []

    def get_schedule(self, schedule_id: str) -> Optional[Dict[str, object]]:
        return None

    def delete_schedule(self, schedule_id: str) -> bool:
        return False

    def get_auth(self) -> Optional[Dict[str, object]]:
        return self.auth_record.copy() if self.auth_record else None

    def save_auth(self, record: Dict[str, object]) -> None:
        self.auth_record = record.copy()

    def status(self) -> Dict[str, object]:
        return {"backend": self.backend, "available": "no", "detail": self.reason}


class FileScanStore:
    backend = "file"

    def __init__(self, path: Optional[Path] = None, detail: str = "local JSONL fallback") -> None:
        self.path = Path(path or os.environ.get("MTSCAN_HISTORY_FILE") or DEFAULT_HISTORY_FILE)
        self.schedule_path = Path(os.environ.get("MTSCAN_SCHEDULE_FILE") or DEFAULT_SCHEDULE_FILE)
        self.auth_path = Path(os.environ.get("MTSCAN_AUTH_FILE") or DEFAULT_AUTH_FILE)
        self.detail = detail
        self.lock = threading.Lock()

    def save_scan(self, record: Dict[str, object]) -> None:
        normalized = normalize_scan_record({**record, "storage": self.backend})
        if not normalized["id"]:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(_json_dumps(normalized) + "\n")

    def _read_records(self) -> List[Dict[str, object]]:
        if not self.path.exists():
            return []
        records: List[Dict[str, object]] = []
        with self.lock:
            try:
                lines = self.path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                return []
        for line in lines:
            if not line.strip():
                continue
            loaded = _json_loads(line, {})
            if isinstance(loaded, dict):
                records.append(normalize_scan_record(loaded))
        return records

    def list_scans(self, limit: int = 100, target: Optional[str] = None) -> List[Dict[str, object]]:
        by_id: Dict[str, Dict[str, object]] = {}
        for record in self._read_records():
            if target and record.get("target") != target:
                continue
            by_id[str(record.get("id"))] = record
        records = sorted(by_id.values(), key=_history_sort_key, reverse=True)
        return records[: max(0, limit)]

    def get_scan(self, scan_id: str) -> Optional[Dict[str, object]]:
        for record in reversed(self._read_records()):
            if record.get("id") == scan_id:
                return record
        return None

    def _read_json_file(self, path: Path, fallback: object) -> object:
        if not path.exists():
            return fallback
        with self.lock:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return fallback
        return _json_loads(text, fallback)

    def _write_json_file(self, path: Path, data: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = _json_dumps(data) + "\n"
        with self.lock:
            path.write_text(payload, encoding="utf-8")

    def _read_schedule_map(self) -> Dict[str, Dict[str, object]]:
        loaded = self._read_json_file(self.schedule_path, {})
        if not isinstance(loaded, dict):
            return {}
        schedules: Dict[str, Dict[str, object]] = {}
        for key, value in loaded.items():
            if isinstance(value, dict):
                record = normalize_schedule_record(value)
                schedule_id = str(record.get("id") or key)
                if schedule_id:
                    record["id"] = schedule_id
                    schedules[schedule_id] = record
        return schedules

    def save_schedule(self, record: Dict[str, object]) -> None:
        normalized = normalize_schedule_record(record)
        schedule_id = str(normalized.get("id") or "")
        if not schedule_id:
            return
        schedules = self._read_schedule_map()
        schedules[schedule_id] = normalized
        self._write_json_file(self.schedule_path, schedules)

    def list_schedules(self, limit: int = 100) -> List[Dict[str, object]]:
        records = sorted(self._read_schedule_map().values(), key=_schedule_sort_key)
        return records[: max(0, limit)]

    def get_schedule(self, schedule_id: str) -> Optional[Dict[str, object]]:
        return self._read_schedule_map().get(schedule_id)

    def delete_schedule(self, schedule_id: str) -> bool:
        schedules = self._read_schedule_map()
        if schedule_id not in schedules:
            return False
        schedules.pop(schedule_id, None)
        self._write_json_file(self.schedule_path, schedules)
        return True

    def get_auth(self) -> Optional[Dict[str, object]]:
        loaded = self._read_json_file(self.auth_path, {})
        return loaded if isinstance(loaded, dict) and loaded else None

    def save_auth(self, record: Dict[str, object]) -> None:
        self._write_json_file(self.auth_path, record)

    def status(self) -> Dict[str, object]:
        return {
            "backend": self.backend,
            "available": "yes",
            "detail": self.detail,
            "path": str(self.path),
            "schedule_path": str(self.schedule_path),
            "auth_path": str(self.auth_path),
        }


class CassandraScanStore:
    backend = "cassandra"

    def __init__(
        self,
        hosts: Optional[Iterable[str]] = None,
        port: Optional[int] = None,
        keyspace: Optional[str] = None,
    ) -> None:
        if Cluster is None:
            raise RuntimeError("cassandra-driver is not installed")

        host_text = os.environ.get("MTSCAN_CASSANDRA_HOSTS", "127.0.0.1")
        self.hosts = list(hosts or [item.strip() for item in host_text.split(",") if item.strip()])
        self.port = int(port or os.environ.get("MTSCAN_CASSANDRA_PORT", "9042"))
        self.keyspace = _cql_identifier(keyspace or os.environ.get("MTSCAN_CASSANDRA_KEYSPACE", DEFAULT_KEYSPACE))
        connect_timeout = float(os.environ.get("MTSCAN_CASSANDRA_CONNECT_TIMEOUT", "2"))
        control_timeout = float(os.environ.get("MTSCAN_CASSANDRA_CONTROL_TIMEOUT", "2"))
        self.cluster = Cluster(  # type: ignore[operator]
            self.hosts,
            port=self.port,
            connect_timeout=connect_timeout,
            control_connection_timeout=control_timeout,
        )
        system_session = self.cluster.connect()
        system_session.execute(
            f"""
            CREATE KEYSPACE IF NOT EXISTS {self.keyspace}
            WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}}
            """
        )
        system_session.shutdown()
        self.session = self.cluster.connect(self.keyspace)
        self._ensure_schema()
        self.imported_file_history = self._import_file_history()

    def _ensure_schema(self) -> None:
        self.session.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_by_id (
                scan_id text PRIMARY KEY,
                target text,
                mode text,
                status text,
                created_at timestamp,
                started_at timestamp,
                finished_at timestamp,
                dry_run boolean,
                json_output boolean,
                output_dir text,
                error text,
                summary_json text,
                results_json text,
                report_file text
            )
            """
        )
        self.session.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                bucket text,
                finished_at timestamp,
                scan_id text,
                target text,
                mode text,
                status text,
                summary_json text,
                PRIMARY KEY ((bucket), finished_at, scan_id)
            ) WITH CLUSTERING ORDER BY (finished_at DESC)
            """
        )
        self.session.execute(
            """
            CREATE TABLE IF NOT EXISTS schedules (
                schedule_id text PRIMARY KEY,
                name text,
                target text,
                mode text,
                profile text,
                options_json text,
                interval_hours int,
                enabled boolean,
                dry_run boolean,
                json_output boolean,
                created_at timestamp,
                updated_at timestamp,
                last_run_at timestamp,
                next_run_at timestamp,
                last_scan_id text,
                last_status text
            )
            """
        )
        self.session.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                setting_key text PRIMARY KEY,
                value_json text,
                updated_at timestamp
            )
            """
        )

    def _import_file_history(self) -> int:
        if os.environ.get("MTSCAN_CASSANDRA_IMPORT_FILE_HISTORY", "1").strip().lower() in {"0", "false", "no", "off"}:
            return 0
        path = Path(os.environ.get("MTSCAN_HISTORY_FILE") or DEFAULT_HISTORY_FILE)
        if not path.exists():
            return 0
        try:
            limit = int(os.environ.get("MTSCAN_CASSANDRA_IMPORT_LIMIT", "5000"))
        except ValueError:
            limit = 5000
        count = 0
        for record in FileScanStore(path).list_scans(limit=max(1, limit)):
            self.save_scan(record)
            count += 1
        return count

    def save_scan(self, record: Dict[str, object]) -> None:
        normalized = normalize_scan_record({**record, "storage": self.backend})
        scan_id = str(normalized.get("id") or "")
        if not scan_id:
            return
        finished_at = _parse_datetime(normalized.get("finished_at")) or _utc_now()
        created_at = _parse_datetime(normalized.get("created_at"))
        started_at = _parse_datetime(normalized.get("started_at"))
        summary_json = _json_dumps(normalized.get("summary") or {})
        results_json = _json_dumps(normalized.get("results") or [])
        params = (
            scan_id,
            normalized.get("target"),
            normalized.get("mode"),
            normalized.get("status"),
            created_at,
            started_at,
            finished_at,
            bool(normalized.get("dry_run")),
            bool(normalized.get("json_output")),
            normalized.get("output_dir"),
            normalized.get("error"),
            summary_json,
            results_json,
            normalized.get("report_file"),
        )
        self.session.execute(
            """
            INSERT INTO scan_by_id (
                scan_id, target, mode, status, created_at, started_at, finished_at,
                dry_run, json_output, output_dir, error, summary_json, results_json, report_file
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            params,
        )
        self.session.execute(
            """
            INSERT INTO scan_history (
                bucket, finished_at, scan_id, target, mode, status, summary_json
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                "all",
                finished_at,
                scan_id,
                normalized.get("target"),
                normalized.get("mode"),
                normalized.get("status"),
                summary_json,
            ),
        )

    def _row_to_record(self, row: object) -> Dict[str, object]:
        data = {
            "id": getattr(row, "scan_id", ""),
            "target": getattr(row, "target", ""),
            "mode": getattr(row, "mode", "chain"),
            "status": getattr(row, "status", "completed"),
            "created_at": getattr(row, "created_at", None),
            "started_at": getattr(row, "started_at", None),
            "finished_at": getattr(row, "finished_at", None),
            "dry_run": getattr(row, "dry_run", False),
            "json_output": getattr(row, "json_output", True),
            "output_dir": getattr(row, "output_dir", None),
            "error": getattr(row, "error", None),
            "summary": _json_loads(getattr(row, "summary_json", None), {}),
            "results": _json_loads(getattr(row, "results_json", None), []),
            "report_file": getattr(row, "report_file", None),
            "storage": self.backend,
        }
        return normalize_scan_record(data)

    def list_scans(self, limit: int = 100, target: Optional[str] = None) -> List[Dict[str, object]]:
        if limit <= 0:
            return []
        fetch_limit = max(1, min(limit * 5 if target else limit, 500))
        rows = self.session.execute(
            """
            SELECT finished_at, scan_id, target, mode, status, summary_json
            FROM scan_history
            WHERE bucket = %s
            LIMIT %s
            """,
            ("all", fetch_limit),
        )
        records: List[Dict[str, object]] = []
        for row in rows:
            record = self._row_to_record(row)
            if target and record.get("target") != target:
                continue
            records.append(record)
            if len(records) >= limit:
                break
        return records

    def get_scan(self, scan_id: str) -> Optional[Dict[str, object]]:
        rows = self.session.execute("SELECT * FROM scan_by_id WHERE scan_id = %s", (scan_id,))
        row = rows.one()
        return self._row_to_record(row) if row else None

    def save_schedule(self, record: Dict[str, object]) -> None:
        normalized = normalize_schedule_record(record)
        schedule_id = str(normalized.get("id") or "")
        if not schedule_id:
            return
        params = (
            schedule_id,
            normalized.get("name"),
            normalized.get("target"),
            normalized.get("mode"),
            normalized.get("profile"),
            _json_dumps(normalized.get("options") or {}),
            int(normalized.get("interval_hours") or 1),
            bool(normalized.get("enabled")),
            bool(normalized.get("dry_run")),
            bool(normalized.get("json_output")),
            _parse_datetime(normalized.get("created_at")),
            _parse_datetime(normalized.get("updated_at")),
            _parse_datetime(normalized.get("last_run_at")),
            _parse_datetime(normalized.get("next_run_at")),
            normalized.get("last_scan_id"),
            normalized.get("last_status"),
        )
        self.session.execute(
            """
            INSERT INTO schedules (
                schedule_id, name, target, mode, profile, options_json,
                interval_hours, enabled, dry_run, json_output, created_at,
                updated_at, last_run_at, next_run_at, last_scan_id, last_status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            params,
        )

    def _row_to_schedule(self, row: object) -> Dict[str, object]:
        data = {
            "id": getattr(row, "schedule_id", ""),
            "name": getattr(row, "name", ""),
            "target": getattr(row, "target", ""),
            "mode": getattr(row, "mode", "chain"),
            "profile": getattr(row, "profile", "default"),
            "options": _json_loads(getattr(row, "options_json", None), {}),
            "interval_hours": getattr(row, "interval_hours", 1),
            "enabled": getattr(row, "enabled", True),
            "dry_run": getattr(row, "dry_run", False),
            "json_output": getattr(row, "json_output", True),
            "created_at": getattr(row, "created_at", None),
            "updated_at": getattr(row, "updated_at", None),
            "last_run_at": getattr(row, "last_run_at", None),
            "next_run_at": getattr(row, "next_run_at", None),
            "last_scan_id": getattr(row, "last_scan_id", None),
            "last_status": getattr(row, "last_status", None),
        }
        return normalize_schedule_record(data)

    def list_schedules(self, limit: int = 100) -> List[Dict[str, object]]:
        if limit <= 0:
            return []
        rows = self.session.execute("SELECT * FROM schedules LIMIT %s", (max(1, min(limit, 500)),))
        records = [self._row_to_schedule(row) for row in rows]
        records.sort(key=_schedule_sort_key)
        return records[:limit]

    def get_schedule(self, schedule_id: str) -> Optional[Dict[str, object]]:
        rows = self.session.execute("SELECT * FROM schedules WHERE schedule_id = %s", (schedule_id,))
        row = rows.one()
        return self._row_to_schedule(row) if row else None

    def delete_schedule(self, schedule_id: str) -> bool:
        existed = self.get_schedule(schedule_id) is not None
        self.session.execute("DELETE FROM schedules WHERE schedule_id = %s", (schedule_id,))
        return existed

    def get_auth(self) -> Optional[Dict[str, object]]:
        rows = self.session.execute("SELECT value_json FROM app_settings WHERE setting_key = %s", ("auth",))
        row = rows.one()
        loaded = _json_loads(getattr(row, "value_json", None), {}) if row else {}
        return loaded if isinstance(loaded, dict) and loaded else None

    def save_auth(self, record: Dict[str, object]) -> None:
        self.session.execute(
            """
            INSERT INTO app_settings (setting_key, value_json, updated_at)
            VALUES (%s, %s, %s)
            """,
            ("auth", _json_dumps(record), _utc_now()),
        )

    def status(self) -> Dict[str, object]:
        return {
            "backend": self.backend,
            "available": "yes",
            "detail": "connected",
            "hosts": self.hosts,
            "port": self.port,
            "keyspace": self.keyspace,
            "imported_file_history": self.imported_file_history,
        }


def create_store() -> object:
    backend = os.environ.get("MTSCAN_STORAGE_BACKEND", "auto").strip().lower()
    if backend in {"off", "none", "disabled"}:
        return DisabledScanStore()
    if backend not in {"auto", "cassandra", "file"}:
        return FileScanStore(detail=f"unknown backend '{backend}', using local JSONL fallback")
    if backend == "file":
        return FileScanStore()

    try:
        return CassandraScanStore()
    except Exception as exc:
        detail = f"Cassandra unavailable ({exc}); using local JSONL fallback"
        return FileScanStore(detail=detail)
