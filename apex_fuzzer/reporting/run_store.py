"""SQLite run-audit store (stdlib only).

Per-target ``apex.db`` next to the JSONL artifacts. Records what the
pipeline decided, not just what it found: every scope-gate denial
with its stable audit reason, plus one row per run. JSONL stays the
interchange format; this store is the queryable audit trail
(``scope decisions: allowed, denied, blocked-by-IP-policy,
redirect-out-of-scope``).

Fail-closed usage: callers wrap writes in try/except — a store
failure must never fail a scan.
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  host TEXT NOT NULL,
  profile TEXT NOT NULL,
  tool_version TEXT NOT NULL,
  authorization_ref TEXT NOT NULL DEFAULT '',
  started_utc TEXT NOT NULL,
  finished_utc TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scope_decisions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  url TEXT NOT NULL,
  method TEXT NOT NULL,
  reason TEXT NOT NULL,
  at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scope_decisions_run
  ON scope_decisions(run_id);
CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  normalized_url TEXT NOT NULL,
  method TEXT NOT NULL,
  host TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  endpoint_type TEXT NOT NULL DEFAULT '',
  sources TEXT NOT NULL DEFAULT '[]',
  query_params TEXT NOT NULL DEFAULT '[]',
  body_params TEXT NOT NULL DEFAULT '[]',
  content_types TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_endpoints_run
  ON endpoints(run_id);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RunStore:
    """Append-only audit store for one target directory."""

    def __init__(self, path):
        self.path = Path(path)
        self._conn: Optional[sqlite3.Connection] = None

    def open(self) -> "RunStore":
        self._conn = sqlite3.connect(str(self.path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        cur = self._conn.execute("SELECT version FROM schema_version")
        if cur.fetchone() is None:
            self._conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,))
        self._conn.commit()
        return self

    def close(self) -> None:
        if self._conn is not None:
            self._conn.commit()
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "RunStore":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()

    def begin_run(self, target: str, host: str, profile: str,
                  tool_version: str, authorization_ref: str = "",
                  started_utc: str = "") -> int:
        assert self._conn is not None
        cur = self._conn.execute(
            "INSERT INTO runs (target, host, profile, tool_version,"
            " authorization_ref, started_utc)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (target, host, profile, tool_version, authorization_ref,
             started_utc or _utcnow()))
        self._conn.commit()
        return int(cur.lastrowid)

    def record_denials(self, run_id: int,
                       denials: List[Dict[str, str]]) -> int:
        """Persist gate denials ({url, method, reason}); returns count."""
        assert self._conn is not None
        rows = [(run_id, str(d.get("url", ""))[:2000],
                 str(d.get("method", "GET"))[:16],
                 str(d.get("reason", ""))[:64], _utcnow())
                for d in denials or [] if isinstance(d, dict)]
        self._conn.executemany(
            "INSERT INTO scope_decisions"
            " (run_id, url, method, reason, at_utc)"
            " VALUES (?, ?, ?, ?, ?)", rows)
        self._conn.commit()
        return len(rows)

    def finish_run(self, run_id: int) -> None:
        assert self._conn is not None
        self._conn.execute(
            "UPDATE runs SET finished_utc = ? WHERE id = ?",
            (_utcnow(), run_id))
        self._conn.commit()

    def denial_counts(self, run_id: int) -> Dict[str, int]:
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT reason, COUNT(*) FROM scope_decisions"
            " WHERE run_id = ? GROUP BY reason", (run_id,))
        return {row[0]: row[1] for row in cur.fetchall()}

    @staticmethod
    def endpoint_row(endpoint) -> tuple:
        """Endpoint → storable row (param names only, never samples)."""
        import json as _json

        def names(params):
            out = []
            for p in params or []:
                name = getattr(p, "name", "")
                if name and name not in out:
                    out.append(str(name))
            return out

        return (
            str(getattr(endpoint, "normalized_url", "") or "")[:2000],
            str(getattr(endpoint, "method", "GET") or "GET")[:16],
            str(getattr(endpoint, "host", "") or "")[:256],
            str(getattr(endpoint, "path", "") or "")[:2000],
            str(getattr(endpoint, "endpoint_type", "") or "")[:64],
            _json.dumps(list(getattr(endpoint, "source", None) or [])[:16]),
            _json.dumps(names(getattr(endpoint, "query_parameters",
                                       None))),
            _json.dumps(names(getattr(endpoint, "body_parameters",
                                       None))),
            _json.dumps(list(getattr(endpoint, "request_content_types",
                                      None) or [])[:8]),
        )

    def record_endpoints(self, run_id: int, endpoints: List) -> int:
        """Persist the endpoint inventory for change detection."""
        assert self._conn is not None
        rows = [(run_id,) + self.endpoint_row(e)
                for e in endpoints or []]
        self._conn.executemany(
            "INSERT INTO endpoints (run_id, normalized_url, method,"
            " host, path, endpoint_type, sources, query_params,"
            " body_params, content_types)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        self._conn.commit()
        return len(rows)

    def endpoints_for_run(self, run_id: int) -> List[Dict]:
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT normalized_url, method, host, path, endpoint_type,"
            " sources, query_params, body_params, content_types"
            " FROM endpoints WHERE run_id = ? ORDER BY normalized_url",
            (run_id,))
        keys = ("normalized_url", "method", "host", "path",
                "endpoint_type", "sources", "query_params",
                "body_params", "content_types")
        return [dict(zip(keys, row)) for row in cur.fetchall()]

    def latest_run(self, target: str) -> Optional[Dict]:
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT id, target, host, profile, tool_version,"
            " authorization_ref, started_utc, finished_utc"
            " FROM runs WHERE target = ? ORDER BY id DESC LIMIT 1",
            (target,))
        row = cur.fetchone()
        if row is None:
            return None
        keys = ("id", "target", "host", "profile", "tool_version",
                "authorization_ref", "started_utc", "finished_utc")
        return dict(zip(keys, row))


def _loads_list(value) -> List[str]:
    import json as _json
    try:
        items = _json.loads(value or "[]")
    except (TypeError, ValueError):
        return []
    return sorted(str(i) for i in items) if isinstance(items, list) \
        else []


def endpoint_fingerprint(row: Dict) -> str:
    """Stable content hash for change detection.

    Identity (URL + method) is the key; the fingerprint covers what
    changed-endpoint monitoring cares about: type, parameters, and
    content types. Sources and hosts are intentionally excluded
    (discovery order is not a change).
    """
    import hashlib as _hl
    import json as _json
    parts = [
        str(row.get("method", "GET") or "GET").upper(),
        str(row.get("endpoint_type", "") or ""),
        _json.dumps(_loads_list(row.get("query_params"))),
        _json.dumps(_loads_list(row.get("body_params"))),
        _json.dumps(_loads_list(row.get("content_types"))),
    ]
    return _hl.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]


def _row_key(row: Dict) -> tuple:
    return (str(row.get("normalized_url", "") or ""),
            str(row.get("method", "GET") or "GET").upper())


def diff_endpoint_runs(old_rows: List[Dict],
                       new_rows: List[Dict]) -> Dict[str, List]:
    """New/changed/gone endpoints between two runs (pure).

    First-run convention: empty old set means baseline, not
    everything-new — callers check ``baseline`` instead.
    """
    old = {_row_key(r): r for r in old_rows or []}
    new = {_row_key(r): r for r in new_rows or []}
    if not old:
        return {"baseline": True, "new": [], "changed": [],
                "gone": []}
    added = [new[k] for k in new.keys() - old.keys()]
    gone = [old[k] for k in old.keys() - new.keys()]
    changed = []
    for key in new.keys() & old.keys():
        if endpoint_fingerprint(new[key]) != \
                endpoint_fingerprint(old[key]):
            changed.append({"url": key[0], "method": key[1],
                            "previous": old[key], "current": new[key]})
    ordered = sorted(added, key=lambda r: (r.get("normalized_url",
                                                 ""), r.get("method", "")))
    return {"baseline": not old, "new": ordered,
            "changed": sorted(changed,
                              key=lambda c: (c["url"], c["method"])),
            "gone": sorted(gone, key=lambda r: (r.get("normalized_url",
                                                      ""),
                                                r.get("method", "")))}
