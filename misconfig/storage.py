"""Findings store: PostgreSQL in production, SQLite for local runs and tests.

DATABASE_URL examples:
  postgresql://misconfig:misconfig@localhost:5432/misconfig
  sqlite:///scans.db
"""

from __future__ import annotations

import json
import sqlite3

from .models import Finding, ScanResult, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id               {pk},
    account_id       VARCHAR(12)  NOT NULL,
    regions          TEXT         NOT NULL,
    checks_run       INTEGER      NOT NULL,
    checks_errored   TEXT         NOT NULL,
    risk_score       NUMERIC(5,1) NOT NULL,
    grade            CHAR(1)      NOT NULL,
    started_at       {ts}         NOT NULL,
    finished_at      {ts}         NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id              {pk},
    scan_id         INTEGER      NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id        VARCHAR(16)  NOT NULL,
    title           TEXT         NOT NULL,
    service         VARCHAR(32)  NOT NULL,
    severity        VARCHAR(10)  NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    resource        TEXT         NOT NULL,
    region          VARCHAR(32)  NOT NULL,
    details         TEXT         NOT NULL,
    remediation     TEXT         NOT NULL,
    auto_remediable BOOLEAN      NOT NULL,
    public_exposure BOOLEAN      NOT NULL,
    risk_score      NUMERIC(5,1) NOT NULL,
    status          VARCHAR(16)  NOT NULL DEFAULT 'OPEN'
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_check ON findings(check_id);
"""

FINDING_COLS = ("id, check_id, title, service, severity, resource, region, details, remediation, "
                "auto_remediable, public_exposure, risk_score, status")


class Store:
    def __init__(self, url: str):
        self.url = url
        if url.startswith("sqlite:///"):
            self.dialect = "sqlite"
            self.conn = sqlite3.connect(url[len("sqlite:///"):] or ":memory:", check_same_thread=False)
            self.conn.execute("PRAGMA foreign_keys = ON")
        elif url.startswith(("postgresql://", "postgres://")):
            import psycopg

            self.dialect = "postgres"
            self.conn = psycopg.connect(url)
        else:
            raise ValueError(f"unsupported DATABASE_URL {url!r}")

    def init_schema(self) -> None:
        pk = "INTEGER PRIMARY KEY AUTOINCREMENT" if self.dialect == "sqlite" else "SERIAL PRIMARY KEY"
        ts = "TEXT" if self.dialect == "sqlite" else "TIMESTAMPTZ"
        ddl = SCHEMA.format(pk=pk, ts=ts)
        cur = self.conn.cursor()
        for stmt in filter(str.strip, ddl.split(";")):
            cur.execute(stmt)
        self.conn.commit()

    def _q(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.dialect == "postgres" else sql

    def _exec(self, sql: str, params: tuple = ()):
        cur = self.conn.cursor()
        cur.execute(self._q(sql), params)
        return cur

    # -- writes ---------------------------------------------------------
    def save_scan(self, r: ScanResult) -> int:
        try:
            scan_id = self._exec(
                "INSERT INTO scans (account_id, regions, checks_run, checks_errored, risk_score, grade, "
                "started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
                (r.account_id, json.dumps(r.regions), r.checks_run, json.dumps(r.checks_failed_to_run),
                 r.risk_score, r.grade, r.started_at, r.finished_at),
            ).fetchone()[0]
            for f in r.findings:
                f.id = self._exec(
                    "INSERT INTO findings (scan_id, check_id, title, service, severity, resource, region, details, "
                    "remediation, auto_remediable, public_exposure, risk_score, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
                    (scan_id, f.check_id, f.title, f.service, f.severity.value, f.resource, f.region, f.details,
                     f.remediation, f.auto_remediable, f.public_exposure, f.risk_score, f.status),
                ).fetchone()[0]
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        r.id = scan_id
        return scan_id

    def set_finding_status(self, finding_id: int, status: str) -> None:
        self._exec("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        self.conn.commit()

    # -- reads ----------------------------------------------------------
    @staticmethod
    def _finding(row) -> Finding:
        (fid, check_id, title, service, sev, resource, region, details, remediation,
         auto, public, risk, status) = row
        return Finding(check_id, title, service, Severity(sev), resource, region, details, remediation,
                       bool(auto), bool(public), float(risk), fid, status)

    def list_scans(self, limit: int = 50) -> list[dict]:
        rows = self._exec(
            "SELECT s.id, s.account_id, s.risk_score, s.grade, s.finished_at, COUNT(f.id) "
            "FROM scans s LEFT JOIN findings f ON f.scan_id = s.id "
            "GROUP BY s.id, s.account_id, s.risk_score, s.grade, s.finished_at "
            "ORDER BY s.id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r[0], "account_id": r[1], "risk_score": float(r[2]), "grade": r[3],
                 "finished_at": str(r[4]), "findings": r[5]} for r in rows]

    def get_scan(self, scan_id: int) -> dict | None:
        row = self._exec("SELECT id, account_id, regions, checks_run, checks_errored, risk_score, grade, "
                         "started_at, finished_at FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        return {"id": row[0], "account_id": row[1], "regions": json.loads(row[2]), "checks_run": row[3],
                "checks_failed_to_run": json.loads(row[4]), "risk_score": float(row[5]), "grade": row[6],
                "started_at": str(row[7]), "finished_at": str(row[8]),
                "severity_counts": self.severity_counts(scan_id)}

    def findings(self, scan_id: int, severity: str | None = None, service: str | None = None,
                 status: str | None = None) -> list[Finding]:
        sql, params = f"SELECT {FINDING_COLS} FROM findings WHERE scan_id = ?", [scan_id]
        for col, val in (("severity", severity), ("service", service), ("status", status)):
            if val:
                sql += f" AND {col} = ?"
                params.append(val.upper() if col != "service" else val)
        sql += " ORDER BY risk_score DESC, id"
        return [self._finding(r) for r in self._exec(sql, tuple(params)).fetchall()]

    def get_finding(self, finding_id: int) -> Finding | None:
        row = self._exec(f"SELECT {FINDING_COLS} FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return self._finding(row) if row else None

    # -- reports (SQL aggregation) ---------------------------------------
    def severity_counts(self, scan_id: int) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for sev, n in self._exec("SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity",
                                 (scan_id,)).fetchall():
            counts[sev] = n
        return counts

    def service_breakdown(self, scan_id: int) -> list[dict]:
        rows = self._exec(
            "SELECT service, COUNT(*), SUM(risk_score) FROM findings WHERE scan_id = ? "
            "GROUP BY service ORDER BY SUM(risk_score) DESC", (scan_id,)).fetchall()
        return [{"service": r[0], "findings": r[1], "risk": float(r[2])} for r in rows]

    def top_resources(self, scan_id: int, limit: int = 10) -> list[dict]:
        rows = self._exec(
            "SELECT resource, COUNT(*), SUM(risk_score) FROM findings WHERE scan_id = ? "
            "GROUP BY resource ORDER BY SUM(risk_score) DESC, resource LIMIT ?", (scan_id, limit)).fetchall()
        return [{"resource": r[0], "findings": r[1], "risk": float(r[2])} for r in rows]

    def trend(self, account_id: str | None = None, limit: int = 30) -> list[dict]:
        sql = "SELECT id, finished_at, risk_score, grade FROM scans"
        params: tuple = ()
        if account_id:
            sql, params = sql + " WHERE account_id = ?", (account_id,)
        rows = self._exec(sql + " ORDER BY id DESC LIMIT ?", params + (limit,)).fetchall()
        return [{"scan_id": r[0], "finished_at": str(r[1]), "risk_score": float(r[2]), "grade": r[3]}
                for r in reversed(rows)]

    def close(self) -> None:
        self.conn.close()
