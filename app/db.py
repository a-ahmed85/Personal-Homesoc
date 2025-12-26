import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DB_PATH = Path("homesoc.db")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = connect()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            host TEXT,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            user TEXT,
            src_ip TEXT,
            action TEXT,
            raw TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_ts TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            mitre_technique TEXT,
            mitre_tactic TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            summary TEXT NOT NULL,
            evidence_json TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            created_ts TEXT NOT NULL,
            note TEXT NOT NULL,
            FOREIGN KEY(alert_id) REFERENCES alerts(id)
        )
        """
    )

    conn.commit()
    conn.close()


def insert_events(events: List[Dict[str, Any]]) -> int:
    conn = connect()
    cur = conn.cursor()
    count = 0
    for e in events:
        cur.execute(
            """
            INSERT INTO events (ts, host, source, event_type, user, src_ip, action, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                e["ts"],
                e.get("host"),
                e["source"],
                e["event_type"],
                e.get("user"),
                e.get("src_ip"),
                e.get("action"),
                e["raw"],
            ),
        )
        count += 1
    conn.commit()
    conn.close()
    return count


def get_counts() -> Dict[str, int]:
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM events")
    events_count = int(cur.fetchone()["c"])
    cur.execute("SELECT COUNT(*) AS c FROM alerts")
    alerts_count = int(cur.fetchone()["c"])
    conn.close()
    return {"events": events_count, "alerts": alerts_count}


def fetch_events(source: Optional[str] = None, limit: int = 5000) -> List[Dict[str, Any]]:
    conn = connect()
    cur = conn.cursor()
    if source:
        cur.execute(
            "SELECT * FROM events WHERE source = ? ORDER BY ts ASC LIMIT ?",
            (source, limit),
        )
    else:
        cur.execute("SELECT * FROM events ORDER BY ts ASC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def insert_alert(
    created_ts: str,
    rule_id: str,
    rule_name: str,
    severity: str,
    summary: str,
    evidence: Dict[str, Any],
    mitre_technique: Optional[str] = None,
    mitre_tactic: Optional[str] = None,
) -> int:
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO alerts (created_ts, rule_id, rule_name, severity, mitre_technique, mitre_tactic, summary, evidence_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            created_ts,
            rule_id,
            rule_name,
            severity,
            mitre_technique,
            mitre_tactic,
            summary,
            json.dumps(evidence, ensure_ascii=False),
        ),
    )
    alert_id = int(cur.lastrowid)
    conn.commit()
    conn.close()
    return alert_id


def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
) -> List[Dict[str, Any]]:
    conn = connect()
    cur = conn.cursor()

    sql = "SELECT * FROM alerts WHERE 1=1"
    params: List[Any] = []

    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if status:
        sql += " AND status = ?"
        params.append(status)
    if q:
        sql += " AND (rule_name LIKE ? OR summary LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])

    sql += " ORDER BY id DESC LIMIT 200"
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alert(alert_id: int) -> Optional[Dict[str, Any]]:
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_alert_notes(alert_id: int) -> List[Dict[str, Any]]:
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM alert_notes WHERE alert_id = ? ORDER BY id DESC",
        (alert_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_note(alert_id: int, created_ts: str, note: str) -> None:
    conn = connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO alert_notes (alert_id, created_ts, note) VALUES (?, ?, ?)",
        (alert_id, created_ts, note),
    )
    conn.commit()
    conn.close()


def set_alert_status(alert_id: int, status: str) -> None:
    conn = connect()
    cur = conn.cursor()
    cur.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    conn.commit()
    conn.close()
