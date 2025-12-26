import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import yaml


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    mitre_technique: Optional[str]
    mitre_tactic: Optional[str]
    match: Dict[str, Any]


def load_rules(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or []
    rules: List[Rule] = []
    for r in data:
        rules.append(
            Rule(
                id=str(r["id"]),
                name=str(r["name"]),
                description=str(r.get("description", "")),
                severity=str(r.get("severity", "medium")),
                mitre_technique=(r.get("mitre", {}) or {}).get("technique"),
                mitre_tactic=(r.get("mitre", {}) or {}).get("tactic"),
                match=dict(r["match"]),
            )
        )
    return rules


def _get_field(event: Dict[str, Any], field: str) -> Any:
    return event.get(field)


def _where_ok(event: Dict[str, Any], where: Dict[str, Any]) -> bool:
    for k, v in (where or {}).items():
        if event.get(k) != v:
            return False
    return True


def _op_ok(value: Any, op: str, expected: Any) -> bool:
    if value is None:
        return False
    s = str(value)
    exp = str(expected)

    if op == "equals":
        return s == exp
    if op == "contains":
        return exp in s
    if op == "startswith":
        return s.startswith(exp)
    if op == "endswith":
        return s.endswith(exp)
    if op == "regex":
        import re
        return re.search(exp, s) is not None
    return False


def _parse_ts(ts: str) -> datetime:
    # Expected ISO with trailing Z
    if ts.endswith("Z"):
        ts = ts[:-1]
    return datetime.fromisoformat(ts)


def run_rules(
    events: List[Dict[str, Any]],
    rules: List[Rule],
    now_iso: str,
) -> List[Dict[str, Any]]:
    """
    Returns a list of alerts dicts:
    {
      created_ts, rule_id, rule_name, severity, summary, evidence, mitre_technique, mitre_tactic
    }
    """
    alerts: List[Dict[str, Any]] = []
    created_ts = now_iso

    for rule in rules:
        m = rule.match
        source = m.get("source")

        # filter events by source early
        scoped = [e for e in events if (source is None or e.get("source") == source)]

        match_type = m.get("type", "event")

        if match_type == "event":
            where = m.get("where", {}) or {}
            field = m.get("field")
            op = m.get("op", "equals")
            value = m.get("value")

            for e in scoped:
                if not _where_ok(e, where):
                    continue
                if field:
                    if not _op_ok(_get_field(e, field), op, value):
                        continue

                summary = m.get("summary") or f"{rule.name} on host={e.get('host')} user={e.get('user')} ip={e.get('src_ip')}"
                evidence = {
                    "event_id": e.get("id"),
                    "event": e,
                    "rule": {
                        "id": rule.id,
                        "name": rule.name,
                        "description": rule.description,
                    },
                }
                alerts.append(
                    {
                        "created_ts": created_ts,
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "summary": summary,
                        "evidence": evidence,
                        "mitre_technique": rule.mitre_technique,
                        "mitre_tactic": rule.mitre_tactic,
                    }
                )

        elif match_type == "threshold":
            where = m.get("where", {}) or {}
            group_field = m.get("field")
            threshold = int(m.get("threshold", 5))
            window_minutes = int(m.get("window_minutes", 10))

            # Collect events that satisfy where
            candidates = [e for e in scoped if _where_ok(e, where) and e.get(group_field) is not None]
            # Sort by timestamp
            candidates.sort(key=lambda x: x.get("ts", ""))

            # Sliding window per group value
            buckets: Dict[str, List[Dict[str, Any]]] = {}
            for e in candidates:
                key = str(e[group_field])
                buckets.setdefault(key, []).append(e)

            for key, evs in buckets.items():
                # two-pointer window
                left = 0
                for right in range(len(evs)):
                    while left <= right:
                        t_left = _parse_ts(evs[left]["ts"])
                        t_right = _parse_ts(evs[right]["ts"])
                        if t_right - t_left <= timedelta(minutes=window_minutes):
                            break
                        left += 1
                    window = evs[left : right + 1]
                    if len(window) >= threshold:
                        first_ts = window[0]["ts"]
                        last_ts = window[-1]["ts"]
                        summary = m.get("summary") or f"{rule.name}: {len(window)} events for {group_field}={key} in {window_minutes}m"
                        evidence = {
                            "group_field": group_field,
                            "group_value": key,
                            "count": len(window),
                            "window_minutes": window_minutes,
                            "first_ts": first_ts,
                            "last_ts": last_ts,
                            "sample_events": window[:10],
                            "rule": {
                                "id": rule.id,
                                "name": rule.name,
                                "description": rule.description,
                            },
                        }
                        alerts.append(
                            {
                                "created_ts": created_ts,
                                "rule_id": rule.id,
                                "rule_name": rule.name,
                                "severity": rule.severity,
                                "summary": summary,
                                "evidence": evidence,
                                "mitre_technique": rule.mitre_technique,
                                "mitre_tactic": rule.mitre_tactic,
                            }
                        )
                        # Avoid spamming duplicates for same group by breaking after first hit
                        break
        else:
            continue

    return alerts
