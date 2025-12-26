from app.rules.engine import load_rules, run_rules
from datetime import datetime


def test_threshold_rule_triggers(tmp_path):
    # create synthetic events
    base = "2025-12-23T12:00:00Z"
    events = []
    for i in range(6):
        events.append(
            {
                "id": i + 1,
                "ts": f"2025-12-23T12:00:0{i}Z",
                "host": "h",
                "source": "linux_auth",
                "event_type": "auth_fail",
                "user": "admin",
                "src_ip": "9.9.9.9",
                "action": "failed_password",
                "raw": "x",
            }
        )

    # load rules from the real file in repo
    rules = load_rules("rules/default_rules.yml")
    alerts = run_rules(events, rules, now_iso="2025-12-23T12:05:00Z")
    assert any(a["rule_id"] == "R-002" for a in alerts)
