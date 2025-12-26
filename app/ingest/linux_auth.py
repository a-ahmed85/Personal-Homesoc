import re
from datetime import datetime
from typing import Any, Dict, List, Optional

# Typical lines:
# Dec 23 12:34:56 myhost sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2
# Dec 23 12:35:10 myhost sshd[1234]: Accepted password for fadi from 1.2.3.4 port 22 ssh2

FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd.*Failed password for (invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

ACCEPT_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd.*Accepted \S+ for (?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


def _to_iso(mon: str, day: str, time_str: str, year: Optional[int] = None) -> str:
    if year is None:
        year = datetime.utcnow().year
    dt = datetime(year, MONTHS[mon], int(day), int(time_str[0:2]), int(time_str[3:5]), int(time_str[6:8]))
    return dt.isoformat() + "Z"


def parse_linux_auth(text: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip("\n")
        if not line.strip():
            continue

        m = FAILED_RE.match(line)
        if m:
            ts = _to_iso(m.group("mon"), m.group("day"), m.group("time"))
            events.append(
                {
                    "ts": ts,
                    "host": m.group("host"),
                    "source": "linux_auth",
                    "event_type": "auth_fail",
                    "user": m.group("user"),
                    "src_ip": m.group("ip"),
                    "action": "failed_password",
                    "raw": line,
                }
            )
            continue

        m = ACCEPT_RE.match(line)
        if m:
            ts = _to_iso(m.group("mon"), m.group("day"), m.group("time"))
            events.append(
                {
                    "ts": ts,
                    "host": m.group("host"),
                    "source": "linux_auth",
                    "event_type": "auth_success",
                    "user": m.group("user"),
                    "src_ip": m.group("ip"),
                    "action": "accepted_login",
                    "raw": line,
                }
            )
            continue

        # Keep unparsed lines as "other" so you do not lose data
        # This is important for real SOC pipelines
        # Timestamp unknown, store current time
        events.append(
            {
                "ts": datetime.utcnow().isoformat() + "Z",
                "host": None,
                "source": "linux_auth",
                "event_type": "other",
                "user": None,
                "src_ip": None,
                "action": None,
                "raw": line,
            }
        )
    return events
