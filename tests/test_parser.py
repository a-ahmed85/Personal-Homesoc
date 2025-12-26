from app.ingest.linux_auth import parse_linux_auth


def test_parse_linux_auth_basic():
    text = "Dec 23 12:00:01 host sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2\n"
    events = parse_linux_auth(text)
    assert len(events) == 1
    assert events[0]["source"] == "linux_auth"
    assert events[0]["event_type"] == "auth_fail"
    assert events[0]["user"] == "admin"
    assert events[0]["src_ip"] == "1.2.3.4"
