import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.db import (
    add_note,
    fetch_events,
    get_alert,
    get_alert_notes,
    get_counts,
    init_db,
    insert_alert,
    insert_events,
    list_alerts,
    set_alert_status,
)
from app.ingest.linux_auth import parse_linux_auth
from app.rules.engine import load_rules, run_rules

app = FastAPI(title="HomeSOC")
templates = Jinja2Templates(directory="templates")

static_dir = Path("static")
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    counts = get_counts()
    return templates.TemplateResponse("index.html", {"request": request, "counts": counts})


@app.post("/upload")
async def upload_log(request: Request, file: UploadFile = File(...)) -> RedirectResponse:
    content = await file.read()
    text = content.decode("utf-8", errors="replace")

    events = parse_linux_auth(text)
    insert_events(events)
    return RedirectResponse(url="/", status_code=303)


@app.post("/load-sample")
def load_sample() -> RedirectResponse:
    sample_path = Path("sample_data/linux_auth_sample.log")
    text = sample_path.read_text(encoding="utf-8", errors="replace")
    events = parse_linux_auth(text)
    insert_events(events)
    return RedirectResponse(url="/", status_code=303)


@app.post("/run-rules")
def run_all_rules() -> RedirectResponse:
    events = fetch_events(source="linux_auth", limit=10000)
    rules = load_rules("rules/default_rules.yml")
    now_iso = datetime.utcnow().isoformat() + "Z"

    alerts = run_rules(events=events, rules=rules, now_iso=now_iso)
    for a in alerts:
        insert_alert(
            created_ts=a["created_ts"],
            rule_id=a["rule_id"],
            rule_name=a["rule_name"],
            severity=a["severity"],
            summary=a["summary"],
            evidence=a["evidence"],
            mitre_technique=a.get("mitre_technique"),
            mitre_tactic=a.get("mitre_tactic"),
        )

    return RedirectResponse(url="/alerts", status_code=303)


@app.get("/alerts", response_class=HTMLResponse)
def alerts(
    request: Request,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
) -> HTMLResponse:
    rows = list_alerts(severity=severity, status=status, q=q)
    return templates.TemplateResponse(
        "alerts.html",
        {"request": request, "alerts": rows, "severity": severity, "status": status, "q": q},
    )


@app.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: int) -> HTMLResponse:
    alert = get_alert(alert_id)
    if not alert:
        return HTMLResponse("Alert not found", status_code=404)
    notes = get_alert_notes(alert_id)
    evidence = json.loads(alert["evidence_json"])
    return templates.TemplateResponse(
        "alert_detail.html",
        {"request": request, "alert": alert, "notes": notes, "evidence": evidence},
    )


@app.post("/alerts/{alert_id}/status")
def update_status(alert_id: int, status: str = Form(...)) -> RedirectResponse:
    allowed = {"new", "triaged", "true_positive", "false_positive"}
    if status not in allowed:
        status = "new"
    set_alert_status(alert_id, status)
    return RedirectResponse(url=f"/alerts/{alert_id}", status_code=303)


@app.post("/alerts/{alert_id}/note")
def add_alert_note(alert_id: int, note: str = Form(...)) -> RedirectResponse:
    note = (note or "").strip()
    if note:
        add_note(alert_id, datetime.utcnow().isoformat() + "Z", note)
    return RedirectResponse(url=f"/alerts/{alert_id}", status_code=303)
