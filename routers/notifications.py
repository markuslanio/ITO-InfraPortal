"""
routers/notifications.py
VDI Power State Unknown — Slack + Email alerting

Sends notifications when Citrix VDI machines enter an "Unknown" power state,
routing to the correct infrastructure teams based on machine naming conventions.

Deduplication: only alerts when machines ENTER unknown state, not on every
scheduler run. Tracks current unknown set in memory (DB-backed for restarts).

Team routing:
  WORKSPA-*          → Citrix + AWS + Wintel  (AWS WorkSpaces)
  Topctxvdi*
  topctxccp*
  topctxadev*        → Citrix + VMware + Wintel (Topeka vCenter)
  vmcectx*
  PVEAAXD*
  DVEAAXD*
  Vmctxvdi*          → Citrix + VMware + Wintel (VMC on AWS)
  Everything else    → Citrix + Wintel

Required .env variables:
  SLACK_WEBHOOK_CITRIX     Incoming webhook URL for Citrix team channel
  SLACK_WEBHOOK_VMWARE     Incoming webhook URL for VMware team channel
  SLACK_WEBHOOK_AWS        Incoming webhook URL for AWS team channel
  SLACK_WEBHOOK_WINTEL     Incoming webhook URL for Wintel team channel

  NOTIFY_EMAIL_CITRIX      Comma-separated email addresses for Citrix team
  NOTIFY_EMAIL_VMWARE      Comma-separated email addresses for VMware team
  NOTIFY_EMAIL_AWS         Comma-separated email addresses for AWS team
  NOTIFY_EMAIL_WINTEL      Comma-separated email addresses for Wintel team

  SMTP_HOST                SMTP relay hostname  — outlook.sbl.com
  SMTP_PORT                SMTP port            — 25  (plain relay, no TLS)
  SMTP_FROM                From address         — Citrix_Alerts@zinnia.com
  SMTP_TLS                 Set to "none" for internal unauthenticated relay
  SMTP_USER / SMTP_PASSWORD  Leave unset for relay; set only if auth is required
"""

import os
import smtplib
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

import requests

logger = logging.getLogger(__name__)

PORTAL_URL = "https://itodash.zinnia.com/infraportal"

# ── Dedup state ───────────────────────────────────────────────────────────────
_alerted_unknowns: set[str] = set()
_state_lock = threading.Lock()
_STATE_DB: Optional[str] = None


def init_notifications(db_path: str = "infraportal.db") -> None:
    """Call once at startup to load persisted alert state from DB."""
    global _STATE_DB, _alerted_unknowns
    _STATE_DB = db_path
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vdi_alert_state (
                machine_name TEXT PRIMARY KEY,
                alerted_at   TEXT NOT NULL,
                alert_type   TEXT NOT NULL DEFAULT 'power_unknown'
            )
        """)
        con.commit()
        rows = cur.execute(
            "SELECT machine_name FROM vdi_alert_state WHERE alert_type='power_unknown'"
        ).fetchall()
        with _state_lock:
            _alerted_unknowns = {r[0] for r in rows}
        con.close()
        logger.info("notifications: loaded %d persisted alert states", len(_alerted_unknowns))
    except Exception as exc:
        logger.warning("notifications: could not init alert state DB — %s", exc)


def _persist_alerted(names: set[str]) -> None:
    if not _STATE_DB:
        return
    try:
        now = datetime.now(timezone.utc).isoformat()
        con = sqlite3.connect(_STATE_DB)
        cur = con.cursor()
        for name in names:
            cur.execute(
                "INSERT OR REPLACE INTO vdi_alert_state (machine_name, alerted_at, alert_type) VALUES (?,?,?)",
                (name, now, "power_unknown"),
            )
        con.commit()
        con.close()
    except Exception as exc:
        logger.warning("notifications: persist error — %s", exc)


def _clear_alerted(names: set[str]) -> None:
    if not _STATE_DB or not names:
        return
    try:
        con = sqlite3.connect(_STATE_DB)
        cur = con.cursor()
        cur.executemany(
            "DELETE FROM vdi_alert_state WHERE machine_name=? AND alert_type='power_unknown'",
            [(n,) for n in names],
        )
        con.commit()
        con.close()
    except Exception as exc:
        logger.warning("notifications: clear error — %s", exc)


# ── Team routing ──────────────────────────────────────────────────────────────

TEAM_LABELS = {"citrix": "Citrix", "vmware": "VMware", "aws": "AWS", "wintel": "Wintel"}


def _teams_for_machine(name: str) -> set[str]:
    n = name.upper()
    teams = {"citrix", "wintel"}
    if n.startswith("WORKSPA"):
        teams.add("aws")
    else:
        teams.add("vmware")
    return teams


def _env_for_machine(name: str) -> str:
    n = name.upper()
    if n.startswith("WORKSPA"):
        return "AWS WorkSpaces"
    if "VMC" in n or n.startswith("PVEAAXD") or n.startswith("DVEAAXD"):
        return "VMC on AWS"
    if n.startswith("TOP") or "TOPEKA" in n:
        return "Topeka"
    return "Unknown"


# ── Slack ─────────────────────────────────────────────────────────────────────

def send_slack(webhook_url: str, text: str, blocks: Optional[list] = None) -> bool:
    payload: dict = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    try:
        r = requests.post(webhook_url, json=payload, timeout=10, verify=False)
        if r.status_code == 200:
            return True
        logger.warning("notifications: Slack → HTTP %s: %s", r.status_code, r.text[:100])
    except Exception as exc:
        logger.warning("notifications: Slack error — %s", exc)
    return False


def _build_slack_blocks(team: str, machines: list[dict]) -> list:
    count     = len(machines)
    env_set   = sorted({_env_for_machine(m["name"]) for m in machines})
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = ""
    for m in machines[:20]:
        last  = (m.get("last_connection") or "—")[:10] if m.get("last_connection") else "—"
        mtype = m.get("machine_type", "")
        scount= m.get("session_count", 0)
        if mtype.lower() == "multisession" or scount > 1:
            type_tag = f" ⚠ *XenApp — {scount} active session(s) affected*"
        else:
            type_tag = ""
        rows += f"• `{m['name']}` ({m.get('delivery_group','—')}) — {m.get('user_display') or 'Unassigned'}{type_tag} — last login: {last}\n"
    if count > 20:
        rows += f"_...and {count - 20} more. See portal for full list._\n"

    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🚨 VDI Power Unknown — {TEAM_LABELS.get(team, team)} Alert",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{count} VDI machine{'s' if count != 1 else ''} entered Unknown power state*\n"
                    f"Environment: {', '.join(env_set)}\n"
                    f"Detected: {timestamp}"
                ),
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Affected machines:*\n{rows}"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*Possible causes:* hypervisor connectivity issue, VM stuck in power transition, "
                    "Citrix Cloud Connector unable to reach the host.\n\n"
                    "*Immediate actions:*\n"
                    "• *Citrix:* check machine registration in Citrix Cloud Studio\n"
                    "• *VMware/AWS:* verify host and VM power state in vCenter / AWS Console\n"
                    "• *Wintel:* check VDA service on affected machines if reachable"
                ),
            },
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Open VDI Report", "emoji": True},
                    "url": f"{PORTAL_URL}/vdi-cost",
                    "style": "primary",
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Open Citrix Page", "emoji": True},
                    "url": f"{PORTAL_URL}/citrix",
                },
            ],
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Zinnia Infrastructure Portal • {PORTAL_URL}"}],
        },
    ]


# ── Email ─────────────────────────────────────────────────────────────────────

def _email_addresses(team: str) -> list[str]:
    raw = os.getenv(f"NOTIFY_EMAIL_{team.upper()}", "").strip()
    return [a.strip() for a in raw.split(",") if a.strip()] if raw else []


def send_email(to_list: list[str], subject: str, html_body: str) -> bool:
    if not to_list:
        return True
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "Citrix_Alerts@zinnia.com").strip()
    smtp_tls  = os.getenv("SMTP_TLS", "true").strip().lower()

    if not smtp_host:
        logger.warning("notifications: SMTP_HOST not set — skipping email")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_from
    msg["To"]      = ", ".join(to_list)
    msg.attach(MIMEText(html_body, "html"))

    try:
        if smtp_tls == "ssl":
            server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            if smtp_tls == "true":
                server.starttls()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_from, to_list, msg.as_string())
        server.quit()
        logger.info("notifications: email sent to %s", ", ".join(to_list))
        return True
    except Exception as exc:
        logger.warning("notifications: email error — %s", exc)
        return False


def _build_email(team: str, machines: list[dict]) -> tuple[str, str]:
    count      = len(machines)
    timestamp  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    team_label = TEAM_LABELS.get(team, team)

    rows_html = ""
    for m in machines:
        last = (m.get("last_connection") or "—")[:10] if m.get("last_connection") else "—"
        user   = m.get("user_display") or m.get("assigned_upn") or "Unassigned"
        env    = _env_for_machine(m["name"])
        mtype  = m.get("machine_type", "")
        scount = m.get("session_count", 0)
        is_xa  = mtype.lower() == "multisession" or scount > 1
        type_badge = (
            f'<span style="background:#f8d7da;color:#721c24;padding:2px 6px;border-radius:10px;font-size:10px;font-weight:600;margin-left:4px;">XenApp · {scount} sessions</span>'
            if is_xa else
            '<span style="background:#d4edda;color:#155724;padding:2px 6px;border-radius:10px;font-size:10px;">VDI</span>'
        )
        user_cell = f"{user} {type_badge}" if is_xa else user
        rows_html += f"""
        <tr style="background:{'#fff8f8' if is_xa else '#ffffff'};">
          <td style="padding:7px 12px;border-bottom:1px solid #e0e0e0;font-family:monospace;font-size:12px;">{m['name']}</td>
          <td style="padding:7px 12px;border-bottom:1px solid #e0e0e0;font-size:12px;">{env}</td>
          <td style="padding:7px 12px;border-bottom:1px solid #e0e0e0;font-size:12px;">{m.get('delivery_group','—')}</td>
          <td style="padding:7px 12px;border-bottom:1px solid #e0e0e0;font-size:12px;">{user_cell}</td>
          <td style="padding:7px 12px;border-bottom:1px solid #e0e0e0;font-size:12px;">
            <span style="background:#fff3cd;color:#856404;padding:2px 7px;border-radius:10px;font-size:11px;font-weight:600;">Unknown</span>
          </td>
          <td style="padding:7px 12px;border-bottom:1px solid #e0e0e0;font-size:12px;">{last}</td>
        </tr>"""

    subject = (
        f"[InfraPortal] 🚨 {count} VDI Machine{'s' if count != 1 else ''} — "
        f"Unknown Power State ({team_label} Alert)"
    )
    html = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f5f5f5;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:24px 0;">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0"
  style="background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08);">
  <tr><td style="background:#c0392b;padding:20px 28px;">
    <p style="margin:0;color:#fff;font-size:18px;font-weight:bold;">🚨 VDI Power State Unknown Alert</p>
    <p style="margin:4px 0 0;color:rgba(255,255,255,.8);font-size:12px;">{team_label} Team • {timestamp}</p>
  </td></tr>
  <tr><td style="padding:20px 28px;border-bottom:1px solid #eee;">
    <p style="margin:0;font-size:14px;color:#333;">
      <strong>{count} VDI machine{'s' if count != 1 else ''}</strong> entered an
      <strong style="color:#856404;">Unknown</strong> power state. This typically indicates
      a hypervisor connectivity issue or a VM stuck in a power transition.
    </p>
  </td></tr>
  <tr><td style="padding:0;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <thead><tr style="background:#0f9b8e;">
        <th style="padding:9px 12px;color:#fff;font-size:11px;text-align:left;text-transform:uppercase;letter-spacing:.05em;">Machine</th>
        <th style="padding:9px 12px;color:#fff;font-size:11px;text-align:left;text-transform:uppercase;letter-spacing:.05em;">Environment</th>
        <th style="padding:9px 12px;color:#fff;font-size:11px;text-align:left;text-transform:uppercase;letter-spacing:.05em;">Delivery Group</th>
        <th style="padding:9px 12px;color:#fff;font-size:11px;text-align:left;text-transform:uppercase;letter-spacing:.05em;">Assigned User</th>
        <th style="padding:9px 12px;color:#fff;font-size:11px;text-align:left;text-transform:uppercase;letter-spacing:.05em;">Power</th>
        <th style="padding:9px 12px;color:#fff;font-size:11px;text-align:left;text-transform:uppercase;letter-spacing:.05em;">Last Login</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
  </td></tr>
  <tr><td style="padding:20px 28px;background:#f9f9f9;border-top:1px solid #eee;">
    <p style="margin:0 0 8px;font-size:13px;color:#555;font-weight:bold;">Suggested actions:</p>
    <ul style="margin:0;padding-left:18px;font-size:13px;color:#555;line-height:1.8;">
      <li><strong>Citrix:</strong> Check machine registration in Citrix Cloud Studio</li>
      <li><strong>VMware / AWS:</strong> Verify host connectivity and VM power state in vCenter / AWS Console</li>
      <li><strong>Wintel:</strong> Check VDA service on affected machines if reachable</li>
    </ul>
  </td></tr>
  <tr><td style="padding:16px 28px;text-align:center;">
    <a href="{PORTAL_URL}/vdi-cost"
      style="display:inline-block;background:#0f9b8e;color:#fff;text-decoration:none;padding:10px 24px;border-radius:5px;font-size:13px;font-weight:bold;">
      Open VDI Report
    </a>
    &nbsp;&nbsp;
    <a href="{PORTAL_URL}/citrix"
      style="display:inline-block;background:#444;color:#fff;text-decoration:none;padding:10px 24px;border-radius:5px;font-size:13px;font-weight:bold;">
      Open Citrix Page
    </a>
  </td></tr>
  <tr><td style="padding:12px 28px;background:#f0f0f0;border-top:1px solid #e0e0e0;">
    <p style="margin:0;font-size:11px;color:#999;text-align:center;">
      Zinnia Infrastructure Portal • Automated alert • job_vdi_power_unknown_check
    </p>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>"""
    return subject, html


# ── Main entry point ──────────────────────────────────────────────────────────

def check_and_notify_vdi_power_unknown(machines: list[dict]) -> dict:
    """
    Called by the scheduler. Takes the current Citrix machine list,
    finds machines with Unknown power state, deduplicates, and fires
    Slack + email notifications for newly-entered unknown machines.

    Returns: { new_unknowns, recovered, notified_teams, machines }
    """
    global _alerted_unknowns

    # Identify currently unknown machines (normalise both field name formats)
    currently_unknown: dict[str, dict] = {}
    for m in machines:
        name  = (m.get("name") or m.get("machine") or "").strip()
        power = (m.get("power_state") or m.get("powerState") or "").strip().lower()
        if name and power in ("unknown", ""):
            currently_unknown[name] = m

    with _state_lock:
        prev_alerted = set(_alerted_unknowns)

    current_names = set(currently_unknown.keys())
    new_unknowns  = {n: currently_unknown[n] for n in current_names - prev_alerted}
    recovered     = prev_alerted - current_names

    # Update state
    if new_unknowns or recovered:
        with _state_lock:
            _alerted_unknowns = (_alerted_unknowns | set(new_unknowns.keys())) - recovered
        if new_unknowns:
            _persist_alerted(set(new_unknowns.keys()))
        if recovered:
            _clear_alerted(recovered)
            logger.info("notifications: %d machine(s) recovered from unknown state", len(recovered))

    if not new_unknowns:
        logger.debug("notifications: no new unknown-state machines (currently %d unknown, %d alerted)",
                     len(current_names), len(prev_alerted))
        return {"new_unknowns": 0, "recovered": len(recovered), "notified_teams": [], "machines": []}

    logger.info("notifications: %d NEW unknown-state machine(s): %s",
                len(new_unknowns), ", ".join(sorted(new_unknowns.keys())))

    # Build per-team machine lists (a machine may appear in multiple teams)
    team_machines: dict[str, list[dict]] = {}
    for name, m in new_unknowns.items():
        for team in _teams_for_machine(name):
            team_machines.setdefault(team, []).append({
                "name":             name,
                "delivery_group":   m.get("delivery_group_name") or m.get("deliveryGroup") or "—",
                "last_connection":  m.get("last_connection_time") or m.get("lastConnectionTime") or "—",
                "assigned_upn":     m.get("assignedUpn") or "",
                "user_display":     m.get("userDisplay") or m.get("user_name") or "",
            })

    notified_teams: list[str] = []
    for team, team_list in team_machines.items():
        ok_slack = ok_email = False

        webhook = os.getenv(f"SLACK_WEBHOOK_{team.upper()}", "").strip()
        if webhook:
            blocks    = _build_slack_blocks(team, team_list)
            fallback  = f"🚨 {len(team_list)} VDI machine(s) entered Unknown power state — see InfraPortal."
            ok_slack  = send_slack(webhook, fallback, blocks)

        to_list = _email_addresses(team)
        if to_list:
            subject, html = _build_email(team, team_list)
            ok_email = send_email(to_list, subject, html)

        if ok_slack or ok_email:
            notified_teams.append(team)

        logger.info("notifications: %s team — %d machines — Slack:%s Email:%s",
                    team, len(team_list), ok_slack, ok_email)

    return {
        "new_unknowns":   len(new_unknowns),
        "recovered":      len(recovered),
        "notified_teams": notified_teams,
        "machines":       list(new_unknowns.keys()),
    }