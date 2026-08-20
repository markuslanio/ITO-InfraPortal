"""
SOC Audit Report — generates self-contained HTML reports of TASI change tickets
for annual compliance audits. Includes full ticket fields, rendered description,
embedded image attachments, and full change history.
"""
import os
import base64
import logging
import time
import threading
import re
from datetime import datetime

import requests
import urllib3
urllib3.disable_warnings()

logger = logging.getLogger(__name__)

VERIFY_SSL = False

# ── Jira helpers (mirrors routers/jira.py patterns) ──────────────────────────

def _cfg():
    from requests.auth import HTTPBasicAuth
    return {
        "base":  os.getenv("JIRA_BASE_URL", "").rstrip("/"),
        "auth":  HTTPBasicAuth(os.getenv("JIRA_EMAIL", ""), os.getenv("JIRA_API_TOKEN", "")),
        "tasi":  os.getenv("JIRA_TASI_PROJECT", "TASI"),
    }

HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

# Fields to request for each ticket
_FIELDS = ",".join([
    "summary", "status", "description", "assignee", "reporter", "priority",
    "created", "updated", "resolved", "attachment",
    "customfield_15736",  # TAS Type
    "customfield_15381",  # Risk/Impact
    "customfield_15243",  # System(s)
    "customfield_15215",  # Client/s
    "customfield_15855",  # Infrastructure Resource Group
    "customfield_15811",  # System Environment
    "customfield_15792",  # Hardware/Server/Database
    "customfield_15812",  # Rollback Plan
    "customfield_15769",  # TAS Start Time
    "customfield_15770",  # TAS End Time
    "customfield_15790",  # FTEV Start
    "customfield_15791",  # FTEV End
    "customfield_15817",  # TAS Already Deployed
])

_FIELD_LABELS = {
    "customfield_15736": "TAS Type",
    "customfield_15381": "Risk / Impact",
    "customfield_15243": "System(s)",
    "customfield_15215": "Client(s)",
    "customfield_15855": "Infrastructure Resource Group",
    "customfield_15811": "System Environment",
    "customfield_15792": "Hardware / Server / Schema",
    "customfield_15812": "Rollback Plan",
    "customfield_15769": "TAS Start Time",
    "customfield_15770": "TAS End Time",
    "customfield_15790": "FTEV Start Date/Time",
    "customfield_15791": "FTEV End Date/Time",
    "customfield_15817": "Already Deployed?",
}


def _get(path, params=None):
    cfg = _cfg()
    try:
        r = requests.get(
            f"{cfg['base']}/rest/api/3{path}",
            auth=cfg["auth"], headers=HEADERS,
            params=params, timeout=20, verify=VERIFY_SSL
        )
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        logger.warning("SOC Jira GET %s failed: %s", path, e)
    return None


_status_cache: dict = {}  # project_key → sorted list of status names

def fetch_project_statuses(project_key: str) -> list:
    """
    Return deduplicated, sorted status names for a project (cached in memory).
    Try 1: /project/{key}/statuses (may 403/404 on some projects).
    Try 2: JQL search of recent issues — works whenever the API token can read tickets.
    """
    key = project_key.upper()
    if key in _status_cache:
        return _status_cache[key]

    cfg = _cfg()
    names: list = []
    seen: set   = set()

    # ── Attempt 1: dedicated statuses endpoint ──────────────────────────────
    try:
        r = requests.get(
            f"{cfg['base']}/rest/api/3/project/{key}/statuses",
            auth=cfg["auth"], headers=HEADERS, timeout=15, verify=VERIFY_SSL,
        )
        if r.status_code == 200:
            for issue_type in r.json():
                for s in issue_type.get("statuses", []):
                    name = s.get("name", "").strip()
                    if name and name not in seen:
                        seen.add(name)
                        names.append(name)
        else:
            logger.warning("SOC project statuses %s → HTTP %s: %s",
                           key, r.status_code, r.text[:200])
    except Exception as e:
        logger.warning("SOC project statuses endpoint failed for %s: %s", key, e)

    # ── Attempt 2: JQL fallback — pull status from real tickets ────────────
    if not names:
        try:
            payload = {
                "jql":        f"project = {key} ORDER BY updated DESC",
                "maxResults": 100,
                "fields":     ["status"],
            }
            r = requests.post(
                f"{cfg['base']}/rest/api/3/search/jql",
                auth=cfg["auth"], headers=HEADERS, verify=VERIFY_SSL,
                json=payload, timeout=20,
            )
            if r.ok:
                for issue in r.json().get("issues", []):
                    name = (((issue.get("fields") or {}).get("status")) or {}).get("name", "").strip()
                    if name and name not in seen:
                        seen.add(name)
                        names.append(name)
                if not names:
                    logger.warning("SOC JQL fallback returned 0 issues for project %s", key)
            else:
                logger.warning("SOC JQL fallback %s → HTTP %s: %s",
                               key, r.status_code, r.text[:200])
        except Exception as e:
            logger.warning("SOC JQL status fallback failed for %s: %s", key, e)

    if names:
        names.sort()
        _status_cache[key] = names
    return names


def _paginate_search(jql, fields):
    """Fetch all results for a JQL query using POST /search/jql with cursor pagination."""
    cfg = _cfg()
    results = []
    next_page_token = None
    batch = 100
    while True:
        payload = {"jql": jql, "maxResults": batch, "fields": fields}
        if next_page_token:
            payload["nextPageToken"] = next_page_token
        r = requests.post(
            f"{cfg['base']}/rest/api/3/search/jql",
            auth=cfg["auth"], headers=HEADERS, verify=VERIFY_SSL,
            json=payload, timeout=20
        )
        if not r.ok:
            err_body = r.text[:300]
            logger.warning("SOC search failed: HTTP %s — %s", r.status_code, err_body)
            raise RuntimeError(f"Jira search returned HTTP {r.status_code}: {err_body}")
        data = r.json()
        issues = data.get("issues", [])
        results.extend(issues)
        next_page_token = data.get("nextPageToken")
        if not next_page_token or not issues:
            break
    return results


# ── Preview ───────────────────────────────────────────────────────────────────

# Per-project config: which date field to use for range filtering
_PROJECT_DATE_FIELD = {
    "TASI": '"TAS Start Time[Time stamp]"',
    "ITSD": "created",
    "ITO":  "created",
    "TAS":  "created",
    "OSC":  "created",
    "IMG":  "created",
}

_PREVIEW_FIELDS = [
    "summary", "status", "customfield_15736", "customfield_15381",
    "customfield_15855", "customfield_15811", "customfield_15769", "customfield_15770",
    "assignee", "reporter", "created", "attachment", "subtasks", "issuetype",
]


def preview_tickets(start_date: str, end_date: str, statuses: list,
                    projects: list = None) -> list:
    """
    Fast JQL search across one or more projects — returns summary rows only.
    start_date / end_date: 'YYYY-MM-DD' strings.
    statuses: list of Jira status names (applied across all projects).
    projects: list of project keys, e.g. ['TASI', 'ITSD']. Defaults to ['TASI'].
    Sub-task counts and keys are returned in the 'subtasks' field for each row;
    the caller can expand them in the UI.
    """
    if not projects:
        projects = ["TASI"]

    status_jql = ", ".join(f'"{s}"' for s in statuses)
    all_rows = []

    for proj in projects:
        date_field = _PROJECT_DATE_FIELD.get(proj, "created")
        jql = (
            f'project = {proj} '
            f'AND status WAS IN ({status_jql}) '
            f'AND {date_field} >= "{start_date}"'
            f' AND issueType not in subTaskIssueTypes()'
        )
        if end_date:
            jql += f' AND {date_field} <= "{end_date} 23:59"'
        jql += f' ORDER BY {date_field} ASC'

        issues = _paginate_search(jql, _PREVIEW_FIELDS)
        for issue in issues:
            f = issue.get("fields", {})
            raw_subtasks = f.get("subtasks") or []
            subtasks = [
                {
                    "key":     st["key"],
                    "summary": (st.get("fields") or {}).get("summary", ""),
                    "status":  ((st.get("fields") or {}).get("status") or {}).get("name", ""),
                }
                for st in raw_subtasks
            ]
            all_rows.append({
                "key":              issue["key"],
                "project":          proj,
                "summary":          f.get("summary", ""),
                "status":           (f.get("status") or {}).get("name", ""),
                "tas_type":         _fval(f, "customfield_15736"),
                "risk":             _fval(f, "customfield_15381"),
                "group":            _fval(f, "customfield_15855"),
                "env":              _fval(f, "customfield_15811"),
                "tas_start":        _fval(f, "customfield_15769"),
                "tas_end":          _fval(f, "customfield_15770"),
                "reporter":         (f.get("reporter") or {}).get("displayName", ""),
                "assignee":         (f.get("assignee") or {}).get("displayName", ""),
                "attachment_count": len(f.get("attachment") or []),
                "subtasks":         subtasks,
            })

    return all_rows


def _fval(fields, key):
    """Extract a plain string value from a Jira field (handles strings and dicts)."""
    v = fields.get(key)
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return v.get("value") or v.get("name") or v.get("displayName") or str(v)
    if isinstance(v, list):
        return ", ".join(
            (x.get("value") or x.get("name") or str(x)) if isinstance(x, dict) else str(x)
            for x in v
        )
    return str(v)


# ── Full ticket fetch ─────────────────────────────────────────────────────────

def fetch_ticket_full(key: str) -> dict | None:
    """Fetch a single ticket with rendered description, changelog, and attachments."""
    data = _get(f"/issue/{key}", params={
        "expand": "renderedFields,changelog",
        "fields": _FIELDS,
    })
    return data


def _download_image_b64(url: str) -> str | None:
    """Download an image attachment URL and return as base64 data URI, or None on failure."""
    cfg = _cfg()
    try:
        r = requests.get(url, auth=cfg["auth"], timeout=15, verify=VERIFY_SSL, stream=True)
        if not r.ok:
            return None
        ctype = r.headers.get("Content-Type", "image/png").split(";")[0].strip()
        if not ctype.startswith("image/"):
            return None
        raw = r.content
        if len(raw) > 8 * 1024 * 1024:  # skip images > 8MB
            return None
        b64 = base64.b64encode(raw).decode()
        return f"data:{ctype};base64,{b64}"
    except Exception as e:
        logger.debug("Attachment download failed %s: %s", url, e)
        return None


def _fmt_ts(ts_str):
    """Format a Jira ISO timestamp to a readable string."""
    if not ts_str:
        return "—"
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00").replace(".000+0000", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ts_str[:16] if ts_str else "—"


# ── Report generation (fire-and-forget) ──────────────────────────────────────

_report_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "current_ticket": "",
    "result_html": None,
    "error": None,
    "started_at": None,
    "completed_at": None,
    "report_meta": {},
}
_report_lock = threading.Lock()


def get_report_state() -> dict:
    with _report_lock:
        return dict(_report_state)


def start_report_generation(ticket_keys: list, include_images: bool,
                            date_range_label: str, report_title: str):
    with _report_lock:
        if _report_state["running"]:
            return False
        _report_state.update({
            "running": True, "progress": 0, "total": len(ticket_keys),
            "current_ticket": "", "result_html": None, "error": None,
            "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "completed_at": None,
            "report_meta": {"date_range": date_range_label, "title": report_title},
        })
    t = threading.Thread(
        target=_generate_report,
        args=(ticket_keys, include_images, date_range_label, report_title),
        daemon=True
    )
    t.start()
    return True


def _generate_report(ticket_keys: list, include_images: bool,
                     date_range_label: str, report_title: str):
    tickets_data = []
    try:
        for i, key in enumerate(ticket_keys):
            with _report_lock:
                _report_state["current_ticket"] = key
                _report_state["progress"] = i

            ticket = fetch_ticket_full(key)
            if not ticket:
                logger.warning("SOC: could not fetch %s", key)
                continue

            fields = ticket.get("fields", {})
            rendered = ticket.get("renderedFields", {})
            changelog = ticket.get("changelog", {})

            # Build attachment list
            attachments_html = ""
            attach_meta = fields.get("attachment") or []
            image_count = 0
            other_files = []
            for att in attach_meta:
                mime = att.get("mimeType", "")
                if include_images and mime.startswith("image/"):
                    b64 = _download_image_b64(att["content"])
                    if b64:
                        fname = att.get("filename", "")
                        size_kb = round(att.get("size", 0) / 1024)
                        attachments_html += (
                            f'<div class="att-item">'
                            f'<div class="att-fname">{_esc(fname)} ({size_kb} KB)</div>'
                            f'<img src="{b64}" alt="{_esc(fname)}" class="att-img">'
                            f'</div>'
                        )
                        image_count += 1
                else:
                    other_files.append(att.get("filename", "unnamed"))

            if other_files:
                attachments_html += (
                    f'<div class="att-other">Non-image attachments '
                    f'(accessible in Jira): {", ".join(_esc(f) for f in other_files)}</div>'
                )
            if not attach_meta:
                attachments_html = '<p class="no-data">No attachments on this ticket.</p>'

            # Build changelog HTML
            histories = changelog.get("histories", [])
            histories_sorted = sorted(histories, key=lambda h: h.get("created", ""))
            cl_rows = ""
            for h in histories_sorted:
                author = (h.get("author") or {}).get("displayName", "Unknown")
                ts     = _fmt_ts(h.get("created", ""))
                for item in h.get("items", []):
                    field = item.get("field", "")
                    from_s = _esc(item.get("fromString") or "—")
                    to_s   = _esc(item.get("toString") or "—")
                    cl_rows += (
                        f'<tr><td>{ts}</td><td>{_esc(author)}</td>'
                        f'<td>{_esc(field)}</td><td>{from_s}</td><td>{to_s}</td></tr>'
                    )
            if not cl_rows:
                cl_rows = '<tr><td colspan="5" class="no-data">No history entries.</td></tr>'

            # Build fields table
            field_rows = ""
            std_fields = [
                ("Status",    (fields.get("status") or {}).get("name", "—")),
                ("Reporter",  (fields.get("reporter") or {}).get("displayName", "—")),
                ("Assignee",  (fields.get("assignee") or {}).get("displayName", "—")),
                ("Priority",  (fields.get("priority") or {}).get("name", "—")),
                ("Created",   _fmt_ts(fields.get("created"))),
                ("Updated",   _fmt_ts(fields.get("updated"))),
                ("Resolved",  _fmt_ts(fields.get("resolved"))),
            ]
            for label, val in std_fields:
                field_rows += f'<tr><th>{label}</th><td>{_esc(str(val))}</td></tr>'
            for cf_key, cf_label in _FIELD_LABELS.items():
                val = _fval(fields, cf_key)
                if val:
                    field_rows += f'<tr><th>{cf_label}</th><td>{_esc(val)}</td></tr>'

            # Description (rendered HTML from Jira, sanitized)
            desc_html = rendered.get("description") or ""
            if not desc_html:
                desc_html = "<p><em>No description.</em></p>"
            desc_html = _sanitize_html(desc_html)

            tickets_data.append({
                "key":             key,
                "summary":         fields.get("summary", ""),
                "field_rows":      field_rows,
                "desc_html":       desc_html,
                "attachments_html": attachments_html,
                "changelog_rows":  cl_rows,
                "attach_count":    len(attach_meta),
            })

        html = _render_report_html(tickets_data, date_range_label, report_title)

        with _report_lock:
            _report_state.update({
                "running": False, "result_html": html,
                "progress": len(ticket_keys), "total": len(ticket_keys),
                "completed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
        logger.info("SOC: report generated for %d tickets", len(tickets_data))

    except Exception as e:
        logger.error("SOC report generation failed: %s", e, exc_info=True)
        with _report_lock:
            _report_state.update({"running": False, "error": str(e)})


def generate_pdf(html: str) -> bytes:
    """Convert report HTML to PDF using xhtml2pdf (pure Python, no GTK needed)."""
    try:
        from xhtml2pdf import pisa
    except ImportError:
        raise ImportError("xhtml2pdf is not installed. Run: pip install xhtml2pdf")
    import io
    buf = io.BytesIO()
    result = pisa.CreatePDF(html, dest=buf, encoding="utf-8")
    if result.err:
        raise RuntimeError(f"xhtml2pdf reported {result.err} error(s) during PDF generation")
    return buf.getvalue()


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _sanitize_html(html: str) -> str:
    """Strip script/style tags and on* attributes from Jira-rendered HTML."""
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'\s+on\w+="[^"]*"', '', html, flags=re.IGNORECASE)
    html = re.sub(r'\s+on\w+=\'[^\']*\'', '', html, flags=re.IGNORECASE)
    return html


# ── Report HTML renderer ──────────────────────────────────────────────────────

def _render_report_html(tickets: list, date_range: str, title: str) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    browse  = os.getenv("JIRA_BASE_URL", "https://zinnia.atlassian.net").rstrip("/") + "/browse/"

    # Table of contents
    toc_items = ""
    for t in tickets:
        toc_items += (
            f'<li><a href="#{t["key"]}">{_esc(t["key"])} — {_esc(t["summary"])}</a></li>'
        )

    # Ticket sections
    ticket_sections = ""
    for i, t in enumerate(tickets):
        page_break = 'style="page-break-before:always"' if i > 0 else ""
        ticket_sections += f"""
<div class="ticket" id="{t['key']}" {page_break}>
  <div class="ticket-header">
    <div class="ticket-key"><a href="{browse}{t['key']}" target="_blank">{t['key']}</a></div>
    <div class="ticket-summary">{_esc(t['summary'])}</div>
  </div>

  <h3 class="section-head">Ticket Details</h3>
  <table class="fields-table">
    <tbody>{t['field_rows']}</tbody>
  </table>

  <h3 class="section-head">Description</h3>
  <div class="description-box">{t['desc_html']}</div>

  <h3 class="section-head">Attachments ({t['attach_count']})</h3>
  <div class="attachments-box">{t['attachments_html']}</div>

  <h3 class="section-head">Change History</h3>
  <table class="history-table">
    <thead><tr>
      <th class="col-date">Date / Time</th>
      <th class="col-author">Author</th>
      <th class="col-field">Field</th>
      <th class="col-from">From</th>
      <th class="col-to">To</th>
    </tr></thead>
    <tbody>{t['changelog_rows']}</tbody>
  </table>
</div>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{_esc(title)}</title>
<style>
  /* ── Page setup ── */
  @page {{ margin: 15mm 12mm; }}

  /* ── Base (PDF-safe: no flex/grid, percentage widths, word-wrap) ── */
  body {{ font-family: Arial, sans-serif; font-size: 11px; color: #1a1a18;
         background: #fff; margin: 0; padding: 0; line-height: 1.5; }}
  a {{ color: #0a7a70; }}
  h1, h2, h3, h4 {{ margin: 0 0 6px; }}

  /* ── Cover page ── */
  .cover-page {{ text-align: center; padding: 60px 20px 40px; page-break-after: always; }}
  .cover-company {{ font-size: 18px; font-weight: 700; color: #0a7a70; margin-bottom: 4px; }}
  .cover-rule {{ border: none; border-top: 3px solid #0a7a70; margin: 16px auto; width: 80px; }}
  .cover-title {{ font-size: 24px; font-weight: 800; color: #1a1a18; margin: 14px 0; }}
  .cover-subtitle {{ font-size: 13px; color: #5f5e5a; margin-bottom: 24px; }}
  .cover-meta {{ font-size: 12px; color: #888780; line-height: 2.2; }}
  .cover-meta strong {{ color: #1a1a18; }}

  /* ── Table of contents ── */
  .toc {{ padding: 20px 0; page-break-after: always; }}
  .toc h2 {{ font-size: 16px; color: #0a7a70; border-bottom: 2px solid #0a7a70;
             padding-bottom: 6px; margin-bottom: 14px; }}
  .toc ol {{ line-height: 2; padding-left: 18px; }}
  .toc li a {{ color: #0a7a70; text-decoration: none; font-size: 11px; }}

  /* ── Ticket section ── */
  .ticket {{ padding: 10px 0; border-bottom: 2px solid #e8e6df; }}
  .ticket-header {{ background: #f5f5f3; border-left: 4px solid #0a7a70;
                    padding: 10px 12px; margin-bottom: 14px; }}
  .ticket-key {{ font-size: 15px; font-weight: 700; color: #0a7a70; }}
  .ticket-key a {{ color: #0a7a70; text-decoration: none; }}
  .ticket-summary {{ font-size: 12px; color: #1a1a18; margin-top: 3px; font-weight: 600;
                      word-wrap: break-word; }}
  .section-head {{ font-size: 10px; font-weight: 700; text-transform: uppercase;
                   color: #5f5e5a; border-bottom: 1px solid #d3d1c7;
                   padding-bottom: 4px; margin: 12px 0 8px; }}

  /* ── Fields table — fixed layout so label col never overflows ── */
  .fields-table {{ width: 100%; border-collapse: collapse; font-size: 11px;
                   table-layout: fixed; margin-bottom: 6px; }}
  .fields-table th {{ background: #f1efe8; color: #5f5e5a; font-weight: 600; text-align: left;
                      padding: 5px 8px; width: 28%; border: 1px solid #d3d1c7;
                      word-wrap: break-word; vertical-align: top; }}
  .fields-table td {{ padding: 5px 8px; border: 1px solid #d3d1c7; color: #1a1a18;
                      word-wrap: break-word; vertical-align: top; }}

  /* ── Description ── */
  .description-box {{ background: #fafaf8; border: 1px solid #d3d1c7;
                       padding: 10px 12px; margin-bottom: 6px; font-size: 11px; line-height: 1.6;
                       word-wrap: break-word; }}
  .description-box h1, .description-box h2, .description-box h3 {{ color: #0a7a70; font-size: 12px; }}
  .description-box table {{ border-collapse: collapse; width: 100%; font-size: 10px; }}
  .description-box td, .description-box th {{ border: 1px solid #d3d1c7; padding: 4px 6px;
                                              word-wrap: break-word; }}
  .description-box code {{ background: #f1efe8; font-family: monospace; font-size: 10px; }}
  .description-box pre {{ background: #f1efe8; padding: 8px; font-size: 10px;
                           font-family: monospace; word-wrap: break-word; }}

  /* ── Attachments ── */
  .attachments-box {{ margin-bottom: 6px; }}
  .att-item {{ margin-bottom: 14px; }}
  .att-fname {{ font-size: 10px; font-weight: 600; color: #5f5e5a; margin-bottom: 4px; }}
  .att-img {{ max-width: 100%; border: 1px solid #d3d1c7; display: block; }}
  .att-other {{ font-size: 10px; color: #888780; font-style: italic; padding: 4px 0; }}
  .no-data {{ color: #888780; font-style: italic; font-size: 10px; }}

  /* ── History table — fixed layout, explicit column widths ── */
  .history-table {{ width: 100%; border-collapse: collapse; font-size: 10px;
                    table-layout: fixed; }}
  .history-table th {{ background: #f1efe8; color: #5f5e5a; font-weight: 600; text-align: left;
                       padding: 5px 6px; border: 1px solid #d3d1c7; word-wrap: break-word; }}
  .history-table td {{ padding: 4px 6px; border: 1px solid #d3d1c7; vertical-align: top;
                       word-wrap: break-word; color: #3a3a38; }}
  .history-table tr:nth-child(even) td {{ background: #fafaf8; }}
  .col-date   {{ width: 17%; font-family: monospace; }}
  .col-author {{ width: 18%; }}
  .col-field  {{ width: 13%; }}
  .col-from   {{ width: 26%; }}
  .col-to     {{ width: 26%; }}

  /* ── Browser-only enhancements (xhtml2pdf ignores @media screen) ── */
  @media screen {{
    body {{ font-size: 13px; }}
    .cover-page {{ display: flex; flex-direction: column; align-items: center;
                   justify-content: center; min-height: 85vh; padding: 60px 40px; }}
    .cover-company {{ font-size: 22px; }}
    .cover-title {{ font-size: 30px; }}
    .cover-subtitle {{ font-size: 16px; }}
    .cover-meta {{ font-size: 14px; }}
    .ticket {{ padding: 28px 36px; }}
    .ticket-header {{ padding: 14px 18px; border-radius: 0 6px 6px 0; }}
    .ticket-key {{ font-size: 17px; }}
    .ticket-summary {{ font-size: 14px; }}
    .section-head {{ font-size: 12px; letter-spacing: .05em; margin: 18px 0 10px; }}
    .fields-table {{ font-size: 12px; }}
    .fields-table th {{ white-space: nowrap; width: auto; min-width: 180px; }}
    .history-table {{ font-size: 12px; }}
    .history-table th {{ white-space: nowrap; }}
    .att-img {{ max-height: 500px; }}
    .description-box {{ font-size: 13px; }}
    .toc li a {{ font-size: 13px; }}
  }}
</style>
</head>
<body>

<!-- Cover page -->
<div class="cover-page">
  <div class="cover-company">Zinnia Infrastructure</div>
  <hr class="cover-rule">
  <div class="cover-title">{_esc(title)}</div>
  <div class="cover-subtitle">Infrastructure Change Management — Compliance Audit</div>
  <div class="cover-meta">
    <div><strong>Audit Period:</strong> {_esc(date_range)}</div>
    <div><strong>Total Tickets:</strong> {len(tickets)}</div>
    <div><strong>Report Generated:</strong> {now_str}</div>
    <div><strong>Classification:</strong> Internal / Compliance</div>
  </div>
</div>

<!-- Table of contents -->
<div class="toc">
  <h2>Table of Contents</h2>
  <ol>{toc_items}</ol>
</div>

<!-- Ticket sections -->
{ticket_sections}

</body>
</html>"""
