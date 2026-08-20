import os
import time
import logging
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)

# --- Config ---
# Read at call time so .env changes take effect without restarting
def _cfg():
    return {
        "base_url":  os.getenv("JIRA_BASE_URL", "").rstrip("/"),
        "auth":      HTTPBasicAuth(os.getenv("JIRA_EMAIL", ""), os.getenv("JIRA_API_TOKEN", "")),
        "helpdesk":  os.getenv("JIRA_HELPDESK_PROJECT", "ITSD"),
        "ito":       os.getenv("JIRA_PROJECT_PROJECT", "ITO"),
        "tasi":      os.getenv("JIRA_TASI_PROJECT", "TASI"),
    }

HEADERS         = {"Accept": "application/json", "Content-Type": "application/json"}
VERIFY_SSL      = False  # Corporate SSL inspection proxy
JIRA_BROWSE_URL = "https://zinnia.atlassian.net/browse"

# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
# Bulk ticket cache — populated by job_jira_prefetch(), keyed by device word
# { device_word: {"ts": epoch, "tickets": [...]} }
_search_cache: dict = {}
_bulk_cache_ts: float = 0.0          # when the last bulk prefetch ran
CACHE_TTL      = 4 * 60 * 60        # 4 hours — bulk cache lifetime
DEVICE_TTL     = 4 * 60 * 60        # 4 hours — per-device direct lookup lifetime


def cache_is_fresh() -> bool:
    """True if the bulk prefetch has run and is less than 4 hours old."""
    return _bulk_cache_ts > 0 and (time.time() - _bulk_cache_ts) < CACHE_TTL


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(path: str, params: dict = None, base_override: str = None) -> dict | None:
    cfg = _cfg()
    base = base_override or f"{cfg['base_url']}/rest/api/3"
    try:
        r = requests.get(
            f"{base}{path}",
            auth=cfg['auth'], headers=HEADERS, params=params, timeout=10, verify=VERIFY_SSL
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error(f"Jira GET {path} failed: {e}")
        return None


def _post(path: str, payload: dict) -> dict | None:
    cfg = _cfg()
    try:
        r = requests.post(
            f"{cfg['base_url']}/rest/api/3{path}",
            auth=cfg['auth'], headers=HEADERS, json=payload, timeout=10, verify=VERIFY_SSL
        )
        # If team ID is invalid, retry without it rather than failing the whole ticket
        if r.status_code == 400 and "customfield_11600" in r.text:
            logger.warning("Team field rejected by Jira — retrying without team assignment")
            fields2 = {k: v for k, v in payload.get("fields", {}).items() if k != "customfield_11600"}
            payload2 = {**payload, "fields": fields2}
            r = requests.post(
                f"{cfg['base_url']}/rest/api/3{path}",
                auth=cfg['auth'], headers=HEADERS, json=payload2, timeout=10, verify=VERIFY_SSL
            )
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        logger.error(f"Jira POST {path} HTTP {r.status_code}: {r.text}")
        return None
    except Exception as e:
        logger.error(f"Jira POST {path} failed: {e}")
        return None


def _search_jql(jql: str, max_results: int = 100,
                fields: list = None, next_page_token: str = None) -> dict | None:
    """POST /rest/api/3/search/jql — cursor-based pagination via nextPageToken."""
    payload = {
        "jql":        jql,
        "maxResults": max_results,
        "fields":     fields or ["summary", "status", "priority"],
    }
    if next_page_token:
        payload["nextPageToken"] = next_page_token
    return _post("/search/jql", payload)


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

def _str_val(val) -> str:
    if not val:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return val.get("value") or val.get("name") or val.get("displayName") or ""
    return str(val)


def _multi_val(val) -> str:
    if not val:
        return ""
    if isinstance(val, list):
        parts = []
        for item in val:
            if isinstance(item, dict):
                parts.append(item.get("value") or item.get("name") or "")
            elif isinstance(item, str):
                parts.append(item)
        return ", ".join(filter(None, parts))
    return _str_val(val)


def _cascade_val(val) -> str:
    if not val or not isinstance(val, dict):
        return ""
    parent = val.get("value", "")
    child  = (val.get("child") or {}).get("value", "")
    return f"{parent} > {child}" if child else parent


def _adf_to_text(val, max_len: int = 400) -> str:
    if not val:
        return ""
    if isinstance(val, str):
        return val[:max_len]
    if isinstance(val, dict) and val.get("type") == "doc":
        parts = []
        def _walk(nodes):
            for node in nodes:
                if node.get("type") == "text":
                    parts.append(node.get("text", ""))
                _walk(node.get("content", []))
        _walk(val.get("content", []))
        return " ".join(parts)[:max_len]
    return str(val)[:max_len]


# ---------------------------------------------------------------------------
# Comprehensive ticket fetchers — used by job_jira_intelligence
# ---------------------------------------------------------------------------

def fetch_itsd_tickets(days: int = 90) -> list[dict]:
    """Fetch ITSD incidents (open + resolved within last N days) for intelligence analysis."""
    cfg = _cfg()
    jql = (
        f'project = {cfg["helpdesk"]} AND issuetype = Incident '
        f'AND (statusCategory != Done OR updated >= -{days}d) '
        f'ORDER BY updated DESC'
    )
    fields = [
        "summary", "status", "priority", "created", "updated", "resolutiondate",
        "reporter", "assignee",
        "customfield_11600",  # Team
        "customfield_15833",  # Severity
        "customfield_15828",  # Urgency
        "customfield_15829",  # Impact
        "customfield_15845",  # Source
        "customfield_16047",  # Server Name
        "customfield_15243",  # System(s)
        "customfield_16054",  # Product categorization
        "customfield_16055",  # Operational categorization
    ]
    tickets, next_token = [], None
    while True:
        data = _search_jql(jql, max_results=100, fields=fields, next_page_token=next_token)
        if not data:
            break
        for issue in data.get("issues", []):
            f = issue.get("fields", {})
            team_raw = f.get("customfield_11600")
            team = (team_raw or {}).get("name") or (team_raw or {}).get("title") or "" if isinstance(team_raw, dict) else ""
            tickets.append({
                "key":                  issue["key"],
                "project":              "ITSD",
                "issue_type":           "Incident",
                "summary":              f.get("summary", ""),
                "status":               _str_val(f.get("status")),
                "status_category":      ((f.get("status") or {}).get("statusCategory") or {}).get("name", ""),
                "priority":             _str_val(f.get("priority")),
                "created":              (f.get("created") or "")[:19],
                "updated":              (f.get("updated") or "")[:19],
                "resolved":             (f.get("resolutiondate") or "")[:19] or None,
                "reporter":             (f.get("reporter") or {}).get("displayName", ""),
                "assignee":             (f.get("assignee") or {}).get("displayName", ""),
                "team":                 team,
                "severity":             _str_val(f.get("customfield_15833")),
                "urgency":              _str_val(f.get("customfield_15828")),
                "impact":               _str_val(f.get("customfield_15829")),
                "source":               _str_val(f.get("customfield_15845")),
                "server_name":          f.get("customfield_16047") or "",
                "systems":              _multi_val(f.get("customfield_15243")),
                "product_category":     _cascade_val(f.get("customfield_16054")),
                "operational_category": _cascade_val(f.get("customfield_16055")),
                "tas_type": None, "risk_impact": None, "resource_group": None,
                "environment": None, "hardware_names": None, "tas_start": None, "tas_end": None,
                "objective": None, "t_shirt_size": None, "due_date": None,
                "parent_key": None, "latest_update": None,
            })
        next_token = data.get("nextPageToken")
        if not next_token or len(tickets) >= 5000:
            break
    logger.info("Jira intelligence: fetched %d ITSD tickets", len(tickets))
    return tickets


def fetch_tasi_tickets(days: int = 90) -> list[dict]:
    """Fetch TASI change records from last N days for intelligence analysis."""
    cfg = _cfg()
    jql = f'project = {cfg["tasi"]} AND updated >= -{days}d ORDER BY updated DESC'
    fields = [
        "summary", "status", "created", "updated", "reporter", "assignee",
        "customfield_15736",  # TAS Type
        "customfield_15381",  # Risk/Impact
        "customfield_15243",  # System(s)
        "customfield_15855",  # Infrastructure Resource Group
        "customfield_15811",  # System Environment
        "customfield_15792",  # Hardware/Server/DB/Schema Name
        "customfield_15769",  # TAS Start Time
        "customfield_15770",  # TAS End Time
    ]
    tickets, next_token = [], None
    while True:
        data = _search_jql(jql, max_results=100, fields=fields, next_page_token=next_token)
        if not data:
            break
        for issue in data.get("issues", []):
            f = issue.get("fields", {})
            tickets.append({
                "key":                  issue["key"],
                "project":              "TASI",
                "issue_type":           "TAS Infrastructure",
                "summary":              f.get("summary", ""),
                "status":               _str_val(f.get("status")),
                "status_category":      ((f.get("status") or {}).get("statusCategory") or {}).get("name", ""),
                "priority":             None,
                "created":              (f.get("created") or "")[:19],
                "updated":              (f.get("updated") or "")[:19],
                "resolved":             None,
                "reporter":             (f.get("reporter") or {}).get("displayName", ""),
                "assignee":             (f.get("assignee") or {}).get("displayName", ""),
                "team":                 None,
                "severity": None, "urgency": None, "impact": None, "source": None,
                "server_name":          None,
                "systems":              _multi_val(f.get("customfield_15243")),
                "product_category":     None,
                "operational_category": None,
                "tas_type":             _str_val(f.get("customfield_15736")),
                "risk_impact":          _str_val(f.get("customfield_15381")),
                "resource_group":       _str_val(f.get("customfield_15855")),
                "environment":          _str_val(f.get("customfield_15811")),
                "hardware_names":       _adf_to_text(f.get("customfield_15792")),
                "tas_start":            (f.get("customfield_15769") or "")[:19] or None,
                "tas_end":              (f.get("customfield_15770") or "")[:19] or None,
                "objective": None, "t_shirt_size": None, "due_date": None,
                "parent_key": None, "latest_update": None,
            })
        next_token = data.get("nextPageToken")
        if not next_token or len(tickets) >= 3000:
            break
    logger.info("Jira intelligence: fetched %d TASI tickets", len(tickets))
    return tickets


def fetch_ito_tickets(days: int = 90) -> list[dict]:
    """Fetch ITO Epics and Tasks (open + completed within last N days) for intelligence analysis."""
    cfg = _cfg()
    jql = (
        f'project = {cfg["ito"]} AND issuetype in (Epic, Task) '
        f'AND (statusCategory != Done OR updated >= -{days}d) '
        f'ORDER BY updated DESC'
    )
    fields = [
        "summary", "status", "priority", "issuetype", "created", "updated",
        "resolutiondate", "reporter", "assignee",
        "customfield_11600",  # Team
        "customfield_16256",  # Objective
        "customfield_16267",  # T-Shirt Size
        "customfield_16456",  # Latest Update
        "customfield_15204",  # Start date
        "duedate", "parent",
    ]
    tickets, next_token = [], None
    while True:
        data = _search_jql(jql, max_results=100, fields=fields, next_page_token=next_token)
        if not data:
            break
        for issue in data.get("issues", []):
            f = issue.get("fields", {})
            team_raw = f.get("customfield_11600")
            team = (team_raw or {}).get("name") or (team_raw or {}).get("title") or "" if isinstance(team_raw, dict) else ""
            parent = f.get("parent")
            tickets.append({
                "key":                  issue["key"],
                "project":              "ITO",
                "issue_type":           _str_val(f.get("issuetype")),
                "summary":              f.get("summary", ""),
                "status":               _str_val(f.get("status")),
                "status_category":      ((f.get("status") or {}).get("statusCategory") or {}).get("name", ""),
                "priority":             _str_val(f.get("priority")),
                "created":              (f.get("created") or "")[:19],
                "updated":              (f.get("updated") or "")[:19],
                "resolved":             (f.get("resolutiondate") or "")[:19] or None,
                "reporter":             (f.get("reporter") or {}).get("displayName", ""),
                "assignee":             (f.get("assignee") or {}).get("displayName", ""),
                "team":                 team,
                "severity": None, "urgency": None, "impact": None, "source": None,
                "server_name":          None,
                "systems":              None,
                "product_category":     None,
                "operational_category": None,
                "tas_type": None, "risk_impact": None, "resource_group": None,
                "environment":          None,
                "hardware_names":       None,
                "tas_start":            None,
                "tas_end":              None,
                "objective":            _multi_val(f.get("customfield_16256")),
                "t_shirt_size":         _str_val(f.get("customfield_16267")),
                "due_date":             f.get("duedate") or None,
                "parent_key":           parent.get("key") if isinstance(parent, dict) else None,
                "latest_update":        _adf_to_text(f.get("customfield_16456")) or None,
            })
        next_token = data.get("nextPageToken")
        if not next_token or len(tickets) >= 3000:
            break
    logger.info("Jira intelligence: fetched %d ITO tickets", len(tickets))
    return tickets


# ---------------------------------------------------------------------------
# Bulk prefetch — runs on scheduler, every 4 hours
# ---------------------------------------------------------------------------

def bulk_prefetch_all_open_tickets() -> int:
    """
    Fetch ALL open ITSD tickets in one paginated query and populate
    _search_cache keyed by every hostname-like word in each ticket summary.
    Returns the number of tickets fetched.
    Called by job_jira_prefetch() in main.py — do not call on page load.
    """
    global _bulk_cache_ts

    cfg = _cfg()
    jql = f'project = {cfg["helpdesk"]} AND statusCategory != Done ORDER BY created DESC'

    all_tickets = []
    next_token  = None
    page_size   = 100

    while True:
        data = _search_jql(jql, max_results=page_size,
                           fields=["summary", "status", "priority"],
                           next_page_token=next_token)
        if not data:
            logger.warning("Jira bulk prefetch: no data returned, stopping")
            break

        issues = data.get("issues", [])
        if not issues:
            break

        for issue in issues:
            f = issue.get("fields", {})
            all_tickets.append({
                "key":      issue["key"],
                "summary":  f.get("summary", ""),
                "status":   (f.get("status") or {}).get("name", ""),
                "priority": (f.get("priority") or {}).get("name", ""),
                "url":      f"{JIRA_BROWSE_URL}/{issue['key']}",
            })

        logger.info(f"Jira bulk prefetch: fetched {len(all_tickets)} tickets so far")

        next_token = data.get("nextPageToken")
        if not next_token:
            break
        if len(all_tickets) > 5000:
            logger.warning("Jira bulk prefetch: hit 5000 ticket safety cap, stopping")
            break

    # Index each ticket under every hostname-like word in its summary
    now = time.time()
    _search_cache.clear()

    for ticket in all_tickets:
        words = ticket["summary"].upper().split()
        for word in words:
            word = word.strip("[](),:;-")
            if len(word) >= 4 and not word.isdigit():
                entry = _search_cache.setdefault(word, {"ts": now, "tickets": []})
                if not any(t["key"] == ticket["key"] for t in entry["tickets"]):
                    entry["tickets"].append(ticket)

    _bulk_cache_ts = now
    logger.info(f"Jira bulk prefetch: {len(all_tickets)} tickets indexed, {len(_search_cache)} words")
    return len(all_tickets)


# ---------------------------------------------------------------------------
# Per-device search
# ---------------------------------------------------------------------------

def search_tickets_by_device(device_name: str, force_live: bool = False) -> list[dict]:
    """
    Return open ITSD tickets mentioning this device name.

    If the bulk cache is fresh, answer from it immediately — no API call.
    If the bulk cache is stale/cold AND we haven't done a direct lookup
    for this device recently, do one targeted API call and cache the result
    for DEVICE_TTL (4 hours).
    Pass force_live=True to bypass all caches and go direct to Jira.
    """
    if not device_name:
        return []

    key = device_name.upper()

    # --- Serve from bulk cache if fresh ---
    if not force_live and cache_is_fresh():
        return _search_cache.get(key, {}).get("tickets", [])

    # --- Check per-device cache ---
    cached = _search_cache.get(key)
    if not force_live and cached and (time.time() - cached["ts"]) < DEVICE_TTL:
        return cached["tickets"]

    # --- Direct API call (cold cache or forced) ---
    jql = (
        f'project = {_cfg()["helpdesk"]} '
        f'AND summary ~ "{device_name}" '
        f'AND statusCategory != Done '
        f'ORDER BY created DESC'
    )
    data = _search_jql(jql, max_results=10, fields=["summary", "status", "priority", "created", "updated"])
    if not data:
        return []

    tickets = []
    for issue in data.get("issues", []):
        f = issue.get("fields", {})
        tickets.append({
            "key":      issue["key"],
            "summary":  f.get("summary", ""),
            "status":   f.get("status", {}).get("name", ""),
            "priority": f.get("priority", {}).get("name", ""),
            "url":      f"{JIRA_BROWSE_URL}/{issue['key']}",
            "created":  f.get("created", "")[:10],
            "updated":  f.get("updated", "")[:10],
        })

    _search_cache[key] = {"ts": time.time(), "tickets": tickets}
    return tickets


# ---------------------------------------------------------------------------
# Ticket creation
# ---------------------------------------------------------------------------

def create_ticket(
    summary: str,
    description: str,
    priority: str = "Medium",
    device_name: str = "",
    alarm_id: str = "",
    team_id: str = "",
) -> dict | None:
    """
    Create an ITSD help desk ticket.
    Returns { key, url } on success, None on failure.
    """
    adf_body = _text_to_adf(description)

    fields = {
        "project":     {"key": _cfg()["helpdesk"]},
        "summary":     summary,
        "description": adf_body,
        "issuetype":   {"name": "Incident"},
        "assignee":    {"accountId": "5b9ffb95c7bab16dd8bfc709"},
        "priority":    {"name": priority},
    }

    if team_id:
        fields["customfield_11600"] = {"id": team_id}

    result = _post("/issue", {"fields": fields})
    if result:
        key = result.get("key")
        # Invalidate cache entry for this device so next lookup reflects new ticket
        upper_dev = device_name.upper() if device_name else ""
        if upper_dev and upper_dev in _search_cache:
            del _search_cache[upper_dev]
        return {"key": key, "url": f"{JIRA_BROWSE_URL}/{key}"}
    return None


# ---------------------------------------------------------------------------
# Team search — tries three endpoints in order, returns first success
# ---------------------------------------------------------------------------

def search_teams(query: str) -> list[dict]:
    """
    Search for Atlassian teams by name.

    Teams live at the org level (api.atlassian.com), not the site level.
    Org ID is read from ATLASSIAN_ORG_ID in .env.

    Tries two endpoints:
    1. api.atlassian.com/admin/v1/orgs/{orgId}/teams  — org-level Teams API
    2. zinnia.atlassian.net/rest/api/3/groups/picker   — fallback (Jira groups)

    Returns list of { id, displayName }.
    """
    if not query or len(query) < 2:
        return []

    query = query.strip().upper()  # groups/picker is case-sensitive — uppercase gives best results
    cfg = _cfg()
    org_id = os.getenv("ATLASSIAN_ORG_ID", "2d58600f-43cd-4055-8f51-1ed98b352967")

    # --- Attempt 1: Atlassian org-level Teams API ---
    try:
        r = requests.get(
            f"https://api.atlassian.com/admin/v1/orgs/{org_id}/teams",
            auth=cfg['auth'],
            headers={"Accept": "application/json"},
            params={"query": query, "maxResults": 20},
            timeout=10,
            verify=VERIFY_SSL,
        )
        if r.ok:
            data = r.json()
            items = data if isinstance(data, list) else data.get("data", data.get("values", data.get("results", [])))
            teams = []
            for item in items:
                tid  = item.get("teamId") or item.get("id")
                name = item.get("displayName") or item.get("name")
                if tid and name and query.lower() in name.lower():
                    teams.append({"id": tid, "displayName": name})
            if teams:
                logger.info(f"Team search via org Teams API: {len(teams)} results")
                return teams[:20]
            else:
                logger.warning(f"Org Teams API returned data but no matches for '{query}': {str(data)[:300]}")
        else:
            logger.warning(f"Org Teams API {r.status_code}: {r.text[:300]}")
    except Exception as e:
        logger.error(f"Org Teams API failed: {e}")

    # --- Attempt 2: Jira groups/picker (fallback — returns Jira groups, not Atlassian Teams) ---
    # Only used if org Teams API fails. Note: group IDs won't work for customfield_11600
    # if it expects an Atlassian Team UUID — use only as last resort.
    try:
        r = requests.get(
            f"{cfg['base_url']}/rest/api/3/groups/picker",
            auth=cfg['auth'],
            headers={"Accept": "application/json"},
            params={"query": query, "maxResults": 20},
            timeout=10,
            verify=VERIFY_SSL,
        )
        if r.ok:
            data = r.json()
            groups = data.get("groups", [])
            results = []
            for g in groups:
                gid  = g.get("groupId") or g.get("name")
                name = g.get("name")
                if gid and name:
                    results.append({"id": gid, "displayName": name})
            if results:
                logger.info(f"Team search via groups/picker (fallback): {len(results)} results")
                return results
        else:
            logger.warning(f"groups/picker {r.status_code}: {r.text[:200]}")
    except Exception as e:
        logger.error(f"groups/picker failed: {e}")

    logger.warning(f"Team search for '{query}' returned no results from any endpoint")
    return []


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

def get_project_issue_types() -> list[dict]:
    data = _get(f"/project/{_cfg()['helpdesk']}")
    if not data:
        return []
    return [{"id": it["id"], "name": it["name"]} for it in data.get("issueTypes", [])]


def get_required_fields(project_key: str = None) -> dict:
    key = project_key or _cfg()["helpdesk"]
    data = _get("/issue/createmeta", params={
        "projectKeys": key,
        "expand": "projects.issuetypes.fields"
    })
    if not data:
        return {}
    result = {}
    for project in data.get("projects", []):
        for issuetype in project.get("issuetypes", []):
            fields = issuetype.get("fields", {})
            required = {k: v.get("name") for k, v in fields.items() if v.get("required")}
            result[issuetype["name"]] = required
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _text_to_adf(text: str) -> dict:
    """Convert plain text to minimal Atlassian Document Format."""
    paragraphs = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if line:
            paragraphs.append({
                "type": "paragraph",
                "content": [{"type": "text", "text": line}]
            })
    if not paragraphs:
        paragraphs = [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]
    return {
        "type":    "doc",
        "version": 1,
        "content": paragraphs
    }