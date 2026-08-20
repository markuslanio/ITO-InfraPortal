"""
routers/vdi_cost.py
VDI Cost Estimation Report — Windows 11 single-session desktops only.

User resolution (3-tier priority):
  1. Citrix AssignedUsers API  — permanent assignment, works even when machine is off
  2. machine assigned_users    — from citrix.py cache if populated
  3. active session map        — fallback for pooled desktops

Citrix User field format handling:
  - DOMAIN\samaccountname  → strip domain prefix, resolve via ENTRA_DEFAULT_DOMAIN
  - email@domain.com       → use as UPN directly
  - multiple comma-sep     → prefer UPN, then non-super SAM, then first entry

Manager resolution: dedicated GET /users/{id}/manager call.
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

GRAPH_BASE   = "https://graph.microsoft.com/v1.0"
_USER_SELECT = "id,displayName,userPrincipalName,department,jobTitle,mail,accountEnabled"
_MGR_SELECT  = "displayName,userPrincipalName,mail"


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _days_since(dt_str: str | None) -> int | None:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def _best_user_from_citrix_field(raw: str) -> str:
    """
    Parse the Citrix 'User' string which can be:
      - A single UPN:               email@domain.com
      - A single domain SAM:        DOMAIN\\samaccountname
      - Comma-separated mix:        DOMAIN\\user, DOMAIN\\superuser
      - UPN + SAM:                  DOMAIN\\user, email@domain.com

    Priority: first UPN found → first non-super SAM → first entry's SAM.
    Returns a clean identifier (UPN with @ or bare SAMAccountName without domain).
    """
    if not raw:
        return ""
    parts = [p.strip() for p in raw.split(",") if p.strip()]

    # Prefer a part that is a full UPN
    for p in parts:
        if "@" in p and "\\" not in p:
            return p

    # Filter out super/admin accounts when picking a SAM
    def is_super(p: str) -> bool:
        sam = p.split("\\")[-1].lower()
        return sam.startswith("super") or sam.startswith("admin")

    regular = [p for p in parts if not is_super(p)]
    candidates = regular if regular else parts

    # Return bare SAMAccountName (strip DOMAIN\ prefix)
    for p in candidates:
        if "\\" in p:
            return p.split("\\")[-1]
        if p:
            return p

    return ""


def _best_user_from_assigned_users(assigned: list) -> str:
    """
    Parse Citrix DaaS API AssignedUsers list:
    [{"Name": "DOMAIN\\sam", "SamAccountName": "sam", "PrincipalName": "upn@domain.com"}]
    Prefers PrincipalName (UPN), falls back to SamAccountName.
    Skips super/admin accounts when regular accounts exist.
    """
    if not assigned:
        return ""

    def is_super(u: dict) -> bool:
        sam = (u.get("SamAccountName") or "").lower()
        return sam.startswith("super") or sam.startswith("admin")

    regular = [u for u in assigned if not is_super(u)]
    candidates = regular if regular else assigned

    for u in candidates:
        upn = (u.get("PrincipalName") or "").strip()
        if upn and "@" in upn:
            return upn

    for u in candidates:
        sam = (u.get("SamAccountName") or "").strip()
        if sam:
            return sam

    return ""


# ─── Citrix assigned users (permanent) ───────────────────────────────────────

def _get_citrix_assigned_users_map() -> dict[str, str]:
    """
    Call the Citrix DaaS /Machines endpoint directly to get AssignedUsers for
    every machine. This reflects permanent assignment and works even when
    machines are powered off or have no active sessions.

    Returns: { MACHINE_NAME_UPPER → best user identifier }
    """
    try:
        from routers.citrix import get_session, API_BASE  # reuse existing auth
    except Exception as exc:
        logger.warning("vdi_cost: cannot import Citrix session — %s", exc)
        return {}

    result: dict[str, str] = {}
    try:
        session      = get_session()
        continuation = None
        page         = 0

        while True:
            params: dict = {"limit": 1000, "fields": "Name,AssignedUsers"}
            if continuation:
                params["continuationToken"] = continuation

            r = session.get(f"{API_BASE}/Machines", params=params, timeout=30)
            if not r.ok:
                logger.warning("vdi_cost: Citrix /Machines → HTTP %s", r.status_code)
                break

            data  = r.json()
            items = data.get("Items", [])
            page += 1

            for machine in items:
                # Strip domain prefix and file extension: "DOMAIN\Name.domain.com" → "NAME"
                raw_name = machine.get("Name") or ""
                name     = raw_name.split("\\")[-1].split(".")[0].upper()
                if not name:
                    continue

                assigned   = machine.get("AssignedUsers") or []
                identifier = _best_user_from_assigned_users(assigned)
                if identifier:
                    result[name] = identifier

            continuation = data.get("ContinuationToken")
            if not continuation or not items:
                break

        logger.info(
            "vdi_cost: Citrix assigned users — %d machines with permanent assignments "
            "(fetched %d page(s))",
            len(result), page,
        )
    except Exception as exc:
        logger.warning("vdi_cost: Citrix assigned users fetch error — %s", exc)

    return result


# ─── VDI filter ───────────────────────────────────────────────────────────────

def _build_vdi_dg_set() -> set[str]:
    try:
        from routers.citrix import get_citrix_delivery_groups
        dgs_raw, _ = get_citrix_delivery_groups(force_refresh=False)
        dgs = dgs_raw or []
        single = {dg["name"] for dg in dgs if dg.get("name") and (dg.get("session_support") or "").lower() != "multisession"}
        multi  = {dg["name"] for dg in dgs if dg.get("name") and (dg.get("session_support") or "").lower() == "multisession"}
        logger.info("vdi_cost: DGs — %d SingleSession (VDI), %d MultiSession (XenApp)", len(single), len(multi))
        return single
    except Exception as exc:
        logger.warning("vdi_cost: could not fetch delivery groups — %s", exc)
        return set()


def _is_vdi_machine(m: dict, vdi_dgs: set[str]) -> bool:
    dg_name = m.get("delivery_group_name") or ""
    if vdi_dgs:
        if dg_name and dg_name in vdi_dgs:
            return True
        if dg_name:
            return False
    ss = (m.get("session_support") or "").strip().lower()
    if ss == "multisession":
        return False
    if ss == "singlesession":
        return True
    os_type = (m.get("os_type") or "").lower()
    if "server" in os_type:
        return False
    if "windows 10" in os_type or "windows 11" in os_type:
        return True
    name = (m.get("name") or "").lower()
    if "srv" in name and "vdi" not in name:
        return False
    return True


# ─── Entra / Graph helpers ────────────────────────────────────────────────────

def _get_graph_token() -> Optional[str]:
    tenant    = os.getenv("AZURE_TENANT_ID", "")
    client_id = os.getenv("AZURE_CLIENT_ID", "")
    secret    = os.getenv("AZURE_CLIENT_SECRET", "")
    if not all([tenant, client_id, secret]):
        logger.error("vdi_cost: missing Azure env vars")
        return None
    try:
        r = requests.post(
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": client_id,
                  "client_secret": secret, "scope": "https://graph.microsoft.com/.default"},
            verify=False, timeout=15,
        )
        r.raise_for_status()
        token = r.json().get("access_token", "")
        if not token:
            logger.error("vdi_cost: token response missing access_token")
        return token or None
    except Exception as exc:
        logger.error("vdi_cost: graph token error — %s", exc)
        return None


def _get_manager(user_id: str, token: str) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"{GRAPH_BASE}/users/{user_id}/manager?$select={_MGR_SELECT}",
                         headers=headers, verify=False, timeout=10)
        if r.status_code == 200:
            return r.json()
        if r.status_code != 404:
            logger.debug("vdi_cost: manager %s → HTTP %s", user_id, r.status_code)
    except Exception as exc:
        logger.debug("vdi_cost: manager %s error — %s", user_id, exc)
    return {}


def _lookup_upn(upn: str, token: str) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(f"{GRAPH_BASE}/users/{requests.utils.quote(upn)}?$select={_USER_SELECT}",
                         headers=headers, verify=False, timeout=10)
        if r.status_code == 200:
            return r.json()
        logger.debug("vdi_cost: UPN '%s' → HTTP %s", upn, r.status_code)
    except Exception as exc:
        logger.debug("vdi_cost: UPN '%s' error — %s", upn, exc)
    return {}


def _lookup_sam(sam: str, token: str) -> dict:
    headers = {"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"}
    safe = sam.replace("'", "''")
    try:
        r = requests.get(
            f"{GRAPH_BASE}/users?$filter=onPremisesSamAccountName eq '{safe}'"
            f"&$select={_USER_SELECT}&$count=true",
            headers=headers, verify=False, timeout=10,
        )
        if r.status_code == 200:
            users = r.json().get("value", [])
            if users:
                return users[0]
            logger.debug("vdi_cost: SAM '%s' — no Entra match", sam)
        else:
            logger.debug("vdi_cost: SAM '%s' → HTTP %s", sam, r.status_code)
    except Exception as exc:
        logger.debug("vdi_cost: SAM '%s' error — %s", sam, exc)
    return {}


def _resolve_user(identifier: str, token: str) -> dict:
    """Resolve identifier → Entra profile + manager."""
    user: dict = {}
    if "@" in identifier:
        user = _lookup_upn(identifier, token)
    else:
        default_domain = os.getenv("ENTRA_DEFAULT_DOMAIN", "").strip()
        if default_domain:
            user = _lookup_upn(f"{identifier}@{default_domain}", token)
        if not user:
            user = _lookup_sam(identifier, token)
    if not user:
        return {}
    user_id = user.get("id", "")
    if user_id:
        mgr = _get_manager(user_id, token)
        if mgr:
            user["manager"] = mgr
    return user


# ─── Cleanup analysis ─────────────────────────────────────────────────────────

def _build_cleanup_report(rows: list[dict], cost_per_machine: float) -> dict:
    categories: dict[str, dict] = {
        "disabled_user": {
            "label": "Assigned to Disabled Account", "severity": "critical", "icon": "🔴",
            "action": "Unassign the machine and return it to the available pool. The user can no longer log in.",
            "machines": [],
        },
        "orphaned_on": {
            "label": "Unassigned & Powered On", "severity": "critical", "icon": "🔴",
            "action": "Power off or assign to a user. Machine is running with no one using it.",
            "machines": [],
        },
        "unregistered_on": {
            "label": "Assigned but Unregistered", "severity": "warning", "icon": "🟠",
            "action": "VDA agent is not communicating with Citrix Cloud. User cannot connect. Check VDA service.",
            "machines": [],
        },
        "stale_90d": {
            "label": "No Login in 90+ Days", "severity": "warning", "icon": "🟡",
            "action": "Contact the assigned user. Strong candidate for reclaim.",
            "machines": [],
        },
        "stale_60d": {
            "label": "No Login in 60–89 Days", "severity": "warning", "icon": "🟡",
            "action": "Reach out to the user to confirm they still need the VDI.",
            "machines": [],
        },
        "stale_30d": {
            "label": "No Login in 30–59 Days", "severity": "info", "icon": "🔵",
            "action": "Monitor. Low usage may indicate the user prefers other devices.",
            "machines": [],
        },
        "unassigned_off": {
            "label": "Unassigned & Powered Off", "severity": "info", "icon": "⚪",
            "action": "Idle pool machines — likely intentional spare capacity. Review if over-provisioned.",
            "machines": [],
        },
    }

    for row in rows:
        assigned     = bool(row.get("assignedUpn"))
        user_enabled = row.get("userEnabled")
        reg_state    = (row.get("registrationState") or "").lower()
        power_state  = (row.get("powerState") or "").lower()
        days         = row.get("daysSinceConnection")
        powered_on   = power_state in ("on", "poweredon", "1")

        item = {
            "machine":           row["machine"],
            "userDisplay":       row.get("userDisplay") or row.get("assignedUpn") or "—",
            "assignedUpn":       row.get("assignedUpn") or "",
            "managerName":       row.get("managerName") or "—",
            "department":        row.get("department") or "—",
            "registrationState": row.get("registrationState") or "—",
            "powerState":        row.get("powerState") or "—",
            "daysSinceConnection": days,
            "lastConnection":    row.get("lastConnectionTime") or "—",
            "monthlyCost":       cost_per_machine,
        }

        if assigned and user_enabled is False:
            categories["disabled_user"]["machines"].append(item)
        elif not assigned and powered_on:
            categories["orphaned_on"]["machines"].append(item)
        elif assigned and reg_state == "unregistered":
            categories["unregistered_on"]["machines"].append(item)
        elif assigned and days is not None and days >= 90:
            categories["stale_90d"]["machines"].append(item)
        elif assigned and days is not None and days >= 60:
            categories["stale_60d"]["machines"].append(item)
        elif assigned and days is not None and days >= 30:
            categories["stale_30d"]["machines"].append(item)
        elif not assigned and not powered_on:
            categories["unassigned_off"]["machines"].append(item)

    critical_count = len(categories["disabled_user"]["machines"]) + len(categories["orphaned_on"]["machines"])
    warning_count  = (len(categories["unregistered_on"]["machines"]) +
                      len(categories["stale_90d"]["machines"]) +
                      len(categories["stale_60d"]["machines"]))

    return {
        "categories":        categories,
        "critical_count":    critical_count,
        "warning_count":     warning_count,
        "info_count":        len(categories["stale_30d"]["machines"]) + len(categories["unassigned_off"]["machines"]),
        "potential_savings": round(critical_count * cost_per_machine, 2),
    }


# ─── Main report builder ──────────────────────────────────────────────────────

def get_vdi_cost_report(force_refresh: bool = False, cost_per_machine: float = 35.0) -> dict:
    from routers.citrix import get_citrix_machines, get_citrix_sessions
    from routers.cache  import cache

    cache_key = f"vdi_cost_report_{int(cost_per_machine * 100)}"
    if not force_refresh:
        cached, _ = cache.get(cache_key)
        if cached:
            return cached

    # ── 1. Fetch Citrix data ──────────────────────────────────────────────────
    machines_raw, _ = get_citrix_machines(force_refresh=False)
    sessions_raw, _ = get_citrix_sessions(force_refresh=False)
    all_machines = machines_raw or []
    sessions     = sessions_raw or []

    # ── 2. Filter to VDI / single-session only ────────────────────────────────
    vdi_dgs  = _build_vdi_dg_set()
    machines = [m for m in all_machines if _is_vdi_machine(m, vdi_dgs)]
    logger.info("vdi_cost: %d total → %d VDI (%d XenApp excluded)",
                len(all_machines), len(machines), len(all_machines) - len(machines))

    # ── 3. Build user identity sources ───────────────────────────────────────
    # Primary: Citrix API AssignedUsers (permanent, works when machine is off)
    citrix_assigned = _get_citrix_assigned_users_map()

    # Secondary: active session map (for pooled desktops or when API fails)
    vdi_names = {(m.get("name") or "").upper() for m in machines}
    session_map: dict[str, str] = {}
    for s in sessions:
        mname = (s.get("machine_name") or "").upper()
        if mname not in vdi_names:
            continue
        uname = s.get("user_name") or s.get("user_display") or ""
        if mname and uname and mname not in session_map:
            session_map[mname] = uname

    logger.info("vdi_cost: %d assigned from Citrix API, %d from active sessions",
                len(citrix_assigned), len(session_map))

    # ── 4. Graph token ────────────────────────────────────────────────────────
    token = _get_graph_token()
    if not token:
        logger.warning("vdi_cost: no Graph token — Entra lookups skipped")

    # ── 5. Enrich each VDI machine ────────────────────────────────────────────
    rows: list[dict] = []
    entra_cache: dict[str, dict] = {}

    for m in machines:
        name = (m.get("name") or "").strip()
        if not name:
            continue

        catalog     = m.get("catalog_name")        or ""
        dg          = m.get("delivery_group_name") or ""
        reg_state   = m.get("registration_state")  or ""
        power_state = m.get("power_state")         or ""
        zone        = m.get("zone")                or ""
        os_type     = m.get("os_type")             or ""
        agent_ver   = m.get("agent_version")       or ""
        last_conn   = m.get("last_connection_time") or ""
        days_conn   = _days_since(last_conn)

        # ── Resolve user identifier (3-tier) ──────────────────────────────────
        # Tier 1: Citrix API AssignedUsers (permanent assignment)
        identifier = citrix_assigned.get(name.upper(), "")

        # Tier 2: machine's own assigned_users field (from citrix.py cache)
        if not identifier:
            for u in (m.get("assigned_users") or []):
                candidate = (u.get("principal_name") or u.get("sam_account_name") or u.get("name") or "")
                if candidate:
                    identifier = candidate
                    break

        # Tier 3: active session map
        if not identifier:
            identifier = session_map.get(name.upper(), "")

        # ── Entra lookup ──────────────────────────────────────────────────────
        user_display = ""
        user_dept    = ""
        user_title   = ""
        mgr_name     = ""
        mgr_upn      = ""
        user_enabled = None
        resolved_upn = ""

        if identifier and token:
            if identifier not in entra_cache:
                entra_cache[identifier] = _resolve_user(identifier, token)
            info = entra_cache[identifier]
            if info:
                resolved_upn = info.get("userPrincipalName", "") or identifier
                user_display = info.get("displayName",  "")
                user_dept    = info.get("department",   "") or ""
                user_title   = info.get("jobTitle",     "") or ""
                user_enabled = info.get("accountEnabled")
                mgr          = info.get("manager") or {}
                mgr_name     = mgr.get("displayName",       "")
                mgr_upn      = mgr.get("userPrincipalName", "")

        rows.append({
            "machine":             name,
            "catalog":             catalog,
            "deliveryGroup":       dg,
            "zone":                zone,
            "osType":              os_type,
            "agentVersion":        agent_ver,
            "registrationState":   reg_state,
            "powerState":          power_state,
            "lastConnectionTime":  last_conn,
            "daysSinceConnection": days_conn,
            "assignedUpn":         resolved_upn or identifier,
            "userDisplay":         user_display or identifier,
            "department":          user_dept,
            "jobTitle":            user_title,
            "userEnabled":         user_enabled,
            "managerName":         mgr_name,
            "managerUpn":          mgr_upn,
            "monthlyCost":         cost_per_machine,
        })

    assigned     = sum(1 for r in rows if r["assignedUpn"])
    with_manager = sum(1 for r in rows if r["managerName"])
    logger.info("vdi_cost: %d VDI rows — %d assigned, %d with manager, %d Entra lookups",
                len(rows), assigned, with_manager, len(entra_cache))

    # ── 6. Aggregations ───────────────────────────────────────────────────────
    by_manager:    dict[str, dict] = {}
    by_department: dict[str, dict] = {}

    for row in rows:
        mk = row["managerUpn"] or "__unassigned__"
        if mk not in by_manager:
            by_manager[mk] = {
                "managerName": row["managerName"] or ("Unassigned" if mk == "__unassigned__" else mk),
                "managerUpn":  row["managerUpn"],
                "machines":    [],
                "total":       0.0,
            }
        by_manager[mk]["machines"].append(row)
        by_manager[mk]["total"] = round(by_manager[mk]["total"] + row["monthlyCost"], 2)

        dk = row["department"] or "Unknown"
        if dk not in by_department:
            by_department[dk] = {"department": dk, "machines": [], "total": 0.0}
        by_department[dk]["machines"].append(row)
        by_department[dk]["total"] = round(by_department[dk]["total"] + row["monthlyCost"], 2)

    # ── 7. Cleanup report ─────────────────────────────────────────────────────
    cleanup = _build_cleanup_report(rows, cost_per_machine)

    grand_total = round(len(rows) * cost_per_machine, 2)
    result = {
        "machines":      rows,
        "by_manager":    by_manager,
        "by_department": by_department,
        "cleanup":       cleanup,
        "summary": {
            "total_machines":    len(rows),
            "assigned":          assigned,
            "unassigned":        len(rows) - assigned,
            "grand_total":       grand_total,
            "cost_per_machine":  cost_per_machine,
            "cleanup_critical":  cleanup["critical_count"],
            "cleanup_warning":   cleanup["warning_count"],
            "potential_savings": cleanup["potential_savings"],
        },
    }

    cache.set(cache_key, result)
    return result