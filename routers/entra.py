"""
routers/entra.py — Microsoft Entra ID / Microsoft 365 via Graph API.

Covers: Licenses, Users, Groups, Enterprise App credentials,
        Mailbox usage, Risky users, Conditional Access policies.

Required Azure App Registration permissions (Application, admin-consented):
    Application.Read.All
    Organization.Read.All
    AuditLog.Read.All          (for signInActivity on users)
    Reports.Read.All           (for mailbox usage reports)
    IdentityRiskyUser.Read.All (requires AAD P2 — graceful fail if missing)
    Policy.Read.All            (for Conditional Access — graceful fail)
"""
import csv
import io
import logging
import os
import time
from datetime import datetime, timezone

import httpx

logger = logging.getLogger(__name__)

GRAPH = "https://graph.microsoft.com/v1.0"

# ── Common M365 SKU part-number → friendly name ──────────────────────────────
SKU_NAMES = {
    "ENTERPRISEPREMIUM":   "Office 365 E5",
    "ENTERPRISEPACK":      "Office 365 E3",
    "SPE_E3":              "Microsoft 365 E3",
    "SPE_E5":              "Microsoft 365 E5",
    "SPE_F1":              "Microsoft 365 F1",
    "SPE_F3":              "Microsoft 365 F3",
    "DEVELOPERPACK_E5":    "M365 E5 Developer",
    "EMS":                 "EMS E3",
    "EMSPREMIUM":          "EMS E5",
    "AAD_PREMIUM":         "Azure AD Premium P1",
    "AAD_PREMIUM_P2":      "Azure AD Premium P2",
    "INTUNE_A":            "Intune",
    "POWER_BI_STANDARD":   "Power BI Free",
    "POWER_BI_PRO":        "Power BI Pro",
    "EXCHANGESTANDARD":    "Exchange Online P1",
    "EXCHANGEENTERPRISE":  "Exchange Online P2",
    "PROJECTPREMIUM":      "Project Plan 5",
    "VISIOCLIENT":         "Visio Plan 2",
    "MCOSTANDARD":         "Skype for Business Online",
    "FLOW_FREE":           "Power Automate Free",
    "TEAMS_EXPLORATORY":   "Teams Exploratory",
    "DEFENDER_ENDPOINT_P1":"Defender for Endpoint P1",
}

_TOKEN_CACHE: dict = {"token": None, "expires": 0}


# ── Auth ──────────────────────────────────────────────────────────────────────

def _get_app_token() -> str:
    """Client-credentials token for Graph API (app-level permissions)."""
    if _TOKEN_CACHE["token"] and time.time() < _TOKEN_CACHE["expires"] - 60:
        return _TOKEN_CACHE["token"]
    tenant = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    secret = os.getenv("AZURE_CLIENT_SECRET")
    resp = httpx.post(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
            "scope": "https://graph.microsoft.com/.default",
        },
        verify=False, timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    _TOKEN_CACHE["token"] = data["access_token"]
    _TOKEN_CACHE["expires"] = time.time() + data.get("expires_in", 3600)
    return _TOKEN_CACHE["token"]


def _graph(url: str, token: str, params: dict = None) -> list | dict:
    """Paginated Graph GET. Returns list when response has @odata.value."""
    headers = {
        "Authorization": f"Bearer {token}",
        "ConsistencyLevel": "eventual",
    }
    items = []
    next_url = url
    while next_url:
        resp = httpx.get(next_url, headers=headers, params=params,
                         verify=False, timeout=60)
        if resp.status_code == 403:
            logger.warning("Graph 403 on %s — missing permission", url)
            return []
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
        params = None
        if "value" in data:
            items.extend(data["value"])
            next_url = data.get("@odata.nextLink")
        else:
            return data
    return items


# ── Licenses ──────────────────────────────────────────────────────────────────

def fetch_licenses() -> list:
    try:
        token = _get_app_token()
        skus = _graph(f"{GRAPH}/subscribedSkus", token)
        results = []
        for sku in (skus if isinstance(skus, list) else []):
            part = sku.get("skuPartNumber") or ""
            name = SKU_NAMES.get(part, part.replace("_", " ").title())
            units = sku.get("prepaidUnits") or {}
            total    = units.get("enabled", 0)
            consumed = sku.get("consumedUnits", 0)
            suspended = units.get("suspended", 0)
            warning  = units.get("warning", 0)
            available = max(0, total - consumed)
            pct = round(consumed / total * 100, 1) if total > 0 else 0
            results.append({
                "sku_id":    sku.get("skuId"),
                "sku_part":  part,
                "name":      name,
                "total":     total,
                "consumed":  consumed,
                "available": available,
                "suspended": suspended,
                "warning_units": warning,
                "pct_used":  pct,
                "status":    sku.get("capabilityStatus") or "Unknown",
            })
        results.sort(key=lambda x: -x["consumed"])
        return results
    except Exception as e:
        logger.error("entra fetch_licenses: %s", e)
        return []


# ── Users ─────────────────────────────────────────────────────────────────────

def fetch_users() -> dict:
    try:
        token = _get_app_token()
        raw = _graph(f"{GRAPH}/users", token, params={
            "$select": "id,displayName,userPrincipalName,accountEnabled,"
                       "userType,signInActivity,assignedLicenses,createdDateTime,mail",
            "$top": "999",
            "$count": "true",
        })
        now = datetime.now(timezone.utc)
        users = []
        stats = {
            "total": 0, "enabled": 0, "disabled": 0,
            "guests": 0, "stale_90d": 0, "no_license": 0,
        }
        for u in (raw if isinstance(raw, list) else []):
            stats["total"] += 1
            enabled   = u.get("accountEnabled", False)
            utype     = u.get("userType") or "Member"
            upn       = u.get("userPrincipalName") or ""
            licenses  = u.get("assignedLicenses") or []
            if enabled: stats["enabled"] += 1
            else:       stats["disabled"] += 1
            if utype == "Guest": stats["guests"] += 1
            if not licenses and enabled and utype != "Guest":
                stats["no_license"] += 1

            last_signin = None
            days_idle   = None
            sia = u.get("signInActivity") or {}
            lsdt = sia.get("lastSignInDateTime") or sia.get("lastNonInteractiveSignInDateTime")
            if lsdt:
                try:
                    ls = datetime.fromisoformat(lsdt.replace("Z", "+00:00"))
                    days_idle = (now - ls).days
                    if days_idle > 90 and enabled and utype != "Guest":
                        stats["stale_90d"] += 1
                    last_signin = lsdt[:10]
                except Exception:
                    pass

            users.append({
                "id":          u.get("id"),
                "name":        u.get("displayName") or upn,
                "upn":         upn,
                "enabled":     enabled,
                "user_type":   utype,
                "license_count": len(licenses),
                "last_signin": last_signin,
                "days_idle":   days_idle,
                "created":     (u.get("createdDateTime") or "")[:10],
            })
        users.sort(key=lambda x: (x["days_idle"] is None, -(x["days_idle"] or 0)))
        return {"users": users, "stats": stats, "fetched_at": int(time.time())}
    except Exception as e:
        logger.error("entra fetch_users: %s", e)
        return {"users": [], "stats": {}, "error": str(e)}


# ── Groups ────────────────────────────────────────────────────────────────────

def fetch_groups() -> dict:
    try:
        token = _get_app_token()
        raw = _graph(f"{GRAPH}/groups", token, params={
            "$select": "id,displayName,groupTypes,securityEnabled,mailEnabled,"
                       "membershipRule,createdDateTime",
            "$top": "999",
        })
        stats = {"total": 0, "m365": 0, "security": 0, "distribution": 0, "dynamic": 0}
        groups = []
        for g in (raw if isinstance(raw, list) else []):
            stats["total"] += 1
            types  = g.get("groupTypes") or []
            is_m365 = "Unified" in types
            is_dyn  = "DynamicMembership" in types
            is_sec  = g.get("securityEnabled") and not is_m365
            is_dist = g.get("mailEnabled") and not is_m365 and not is_sec
            if is_m365: stats["m365"] += 1
            if is_sec:  stats["security"] += 1
            if is_dist: stats["distribution"] += 1
            if is_dyn:  stats["dynamic"] += 1
            gtype = "M365" if is_m365 else ("Security" if is_sec else ("Distribution" if is_dist else "Other"))
            groups.append({
                "id":      g.get("id"),
                "name":    g.get("displayName") or "",
                "type":    gtype,
                "dynamic": is_dyn,
                "created": (g.get("createdDateTime") or "")[:10],
            })
        groups.sort(key=lambda x: x["name"].lower())
        return {"groups": groups, "stats": stats, "fetched_at": int(time.time())}
    except Exception as e:
        logger.error("entra fetch_groups: %s", e)
        return {"groups": [], "stats": {}, "error": str(e)}


# ── Enterprise App / App Registration credentials ─────────────────────────────

def fetch_apps() -> dict:
    try:
        token = _get_app_token()
        raw = _graph(f"{GRAPH}/applications", token, params={
            "$select": "id,displayName,appId,createdDateTime,"
                       "passwordCredentials,keyCredentials,signInAudience",
            "$top": "999",
        })
        now = datetime.now(timezone.utc)
        apps = []
        stats = {
            "total": 0, "creds_expired": 0,
            "creds_expiring_30": 0, "creds_expiring_90": 0, "no_creds": 0,
        }
        for app in (raw if isinstance(raw, list) else []):
            stats["total"] += 1
            creds = []
            for c in (app.get("passwordCredentials") or []):
                end = c.get("endDateTime")
                if end:
                    try:
                        exp = datetime.fromisoformat(end.replace("Z", "+00:00"))
                        days = (exp - now).days
                        creds.append({
                            "type": "secret",
                            "hint": c.get("displayName") or c.get("hint") or "Secret",
                            "expires": end[:10], "days": days,
                        })
                    except Exception:
                        pass
            for c in (app.get("keyCredentials") or []):
                end = c.get("endDateTime")
                if end:
                    try:
                        exp = datetime.fromisoformat(end.replace("Z", "+00:00"))
                        days = (exp - now).days
                        creds.append({
                            "type": "cert",
                            "hint": c.get("displayName") or "Certificate",
                            "expires": end[:10], "days": days,
                        })
                    except Exception:
                        pass

            worst = min((c["days"] for c in creds), default=None)
            if not creds:           stats["no_creds"] += 1
            elif worst is not None:
                if worst < 0:        stats["creds_expired"] += 1
                elif worst <= 30:    stats["creds_expiring_30"] += 1
                elif worst <= 90:    stats["creds_expiring_90"] += 1

            apps.append({
                "id":         app.get("id"),
                "name":       app.get("displayName") or "",
                "app_id":     app.get("appId"),
                "created":    (app.get("createdDateTime") or "")[:10],
                "audience":   app.get("signInAudience") or "",
                "creds":      creds,
                "worst_days": worst,
                "cred_count": len(creds),
            })
        apps.sort(key=lambda x: (x["worst_days"] is None, x["worst_days"] or 9999))
        return {"apps": apps, "stats": stats, "fetched_at": int(time.time())}
    except Exception as e:
        logger.error("entra fetch_apps: %s", e)
        return {"apps": [], "stats": {}, "error": str(e)}


# ── Mailbox usage ─────────────────────────────────────────────────────────────

def fetch_mailbox_usage() -> dict:
    try:
        token = _get_app_token()
        resp = httpx.get(
            f"{GRAPH}/reports/getMailboxUsageDetail(period='D30')",
            headers={"Authorization": f"Bearer {token}"},
            verify=False, timeout=60, follow_redirects=True,
        )
        if resp.status_code == 403:
            return {"mailboxes": [], "stats": {}, "error": "Reports.Read.All permission required"}
        resp.raise_for_status()

        reader = csv.DictReader(io.StringIO(resp.content.decode("utf-8-sig")))
        mailboxes = []
        stats = {"total": 0, "over_90pct": 0, "over_75pct": 0, "inactive_30d": 0}

        for row in reader:
            if row.get("Is Deleted", "False") == "True":
                continue
            stats["total"] += 1
            try:
                used_b   = float(row.get("Storage Used (Byte)") or 0)
                quota_b  = float(row.get("Prohibit Send Quota (Byte)") or 0)
                used_gb  = round(used_b  / (1024**3), 2)
                quota_gb = round(quota_b / (1024**3), 1)
                pct = round(used_gb / quota_gb * 100, 1) if quota_gb > 0 else 0
                last_act = row.get("Last Activity Date") or ""
                days_inactive = None
                if last_act:
                    try:
                        la = datetime.fromisoformat(last_act)
                        days_inactive = (datetime.now() - la).days
                        if days_inactive > 30: stats["inactive_30d"] += 1
                    except Exception:
                        pass
                if pct >= 90:   stats["over_90pct"] += 1
                elif pct >= 75: stats["over_75pct"] += 1
                mailboxes.append({
                    "upn":           row.get("User Principal Name") or "",
                    "name":          row.get("Display Name") or "",
                    "used_gb":       used_gb,
                    "quota_gb":      quota_gb,
                    "pct_used":      pct,
                    "item_count":    int(row.get("Item Count") or 0),
                    "last_activity": last_act,
                    "days_inactive": days_inactive,
                })
            except Exception:
                continue

        mailboxes.sort(key=lambda x: -x["pct_used"])
        return {"mailboxes": mailboxes, "stats": stats, "fetched_at": int(time.time())}
    except Exception as e:
        logger.error("entra fetch_mailbox: %s", e)
        return {"mailboxes": [], "stats": {}, "error": str(e)}


# ── Risky users (AAD P2 required) ────────────────────────────────────────────

def fetch_risky_users() -> list:
    try:
        token = _get_app_token()
        users = _graph(
            f"{GRAPH}/identityProtection/riskyUsers",
            token,
            params={"$filter": "riskState ne 'dismissed' and riskState ne 'remediated'", "$top": "50"},
        )
        return users if isinstance(users, list) else []
    except Exception as e:
        logger.warning("entra risky_users (P2 feature, may be unavailable): %s", e)
        return []


# ── Conditional Access policies ───────────────────────────────────────────────

def fetch_ca_policies() -> list:
    try:
        token = _get_app_token()
        raw = _graph(f"{GRAPH}/identity/conditionalAccess/policies", token)
        return [
            {
                "id":       p.get("id"),
                "name":     p.get("displayName") or "",
                "state":    p.get("state") or "unknown",
                "created":  (p.get("createdDateTime") or "")[:10],
                "modified": (p.get("modifiedDateTime") or "")[:10],
            }
            for p in (raw if isinstance(raw, list) else [])
        ]
    except Exception as e:
        logger.warning("entra ca_policies (needs Policy.Read.All): %s", e)
        return []


# ── Scheduler entry point ─────────────────────────────────────────────────────

def refresh_all() -> dict:
    """Refresh all Entra data into cache. Called every hour by scheduler."""
    from routers.cache import cache
    results = {}
    for name, fn, key in [
        ("licenses",   fetch_licenses,      "entra_licenses"),
        ("users",      fetch_users,         "entra_users"),
        ("groups",     fetch_groups,        "entra_groups"),
        ("apps",       fetch_apps,          "entra_apps"),
        ("mailbox",    fetch_mailbox_usage, "entra_mailbox"),
        ("risky",      fetch_risky_users,   "entra_risky"),
        ("ca_policies",fetch_ca_policies,   "entra_ca_policies"),
    ]:
        try:
            data = fn()
            cache.set(key, data)
            cnt = len(data) if isinstance(data, list) else data.get("stats", {}).get("total", "?")
            results[name] = cnt
        except Exception as e:
            logger.error("entra refresh %s: %s", name, e)
            results[name] = f"error: {e}"
    logger.info("Entra refresh complete: %s", results)
    return results
