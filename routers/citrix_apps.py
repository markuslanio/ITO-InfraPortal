"""
routers/citrix_apps.py
Citrix published app management — clone, test-access assignment, security cutover.
Drop this file into routers/ alongside citrix.py.
"""

import json
import logging
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime

import requests
import urllib3

from routers.citrix import get_session, API_BASE

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


# ── Application API helpers ───────────────────────────────────────────────────

def _app_summary(app: dict) -> dict:
    """Normalize a raw application object from the Citrix DaaS API."""
    # Collect DG associations from all possible field names the API might use
    dg_uuids   = app.get("AssociatedDeliveryGroupUuids") or []
    dg_objects = app.get("DeliveryGroups") or app.get("AssociatedDeliveryGroups") or []
    # Normalise to lowercase for reliable UUID comparison
    dg_ids_lower = {str(uid).lower() for uid in dg_uuids}
    for d in dg_objects:
        uid = d.get("Id") or d.get("id") or d.get("Uid") or ""
        if uid:
            dg_ids_lower.add(str(uid).lower())

    def _f(v):
        if isinstance(v, dict): return (v.get("Name") or v.get("name") or "").lstrip("/")
        return (v or "").lstrip("/")
    folder = _f(app.get("ApplicationFolder")) or _f(app.get("ClientFolder"))
    # Paths are nested inside InstalledAppProperties
    installed = app.get("InstalledAppProperties") or {}

    return {
        "id":                   app.get("Id") or app.get("Uid") or "",
        "name":                 app.get("Name") or "",
        "published_name":       app.get("PublishedName") or app.get("Name") or "",
        "description":          app.get("Description") or "",
        "folder":               folder,
        "command_line":         _f(installed.get("CommandLineExecutable") or app.get("CommandLineExecutable")),
        "command_line_args":    _f(installed.get("CommandLineArguments")  or app.get("CommandLineArguments")),
        "working_directory":    _f(installed.get("WorkingDirectory")      or app.get("WorkingDirectory")),
        "enabled":              app.get("Enabled", True),
        "visible":              app.get("Visible", True),
        "delivery_group_ids":   list(dg_ids_lower),
        "delivery_groups":      [{"id": d.get("Id") or d.get("id"), "name": d.get("Name") or d.get("name")} for d in dg_objects],
        "included_users":       app.get("IncludedUsers") or [],
        "excluded_users":       app.get("ExcludedUsers") or [],
        "user_filter_enabled":  app.get("IncludedUserFilterEnabled", False),
        "icon_id":              app.get("IconId") or app.get("AssociatedIconUid"),
        "tags":                 app.get("Tags") or [],
    }


def get_applications_for_dg(dg_id: str) -> list[dict]:
    """
    Fetch all published applications for a delivery group.
    The Citrix Cloud API does not reliably filter by deliveryGroupId as a query
    parameter, so we try the dedicated sub-resource first, then fall back to a
    full fetch with client-side filtering by DG association.
    """
    session = get_session()

    # Attempt 1: dedicated sub-resource endpoint
    try:
        url   = f"{API_BASE}/DeliveryGroups/{dg_id}/Applications"
        items: list = []
        continuation = None
        while True:
            params: dict = {"limit": 250}
            if continuation:
                params["continuationToken"] = continuation
            r = session.get(url, params=params, timeout=30)
            if r.status_code == 404:
                raise ValueError("sub-resource not supported")
            r.raise_for_status()
            data = r.json()
            items.extend(data.get("Items", []))
            continuation = data.get("ContinuationToken")
            if not continuation:
                break
        return [_app_summary(a) for a in items]
    except Exception:
        pass

    # Attempt 2: fetch all apps, filter client-side by DG association
    url   = f"{API_BASE}/Applications"
    items = []
    continuation = None
    while True:
        params = {"limit": 250}
        if continuation:
            params["continuationToken"] = continuation
        r = session.get(url, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
        items.extend(data.get("Items", []))
        continuation = data.get("ContinuationToken")
        if not continuation:
            break

    all_apps = [_app_summary(a) for a in items]

    # Normalise the requested DG id for comparison
    dg_id_lower = dg_id.lower()

    # Filter: delivery_group_ids are already lowercase-normalised in _app_summary
    filtered = [
        a for a in all_apps
        if dg_id_lower in (a.get("delivery_group_ids") or [])
    ]

    if filtered:
        return filtered

    # If filter returns nothing, the API is not populating DG associations on
    # Application objects. Fall back to folder-prefix heuristic: fetch the DG
    # name and keep only apps whose folder starts with it.
    try:
        r = session.get(f"{API_BASE}/DeliveryGroups/{dg_id}", timeout=15)
        if r.ok:
            dg_name = (r.json().get("Name") or "").strip()
            if dg_name:
                folder_filtered = [
                    a for a in all_apps
                    if (a.get("folder") or "").lower().startswith(dg_name.lower())
                ]
                if folder_filtered:
                    return folder_filtered
    except Exception:
        pass

    # Last resort: return all apps but tag them with a warning flag so the
    # caller / UI knows filtering did not work
    for a in all_apps:
        a["_filter_unavailable"] = True
    return all_apps


def get_application_detail(app_id: str) -> dict:
    """Fetch full detail for a single application, including current user assignments."""
    session = get_session()
    r = session.get(f"{API_BASE}/Applications/{app_id}", timeout=15)
    r.raise_for_status()
    return _app_summary(r.json())


def create_application_via_powershell(
    name: str,
    published_name: str,
    command_line: str,
    working_directory: str,
    desktop_group_name: str,
    client_id: str,
    client_secret: str,
    customer_id: str,
    enabled: bool = True,
    cmd_args: str = "",
    folder: str = "",
    icon_uid: str | int | None = None,
) -> dict:
    """
    Create a Citrix published app via the PowerShell Broker SDK.
    Bypasses the REST API entirely — uses New-BrokerApplication which is
    confirmed working via the Citrix DaaS Remote PowerShell SDK.

    Folder handling — Citrix has two separate folder concepts:
      - ClientFolder (Folder for users): what appears in the user's Workspace.
        Set via Set-BrokerApplication -ClientFolder.
      - Admin folder (Folder for administrators): the tree position in Web Studio.
        Set via New-BrokerApplicationFolder + Move-BrokerApplication.
    Both are set to the same `folder` value so Studio and Workspace stay in sync.
    """
    import subprocess
    import json as _json

    def _esc(s: str) -> str:
        """Escape for PowerShell double-quoted strings. Doubles backslashes for
        file system paths like CommandLineExecutable and WorkingDirectory."""
        return (s
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("`", "``")
            .replace("$", "`$"))

    def _esc_folder(s: str) -> str:
        """Escape for PowerShell double-quoted strings for Citrix folder paths.
        Does NOT double backslashes — PowerShell double-quoted strings pass
        backslashes through literally.  Strips trailing backslashes because a
        path ending in backslash causes PowerShell to treat the closing quote
        as \\\" (escaped quote), silently breaking the assignment."""
        s = s.rstrip("\\")
        return (s
            .replace('"', '\\"')
            .replace("`", "``")
            .replace("$", "`$"))


    # Pre-compute folder values used in the script below
    if folder:
        clean_folder   = folder.rstrip('\\')
        escaped_folder = _esc_folder(clean_folder)
        logger.info(f"Folder PS — raw='{folder}' clean='{clean_folder}' escaped='{escaped_folder}'")
    else:
        clean_folder   = ""
        escaped_folder = ""

    # Build script as a list of lines then join with newline
    parts = [
        '[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}',
        '[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12',
        r'Import-Module "C:\Program Files\Citrix\CloudPowerShellModules\Citrix.PoshSdkProxy.Commands\Citrix.PoshSdkProxy.Commands.psm1" -ErrorAction Stop',
        r'Import-Module "C:\Program Files\Citrix\CloudPowerShellModules\Citrix.Broker.Commands\Citrix.Broker.Commands.psm1" -ErrorAction Stop',
        f'Set-XDCredentials -CustomerId "{_esc(customer_id)}" -ApiKey "{_esc(client_id)}" -SecretKey "{_esc(client_secret)}" -ProfileType CloudAPI',
        f'$app = New-BrokerApplication `',
        f'    -Name "{_esc(name)}" `',
        f'    -PublishedName "{_esc(published_name)}" `',
        f'    -ApplicationType "HostedOnDesktop" `',
        f'    -CommandLineExecutable "{_esc(command_line)}" `',
        f'    -DesktopGroup "{_esc(desktop_group_name)}" `',
        f'    -Enabled ${str(enabled).lower()}',
    ]
    if cmd_args:
        parts.append(f'Set-BrokerApplication -InputObject $app -CommandLineArguments "{_esc(cmd_args)}"')
    if working_directory:
        parts.append(f'Set-BrokerApplication -InputObject $app -WorkingDirectory "{_esc(working_directory)}"')
    if folder:
        # ClientFolder = user-facing folder in Workspace / receiver.
        # Admin folder is set via REST PATCH in create_application() after this
        # returns, since New-BrokerApplicationFolder is not available in this SDK.
        parts.append(f'Set-BrokerApplication -InputObject $app -ClientFolder "{escaped_folder}"')
    if icon_uid:
        parts.append(f'Set-BrokerApplication -InputObject $app -IconUid {int(icon_uid)}')
    parts.append('$app | Select-Object Name,UUID,Uid | ConvertTo-Json')

    script = "\n".join(parts)
    # Log script with credentials redacted
    redacted = script.replace(client_secret, "***").replace(client_id, "***")
    logger.info(f"PowerShell script: {redacted}")

    # Write script to a temp file and invoke with -File to avoid IIS stdin-pipe hang.
    import tempfile, os as _os
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8')
    try:
        tmp.write(script)
        tmp.flush()
        tmp.close()
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", tmp.name],
            capture_output=True, text=True, timeout=90,
            stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    finally:
        try: _os.unlink(tmp.name)
        except Exception: pass

    logger.info(f"PS stdout: {result.stdout[:600]}")
    if result.returncode != 0 or result.stderr.strip():
        logger.error(f"PS stderr: {result.stderr[:400]}")

    stdout = result.stdout.strip()
    brace  = stdout.rfind("{")
    if brace >= 0:
        try:
            data = _json.loads(stdout[brace:])
            return {
                "Id":   str(data.get("UUID", "")),
                "Name": data.get("Name", name),
                "Uid":  data.get("Uid", 0),
            }
        except Exception as parse_err:
            logger.error(f"PS JSON parse failed: {parse_err} | {stdout}")

    raise Exception(f"PowerShell create failed. stdout={stdout[:300]} stderr={result.stderr[:300]}")


def create_application(payload: dict, target_dg_id: str | None = None) -> dict:
    """
    Create a new published app using the PowerShell Broker SDK.
    """
    dg_id     = target_dg_id or payload.pop("_target_dg_id", None)
    name      = payload.get("Name", "")
    installed = payload.get("InstalledAppProperties", {})

    # Resolve DG name from cached delivery groups or direct API call
    dg_name = ""
    try:
        from routers.cache import cache
        dg_data, _ = cache.get("citrix_delivery_groups")
        if dg_data:
            match = next((d for d in dg_data if d.get("id") == dg_id), None)
            if match:
                dg_name = match.get("name", "")
    except Exception:
        pass

    if not dg_name and dg_id:
        try:
            session = get_session()
            r = session.get(f"{API_BASE}/DeliveryGroups/{dg_id}", timeout=10)
            if r.ok:
                dg_name = r.json().get("Name", "")
        except Exception:
            pass

    if not dg_name:
        raise Exception(f"Could not resolve DG name for id {dg_id}")

    created = create_application_via_powershell(
        name               = name,
        published_name     = payload.get("PublishedName", name),
        command_line       = installed.get("CommandLineExecutable", ""),
        working_directory  = installed.get("WorkingDirectory", "") or "",
        cmd_args           = installed.get("CommandLineArguments", "") or "",
        desktop_group_name = dg_name,
        client_id          = os.getenv("CITRIX_CLIENT_ID", ""),
        client_secret      = os.getenv("CITRIX_CLIENT_SECRET", ""),
        customer_id        = os.getenv("CITRIX_CUSTOMER_ID", ""),
        enabled            = payload.get("Enabled", True),
        folder             = payload.get("ApplicationFolder", ""),
        icon_uid           = payload.get("IconUid"),
    )

    # ── Admin folder via REST PATCH ───────────────────────────────────────────
    # New-BrokerApplicationFolder does not exist in the DaaS Remote PowerShell
    # SDK, so folder creation and placement via PowerShell is not possible.
    # The REST API PATCH endpoint does support ApplicationFolder, so we use it
    # immediately after the app is created to set the admin tree position.
    admin_folder = payload.get("ApplicationFolder", "")
    app_uuid     = created.get("Id", "")
    if admin_folder and app_uuid:
        try:
            update_application(app_uuid, {"ApplicationFolder": admin_folder})
            logger.info(f"Admin folder set via REST PATCH — {app_uuid} → '{admin_folder}'")
        except Exception as e:
            logger.warning(f"Admin folder REST PATCH failed for {app_uuid}: {e} — app created but in root folder")

    return created


def update_application(app_id: str, patch: dict) -> dict:
    """PATCH /Applications/{id} — update properties such as IncludedUsers."""
    session = get_session()
    r = session.patch(
        f"{API_BASE}/Applications/{app_id}",
        json=patch,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    r.raise_for_status()
    # Citrix returns 204 No Content on success for some fields (e.g. ApplicationFolder).
    # r.json() raises on an empty body — return {} in that case.
    if not r.content:
        return {}
    return r.json()


# ── Entra / Graph search ──────────────────────────────────────────────────────
# Uses the InfraPortal app registration (already has GroupMember.Read.All)
# with client-credentials flow — no user token required.

_graph_token_cache: dict = {"token": None, "expires_at": 0}


def _get_graph_token() -> str:
    now = time.time()
    if _graph_token_cache["token"] and now < _graph_token_cache["expires_at"] - 60:
        return _graph_token_cache["token"]
    r = requests.post(
        f"https://login.microsoftonline.com/{os.getenv('AZURE_TENANT_ID', '')}/oauth2/v2.0/token",
        data={
            "grant_type":    "client_credentials",
            "client_id":     os.getenv("AZURE_CLIENT_ID", ""),
            "client_secret": os.getenv("AZURE_CLIENT_SECRET", ""),
            "scope":         "https://graph.microsoft.com/.default",
        },
        timeout=15,
        verify=False,
    )
    r.raise_for_status()
    data = r.json()
    _graph_token_cache["token"]      = data["access_token"]
    _graph_token_cache["expires_at"] = now + int(data.get("expires_in", 3600))
    return _graph_token_cache["token"]


def search_entra_principals(query: str) -> list[dict]:
    """
    Search Entra ID for groups and users matching `query`.
    Tries $search first (requires ConsistencyLevel: eventual), falls back to
    $filter startswith() which works without that header.
    Requires Group.Read.All and User.Read.All on the app registration.
    """
    if not query or len(query.strip()) < 2:
        return []
    try:
        token = _get_graph_token()
    except Exception as e:
        logger.error(f"Graph token failed: {e}")
        raise RuntimeError(f"Could not get Graph token: {e}")

    # $search requires ConsistencyLevel: eventual — but $orderby cannot be used with $search
    search_headers = {
        "Authorization":    f"Bearer {token}",
        "ConsistencyLevel": "eventual",
    }
    filter_headers = {"Authorization": f"Bearer {token}"}
    results: list[dict] = []
    q = query.strip()

    def _get(url, params, headers):
        r = requests.get(url, params=params, headers=headers,
                         timeout=15, verify=False)
        logger.debug(f"Graph {url} → {r.status_code}: {r.text[:300]}")
        return r

    # ── Groups ────────────────────────────────────────────────────────────────
    group_items = []
    try:
        # Attempt 1: $search (faster, partial match anywhere in name)
        r = _get(
            "https://graph.microsoft.com/v1.0/groups",
            {"$search": f'"displayName:{q}"', "$select": "id,displayName,mail,onPremisesSamAccountName", "$top": "10", "$count": "true"},
            search_headers,
        )
        if r.ok:
            group_items = r.json().get("value", [])
        else:
            # Attempt 2: $filter startswith (no ConsistencyLevel needed)
            r2 = _get(
                "https://graph.microsoft.com/v1.0/groups",
                {"$filter": f"startswith(displayName,'{q}')", "$select": "id,displayName,mail,onPremisesSamAccountName", "$top": "10"},
                filter_headers,
            )
            if r2.ok:
                group_items = r2.json().get("value", [])
            else:
                logger.warning(f"Group search failed: {r.status_code} {r.text[:200]}")
    except Exception as e:
        logger.warning(f"Entra group search error: {e}")

    for g in group_items:
        sam = g.get("onPremisesSamAccountName") or ""
        results.append({
            "type":   "group",
            "id":     g["id"],
            "name":   g["displayName"],
            "detail": g.get("mail") or (f"AD: {sam}" if sam else f"Object: {g['id'][:8]}…"),
            "upn":    sam or g["displayName"],
        })

    # ── Users ─────────────────────────────────────────────────────────────────
    user_items = []
    try:
        # Attempt 1: $search
        r = _get(
            "https://graph.microsoft.com/v1.0/users",
            {"$search": f'"displayName:{q}"', "$select": "id,displayName,userPrincipalName,jobTitle", "$top": "10", "$count": "true"},
            search_headers,
        )
        if r.ok:
            user_items = r.json().get("value", [])
        else:
            # Attempt 2: $filter startswith on both displayName and userPrincipalName
            r2 = _get(
                "https://graph.microsoft.com/v1.0/users",
                {"$filter": f"startswith(displayName,'{q}') or startswith(userPrincipalName,'{q}')",
                 "$select": "id,displayName,userPrincipalName,jobTitle", "$top": "10"},
                filter_headers,
            )
            if r2.ok:
                user_items = r2.json().get("value", [])
            else:
                logger.warning(f"User search failed: {r.status_code} {r.text[:200]}")
    except Exception as e:
        logger.warning(f"Entra user search error: {e}")

    for u in user_items:
        results.append({
            "type":   "user",
            "id":     u["id"],
            "name":   u["displayName"],
            "detail": u.get("userPrincipalName", ""),
            "upn":    u.get("userPrincipalName", ""),
        })

    return results[:15]


# ── Clone job persistence ─────────────────────────────────────────────────────

def _db_path() -> str:
    """Resolve the portal SQLite database path the same way database.py does."""
    try:
        from routers.database import DB_PATH
        return DB_PATH
    except ImportError:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, "infraportal.db")


def _db():
    conn = sqlite3.connect(_db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_clone_jobs_table():
    """
    Create the clone_jobs table if it doesn't already exist.
    Call this from main.py right after init_db().
    """
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS clone_jobs (
                id              TEXT PRIMARY KEY,
                source_dg_id    TEXT NOT NULL,
                source_dg_name  TEXT NOT NULL DEFAULT '',
                target_dg_id    TEXT NOT NULL,
                target_dg_name  TEXT NOT NULL DEFAULT '',
                cloned_apps     TEXT NOT NULL DEFAULT '[]',
                test_assignees  TEXT NOT NULL DEFAULT '[]',
                folder_map      TEXT NOT NULL DEFAULT '{}',
                attr_flags      TEXT NOT NULL DEFAULT '{}',
                path_rules      TEXT NOT NULL DEFAULT '[]',
                status          TEXT NOT NULL DEFAULT 'cloned',
                created_at      TEXT NOT NULL,
                cutover_at      TEXT
            )
        """)
        conn.commit()


def _row_to_job(row) -> dict:
    d = dict(row)
    for field in ("cloned_apps", "test_assignees", "path_rules"):
        try:
            d[field] = json.loads(d[field])
        except Exception:
            d[field] = []
    for field in ("folder_map", "attr_flags"):
        try:
            d[field] = json.loads(d[field])
        except Exception:
            d[field] = {}
    return d


def save_clone_job(job: dict) -> str:
    job_id = job.get("id") or str(uuid.uuid4())
    with _db() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO clone_jobs
                (id, source_dg_id, source_dg_name, target_dg_id, target_dg_name,
                 cloned_apps, test_assignees, folder_map, attr_flags, path_rules,
                 status, created_at, cutover_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            job_id,
            job["source_dg_id"],
            job.get("source_dg_name", ""),
            job["target_dg_id"],
            job.get("target_dg_name", ""),
            json.dumps(job.get("cloned_apps",    [])),
            json.dumps(job.get("test_assignees", [])),
            json.dumps(job.get("folder_map",     {})),
            json.dumps(job.get("attr_flags",     {})),
            json.dumps(job.get("path_rules",     [])),
            job.get("status", "cloned"),
            job.get("created_at", datetime.utcnow().isoformat()),
            job.get("cutover_at"),
        ))
        conn.commit()
    return job_id


def get_clone_jobs() -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM clone_jobs ORDER BY created_at DESC"
        ).fetchall()
    return [_row_to_job(r) for r in rows]


def get_clone_job(job_id: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM clone_jobs WHERE id = ?", (job_id,)
        ).fetchone()
    return _row_to_job(row) if row else None


def delete_clone_job(job_id: str) -> bool:
    """Delete a single clone job. Returns True if a row was deleted."""
    with _db() as conn:
        cur = conn.execute("DELETE FROM clone_jobs WHERE id = ?", (job_id,))
        conn.commit()
    return cur.rowcount > 0


def delete_clone_jobs(status: str | None = None) -> int:
    """Delete clone jobs. Pass status='cutover' to clear only completed jobs,
    or None to delete all. Returns the number of rows deleted."""
    with _db() as conn:
        if status:
            cur = conn.execute("DELETE FROM clone_jobs WHERE status = ?", (status,))
        else:
            cur = conn.execute("DELETE FROM clone_jobs")
        conn.commit()
    return cur.rowcount


def _update_job(job_id: str, **kwargs):
    sets   = ", ".join(f"{k}=?" for k in kwargs)
    values = list(kwargs.values()) + [job_id]
    with _db() as conn:
        conn.execute(f"UPDATE clone_jobs SET {sets} WHERE id=?", values)
        conn.commit()


# ── Path rule application ─────────────────────────────────────────────────────

def _apply_rules(value: str, rules: list[dict]) -> str:
    """Apply ordered find/replace rules to a string. Supports regex."""
    for rule in rules:
        find    = (rule.get("from") or "").strip()
        replace = (rule.get("to")   or "").strip()
        if not find:
            continue
        try:
            value = re.sub(find, replace, value, flags=re.IGNORECASE)
        except re.error:
            value = value.replace(find, replace)
    return value


def _preview_rules(value: str, rules: list[dict]) -> tuple[str, bool]:
    """Return (transformed_value, was_changed)."""
    result = _apply_rules(value, rules)
    return result, result != value


# ── Clone operation ───────────────────────────────────────────────────────────

_PATH_ATTRS = {"command_line", "command_line_args", "working_directory"}


def _assignees_to_upn_list(assignees: list[dict]) -> list[str]:
    """Convert test assignee objects to UPN / displayName strings for Citrix."""
    return [a.get("upn") or a.get("name", "") for a in assignees if a.get("upn") or a.get("name")]


def _build_clone_payload(
    app:             dict,
    target_dg_id:    str,
    target_dg_name:  str,
    attr_flags:      dict,
    folder_map:      dict,
    path_rules:      list[dict],
    test_assignees:  list[dict],
) -> dict:
    # Build the minimum viable payload first — Citrix returns a vague
    # ArgumentException if any field is wrong, so start minimal and add fields.
    exe     = _apply_rules(app.get("command_line", ""), path_rules)
    args    = _apply_rules(app.get("command_line_args", "") or "", path_rules)
    workdir = _apply_rules(app.get("working_directory", "") or "", path_rules)

    # Citrix app Names must be unique across the entire site — not just per DG.
    # Append the target DG name so clones don't collide with source apps.
    # The PublishedName (what users see) stays the same as the source.
    dg_label    = (target_dg_name or target_dg_id[:8]).strip()
    unique_name = f"{app['name']} - {dg_label}"

    payload: dict = {
        "Name":            unique_name,
        "PublishedName":   app["published_name"],
        "ApplicationType": "HostedOnDesktop",
        "InstalledAppProperties": {
            "CommandLineExecutable": exe,
        },
    }

    # WorkingDirectory only if non-empty
    if workdir:
        payload["InstalledAppProperties"]["WorkingDirectory"] = workdir

    # ── Folder ────────────────────────────────────────────────────────────────
    source_folder = app.get("folder") or ""
    logger.info(
        f"Folder debug — app='{app['name']}' source_folder='{source_folder}' "
        f"folder_map={folder_map} attr_flags={attr_flags}"
    )
    if attr_flags.get("folder", True):
        # Use explicit mapping if one exists, otherwise preserve source folder.
        # folder_map may contain a "" key as a catch-all for root-level apps.
        target_folder = folder_map.get(source_folder, source_folder)
        logger.info(f"Folder — source='{source_folder}' → target='{target_folder}'")
        if target_folder:
            # ApplicationFolder is passed to create_application_via_powershell
            # which uses it to set BOTH the admin folder (Move-BrokerApplication)
            # and the user-facing folder (Set-BrokerApplication -ClientFolder).
            payload["ApplicationFolder"] = target_folder
        else:
            logger.info("Folder — no folder set (root-level source with no catch-all mapping)")
    else:
        logger.info("Folder — skipped (attr_flags.folder is False)")

    # ── Icon ──────────────────────────────────────────────────────────────────
    # icon_id from _app_summary is the Broker IconUid integer — reuse it directly
    # so the clone gets the same icon without any extra API calls.
    icon_id = app.get("icon_id")
    logger.info(
        f"Icon debug — app='{app['name']}' icon_id={icon_id!r} "
        f"attr_flags.icon={attr_flags.get('icon', True)}"
    )
    if attr_flags.get("icon", True) and icon_id:
        try:
            payload["IconUid"] = int(icon_id)
            logger.info(f"Icon — set IconUid={payload['IconUid']}")
        except (TypeError, ValueError):
            logger.warning(f"Icon — could not convert icon_id {icon_id!r} to int, skipping")
    else:
        logger.info(f"Icon — skipped (icon_id={icon_id!r}, flag={attr_flags.get('icon', True)})")

    # DG association is added by create_application based on target_dg_id.
    # Store it here so create_application can resolve the DG name.
    payload["_target_dg_id"] = target_dg_id

    return payload


def apply_test_assignees_via_powershell(
    app_uid:        int,
    assignees:      list[dict],
    client_id:      str,
    client_secret:  str,
    customer_id:    str,
) -> None:
    """
    Apply test assignees via PowerShell Add-BrokerUser, looked up by Uid integer.
    Uid is stable and unaffected by admin folder moves.
    AD groups (no @ in name) get DOMAIN prefix via $env:USERDOMAIN.
    UPNs (user@domain) are passed as-is.
    """
    import subprocess

    def _esc(s: str) -> str:
        return (s
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("`", "``")
            .replace("$", "`$"))

    upns = _assignees_to_upn_list(assignees)
    if not upns:
        return

    parts = [
        '[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}',
        '[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12',
        r'Import-Module "C:\Program Files\Citrix\CloudPowerShellModules\Citrix.PoshSdkProxy.Commands\Citrix.PoshSdkProxy.Commands.psm1" -ErrorAction Stop',
        r'Import-Module "C:\Program Files\Citrix\CloudPowerShellModules\Citrix.Broker.Commands\Citrix.Broker.Commands.psm1" -ErrorAction Stop',
        f'Set-XDCredentials -CustomerId "{_esc(customer_id)}" -ApiKey "{_esc(client_id)}" -SecretKey "{_esc(client_secret)}" -ProfileType CloudAPI',
        f'$_app = Get-BrokerApplication -Uid {int(app_uid)} -ErrorAction Stop',
    ]
    for upn in upns:
        if "@" in upn:
            name_expr = f'"{_esc(upn)}"'
        else:
            name_expr = f'"$env:USERDOMAIN\\{_esc(upn)}"'
        parts.append(f'Add-BrokerUser -Name {name_expr} -Application $_app -ErrorAction SilentlyContinue')
    parts.append('Set-BrokerApplication -InputObject $_app -UserFilterEnabled $true')

    script   = "\n".join(parts)
    redacted = script.replace(client_secret, "***").replace(client_id, "***")
    logger.info(f"Test assignee PS script: {redacted}")

    # Write script to a temp file and invoke with -File to avoid IIS stdin-pipe hang.
    import tempfile, os as _os
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.ps1', delete=False, encoding='utf-8')
    try:
        tmp.write(script)
        tmp.flush()
        tmp.close()
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", tmp.name],
            capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    finally:
        try: _os.unlink(tmp.name)
        except Exception: pass

    if result.stdout.strip():
        logger.info(f"Test assignee PS stdout: {result.stdout.strip()[:300]}")
    if result.returncode != 0 or result.stderr.strip():
        logger.error(f"Test assignee PS stderr: {result.stderr.strip()[:400]}")
    else:
        logger.info(f"Test assignees applied via PS — uid={app_uid} assignees={upns}")


def clone_apps(
    source_dg_id:   str,
    source_dg_name: str,
    target_dg_id:   str,
    target_dg_name: str,
    app_ids:        list[str],
    attr_flags:     dict,
    folder_map:     dict,
    path_rules:     list[dict],
    test_assignees: list[dict],
) -> dict:
    """
    Clone selected apps from source DG to target DG.
    Persists a clone_job record for use in step 4 cutover.
    Returns {job_id, cloned: [{source_id, target_id, name}], errors: [...]}
    """
    source_apps = {a["id"]: a for a in get_applications_for_dg(source_dg_id)}
    cloned: list[dict] = []
    errors: list[dict] = []

    for app_id in app_ids:
        app = source_apps.get(app_id)
        if not app:
            errors.append({"id": app_id, "error": "App not found in source delivery group"})
            continue
        try:
            payload = _build_clone_payload(
                app, target_dg_id, target_dg_name, attr_flags, folder_map, path_rules, test_assignees
            )
            logger.info(f"Cloning '{app['name']}' payload: {payload}")
            created = create_application(payload, target_dg_id=target_dg_id)
            target_id = created.get("Id") or created.get("id") or ""

            # Apply test assignees via PowerShell using Uid lookup.
            # REST PATCH silently ignores plain AD group names.
            # PowerShell Add-BrokerUser + $env:USERDOMAIN resolves them correctly.
            # Uid lookup is immune to folder-prefixed name changes after REST PATCH.
            if test_assignees and target_id:
                app_uid = created.get("Uid", 0)
                try:
                    apply_test_assignees_via_powershell(
                        app_uid       = app_uid,
                        assignees     = test_assignees,
                        client_id     = os.getenv("CITRIX_CLIENT_ID", ""),
                        client_secret = os.getenv("CITRIX_CLIENT_SECRET", ""),
                        customer_id   = os.getenv("CITRIX_CUSTOMER_ID", ""),
                    )
                except Exception as e:
                    logger.warning(f"Failed to apply test assignees to uid={app_uid}: {e}")

            cloned.append({
                "source_id":      app_id,
                "target_id":      target_id,
                "name":           payload.get("Name", app["name"]),
                "source_name":    app["name"],
                "published_name": app["published_name"],
            })
            logger.info(f"Cloned: {app['name']} → {target_id}")
        except Exception as e:
            logger.error(f"Clone failed for '{app.get('name')}': {e}")
            errors.append({"id": app_id, "name": app.get("name", ""), "error": str(e)})

    job_id = save_clone_job({
        "source_dg_id":   source_dg_id,
        "source_dg_name": source_dg_name,
        "target_dg_id":   target_dg_id,
        "target_dg_name": target_dg_name,
        "cloned_apps":    cloned,
        "test_assignees": test_assignees,
        "folder_map":     folder_map,
        "attr_flags":     attr_flags,
        "path_rules":     path_rules,
        "status":         "cloned",
        "created_at":     datetime.utcnow().isoformat(),
    })
    return {"job_id": job_id, "cloned": cloned, "errors": errors}


# ── Security cutover ──────────────────────────────────────────────────────────

def run_security_cutover(job_id: str) -> dict:
    """
    For every app pair recorded in the clone job:
      1. Read current IncludedUsers from the SOURCE app (the live prod groups).
      2. Remove test assignees from that list (safety: only remove what we added).
      3. PATCH the TARGET (cloned) app with the cleaned prod group list.

    This means even if an admin manually added extra groups to the source app
    after the clone, those are picked up correctly at cutover time.

    Returns {job_id, succeeded: [...], failed: [...]}
    """
    job = get_clone_job(job_id)
    if not job:
        raise ValueError(f"Clone job '{job_id}' not found.")
    if job["status"] == "cutover":
        raise ValueError("Cutover has already been completed for this job.")

    test_upns = set(_assignees_to_upn_list(job["test_assignees"]))
    succeeded: list[dict] = []
    failed:    list[dict] = []

    for pair in job["cloned_apps"]:
        source_id = pair["source_id"]
        target_id = pair["target_id"]
        name      = pair.get("name", target_id)
        try:
            # Always read live source at cutover time — captures any changes
            # made to prod groups during the testing window.
            source_app = get_application_detail(source_id)
            prod_users = source_app.get("included_users", [])

            # Strip any test assignees that might appear in the prod list too
            clean_users = [u for u in prod_users if u not in test_upns]

            update_application(target_id, {
                "IncludedUsers":             clean_users,
                "IncludedUserFilterEnabled": bool(clean_users),
            })
            succeeded.append({
                "target_id":      target_id,
                "name":           name,
                "groups_applied": len(clean_users),
            })
            logger.info(f"Cutover OK: {name} — {len(clean_users)} groups applied")
        except Exception as e:
            logger.error(f"Cutover failed for '{name}' ({target_id}): {e}")
            failed.append({"target_id": target_id, "name": name, "error": str(e)})

    # Mark job complete only if everything succeeded
    if not failed:
        _update_job(job_id, status="cutover", cutover_at=datetime.utcnow().isoformat())
    else:
        logger.warning(
            f"Cutover job {job_id} partially failed: "
            f"{len(succeeded)} ok, {len(failed)} failed"
        )

    return {"job_id": job_id, "succeeded": succeeded, "failed": failed}