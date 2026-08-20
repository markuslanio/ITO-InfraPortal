import os
import re
import time
import requests
import urllib3
from dotenv import load_dotenv
from routers.cache import cache

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CLIENT_ID     = os.getenv("CITRIX_CLIENT_ID")
CLIENT_SECRET = os.getenv("CITRIX_CLIENT_SECRET")
CUSTOMER_ID   = os.getenv("CITRIX_CUSTOMER_ID")
SITE_ID       = os.getenv("CITRIX_SITE_ID", "4d60e6f7-1b21-4c6a-8400-c2c87c234ad2")
API_BASE      = f"https://api-us.cloud.com/cvadapis/{SITE_ID}"

# ── Token management ──────────────────────────────────────────────────────────

_token_cache = {"token": None, "expires_at": 0}

def get_token():
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"] - 60:
        return _token_cache["token"]
    r = requests.post(
        f"https://api.cloud.com/cctrustoauth2/{CUSTOMER_ID}/tokens/clients",
        headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
        timeout=15,
        verify=False
    )
    r.raise_for_status()
    data = r.json()
    _token_cache["token"]      = data["access_token"]
    _token_cache["expires_at"] = now + int(data.get("expires_in", 3600))
    return _token_cache["token"]

def get_session():
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "Authorization":     f"CwsAuth Bearer={get_token()}",
        "Citrix-CustomerId": CUSTOMER_ID,
        "Accept":            "application/json"
    })
    return session

# ── Paginated fetch ───────────────────────────────────────────────────────────

def fetch_all(session, url, params=None):
    items = []
    continuation = None
    while True:
        p = dict(params or {})
        p["limit"] = 250
        if continuation:
            p["continuationToken"] = continuation
        r = session.get(url, params=p, timeout=30)
        r.raise_for_status()
        data = r.json()
        items.extend(data.get("Items", []))
        continuation = data.get("ContinuationToken")
        if not continuation:
            break
    return items

# ── Data helpers ──────────────────────────────────────────────────────────────

def _parse_master_image_from_description(description):
    if not description:
        return None
    desc = description.strip()
    m = re.search(r'[Mm]aster\s+[Ii]mage\s+is\s+([\w.\-]+)', desc)
    if m:
        return m.group(1).strip()
    m = re.search(r'master\s+([\w.\-]+\.(?:sbl|com|local|net|org)\b)', desc, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r'\b([\w\-]+\.sbl\.com)\b', desc, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r'\b([A-Za-z0-9\-]{6,30}(?:ctx|xdmi|master|gold|base|img)[A-Za-z0-9\-]*)\b', desc, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None

def _machine_summary(m):
    hosting  = m.get("Hosting") or {}
    catalog  = m.get("MachineCatalog") or {}
    dg       = m.get("DeliveryGroup") or {}
    zone     = m.get("Zone") or {}
    name     = m.get("Name") or ""
    short_name = name.split("\\")[-1] if "\\" in name else name
    is_master = (
        m.get("IsMasterImageAssociated", False) or
        any(p in short_name.upper() for p in ["MASTER", "GOLD", "BASE", "TEMPLATE", "IMG"])
    )
    return {
        "id":                  m.get("Id"),
        "name":                short_name,
        "full_name":           name,
        "dns_name":            m.get("DnsName"),
        "ip_address":          m.get("IPAddress"),
        "power_state":         m.get("PowerState"),
        "registration_state":  m.get("RegistrationState"),
        "summary_state":       m.get("SummaryState"),
        "in_maintenance_mode": m.get("InMaintenanceMode", False),
        "maintenance_reason":  m.get("MaintenanceModeReason"),
        "fault_state":         m.get("FaultState"),
        "session_count":       m.get("SessionCount", 0),
        "os_type":             m.get("OSType"),
        "provisioning_type":   m.get("ProvisioningType"),
        "allocation_type":     m.get("AllocationType"),
        "agent_version":       m.get("AgentVersion"),
        "functional_level":    m.get("FunctionalLevel"),
        "last_connection_time": m.get("FormattedLastConnectionTime"),
        "last_deregistration": m.get("LastDeregistrationReason"),
        "last_error_reason":   m.get("LastErrorReason"),
        "image_out_of_date":   hosting.get("ImageOutOfDate", False),
        "hypervisor":          (hosting.get("HypervisorConnection") or {}).get("Name"),
        "hosted_machine_name": hosting.get("HostedMachineName"),
        "catalog_name":        catalog.get("Name"),
        "catalog_id":          catalog.get("Id"),
        "delivery_group_name": dg.get("Name"),
        "delivery_group_id":   dg.get("Id"),
        "zone":                zone.get("Name"),
        "upgrade_state":       m.get("UpgradeState"),
        "upgrade_type":        m.get("UpgradeType"),
        "is_master_image":     is_master,
        "tags":                [t.get("Name", t) if isinstance(t, dict) else t for t in (m.get("Tags") or [])],
        "critical_issues":     m.get("CriticalIssues", []),
        "non_critical_issues": m.get("NonCriticalIssues", []),
    }

def _dg_summary(dg):
    zone = dg.get("Zone") or {}
    return {
        "id":                      dg.get("Id"),
        "name":                    dg.get("Name"),
        "description":             dg.get("Description"),
        "enabled":                 dg.get("Enabled", True),
        "delivery_type":           dg.get("DeliveryType"),
        "session_support":         dg.get("SessionSupport"),
        "total_machines":          dg.get("TotalMachines", 0),
        "machines_in_maintenance": dg.get("MachinesInMaintenanceMode", 0),
        "total_sessions":          dg.get("TotalApplicationSessions", 0) or dg.get("Sessions", 0) or 0,
        "disconnected_sessions":   dg.get("DisconnectedSessionCount", 0),
        "total_desktops":          dg.get("TotalDesktops", 0),
        "desktops_available":      dg.get("DesktopsAvailable", 0),
        "desktops_in_use":         dg.get("DesktopsInUse", 0),
        "desktops_unregistered":   dg.get("DesktopsUnregistered", 0),
        "desktops_never_registered": dg.get("DesktopsNeverRegistered", 0),
        "load_index":              dg.get("AverageLoadIndex", 0),
        "zone":                    zone.get("Name"),
        "minimum_functional_level": dg.get("MinimumFunctionalLevel"),
        "tags":                    dg.get("Tags", []),
    }

def _catalog_summary(c):
    zone        = c.get("Zone") or {}
    upgrade     = c.get("UpgradeInfo") or {}
    description = c.get("Description") or ""
    master_image = _parse_master_image_from_description(description)
    return {
        "id":                        c.get("Id"),
        "name":                      c.get("Name"),
        "description":               description,
        "master_image_server":       master_image,
        "allocation_type":           c.get("AllocationType"),
        "session_support":           c.get("SessionSupport"),
        "provisioning_type":         c.get("ProvisioningType"),
        "total_count":               c.get("TotalCount", 0),
        "available_count":           c.get("AvailableCount", 0),
        "used_count":                c.get("UsedCount", 0),
        "unassigned_count":          c.get("UnassignedCount", 0),
        "is_broken":                 c.get("IsBroken", False),
        "is_master_image_associated": c.get("IsMasterImageAssociated", False),
        "image_update_status":       c.get("ImageUpdateStatus"),
        "zone":                      zone.get("Name"),
        "upgrade_type":              upgrade.get("UpgradeType"),
        "upgrade_state":             upgrade.get("UpgradeState"),
        "upgrade_schedule_status":   upgrade.get("UpgradeScheduleStatus"),
        "upgrade_ongoing_count":     upgrade.get("UpgradeOngoingMachinesCount", 0),
        "upgrade_failed_count":      upgrade.get("UpgradeFailedMachinesCount", 0),
        "errors":                    c.get("Errors", []),
        "warnings":                  c.get("Warnings", []),
        "critical_issues":           c.get("CriticalIssues", []),
    }

def _session_summary(s):
    machine      = s.get("Machine") or {}
    user         = s.get("User") or {}
    client       = s.get("Client") or {}
    connection   = s.get("Connection") or {}
    dg           = machine.get("DeliveryGroup") or {}
    catalog      = machine.get("MachineCatalog") or {}
    machine_name = machine.get("Name") or ""
    short_machine = machine_name.split("\\")[-1] if "\\" in machine_name else machine_name
    return {
        "id":               s.get("Id"),
        "state":            s.get("State"),
        "session_type":     s.get("SessionType"),
        "start_time":       s.get("FormattedStartTime"),
        "state_change_time": s.get("FormattedStateChangeTime"),
        "user_name":        (s.get("UntrustedUserName") or "").split("\\")[-1],
        "user_display":     user.get("DisplayName"),
        "machine_name":     short_machine,
        "delivery_group":   dg.get("Name"),
        "catalog":          catalog.get("Name"),
        "protocol":         connection.get("Protocol"),
        "client_name":      client.get("Name"),
        "client_ip":        client.get("IPAddress"),
        "client_platform":  client.get("Platform"),
        "is_anonymous":     s.get("IsAnonymousUser", False),
    }

# ── Main data functions ───────────────────────────────────────────────────────

def get_citrix_summary(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("citrix_summary")
        if data is not None:
            return data, ts

    session      = get_session()
    dgs_raw      = fetch_all(session, f"{API_BASE}/DeliveryGroups")
    dgs          = [_dg_summary(d) for d in dgs_raw]
    cats_raw     = fetch_all(session, f"{API_BASE}/MachineCatalogs")
    cats         = [_catalog_summary(c) for c in cats_raw]
    sessions_raw = fetch_all(session, f"{API_BASE}/Sessions")
    sessions     = [_session_summary(s) for s in sessions_raw]
    machines_raw = fetch_all(session, f"{API_BASE}/Machines")
    machines     = [_machine_summary(m) for m in machines_raw]

    active_sessions       = sum(1 for s in sessions if s["state"] == "Active")
    disconnected_sessions = sum(1 for s in sessions if s["state"] == "Disconnected")
    registered            = sum(1 for m in machines if m["registration_state"] == "Registered")
    unregistered          = sum(1 for m in machines if m["registration_state"] == "Unregistered")
    in_maintenance        = sum(1 for m in machines if m["in_maintenance_mode"])
    powered_off           = sum(1 for m in machines if m["power_state"] == "Off")
    image_out_of_date     = sum(1 for m in machines if m["image_out_of_date"])
    with_faults           = sum(1 for m in machines if m["fault_state"] not in (None, "None", "Unknown", ""))
    with_errors           = sum(1 for m in machines if m["critical_issues"])
    agent_versions        = {}
    for m in machines:
        v = m["agent_version"] or "Unknown"
        agent_versions[v] = agent_versions.get(v, 0) + 1

    summary = {
        "delivery_groups":       dgs,
        "catalogs":              cats,
        "total_machines":        len(machines),
        "registered":            registered,
        "unregistered":          unregistered,
        "in_maintenance":        in_maintenance,
        "powered_off":           powered_off,
        "image_out_of_date":     image_out_of_date,
        "with_faults":           with_faults,
        "with_errors":           with_errors,
        "active_sessions":       active_sessions,
        "disconnected_sessions": disconnected_sessions,
        "total_sessions":        len(sessions),
        "agent_versions":        agent_versions,
        "master_image_count":    sum(1 for m in machines if m["is_master_image"]),
        "total_delivery_groups": len(dgs),
        "total_catalogs":        len(cats),
        "broken_catalogs":       sum(1 for c in cats if c["is_broken"]),
        "catalogs_with_errors":  sum(1 for c in cats if c["errors"] or c["critical_issues"]),
        "upgrade_available":     sum(1 for c in cats if c["upgrade_state"] == "UpgradeAvailable"),
    }
    cache.set("citrix_summary", summary)
    _, ts = cache.get("citrix_summary")
    return summary, ts


def get_citrix_machines(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("citrix_machines")
        if data is not None:
            return data, ts
    session  = get_session()
    machines = [_machine_summary(m) for m in fetch_all(session, f"{API_BASE}/Machines")]
    cache.set("citrix_machines", machines)
    _, ts = cache.get("citrix_machines")
    return machines, ts


def get_citrix_sessions(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("citrix_sessions")
        if data is not None:
            return data, ts
    session  = get_session()
    sessions = [_session_summary(s) for s in fetch_all(session, f"{API_BASE}/Sessions")]
    cache.set("citrix_sessions", sessions)
    _, ts = cache.get("citrix_sessions")
    return sessions, ts


def get_citrix_delivery_groups(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("citrix_delivery_groups")
        if data is not None:
            return data, ts
    session = get_session()
    dgs     = [_dg_summary(d) for d in fetch_all(session, f"{API_BASE}/DeliveryGroups")]
    cache.set("citrix_delivery_groups", dgs)
    _, ts = cache.get("citrix_delivery_groups")
    return dgs, ts


def get_citrix_catalogs(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("citrix_catalogs")
        if data is not None:
            return data, ts
    session = get_session()
    cats    = [_catalog_summary(c) for c in fetch_all(session, f"{API_BASE}/MachineCatalogs")]
    cache.set("citrix_catalogs", cats)
    _, ts = cache.get("citrix_catalogs")
    return cats, ts


def get_master_images():
    cats, _ = get_citrix_catalogs()
    images = []
    for c in cats:
        mi = c.get("master_image_server")
        if mi:
            images.append({
                "hostname":       mi,
                "hostname_lower": mi.lower().split(".")[0],
                "catalog_name":   c["name"],
                "catalog_id":     c["id"],
                "zone":           c["zone"],
                "provisioning":   c["provisioning_type"],
            })
    return images


def logoff_session(session_id):
    s = get_session()
    r = s.post(
        f"{API_BASE}/Sessions/{session_id}/$logoff",
        headers={"Content-Type": "application/json"},
        json={},
        timeout=15
    )
    return r.status_code, r.text


def get_shadow_url(session_id):
    s = get_session()
    r = s.get(f"{API_BASE}/Sessions/{session_id}/launchica", timeout=15)
    return r.status_code, r.text


def get_citrix_analysis_for_ai():
    try:
        summary, _  = get_citrix_summary()
        machines, _ = get_citrix_machines()
        master_images = get_master_images()

        unregistered   = [m for m in machines if m["registration_state"] == "Unregistered"]
        in_maintenance = [m for m in machines if m["in_maintenance_mode"]]
        image_stale    = [m for m in machines if m["image_out_of_date"]]
        faulted        = [m for m in machines if m["fault_state"] not in (None, "None", "Unknown", "")]

        return {
            "total_machines":        summary["total_machines"],
            "registered":            summary["registered"],
            "unregistered":          summary["unregistered"],
            "in_maintenance":        summary["in_maintenance"],
            "powered_off":           summary["powered_off"],
            "image_out_of_date":     summary["image_out_of_date"],
            "active_sessions":       summary["active_sessions"],
            "disconnected_sessions": summary["disconnected_sessions"],
            "total_delivery_groups": summary["total_delivery_groups"],
            "total_catalogs":        summary["total_catalogs"],
            "broken_catalogs":       summary["broken_catalogs"],
            "upgrade_available":     summary["upgrade_available"],
            "agent_versions":        summary["agent_versions"],
            "delivery_groups":       summary["delivery_groups"],
            "catalogs":              summary["catalogs"],
            "master_images":         master_images,
            "problem_machines": {
                "unregistered":   [{"name": m["name"], "catalog": m["catalog_name"], "dg": m["delivery_group_name"], "last_dereg": m["last_deregistration"], "zone": m["zone"]} for m in unregistered[:20]],
                "in_maintenance": [{"name": m["name"], "catalog": m["catalog_name"], "reason": m["maintenance_reason"]} for m in in_maintenance[:20]],
                "image_stale":    [{"name": m["name"], "catalog": m["catalog_name"]} for m in image_stale[:20]],
                "faulted":        [{"name": m["name"], "fault": m["fault_state"], "catalog": m["catalog_name"]} for m in faulted[:20]],
            },
        }
    except Exception as e:
        return {"error": str(e)}

def get_citrix_machine_name_set():
    """
    Returns a dict keyed by lowercase short hostname (no domain, no path).
    Value contains enough metadata for cross-referencing with VMware and AD.
    Uses the existing citrix_machines cache — no extra API calls.

    Example key: "topctxxdmi01p"
    Example value: {
        "full_name":           "DOMAIN\\TOPCTXXDMI01P",
        "catalog_name":        "Win11-OnpremVDI-Topeka",
        "delivery_group_name": "Win11-OnpremVDI-Topeka",
        "session_support":     "SingleSession",   # SingleSession=VDI, MultiSession=XenApp
        "is_vdi":              True,
        "is_master_image":     False,
        "registration_state":  "Registered",
        "power_state":         "On",
        "in_maintenance_mode": False,
        "zone":                "US EAST VMC",
    }
    """
    try:
        machines, _ = get_citrix_machines()
    except Exception:
        return {}

    # Need delivery group session_support — get from summary cache if available
    dg_session_support = {}
    try:
        summary, _ = get_citrix_summary()
        for dg in summary.get("delivery_groups", []):
            dg_session_support[dg["name"]] = dg.get("session_support", "")
    except Exception:
        pass

    result = {}
    for m in machines:
        name = m.get("name") or m.get("full_name") or ""
        short = name.split("\\")[-1].lower().split(".")[0]
        if not short:
            continue
        dg_name = m.get("delivery_group_name") or ""
        session_support = dg_session_support.get(dg_name, "")
        is_vdi = (
            session_support == "SingleSession" or
            m.get("allocation_type") == "Random"  # pooled/random = VDI
        )
        result[short] = {
            "full_name":           m.get("full_name", name),
            "catalog_name":        m.get("catalog_name"),
            "delivery_group_name": dg_name,
            "session_support":     session_support,
            "is_vdi":              is_vdi,
            "is_master_image":     m.get("is_master_image", False),
            "registration_state":  m.get("registration_state"),
            "power_state":         m.get("power_state"),
            "in_maintenance_mode": m.get("in_maintenance_mode", False),
            "fault_state":         m.get("fault_state"),
            "zone":                m.get("zone"),
            "last_deregistration": m.get("last_deregistration"),
        }
    return result