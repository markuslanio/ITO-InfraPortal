import requests
import urllib3
import os
from dotenv import load_dotenv
from routers.cache import cache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

OPM_HOST    = os.getenv("OPMANAGER_HOST")
OPM_PORT    = os.getenv("OPMANAGER_PORT", "8060")
OPM_API_KEY = os.getenv("OPMANAGER_API_KEY")
BASE_URL    = f"https://{OPM_HOST}:{OPM_PORT}/api/json"

# Probe hosts — each may carry its own API key.
# Smyrna probe uses OPMANAGER_SMYRNA_PROBE_API_KEY; all others use OPMANAGER_PROBE_API_KEY.
_PROBE_HOSTS  = [h.strip() for h in (os.getenv("OPMANAGER_PROBE_HOSTS") or "").split(",") if h.strip()]
PROBE_API_KEY = os.getenv("OPMANAGER_PROBE_API_KEY") or OPM_API_KEY  # kept for back-compat / diag
_SMYRNA_KEY   = os.getenv("OPMANAGER_SMYRNA_PROBE_API_KEY") or PROBE_API_KEY

# Map probe_url → the correct API key for that probe
PROBE_KEY_MAP: dict[str, str] = {}
for _h in _PROBE_HOSTS:
    _url = f"https://{_h}:{OPM_PORT}/api/json"
    PROBE_KEY_MAP[_url] = _SMYRNA_KEY if "smy" in _h.lower() else PROBE_API_KEY

PROBE_URLS = list(PROBE_KEY_MAP.keys())

SEVERITY_MAP = {
    1: {"label": "Critical",     "color": "#ff2222", "order": 1},
    2: {"label": "Trouble",      "color": "#ff8800", "order": 2},
    3: {"label": "Attention",    "color": "#ffcc00", "order": 3},
    4: {"label": "Service Down", "color": "#aa44ff", "order": 4},
    5: {"label": "Clear",        "color": "#22aa44", "order": 5},
}

# ── base helpers ──────────────────────────────────────────────────────────────

def _get(endpoint, params=None, base_url=None, api_key=None):
    p = {"apiKey": api_key or OPM_API_KEY}
    if params:
        p.update(params)
    url = (base_url or BASE_URL) + endpoint
    r = requests.get(url, params=p, verify=False, timeout=30)
    r.raise_for_status()
    return r.json()


def _probe_get(endpoint, params=None):
    """Query all configured probe servers; return merged list of raw device dicts."""
    results = []
    for probe_url in PROBE_URLS:
        try:
            data = _get(endpoint, params=params, base_url=probe_url,
                        api_key=PROBE_KEY_MAP.get(probe_url, PROBE_API_KEY))
            items = data if isinstance(data, list) else data.get("data") or []
            results.extend(items)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("Probe %s %s failed: %s", probe_url, endpoint, exc)
    return results

def _post(endpoint, params=None):
    p = {"apiKey": OPM_API_KEY}
    if params:
        p.update(params)
    r = requests.post(BASE_URL + endpoint, params=p, verify=False, timeout=30)
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return {"status": r.status_code, "text": r.text}

# ── alarms ────────────────────────────────────────────────────────────────────

def get_alarms(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("opm_alarms")
        if data is not None:
            return data, ts

    raw    = _get("/alarm/listAlarms")
    alarms = []
    for a in raw:
        sev_num  = a.get("numericSeverity", 5)
        sev_info = SEVERITY_MAP.get(sev_num, {"label": "Unknown", "color": "#888888", "order": 99})
        alarms.append({
            "alarm_id":      a.get("alarmId"),
            "device_name":   a.get("displayName"),
            "ip_address":    a.get("ipAddress"),
            "category":      a.get("category"),
            "event_type":    a.get("eventType"),
            "message":       a.get("message"),
            "severity":      sev_info["label"],
            "severity_color":sev_info["color"],
            "severity_order":sev_info["order"],
            "severity_num":  sev_num,
            "status":        a.get("statusStr"),
            "acknowledged":  a.get("who") != "Unacknowledged",
            "time":          a.get("modTime"),
        })
    alarms.sort(key=lambda x: x["severity_order"])
    cache.set("opm_alarms", alarms)
    _, ts = cache.get("opm_alarms")
    return alarms, ts

# ── acknowledge ───────────────────────────────────────────────────────────────

def acknowledge_alarm(alarm_id: str):
    try:
        r = requests.post(
            BASE_URL + "/alarm/acknowledgeAlarm",
            params={"apiKey": OPM_API_KEY},
            data={"alarmId": str(alarm_id)},
            verify=False, timeout=30
        )
        data = r.json()
        if "error" in data:
            return False, data["error"].get("message", "Unknown error")
        cache.invalidate("opm_alarms")
        return True, data
    except Exception as e:
        return False, str(e)

def acknowledge_alarms_bulk(alarm_ids: list):
    success, fail, errors = 0, 0, []
    for aid in alarm_ids:
        ok, msg = acknowledge_alarm(str(aid))
        if ok: success += 1
        else:  fail += 1; errors.append({"alarm_id": aid, "error": str(msg)})
    cache.invalidate("opm_alarms")
    return success, fail, errors

# ── clear ─────────────────────────────────────────────────────────────────────

def clear_alarm(alarm_id: str):
    try:
        r = requests.post(
            BASE_URL + "/alarm/clearAlarm",
            params={"apiKey": OPM_API_KEY},
            data={"alarmId": str(alarm_id)},
            verify=False, timeout=30
        )
        data = r.json()
        if "error" in data:
            return False, data["error"].get("message", "Unknown error")
        cache.invalidate("opm_alarms")
        return True, data
    except Exception as e:
        return False, str(e)

def clear_alarms_bulk(alarm_ids: list):
    success, fail, errors = 0, 0, []
    for aid in alarm_ids:
        ok, msg = clear_alarm(str(aid))
        if ok: success += 1
        else:  fail += 1; errors.append({"alarm_id": aid, "error": str(msg)})
    cache.invalidate("opm_alarms")
    return success, fail, errors

# ── devices ───────────────────────────────────────────────────────────────────

def get_devices(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("opm_devices")
        if data is not None:
            return data, ts

    raw = _get("/device/listDevices")
    raw = raw if isinstance(raw, list) else (raw.get("data") or [])

    # Build probe group index AND collect probe-exclusive devices.
    # Central server often doesn't sync group assignments from probes, and some
    # devices may exist only on the probe (not registered in central at all).
    probe_group: dict[str, tuple] = {}   # upper(name) → (group_id, group_name)
    probe_raw:   list[dict]        = []  # all raw probe device records
    if PROBE_URLS:
        for pd in _probe_get("/device/listDevices"):
            name = (pd.get("displayName") or "").strip()
            gid  = pd.get("groupId") or pd.get("deviceGroupId")
            gnm  = pd.get("groupName") or pd.get("deviceGroupName") or ""
            if name and gnm:
                probe_group[name.upper()] = (gid, gnm)
            if name:
                probe_raw.append(pd)

    # Merge: start with central, then append probe-only devices
    central_names = {(d.get("displayName") or "").strip().upper() for d in raw}
    probe_only = [pd for pd in probe_raw
                  if (pd.get("displayName") or "").strip().upper() not in central_names]
    all_raw = raw + probe_only

    devices = []
    for d in all_raw:
        status_num  = int(d.get("statusNum", 5))
        status_info = SEVERITY_MAP.get(status_num, {"label": "Unknown", "color": "#888888"})
        dname = (d.get("displayName") or "").strip()
        # Prefer probe group info (central often has blank group_name for probe-managed devices)
        cen_gid  = d.get("groupId") or d.get("deviceGroupId")
        cen_gnm  = d.get("groupName") or d.get("deviceGroupName") or ""
        prb_gid, prb_gnm = probe_group.get(dname.upper(), (None, ""))
        group_id   = prb_gid  if prb_gnm else cen_gid
        # mapName is OpManager's own topology-map bucket ("Servers_Map.netmap" →
        # "Servers") — it's what a device gets categorized under when NO one ever
        # assigned it a real group, not a curated group someone set up. Devices with
        # no explicit assignment get bucketed generically (e.g. "Servers" holding
        # 3000+ devices) — real, but not a "group" in any meaningful sense. Track
        # group_is_explicit so callers that are discovering *groups* (as opposed to
        # just wanting a non-empty label) can tell the difference and skip these.
        raw_map    = (d.get("mapName") or "").strip()
        map_name   = (raw_map.replace(".netmap", "").replace("_Map", "").replace("_", " ").strip()
                      if raw_map and raw_map != "Unknown_Map.netmap" else "")
        explicit_group_name = prb_gnm if prb_gnm else cen_gnm
        group_name = explicit_group_name or map_name
        devices.append({
            "id":                 d.get("id"),
            "display_name":       dname,
            "ip_address":         d.get("ipaddress"),
            "category":           d.get("category"),
            "type":               d.get("type"),
            "type_string":        d.get("typeString", ""),   # device category, kept separately
            "vendor":             d.get("vendorName"),
            "status":             status_info["label"],
            "status_color":       status_info["color"],
            "status_num":         status_num,
            "probe":              d.get("probeDisplayName"),
            "added_time":         d.get("addedTime"),
            "last_poll":          d.get("prettyTime"),
            "group_id":           group_id,
            "group_name":         group_name,
            "group_is_explicit":  bool(explicit_group_name),
        })
    devices.sort(key=lambda x: x["status_num"])
    cache.set("opm_devices", devices)
    _, ts = cache.get("opm_devices")
    return devices, ts


# ── groups ────────────────────────────────────────────────────────────────────

_GROUP_ENDPOINTS = [
    "/group/listGroups",
    "/group/listGroup",
    "/group/getAllGroups",
    "/device/listDeviceGroups",
]


def _parse_groups_response(raw) -> list:
    items = raw if isinstance(raw, list) else raw.get("groups") or raw.get("data") or []
    groups = []
    for g in items:
        gid  = g.get("groupId") or g.get("id") or 0
        name = g.get("groupName") or g.get("name") or g.get("displayName") or ""
        if name:
            groups.append({
                "id":           gid,
                "name":         name,
                "description":  g.get("description", ""),
                "device_count": g.get("count") or g.get("deviceCount") or 0,
                "source":       "api",
            })
    return groups


def _groups_from_devices() -> list:
    """Synthesize groups from the device category+type when the groups API is unavailable."""
    import logging
    log = logging.getLogger(__name__)
    try:
        devices, _ = get_devices()
    except Exception as e:
        log.warning("get_groups fallback: get_devices failed: %s", e)
        return []

    # Prefer real group_name/group_id from device record; fall back to category string.
    # For synthesized (category-based) groups, use the category NAME as the ID so
    # get_group_devices() can filter by matching d["category"] == group_id.
    by_group: dict = {}
    for d in devices:
        gid  = d.get("group_id")
        name = d.get("group_name")
        if not name:
            name = (d.get("category") or "Uncategorized").strip()
            gid  = name   # category string doubles as the lookup key
        if not name:
            continue
        key = str(gid)
        if key not in by_group:
            by_group[key] = {
                "id":           gid,   # real int for API groups; string for synthesized
                "name":         name,
                "description":  "",
                "device_count": 0,
                "source":       "synthesized",
            }
        by_group[key]["device_count"] += 1

    return sorted(by_group.values(), key=lambda x: x["name"].lower())


def get_groups(force_refresh=False):
    """Fetch OpManager device groups, trying multiple API endpoints with device-list fallback."""
    import logging
    log = logging.getLogger(__name__)

    if not force_refresh:
        data, ts = cache.get("opm_groups")
        if data is not None:
            return data, ts

    groups = None
    for endpoint in _GROUP_ENDPOINTS:
        try:
            raw    = _get(endpoint)
            parsed = _parse_groups_response(raw)
            if parsed:                      # accept first non-empty result
                groups = parsed
                log.info("OpManager groups loaded from %s (%d groups)", endpoint, len(groups))
                break
        except Exception as e:
            log.debug("OpManager groups endpoint %s failed: %s", endpoint, e)

    if groups is None:
        log.warning(
            "All OpManager group endpoints failed — synthesizing groups from device list"
        )
        groups = _groups_from_devices()

    groups.sort(key=lambda x: x["name"].lower())
    cache.set("opm_groups", groups)
    _, ts = cache.get("opm_groups")
    return groups, ts


def _fetch_device_tree_groups() -> dict[str, dict]:
    """Fetch all groups from /device/getDeviceTree on central + probe servers.

    Returns dict keyed by lowercased group name for dedup; value contains display
    name, group id, device_count, problematic_count, source_server.
    """
    import logging
    log = logging.getLogger(__name__)
    groups: dict[str, dict] = {}

    def _flatten(items: list, server: str) -> None:
        for item in items:
            if not isinstance(item, dict):
                continue
            name = (item.get("text") or "").strip()
            if not name:
                continue
            a_attr = item.get("a_attr") or {}
            try:
                device_count = int(a_attr.get("membersCount", 0))
            except (ValueError, TypeError):
                device_count = 0
            try:
                problematic = int(a_attr.get("problematicMembers", 0))
            except (ValueError, TypeError):
                problematic = 0
            key = name.lower()
            if key not in groups:
                groups[key] = {
                    "name":             name,
                    "id":               item.get("id") or item.get("groupName") or name,
                    "device_count":     device_count,
                    "problematic_count": problematic,
                    "source_server":    server,
                    "group_type":       item.get("groupType", "Device"),
                }
            else:
                groups[key]["device_count"]      += device_count
                groups[key]["problematic_count"] += problematic
            children = item.get("children")
            if isinstance(children, list):
                _flatten(children, server)

    _TREE_PARAMS = {"groupBy": "group", "pageName": "groups"}
    try:
        raw = _get("/device/getDeviceTree", params=_TREE_PARAMS)
        if isinstance(raw, list):
            _flatten(raw, "central")
            log.info("_fetch_device_tree_groups: %d groups from central", len(groups))
    except Exception as exc:
        log.debug("getDeviceTree central failed: %s", exc)

    before = len(groups)
    for probe_url in PROBE_URLS:
        try:
            raw = _get("/device/getDeviceTree", params=_TREE_PARAMS,
                       base_url=probe_url, api_key=PROBE_KEY_MAP.get(probe_url, PROBE_API_KEY))
            if isinstance(raw, list):
                _flatten(raw, "probe")
        except Exception as exc:
            log.debug("getDeviceTree probe %s failed: %s", probe_url, exc)
    log.info("_fetch_device_tree_groups: +%d groups from probes (total %d)", len(groups) - before, len(groups))

    return groups


def get_named_groups(force_refresh=False) -> list[dict]:
    """
    Build the list of OpManager device groups — structure only. Group *existence*
    in this list is decided purely by structural sources (what OpManager's device
    tree and device attributes actually say exists, plus manually-added names).
    Alarms are never used to discover a group here — that mixed alert data (which
    is noisy, historical, and belongs on the NOC page) into "does this group
    exist," which is how long-gone/renamed groups kept showing up here forever.

    Discovery sources (merged, deduped by normalized name):
      1. /device/getDeviceTree (central + probe) — primary: returns all defined groups
         including application groups (Lifecad, FAST, etc.) with member counts.
      2. Device list group_name field — supplementary gap-fill (catches groups that
         exist as a device attribute but were never registered as an Admin Logical Group).
      3. Custom names — manually added for groups OpManager doesn't otherwise surface.

    Live alarms are still fetched below and attached as alert_count/worst_sev
    metadata on top of groups already found via the sources above (used by the
    NOC map/topology views) — they just can't add a group to the list themselves.
    """
    if not force_refresh:
        data, ts = cache.get("opm_named_groups")
        if data is not None:
            return data

    import logging
    from routers.database import list_opm_group_names
    log = logging.getLogger(__name__)

    # 1. Device tree — authoritative group source
    tree_groups = _fetch_device_tree_groups()
    tree_by_name = {info["name"]: info for info in tree_groups.values()}

    # 2. Device list group_name — supplementary. Only devices with an explicit
    # group assignment count here; devices that fell back to OpManager's generic
    # topology-map bucket (group_is_explicit=False — "Servers", "Desktops", etc.,
    # sometimes holding thousands of unrelated devices) are not a real group and
    # must never be allowed to add one to this list.
    device_counts: dict[str, int] = {}
    try:
        opm_devices, _ = get_devices(force_refresh=force_refresh)
        for d in (opm_devices or []):
            if not d.get("group_is_explicit"):
                continue
            gn = (d.get("group_name") or "").strip()
            if gn:
                device_counts[gn] = device_counts.get(gn, 0) + 1
    except Exception as e:
        log.warning("get_named_groups: device list query failed: %s", e)

    # 3. Custom names — manually added, deliberately persistent
    try:
        custom_names = list_opm_group_names()
    except Exception as e:
        log.warning("get_named_groups: custom names query failed: %s", e)
        custom_names = []

    all_names: set[str] = (
        set(tree_by_name.keys())
        | set(device_counts.keys())
        | set(custom_names)
    )

    # Alert overlay — attached below to groups the structural sources already
    # found; never used to add a name to all_names above.
    live_status: dict[str, dict] = {}
    try:
        alarms, _ = cache.get("opm_alarms")
        if alarms is None:
            alarms, _ = get_alarms()
        for a in (alarms or []):
            if a.get("category") != "Group":
                continue
            name = (a.get("device_name") or "").strip()
            if not name:
                continue
            sev = int(a.get("severity_num") or 5)
            if name not in live_status:
                live_status[name] = {"severity_num": sev, "alert_count": 0}
            elif sev < live_status[name]["severity_num"]:
                live_status[name]["severity_num"] = sev
            if sev < 5:
                live_status[name]["alert_count"] += 1
    except Exception as e:
        log.warning("get_named_groups: alarm query failed: %s", e)

    # Collapse name variants that only differ by case/whitespace ("Domain Controllers",
    # "DomainController", "Domain COntrollers") into one row — same drift problem the
    # sync matching handles, just showing up here as duplicate list entries instead.
    variants_by_norm: dict[str, list[str]] = {}
    for n in all_names:
        variants_by_norm.setdefault(_norm_group_name(n), []).append(n)

    groups = []
    for norm_key, variants in sorted(variants_by_norm.items()):
        variants.sort()
        # Prefer whichever spelling the device tree actually recognizes (the closest
        # thing to an "official" name); else whichever has device-list data; else
        # just the first alphabetically.
        display_name = (next((v for v in variants if v in tree_by_name), None)
                         or next((v for v in variants if v in device_counts), None)
                         or variants[0])

        tree_info = next((tree_by_name[v] for v in variants if v in tree_by_name), {})
        device_count = next((device_counts[v] for v in variants if v in device_counts), None)
        stat = next((live_status[v] for v in variants if v in live_status), {})

        device_count = tree_info.get("device_count") or device_count

        # Alert count: live alarm overlay preferred; fall back to tree's problematic count
        alert_count = stat.get("alert_count") or tree_info.get("problematic_count", 0)

        # Severity: live alarm preferred; any problematic devices → warning; else clear
        if stat.get("severity_num"):
            worst_sev = stat["severity_num"]
        elif tree_info.get("problematic_count", 0) > 0:
            worst_sev = 2
        else:
            worst_sev = 5

        # Only two ways a group can exist here now: found via structural OpManager
        # data, or manually added. Alarms can never be the sole reason a row exists.
        source = "device" if any(v in tree_by_name or v in device_counts for v in variants) else "custom"

        other_variants = [v for v in variants if v != display_name]
        groups.append({
            "id":            tree_info.get("id") or display_name,
            "name":          display_name,
            "description":   "",
            "device_count":  device_count,
            "alert_count":   alert_count,
            "worst_sev":     worst_sev,
            "status":        _sev_to_status(worst_sev),
            "location":      "Unknown",
            "source":        source,
            "name_variants": other_variants or None,  # other spellings seen for this same group, if any
        })

    cache.set("opm_named_groups", groups)
    log.info("get_named_groups: %d total (tree:%d device_list:%d alarm_only:%d custom:%d)",
             len(groups), len(tree_groups), len(device_counts),
             sum(1 for g in groups if g["source"] == "alarm"), len(custom_names))
    return groups


# Per-server group map cache: {base_url: {displayName_lower: group_row_dict}}
# Populated on first call; cleared by invalidate_opm_group_cache() before bulk syncs.
_opm_group_map_cache: dict[str, dict] = {}


def invalidate_opm_group_cache() -> None:
    _opm_group_map_cache.clear()


def _norm_group_name(s: str) -> str:
    """Lowercase + strip all whitespace so 'Domain Controllers', 'DomainController',
    and 'Domain COntrollers' all compare equal. Group names have drifted across
    manual entry, OpManager's admin group list, and its device tree/device
    attributes — this is deliberately lenient rather than a strict rename."""
    import re
    return re.sub(r"\s+", "", (s or "").strip().lower())


def _fetch_group_map(base_url: str, api_key: str) -> dict:
    """Return {normalized_name: group_row} from listAllLogicalGroups. Cached per server."""
    if base_url in _opm_group_map_cache:
        return _opm_group_map_cache[base_url]
    try:
        raw = _get("/admin/listAllLogicalGroups",
                   params={"isGroupPage": "true", "_search": "false",
                           "rows": "500", "page": "1",
                           "sortByColumn": "groupDisplayName", "sortByType": "asc"},
                   base_url=base_url, api_key=api_key)
        rows = raw.get("rows", []) if isinstance(raw, dict) else []
        result = {_norm_group_name(g.get("groupDisplayName")): g
                  for g in rows if isinstance(g, dict)}
    except Exception:
        result = {}
    _opm_group_map_cache[base_url] = result
    return result


def _get_opm_group_member_names(opm_group_name: str) -> tuple[list[str], list[dict]]:
    """Return all device displayNames in an OPM logical group.

    Primary path: listAllLogicalGroups (REST API + apiKey) to find the group's
    composite groupName (e.g. 'billing-10000059368'), then listDevices?groupName=
    <composite> to retrieve actual members. Works on both central and probe servers.

    Fallback: some groups exist in OpManager's device tree / on individual devices'
    own group attribute but were never registered as an "Admin Logical Group" at
    all — for those, listAllLogicalGroups will never find a match no matter how the
    name is spelled. If the primary path comes up empty, fall back to matching
    directly against each device's own group field (the same data get_named_groups()
    already uses successfully for the group list's device counts).
    """
    import logging
    log = logging.getLogger(__name__)
    target = _norm_group_name(opm_group_name)
    names: set[str] = set()
    diag: list[dict] = []

    def _try_server(base_url: str, api_key: str) -> None:
        entry: dict = {"server": base_url, "group_found": False, "composite_name": None,
                       "device_count": 0, "error": None}
        diag.append(entry)
        try:
            # Step 1: look up group in cached listAllLogicalGroups map
            group_map = _fetch_group_map(base_url, api_key)
            entry["total_groups"] = len(group_map)
            matched_group = group_map.get(target)
            if not matched_group:
                entry["sample_names"] = list(group_map.keys())[:15]
                log.debug("OPM group '%s' not found in listAllLogicalGroups on %s", opm_group_name, base_url)
                return
            composite = matched_group.get("groupName", "")
            entry["group_found"] = True
            entry["composite_name"] = composite
            expected_count = int(matched_group.get("count") or 0)
            entry["expected_count"] = expected_count
            if expected_count == 0:
                # OPM returns ALL devices when groupName filter matches an empty group
                log.debug("OPM group '%s' has count=0 on %s — skipping listDevices", opm_group_name, base_url)
                return

            # Step 2: get devices via listDevices?groupName=<composite>
            devices = _get("/device/listDevices",
                           params={"groupName": composite},
                           base_url=base_url, api_key=api_key)
            if isinstance(devices, list):
                before = len(names)
                for d in devices:
                    if isinstance(d, dict):
                        dn = (d.get("displayName") or "").strip()
                        if dn:
                            names.add(dn)
                entry["device_count"] = len(names) - before
                log.info("OPM sync '%s' on %s: +%d devices via groupName=%s",
                         opm_group_name, base_url, entry["device_count"], composite)
            else:
                entry["error"] = f"listDevices returned unexpected: {str(devices)[:200]}"
        except Exception as e:
            entry["error"] = str(e)
            log.warning("OPM sync '%s' on %s failed: %s", opm_group_name, base_url, e)

    _try_server(BASE_URL, OPM_API_KEY)
    for probe_url in PROBE_URLS:
        _try_server(probe_url, PROBE_KEY_MAP.get(probe_url, PROBE_API_KEY))

    if not names:
        fallback_entry: dict = {"server": "device list (fallback)", "group_found": False,
                                 "composite_name": None, "device_count": 0, "error": None}
        diag.append(fallback_entry)
        try:
            devices, _ts = get_devices()
            # Only devices with an explicit group assignment count — a device that
            # fell back to OpManager's generic topology-map bucket (e.g. "Servers"
            # holding 3000+ unrelated devices) was never really put in this group.
            matches = [d for d in (devices or [])
                       if d.get("group_is_explicit") and _norm_group_name(d.get("group_name")) == target]
            for d in matches:
                dn = (d.get("display_name") or "").strip()
                if dn:
                    names.add(dn)
            fallback_entry["group_found"] = bool(matches)
            fallback_entry["device_count"] = len(matches)
            log.info("OPM sync '%s': device-list fallback matched %d devices", opm_group_name, len(matches))
        except Exception as e:
            fallback_entry["error"] = str(e)
            log.warning("OPM sync '%s' device-list fallback failed: %s", opm_group_name, e)

    log.info("_get_opm_group_member_names('%s') diag: %s", opm_group_name, diag)
    return sorted(names), diag


def _sev_to_status(sev_num: int) -> str:
    if sev_num <= 1: return "critical"
    if sev_num <= 2: return "warning"
    if sev_num <= 3: return "minor"
    return "clear"


def get_group_devices(group_id, force_refresh=False) -> list:
    """Fetch devices belonging to a specific OpManager group."""
    cache_key = f"opm_group_{group_id}"
    if not force_refresh:
        data, _ = cache.get(cache_key)
        if data is not None:
            return data
    try:
        raw     = _get("/device/listDevices", {"groupId": str(group_id)})
        devices = []
        for d in (raw if isinstance(raw, list) else []):
            sn = int(d.get("statusNum", 5))
            si = SEVERITY_MAP.get(sn, {"label": "Unknown", "color": "#888888"})
            devices.append({
                "id":           d.get("id"),
                "display_name": d.get("displayName", ""),
                "ip_address":   d.get("ipaddress", ""),
                "category":     d.get("category", ""),
                "type":         d.get("type", ""),
                "status":       si["label"],
                "status_color": si["color"],
                "status_num":   sn,
            })
        cache.set(cache_key, devices)
        return devices
    except Exception as e:
        import logging
        logging.getLogger(__name__).debug(
            "OpManager group %s API failed (%s) — falling back to device-list filter", group_id, e
        )
        # Fallback: filter the already-cached full device list.
        # Match on raw group_id OR on group_name/category (for synthesized groups where
        # the group "id" is the category name string).
        try:
            all_devices, _ = get_devices()
            gid_str = str(group_id)
            filtered = [
                {
                    "id":           d["id"],
                    "display_name": d["display_name"] or "",
                    "ip_address":   d["ip_address"] or "",
                    "category":     d["category"] or "",
                    "type":         d["type"] or "",
                    "status":       d["status"],
                    "status_color": d["status_color"],
                    "status_num":   d["status_num"],
                }
                for d in all_devices
                if str(d.get("group_id") or "") == gid_str
                   or str(d.get("group_name") or "") == gid_str
                   or str(d.get("category") or "") == gid_str
            ]
            cache.set(cache_key, filtered)
            return filtered
        except Exception:
            return []