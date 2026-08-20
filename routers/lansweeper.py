import os
import requests
import urllib3
from datetime import datetime, timezone
from dotenv import load_dotenv
from routers.cache import cache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

TOKEN   = os.getenv("LANSWEEPER_TOKEN")
SITE_ID = os.getenv("LANSWEEPER_SITE_ID")
URL     = "https://api.lansweeper.com/api/v2/graphql"

# ── base GQL caller ───────────────────────────────────────────────────────────

def _gql(query, variables=None):
    body = {"query": query}
    if variables:
        body["variables"] = variables
    resp = requests.post(
        URL,
        headers={"Authorization": f"Token {TOKEN}", "Content-Type": "application/json"},
        json=body, timeout=30, verify=False
    )
    if not resp.ok:
        # Capture the actual GraphQL error body before raising
        try:
            err_body = resp.json()
        except Exception:
            err_body = resp.text[:500]
        raise RuntimeError(f"Lansweeper {resp.status_code}: {err_body}")
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"Lansweeper GraphQL error: {data['errors']}")
    return data.get("data", {})

# ── paginated asset fetch ─────────────────────────────────────────────────────

def _fetch_all_assets(fields):
    """Fetch all assets across pages. Returns list of raw item dicts."""
    results = []
    cursor  = None
    page    = "FIRST"

    while True:
        pagination = {"limit": 500, "page": page}
        if cursor:
            pagination["cursor"] = cursor

        data = _gql("""
        query($id: ID!, $pagination: AssetsPaginationInput!, $fields: [String!]!) {
          site(id: $id) {
            assetResources(fields: $fields, pagination: $pagination) {
              total
              pagination { next }
              items
            }
          }
        }
        """, {"id": SITE_ID, "fields": fields, "pagination": pagination})

        ar    = (data.get("site") or {}).get("assetResources") or {}
        items = ar.get("items") or []
        results.extend(items)

        next_cursor = (ar.get("pagination") or {}).get("next")
        if not next_cursor:
            break
        cursor = next_cursor
        page   = "NEXT"

    return results

# ── helpers ───────────────────────────────────────────────────────────────────

def _days_ago(iso_str):
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None

def _basic(item):
    return item.get("assetBasicInfo") or {}

def _kb_to_gb(kb):
    """Convert kilobytes to GB rounded to 1 decimal."""
    if not kb:
        return None
    return round(kb / 1024 / 1024, 1)

# ── OS normalisation ──────────────────────────────────────────────────────────

_EOL_OS = {
    "Windows Server 2012 R2", "Windows Server 2012",
    "Windows Server 2008 R2", "Windows Server 2008", "Windows Server 2003",
    "Windows 7", "Windows 8", "Windows 8.1",
}

def _os_group(asset_type, os_name):
    candidates = [
        "Windows Server 2022", "Windows Server 2019", "Windows Server 2016",
        "Windows Server 2012 R2", "Windows Server 2012",
        "Windows Server 2008 R2", "Windows Server 2008", "Windows Server 2003",
        "Windows 11", "Windows 10", "Windows 8.1", "Windows 8", "Windows 7",
        "Red Hat Enterprise Linux", "Ubuntu", "CentOS", "Debian", "SUSE",
    ]
    src = os_name or asset_type or ""
    for c in candidates:
        if c.lower() in src.lower():
            return c
    if "linux" in src.lower():
        return "Linux"
    if "mac" in src.lower():
        return "macOS"
    return src or "Unknown"

# ── asset summary ─────────────────────────────────────────────────────────────

def get_asset_summary(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ls_asset_summary")
        if data is not None:
            return data, ts

    fields = [
        "assetBasicInfo.name", "assetBasicInfo.type", "assetBasicInfo.typeGroup",
        "assetBasicInfo.firstSeen", "assetBasicInfo.lastSeen", "assetBasicInfo.domain",
        "assetBasicInfo.scannerType",
        "operatingSystem.name",
    ]

    raw = _fetch_all_assets(fields)

    by_type  = {}
    by_os    = {}
    by_year  = {}
    eol      = 0
    dead_30  = 0
    dead_60  = 0
    dead_90  = 0

    for item in raw:
        b  = _basic(item)
        os = (item.get("operatingSystem") or {}).get("name", "")

        # Type group
        t = b.get("typeGroup") or b.get("type") or "Unknown"
        by_type[t] = by_type.get(t, 0) + 1

        # OS group
        og = _os_group(b.get("type"), os)
        by_os[og] = by_os.get(og, 0) + 1
        if og in _EOL_OS:
            eol += 1

        # First seen year
        fs = b.get("firstSeen")
        if fs:
            yr = fs[:4]
            by_year[yr] = by_year.get(yr, 0) + 1

        # Last seen staleness
        days = _days_ago(b.get("lastSeen"))
        if days is not None:
            if days >= 30: dead_30 += 1
            if days >= 60: dead_60 += 1
            if days >= 90: dead_90 += 1

    result = {
        "total":        len(raw),
        "by_type":      dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
        "by_os":        dict(sorted(by_os.items(),   key=lambda x: x[1], reverse=True)),
        "by_year":      dict(sorted(by_year.items())),
        "eol_count":    eol,
        "not_seen_30d": dead_30,
        "not_seen_60d": dead_60,
        "not_seen_90d": dead_90,
    }

    cache.set("ls_asset_summary", result)
    _, ts = cache.get("ls_asset_summary")
    return result, ts

# ── patch status ──────────────────────────────────────────────────────────────

def get_patch_status(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ls_patch_status")
        if data is not None:
            return data, ts

    fields = [
        "assetBasicInfo.name", "assetBasicInfo.type", "assetBasicInfo.ipAddress",
        "assetBasicInfo.lastSeen", "assetBasicInfo.domain",
        "operatingSystem.name", "operatingSystem.version",
        "assetCustom.stateName",
    ]

    raw = _fetch_all_assets(fields)

    patched       = 0
    unpatched     = 0
    unknown       = 0
    eol_assets    = []
    unpatched_list = []

    for item in raw:
        b     = _basic(item)
        os    = (item.get("operatingSystem") or {})
        name  = b.get("name", "")
        os_n  = os.get("name", "")
        days  = _days_ago(b.get("lastSeen"))
        state = ((item.get("assetCustom") or {}).get("stateName") or "").lower()
        og    = _os_group(b.get("type"), os_n)

        if og in _EOL_OS:
            eol_assets.append({
                "name":          name,
                "os":            og,
                "ip":            b.get("ipAddress"),
                "lastSeen":      b.get("lastSeen"),
                "daysSinceSeen": days,
            })

        if state in ("active",):
            # Active + seen within 30d = patched; older = unknown
            if days is not None and days <= 30:
                patched += 1
            elif days is not None and days > 90:
                unpatched += 1
                unpatched_list.append({
                    "name": name, "os": os_n,
                    "ip": b.get("ipAddress"), "daysSinceSeen": days,
                })
            else:
                unknown += 1
        elif state in ("unpatched", "needs update"):
            unpatched += 1
            unpatched_list.append({"name": name, "os": os_n, "ip": b.get("ipAddress")})
        elif days is not None and days <= 30:
            patched += 1
        elif days is not None and days > 90:
            unpatched += 1
            unpatched_list.append({
                "name": name, "os": os_n,
                "ip": b.get("ipAddress"), "daysSinceSeen": days,
            })
        else:
            unknown += 1

    total = patched + unpatched + unknown
    result = {
        "total":          total,
        "patched":        patched,
        "unpatched":      unpatched,
        "unknown":        unknown,
        "patch_pct":      round(patched / total * 100, 1) if total else 0,
        "eol_count":      len(eol_assets),
        "eol_assets":     sorted(eol_assets,
                              key=lambda x: x.get("daysSinceSeen") or 0,
                              reverse=True)[:50],
        "unpatched_list": unpatched_list[:50],
    }

    cache.set("ls_patch_status", result)
    _, ts = cache.get("ls_patch_status")
    return result, ts

# ── single asset detail ───────────────────────────────────────────────────────

# Fields confirmed working from schema testing
_DETAIL_FIELDS = [
    "assetBasicInfo.name", "assetBasicInfo.type", "assetBasicInfo.subType",
    "assetBasicInfo.ipAddress", "assetBasicInfo.fqdn", "assetBasicInfo.domain",
    "assetBasicInfo.firstSeen", "assetBasicInfo.lastSeen", "assetBasicInfo.lastActiveScan",
    "assetBasicInfo.scannerType", "assetBasicInfo.scannerTypes", "assetBasicInfo.description",
    "operatingSystem.name", "operatingSystem.version",
    "assetCustom.stateName", "assetCustom.manufacturer",
    "assetCustom.model", "assetCustom.serialNumber", "assetCustom.location",
    "processors.name", "processors.numberOfCores", "processors.currentClockSpeed",
    "processors.manufacturer",
    "logicalDisks.size", "logicalDisks.freeSpace",
]

def get_asset_detail(name):
    """
    Look up a single asset by name. Fetches first page and scans for name match.
    Returns detail dict or None if not found.
    Uses cache keyed by asset name.
    """
    cache_key = f"ls_asset_{name.lower()}"
    cached, ts = cache.get(cache_key)
    if cached is not None:
        return cached, ts

    # Fetch up to 500 at a time and scan — most environments will find the
    # asset in the first page since Lansweeper sorts by lastSeen desc.
    # If not found in first 500 we do a full paginated scan.
    found = None
    cursor = None
    page   = "FIRST"

    while True:
        pagination = {"limit": 500, "page": page}
        if cursor:
            pagination["cursor"] = cursor

        data = _gql("""
        query($id: ID!, $pagination: AssetsPaginationInput!, $fields: [String!]!) {
          site(id: $id) {
            assetResources(fields: $fields, pagination: $pagination) {
              pagination { next }
              items
            }
          }
        }
        """, {"id": SITE_ID, "fields": _DETAIL_FIELDS, "pagination": pagination})

        ar    = (data.get("site") or {}).get("assetResources") or {}
        items = ar.get("items") or []

        for item in items:
            if (_basic(item).get("name") or "").upper() == name.upper():
                found = item
                break

        if found:
            break

        next_cursor = (ar.get("pagination") or {}).get("next")
        if not next_cursor:
            break
        cursor = next_cursor
        page   = "NEXT"

    if not found:
        return None, None

    b    = _basic(found)
    os   = (found.get("operatingSystem") or {})
    cust = (found.get("assetCustom") or {})
    procs = found.get("processors") or []
    disks = found.get("logicalDisks") or []

    os_name = _os_group(b.get("type"), os.get("name"))

    # Aggregate disk info
    total_disk_gb = _kb_to_gb(sum(d.get("size") or 0 for d in disks)) if disks else None
    free_disk_gb  = _kb_to_gb(sum(d.get("freeSpace") or 0 for d in disks)) if disks else None
    used_disk_pct = None
    if total_disk_gb and free_disk_gb is not None:
        used = total_disk_gb - free_disk_gb
        used_disk_pct = round(used / total_disk_gb * 100, 1)

    # Primary processor
    proc = procs[0] if procs else {}

    result = {
        "name":           b.get("name"),
        "ip":             b.get("ipAddress"),
        "fqdn":           b.get("fqdn"),
        "domain":         b.get("domain"),
        "type":           b.get("type"),
        "os":             os_name,
        "os_raw":         os.get("name"),
        "os_version":     os.get("version"),
        "is_eol":         os_name in _EOL_OS,
        "first_seen":     b.get("firstSeen"),
        "last_seen":      b.get("lastSeen"),
        "days_since_seen":_days_ago(b.get("lastSeen")),
        "last_scan":      b.get("lastActiveScan"),
        "scanner_types":  b.get("scannerTypes") or [b.get("scannerType")],
        "manufacturer":   cust.get("manufacturer"),
        "model":          cust.get("model"),
        "serial":         cust.get("serialNumber"),
        "location":       cust.get("location"),
        "state":          cust.get("stateName"),
        "cpu":            proc.get("name"),
        "cpu_cores":      proc.get("numberOfCores"),
        "cpu_ghz":        round(proc.get("currentClockSpeed") or 0, 2) or None,
        "cpu_mfr":        proc.get("manufacturer"),
        "total_disk_gb":  total_disk_gb,
        "free_disk_gb":   free_disk_gb,
        "used_disk_pct":  used_disk_pct,
        "disk_count":     len(disks),
        "description":    b.get("description"),
    }

    cache.set(cache_key, result)
    _, ts = cache.get(cache_key)
    return result, ts

# ── AI analysis helper ────────────────────────────────────────────────────────

def get_lansweeper_analysis_for_ai():
    try:
        summary, _ = get_asset_summary()
        patches, _ = get_patch_status()

        eol_by_os = {}
        for a in patches.get("eol_assets", []):
            k = a.get("os", "Unknown")
            eol_by_os[k] = eol_by_os.get(k, 0) + 1

        return {
            "asset_counts": {
                "total":        summary.get("total"),
                "by_type":      summary.get("by_type"),
                "eol_count":    summary.get("eol_count"),
                "not_seen_30d": summary.get("not_seen_30d"),
                "not_seen_90d": summary.get("not_seen_90d"),
            },
            "os_breakdown":  summary.get("by_os"),
            "asset_age":     summary.get("by_year"),
            "patch_health": {
                "patch_pct":  patches.get("patch_pct"),
                "patched":    patches.get("patched"),
                "unpatched":  patches.get("unpatched"),
                "unknown":    patches.get("unknown"),
            },
            "eol_breakdown": eol_by_os,
            "top_unpatched": patches.get("unpatched_list", [])[:10],
            "top_eol":       patches.get("eol_assets", [])[:10],
        }
    except Exception as e:
        return {"error": str(e)}