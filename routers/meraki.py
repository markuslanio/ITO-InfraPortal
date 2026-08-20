"""
routers/meraki.py — Cisco Meraki integration
Covers two orgs: SE2 (634524) and Policygenius (624874448297656685)
All data cached in memory; refreshed by scheduler job every 15 min.
verify=False on all requests (corporate SSL inspection proxy).
"""

import os
import time
import logging
import re
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

BASE_URL = "https://api.meraki.com/api/v1"

ORGS = {
    "SE2":          os.getenv("MERAKI_ORG_ID_SE2", "634524"),
    "Policygenius": os.getenv("MERAKI_ORG_ID_PG",  "624874448297656685"),
}

def _headers() -> dict:
    """Build headers at request time so the API key is always read fresh from env."""
    return {
        "X-Cisco-Meraki-API-Key": os.getenv("MERAKI_API_KEY", ""),
        "Content-Type": "application/json",
    }

CACHE_TTL = 900  # 15 minutes

# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------

_cache: dict = {
    "networks":   {"data": [], "ts": 0},
    "devices":    {"data": [], "ts": 0},
    "uplinks":    {"data": [], "ts": 0},
    "clients":    {"data": [], "ts": 0},
}


def _stale(key: str) -> bool:
    return (time.time() - _cache[key]["ts"]) > CACHE_TTL


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _get(path: str, params: dict = None) -> list | dict | None:
    """GET from Meraki API. Returns parsed JSON or None on error."""
    try:
        resp = requests.get(
            f"{BASE_URL}{path}",
            headers=_headers(),
            params=params or {},
            verify=False,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning(f"Meraki GET {path} failed: {e}")
        return None


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_ip(s: str) -> bool:
    return bool(_IP_RE.match(s or ""))


# ---------------------------------------------------------------------------
# Data fetchers
# ---------------------------------------------------------------------------

def fetch_networks() -> list[dict]:
    """Return all networks across both orgs, tagged with org_name."""
    results = []
    for org_name, org_id in ORGS.items():
        data = _get(f"/organizations/{org_id}/networks")
        if not data:
            continue
        for n in data:
            n["org_name"] = org_name
            n["org_id"] = org_id
            results.append(n)
    logger.info(f"Meraki: fetched {len(results)} networks across {len(ORGS)} orgs.")
    return results


def fetch_devices() -> list[dict]:
    """Return all devices across both orgs, enriched with network + org info."""
    networks = _cache["networks"]["data"] or fetch_networks()
    net_map = {n["id"]: n for n in networks}
    results = []

    for org_name, org_id in ORGS.items():
        data = _get(f"/organizations/{org_id}/devices")
        if not data:
            continue
        for d in data:
            net = net_map.get(d.get("networkId"), {})
            d["org_name"] = org_name
            d["org_id"] = org_id
            d["network_name"] = net.get("name", "")
            d["product_types"] = net.get("productTypes", [])
            results.append(d)

    logger.info(f"Meraki: fetched {len(results)} devices.")
    return results


def fetch_uplinks() -> list[dict]:
    """Return WAN uplink statuses for all orgs."""
    results = []
    for org_name, org_id in ORGS.items():
        data = _get(f"/organizations/{org_id}/appliance/uplink/statuses")
        if not data:
            continue
        for u in data:
            u["org_name"] = org_name
            results.append(u)
    logger.info(f"Meraki: fetched uplinks for {len(results)} appliances.")
    return results


def fetch_clients(timespan: int = 3600) -> list[dict]:
    """
    Return recent clients (default: last 1 hour) across all networks.
    Meraki client data is per-network so we iterate networks.
    Only fetches networks that have 'wireless' or 'switch' product types.
    """
    networks = _cache["networks"]["data"] or fetch_networks()
    results = []

    for net in networks:
        types = net.get("productTypes", [])
        if not any(t in types for t in ["wireless", "switch", "appliance"]):
            continue
        data = _get(f"/networks/{net['id']}/clients", params={"timespan": timespan, "perPage": 1000})
        if not data:
            continue
        for c in data:
            c["network_id"] = net["id"]
            c["network_name"] = net.get("name", "")
            c["org_name"] = net.get("org_name", "")
        results.extend(data)

    logger.info(f"Meraki: fetched {len(results)} clients.")
    return results


# ---------------------------------------------------------------------------
# Scheduler job — called by scheduler.py
# ---------------------------------------------------------------------------

def job_meraki_refresh():
    """Full refresh of all Meraki caches. Called on startup + every 15 min."""
    logger.info("Meraki refresh: starting...")
    try:
        networks = fetch_networks()
        _cache["networks"] = {"data": networks, "ts": time.time()}

        devices = fetch_devices()
        _cache["devices"] = {"data": devices, "ts": time.time()}

        uplinks = fetch_uplinks()
        _cache["uplinks"] = {"data": uplinks, "ts": time.time()}

        clients = fetch_clients()
        _cache["clients"] = {"data": clients, "ts": time.time()}

        logger.info(
            f"Meraki refresh complete. "
            f"{len(networks)} networks, {len(devices)} devices, "
            f"{len(uplinks)} uplink appliances, {len(clients)} recent clients."
        )
    except Exception as e:
        logger.error(f"Meraki refresh failed: {e}")


# ---------------------------------------------------------------------------
# API response builders — called by main.py endpoints
# ---------------------------------------------------------------------------

def get_summary() -> dict:
    """
    Top-level summary for the network page hero section.
    Returns org counts, network counts, device counts, uplink health.
    """
    networks = _cache["networks"]["data"]
    devices  = _cache["devices"]["data"]
    uplinks  = _cache["uplinks"]["data"]

    # Uplink health
    total_uplinks = 0
    active_uplinks = 0
    for appliance in uplinks:
        for ul in appliance.get("uplinks", []):
            total_uplinks += 1
            if ul.get("status") == "active":
                active_uplinks += 1

    # Device type breakdown
    type_counts: dict[str, int] = {}
    for d in devices:
        model = d.get("model", "")
        if model.startswith("MX"):
            t = "Firewalls/Appliances"
        elif model.startswith("MS"):
            t = "Switches"
        elif model.startswith("MR"):
            t = "Access Points"
        elif model.startswith("MV"):
            t = "Cameras"
        elif model.startswith("MG"):
            t = "Cellular Gateways"
        elif model.startswith("MT"):
            t = "Sensors"
        else:
            t = "Other"
        type_counts[t] = type_counts.get(t, 0) + 1

    return {
        "orgs": [
            {
                "name": org_name,
                "org_id": org_id,
                "network_count": sum(1 for n in networks if n["org_name"] == org_name),
                "device_count":  sum(1 for d in devices  if d["org_name"] == org_name),
            }
            for org_name, org_id in ORGS.items()
        ],
        "total_networks": len(networks),
        "total_devices":  len(devices),
        "uplinks_active": active_uplinks,
        "uplinks_total":  total_uplinks,
        "device_types":   type_counts,
        "cache_age_sec":  int(time.time() - _cache["devices"]["ts"]) if _cache["devices"]["ts"] else None,
    }


def get_networks() -> list[dict]:
    """Networks list with uplink health injected per network."""
    networks = _cache["networks"]["data"]
    uplinks  = _cache["uplinks"]["data"]
    devices  = _cache["devices"]["data"]

    # Build uplink map: networkId → uplink list
    uplink_map: dict[str, list] = {}
    for appliance in uplinks:
        net_id = appliance.get("networkId")
        if net_id:
            uplink_map[net_id] = appliance.get("uplinks", [])

    result = []
    for n in networks:
        net_id = n["id"]
        net_uplinks = uplink_map.get(net_id, [])
        net_devices = [d for d in devices if d.get("networkId") == net_id]

        # Determine site health
        if not net_uplinks:
            health = "unknown"
        elif all(u.get("status") == "active" for u in net_uplinks):
            health = "online"
        elif any(u.get("status") == "active" for u in net_uplinks):
            health = "degraded"
        else:
            health = "offline"

        result.append({
            "id":           net_id,
            "name":         n.get("name", ""),
            "org_name":     n.get("org_name", ""),
            "product_types": n.get("productTypes", []),
            "health":       health,
            "uplinks":      net_uplinks,
            "device_count": len(net_devices),
            "url":          n.get("url", ""),
        })

    return result


def get_devices(org: str = None, network_id: str = None, device_type: str = None) -> list[dict]:
    """
    Device inventory with optional filters.
    org: 'SE2' or 'Policygenius'
    network_id: Meraki network ID
    device_type: 'switch' | 'ap' | 'appliance' | 'camera' | 'sensor' | 'cellular'
    """
    devices = _cache["devices"]["data"]

    type_prefix = {
        "switch":    "MS",
        "ap":        "MR",
        "appliance": "MX",
        "camera":    "MV",
        "sensor":    "MT",
        "cellular":  "MG",
    }

    results = []
    for d in devices:
        if org and d.get("org_name") != org:
            continue
        if network_id and d.get("networkId") != network_id:
            continue
        if device_type:
            prefix = type_prefix.get(device_type, "")
            if not d.get("model", "").startswith(prefix):
                continue
        results.append({
            "name":         d.get("name") or d.get("mac", ""),
            "model":        d.get("model", ""),
            "serial":       d.get("serial", ""),
            "mac":          d.get("mac", ""),
            "lan_ip":       d.get("lanIp", ""),
            "wan1_ip":      d.get("wan1Ip", ""),
            "wan2_ip":      d.get("wan2Ip", ""),
            "network_id":   d.get("networkId", ""),
            "network_name": d.get("network_name", ""),
            "org_name":     d.get("org_name", ""),
            "firmware":     d.get("firmware", ""),
            "tags":         d.get("tags", []),
            "notes":        d.get("notes", ""),
            "address":      d.get("address", ""),
        })

    return results


def get_uplinks() -> list[dict]:
    """WAN uplink health per site, formatted for the UI."""
    uplinks  = _cache["uplinks"]["data"]
    networks = _cache["networks"]["data"]
    net_map  = {n["id"]: n for n in networks}

    result = []
    for appliance in uplinks:
        net_id = appliance.get("networkId", "")
        net    = net_map.get(net_id, {})
        result.append({
            "network_id":   net_id,
            "network_name": net.get("name", net_id),
            "org_name":     net.get("org_name", ""),
            "serial":       appliance.get("serial", ""),
            "model":        appliance.get("model", ""),
            "uplinks": [
                {
                    "interface":  u.get("interface", ""),
                    "status":     u.get("status", ""),
                    "ip":         u.get("ip", ""),
                    "gateway":    u.get("gateway", ""),
                    "public_ip":  u.get("publicIp", ""),
                    "isp":        u.get("provider", ""),
                    "connection": u.get("connectionType", ""),
                }
                for u in appliance.get("uplinks", [])
            ],
        })

    return result


_MAC_RE = re.compile(r"^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$", re.IGNORECASE)

def _is_mac(s: str) -> bool:
    return bool(_MAC_RE.match(s or ""))

def _normalize_mac(mac: str) -> str:
    """Normalize MAC to lowercase colon-separated format."""
    return mac.lower().replace("-", ":").strip()

def _enrich_client(c: dict, networks: list, devices: list) -> dict:
    """
    Build a fully enriched client record.
    Resolves AP name, switch name, switch port, VLAN, firewall (MX) for the network.
    """
    net_map    = {n["id"]: n for n in networks}
    device_map = {d.get("mac", "").lower(): d for d in devices}
    # Also index devices by networkId + model prefix for firewall lookup
    net_id     = c.get("networkId") or c.get("network_id", "")
    net        = net_map.get(net_id, {})
    org_name   = net.get("org_name", "") or c.get("org_name", "")

    connection_type = "wireless" if c.get("ssid") else "wired"

    # ── Access Point ──────────────────────────────────────────────────────────
    ap_mac  = (c.get("recentDeviceMac") or "").lower()
    ap_dev  = device_map.get(ap_mac, {})
    ap_info = None
    if ap_mac:
        ap_info = {
            "mac":          ap_mac,
            "name":         c.get("recentDeviceName") or ap_dev.get("name", ""),
            "model":        ap_dev.get("model", ""),
            "serial":       ap_dev.get("serial", ""),
            "network_name": net.get("name", ""),
        }

    # ── Switch / wired connection ─────────────────────────────────────────────
    switch_info = None
    switchport  = c.get("switchport") or c.get("recentDevicePort")
    if connection_type == "wired" and ap_mac:
        sw_dev = device_map.get(ap_mac, {})
        if sw_dev.get("model", "").startswith("MS"):
            switch_info = {
                "mac":          ap_mac,
                "name":         sw_dev.get("name", ""),
                "model":        sw_dev.get("model", ""),
                "serial":       sw_dev.get("serial", ""),
                "port":         switchport or "",
                "network_name": net.get("name", ""),
            }

    # ── Firewall (MX appliance for this network) ───────────────────────────────
    firewall_info = None
    for d in devices:
        if d.get("networkId") == net_id and d.get("model", "").startswith("MX"):
            firewall_info = {
                "name":    d.get("name", ""),
                "model":   d.get("model", ""),
                "serial":  d.get("serial", ""),
                "lan_ip":  d.get("lanIp", ""),
                "wan1_ip": d.get("wan1Ip", ""),
                "wan2_ip": d.get("wan2Ip", ""),
            }
            break  # take first MX found for the network

    # ── Usage ──────────────────────────────────────────────────────────────────
    usage = c.get("usage") or {}
    usage_kb = (usage.get("sent") or 0) + (usage.get("recv") or 0)

    return {
        "description":      c.get("description") or c.get("dhcpHostname") or "",
        "hostname":         c.get("dhcpHostname") or "",
        "ip":               c.get("ip", ""),
        "mac":              c.get("mac", ""),
        "user":             c.get("user") or "",
        "os":               c.get("os") or "",
        "vlan":             c.get("vlan") or "",
        "ssid":             c.get("ssid") or "",
        "switchport":       switchport or "",
        "connection_type":  connection_type,
        "last_seen":        c.get("lastSeen") or "",
        "first_seen":       c.get("firstSeen") or "",
        "usage_kb":         usage_kb,
        "usage_sent_kb":    usage.get("sent") or 0,
        "usage_recv_kb":    usage.get("recv") or 0,
        "network_id":       net_id,
        "network_name":     net.get("name", "") or c.get("network_name", ""),
        "org_name":         org_name,
        # Resolved infrastructure chain
        "access_point":     ap_info,
        "switch":           switch_info,
        "firewall":         firewall_info,
    }


def mac_lookup(mac: str) -> dict:
    """
    Deep MAC address lookup.
    1. Check the in-memory client cache first (fast).
    2. If not found, search across all networks via live API calls (slower but thorough).
    3. Enrich result with AP, switch, firewall chain.
    Returns a structured dict with the full network path for the device.
    """
    mac = _normalize_mac(mac)
    networks = _cache["networks"]["data"]
    devices  = _cache["devices"]["data"]
    clients  = _cache["clients"]["data"]

    # ── Step 1: Check cache ───────────────────────────────────────────────────
    cached_match = next(
        (c for c in clients if _normalize_mac(c.get("mac", "")) == mac),
        None
    )
    if cached_match:
        logger.info(f"Meraki MAC lookup: {mac} found in cache.")
        enriched = _enrich_client(cached_match, networks, devices)
        return {
            "found":      True,
            "mac":        mac,
            "source":     "cache",
            "client":     enriched,
            "checkpoint": None,  # placeholder — wired in Monday
            "zscaler":    None,  # placeholder — wired in Monday
        }

    # ── Step 2: Live search across all networks ───────────────────────────────
    logger.info(f"Meraki MAC lookup: {mac} not in cache — searching live across {len(networks)} networks...")
    for net in networks:
        # Use a longer timespan for live search (24h) to catch less-active devices
        data = _get(
            f"/networks/{net['id']}/clients",
            params={"timespan": 86400, "perPage": 1000}
        )
        if not data:
            continue
        for c in data:
            if _normalize_mac(c.get("mac", "")) == mac:
                c["network_id"]   = net["id"]
                c["network_name"] = net.get("name", "")
                c["org_name"]     = net.get("org_name", "")
                enriched = _enrich_client(c, networks, devices)
                logger.info(f"Meraki MAC lookup: {mac} found live in network {net['name']}.")
                return {
                    "found":      True,
                    "mac":        mac,
                    "source":     "live",
                    "client":     enriched,
                    "checkpoint": None,
                    "zscaler":    None,
                }

    # ── Step 3: Check if it's an infrastructure device MAC ───────────────────
    infra_match = next(
        (d for d in devices if _normalize_mac(d.get("mac", "")) == mac),
        None
    )
    if infra_match:
        return {
            "found":   True,
            "mac":     mac,
            "source":  "infrastructure",
            "client":  None,
            "device": {
                "name":         infra_match.get("name", ""),
                "model":        infra_match.get("model", ""),
                "serial":       infra_match.get("serial", ""),
                "lan_ip":       infra_match.get("lanIp", ""),
                "mac":          infra_match.get("mac", ""),
                "network_name": infra_match.get("network_name", ""),
                "org_name":     infra_match.get("org_name", ""),
                "note":         "This MAC belongs to a Meraki infrastructure device, not an endpoint.",
            },
            "checkpoint": None,
            "zscaler":    None,
        }

    logger.info(f"Meraki MAC lookup: {mac} not found anywhere.")
    return {
        "found":      False,
        "mac":        mac,
        "source":     None,
        "client":     None,
        "checkpoint": None,
        "zscaler":    None,
    }


def lookup_endpoint(query: str) -> dict:
    """
    General endpoint lookup — given an IP, MAC, or hostname fragment,
    find where the device is connected in Meraki.
    For MAC addresses, delegates to mac_lookup() for deep enrichment.
    """
    query = (query or "").strip().lower()
    if not query:
        return {"query": query, "clients": [], "devices": [], "mac_result": None}

    # If the query looks like a MAC, do a deep MAC lookup
    if _is_mac(query):
        result = mac_lookup(query)
        return {
            "query":      query,
            "is_mac":     True,
            "mac_result": result,
            "clients":    [result["client"]] if result.get("client") else [],
            "devices":    [result["device"]] if result.get("device") else [],
        }

    # General search — IP, hostname, username fragment
    clients = _cache["clients"]["data"]
    devices = _cache["devices"]["data"]
    networks = _cache["networks"]["data"]

    matched_clients = []
    for c in clients:
        haystack = " ".join([
            c.get("ip", ""),
            c.get("mac", ""),
            c.get("description", "") or "",
            c.get("dhcpHostname", "") or "",
            c.get("user", "") or "",
        ]).lower()
        if query in haystack:
            matched_clients.append(_enrich_client(c, networks, devices))

    matched_devices = []
    for d in devices:
        haystack = " ".join([
            d.get("name", "") or "",
            d.get("lanIp", "") or "",
            d.get("wan1Ip", "") or "",
            d.get("mac", "") or "",
            d.get("serial", "") or "",
        ]).lower()
        if query in haystack:
            matched_devices.append({
                "name":         d.get("name") or d.get("mac", ""),
                "model":        d.get("model", ""),
                "serial":       d.get("serial", ""),
                "lan_ip":       d.get("lanIp", ""),
                "mac":          d.get("mac", ""),
                "network_name": d.get("network_name", ""),
                "org_name":     d.get("org_name", ""),
            })

    return {
        "query":      query,
        "is_mac":     False,
        "mac_result": None,
        "clients":    matched_clients[:50],
        "devices":    matched_devices[:20],
    }


def get_clients(network_id: str = None, limit: int = 200) -> list[dict]:
    """Recent clients, optionally filtered by network."""
    clients = _cache["clients"]["data"]
    result = []
    for c in clients:
        if network_id and c.get("network_id") != network_id:
            continue
        result.append({
            "description":  c.get("description") or c.get("dhcpHostname", ""),
            "ip":           c.get("ip", ""),
            "mac":          c.get("mac", ""),
            "user":         c.get("user", ""),
            "vlan":         c.get("vlan", ""),
            "switchport":   c.get("switchport", ""),
            "ssid":         c.get("ssid", ""),
            "network_name": c.get("network_name", ""),
            "org_name":     c.get("org_name", ""),
            "last_seen":    c.get("lastSeen", ""),
            "connection_type": "wireless" if c.get("ssid") else "wired",
        })
    return result[:limit]