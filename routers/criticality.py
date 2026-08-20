"""
routers/criticality.py
Asset Criticality Registry — backend logic and AI-assist suggestion.
Routes are registered in main.py.
"""

import os
import json
import re
import threading
import httpx
from anthropic import Anthropic

_TEAMS = [
    "Wintel", "Citrix", "VMware", "Network", "Linux",
    "DBA", "O365 / Entra", "Security", "AWS", "Storage", "Other"
]

TEAMS = _TEAMS


def _client():
    return Anthropic(
        api_key=os.getenv("CLAUDE_API_KEY"),
        http_client=httpx.Client(verify=False, timeout=30.0),
    )


def _parse_json_response(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    return json.loads(text)


def ai_suggest_criticality(device_name: str,
                            lansweeper_data: "dict | None" = None,
                            vmware_data: "dict | None" = None) -> dict:
    """
    Use Claude to suggest a criticality tier, service description, and blast radius
    for a device. Enriches the prompt with Lansweeper and/or VMware data when available.

    Returns: {tier, service_description, blast_radius, owner_team, is_singleton, confidence, notes}
    """
    ls_context = ""
    if lansweeper_data:
        ls_context = (
            f"\nLansweeper inventory data for this device:\n"
            f"  OS: {lansweeper_data.get('os_name') or lansweeper_data.get('os', 'Unknown')}\n"
            f"  Type: {lansweeper_data.get('type', 'Unknown')}\n"
            f"  Last seen: {lansweeper_data.get('last_seen', 'Unknown')}\n"
            f"  IP: {lansweeper_data.get('ip_address') or lansweeper_data.get('ip', 'Unknown')}\n"
            f"  Manufacturer: {lansweeper_data.get('manufacturer', '')}\n"
            f"  Model: {lansweeper_data.get('model', '')}\n"
            f"  Description: {lansweeper_data.get('description', '')}\n"
        )

    vm_context = ""
    if vmware_data:
        vm_context = (
            f"\nVMware inventory data for this device:\n"
            f"  OS: {vmware_data.get('os_name', 'Unknown')}\n"
            f"  CPU count: {vmware_data.get('cpu_count', 'Unknown')}\n"
            f"  Power state: {vmware_data.get('power_state', 'Unknown')}\n"
            f"  Environment: {vmware_data.get('environment', 'Unknown')}\n"
            f"  IP: {vmware_data.get('ip_address', 'Unknown')}\n"
        )

    prompt = f"""You are a senior infrastructure analyst at Zinnia, an insurance technology company.

Zinnia's server naming convention: LOCATION+ROLE+NUMBER+TIER
  Locations: TOP=Topeka, VMCE=VMC on AWS, CAN=Candor India
  Tiers: P=Production (highest priority), Q=QA, D/U/T=Dev/UAT/Test (lowest priority)

Examples of role keywords in names:
  LIC/LICENSE = license server (often singleton, high blast radius)
  DC/AD = Active Directory domain controller (critical infrastructure)
  SQL/DB = database server
  FS/FILE = file server
  APP = application server
  CTX/XA/VDA = Citrix
  WEB/IIS = web server
  SMTP/MAIL = mail/SMTP relay
  PROXY/GW = gateway/proxy
  BACKUP/VBR = backup server
  MGT/MGMT = management server
  MON/SCOM = monitoring server
{ls_context}{vm_context}
Device to classify: {device_name}

Respond with ONLY valid JSON, no prose or markdown:
{{
  "tier": "P1|P2|P3|INFO",
  "service_description": "one concise sentence describing what this server does",
  "blast_radius": "one sentence describing what breaks or who is affected if this goes down",
  "owner_team": "most likely owner team from: Wintel, Citrix, VMware, Network, Linux, DBA, O365 / Entra, Security, AWS, Storage, Other",
  "is_singleton": true|false,
  "confidence": "high|medium|low",
  "notes": "brief reasoning for the tier choice"
}}

Tier guidance:
  P1 = Critical singleton with wide blast radius (license servers, primary DCs, core auth services)
  P2 = Important but has some redundancy or limited to a team/application
  P3 = Normal server — dev/test, redundant, or limited impact if down
  INFO = Informational/monitoring interest only"""

    client = _client()
    resp = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    return _parse_json_response(resp.content[0].text)


def ai_suggest_group(group_name: str, match_type: str, match_value: str,
                     sample_devices: list,
                     existing_members: "list[str] | None" = None) -> dict:
    """
    Suggest default tier, team, and descriptions for a device group based on
    the naming pattern and sample matching devices from multiple inventory sources.

    sample_devices: additional candidate devices (not yet in the group).
    existing_members: device names already in the group (OPM-synced).

    Returns: {default_tier, owner_team, service_description, blast_radius,
              is_singleton, confidence, notes}
    """
    match_label = {
        "prefix": f"starts with \"{match_value}\"",
        "suffix": f"ends with \"{match_value}\"",
        "contains": f"contains \"{match_value}\"",
        "exact": f"exactly equals \"{match_value}\"",
    }.get(match_type, f"{match_type} \"{match_value}\"")

    # Build samples section — show up to 20 devices, grouped by source for readability
    samples_text = ""
    if sample_devices:
        by_source: dict = {}
        for d in sample_devices[:20]:
            src = d.get("source", "unknown")
            by_source.setdefault(src, []).append(d)

        total = len(sample_devices)
        samples_text = f"\nDevice inventory context ({total} devices found across all connected sources):\n"
        for src, devs in by_source.items():
            source_label = {
                "lansweeper": "Lansweeper (Windows/physical inventory)",
                "vmware": "VMware vCenter (virtual machines)",
                "meraki": "Cisco Meraki (network devices)",
                "citrix": "Citrix Cloud (VDI/app delivery)",
                "opmanager": "OpManager (monitored devices)",
            }.get(src, src.capitalize())
            samples_text += f"\n  [{source_label}]\n"
            for d in devs[:8]:
                line = f"    - {d['device_name']}"
                if d.get('type'):        line += f"  |  Type: {d['type']}"
                if d.get('os'):          line += f"  |  OS: {d['os']}"
                if d.get('environment'): line += f"  |  Context: {d['environment']}"
                samples_text += line + "\n"

    # Existing members context (for edit mode)
    existing_text = ""
    if existing_members:
        member_list = "\n".join(f"    - {n}" for n in existing_members[:30])
        existing_text = f"\nThis group already has {len(existing_members)} confirmed member(s) (synced from OpManager):\n{member_list}\n"

    # Indicate whether match_value was pre-supplied or needs to be suggested
    pattern_note = (
        f'The user has already specified: device name {match_label}. Confirm or refine the match_value.'
        if match_value else
        'The user has NOT yet specified a match pattern — infer the best match_type and match_value from the device names in the inventory data.'
    )

    # Label for the additional devices section
    additional_label = (
        "Additional candidate devices from inventory (NOT yet in this group — suggest which belong):"
        if existing_members else
        "Device inventory context"
    )
    if samples_text:
        samples_text = samples_text.replace("Device inventory context", additional_label)

    prompt = f"""You are a senior infrastructure analyst at Zinnia, an insurance technology company.

Zinnia's server naming convention: LOCATION+ROLE+NUMBER+TIER
  Locations: TOP=Topeka, AWS=cloud (VMCE prefix), CAN=Candor India
  Tiers: P=Production, Q=QA, D/U/T=Dev/UAT/Test
  Owner teams: Wintel (Windows servers), Citrix (VDI/app delivery), VMware (hypervisor/vCenter),
    Network (switches/routers/firewalls), Linux, DBA (databases), O365 / Entra, Security, AWS, Storage
{existing_text}
I'm {"editing" if existing_members else "creating"} a device GROUP in our criticality registry.
  Group name: "{group_name}"
  {pattern_note}
{samples_text}
{"Use the existing members and their naming patterns to identify the owner team, tier, and service purpose." if existing_members else "Use the actual device types, OS, and context shown to reason about what these devices do and who owns them."}
Suggest the default criticality settings that should apply to ALL devices in this group.

Respond with ONLY valid JSON, no prose or markdown:
{{
  "default_tier": "P1|P2|P3|INFO",
  "owner_team": "most likely team from: Wintel, Citrix, VMware, Network, Linux, DBA, O365 / Entra, Security, AWS, Storage, Other",
  "match_type": "prefix|suffix|contains|exact",
  "match_value": "the string to match device names against (e.g. TOPCTX, CTX, -SW-, leave empty string if no reliable pattern exists)",
  "service_description": "one sentence describing what these devices collectively do",
  "blast_radius": "one sentence describing the impact if devices in this group are unavailable",
  "is_singleton": false,
  "confidence": "high|medium|low",
  "notes": "brief reasoning citing specific device names as evidence"
}}

Tier guidance:
  P1 = Critical singletons or small groups with wide blast radius (core auth, license servers, primary network)
  P2 = Important group — some redundancy or bounded impact (team-specific, application-scoped)
  P3 = Normal devices — dev/test, redundant, or limited impact if down
  INFO = Informational/monitoring only

Match type guidance:
  prefix  = all devices share a common name start (most reliable, prefer this when possible)
  suffix  = share a common name ending (e.g. tier suffix like -P or -Q)
  contains = a substring appears anywhere in the name
  exact   = single specific device name"""

    client = _client()
    resp = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=600,
        messages=[{"role": "user", "content": prompt}],
    )
    return _parse_json_response(resp.content[0].text)


def ai_noc_triage(alarms: list, crit_map: dict, cascades: list) -> dict:
    """
    AI root-cause analysis for the NOC dashboard.
    Returns: {root_cause, severity, affected_count, primary_team, all_teams,
              next_steps, confidence, summary}
    """
    critical = [a for a in alarms if a.get("severity") in ("Critical", "Major")][:20]
    warning  = [a for a in alarms if a.get("severity") == "Warning"][:8]

    alarm_lines = []
    for a in critical:
        name  = a.get("device_name", "")
        tier  = a.get("criticality_tier") or "?"
        team  = a.get("criticality_team") or "?"
        desc  = a.get("criticality_desc") or ""
        loc   = a.get("location") or "?"
        alarm_lines.append(
            f"  CRITICAL: {name} [{tier}] team={team} loc={loc} — {a.get('alarm_name','?')}"
            + (f" | {desc}" if desc else "")
        )
    for a in warning:
        name = a.get("device_name", "")
        tier = a.get("criticality_tier") or "?"
        team = a.get("criticality_team") or "?"
        alarm_lines.append(f"  WARNING:  {name} [{tier}] team={team} — {a.get('alarm_name','?')}")

    cascade_text = ""
    if cascades:
        cascade_text = "\n\nDetected cascade patterns:\n"
        for c in cascades:
            cascade_text += f"  - {c.get('location','?')} site: {c['device_count']} devices affected\n"
            cascade_text += f"    Devices: {', '.join(c['devices'][:6])}\n"

    prompt = f"""You are a NOC analyst at Zinnia, an insurance technology company.

Zinnia naming: TOP=Topeka site, CAN=Candor India, VMCE=VMware Cloud on AWS
Tiers: P1=critical singleton, P2=important, P3=normal

Current active alarms (most critical first):
{chr(10).join(alarm_lines) if alarm_lines else '  No critical alarms — all clear'}
{cascade_text}
Look for common root causes, location patterns, and P1 singletons needing immediate action.

Respond with ONLY valid JSON, no prose or markdown:
{{
  "root_cause": "one sentence — most likely root cause, or 'Multiple independent issues' if unrelated",
  "severity": "critical|high|medium|low|none",
  "affected_count": {len(set(a.get('device_name','') for a in critical))},
  "primary_team": "team to escalate FIRST from: Wintel, Citrix, VMware, Network, Linux, DBA, O365 / Entra, Security, AWS, Storage, Other",
  "all_teams": ["every team that needs notification"],
  "next_steps": ["action 1", "action 2", "action 3"],
  "confidence": "high|medium|low",
  "summary": "2-3 sentence NOC-ready summary for the on-call engineer"
}}"""

    client = _client()
    resp = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    return _parse_json_response(resp.content[0].text)


# ── Dependency suggestion state ───────────────────────────────────────────────

_dep_state: dict = {"running": False, "result": None, "error": None, "added": 0}
_dep_lock = threading.Lock()


def ai_suggest_dependencies(groups: list) -> list:
    """
    Analyse OpManager group names and sample devices to infer dependency edges.
    Returns: [{from_group, to_group, dep_type, confidence, notes}]
    """
    group_lines = []
    for g in groups[:50]:
        devices_preview = ", ".join((g.get("devices") or [])[:6])
        group_lines.append(
            f"  - {g['name']} | Location: {g.get('location','?')} | "
            f"Devices: {g.get('device_count',0)} | "
            f"Sample: {devices_preview or 'none'} | "
            f"Desc: {(g.get('description') or '')[:80]}"
        )

    prompt = f"""You are a senior infrastructure analyst at Zinnia, an insurance technology company.

Zinnia runs infrastructure across:
  - Topeka (TOP prefix) — primary US datacenter
  - Candor (CAN prefix) — India office
  - VMC (VMCE prefix) — VMware Cloud on AWS

Below are OpManager device groups with sample device names. Identify DEPENDENCY relationships:
if Group B (root cause) fails → Group A (dependent) is likely impacted.

Groups:
{chr(10).join(group_lines)}

Suggest dependencies based on:
1. GEOGRAPHIC: groups in a location depend on that location's network/router group
2. APPLICATION: web/app servers depend on database groups; apps depend on auth/license servers
3. INFRASTRUCTURE: all groups depend on AD, DNS, NTP groups (if present)
4. SERVICE: specific apps depend on license servers, print servers, SMTP relays

Return ONLY a JSON array of up to 25 edges. Use EXACT group names from the list:
[
  {{
    "from_group": "group name that has the dependency (dependent)",
    "to_group": "group name being depended upon (root cause candidate)",
    "dep_type": "geographic|application|infrastructure|service",
    "confidence": "high|medium|low",
    "notes": "one sentence explaining the relationship"
  }}
]

Only include edges where there is clear evidence. Return [] if none."""

    client = _client()
    resp = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )
    result = _parse_json_response(resp.content[0].text)
    return result if isinstance(result, list) else []


def run_dep_suggest_background(groups: list) -> None:
    """Fire-and-forget wrapper — stores result in _dep_state."""
    from routers.database import bulk_add_dependencies

    with _dep_lock:
        _dep_state["running"] = True
        _dep_state["result"]  = None
        _dep_state["error"]   = None
        _dep_state["added"]   = 0

    def _worker():
        try:
            edges = ai_suggest_dependencies(groups)
            added = bulk_add_dependencies(edges)
            with _dep_lock:
                _dep_state["result"]  = edges
                _dep_state["added"]   = added
        except Exception as exc:
            with _dep_lock:
                _dep_state["error"] = str(exc)
        finally:
            with _dep_lock:
                _dep_state["running"] = False

    threading.Thread(target=_worker, daemon=True).start()


def get_dep_suggest_status() -> dict:
    with _dep_lock:
        return dict(_dep_state)


# ── Location detection ────────────────────────────────────────────────────────

def detect_location(display_name: str) -> str:
    """Infer Zinnia site from device naming convention."""
    n = (display_name or "").upper()
    if n.startswith("VMCE"):   return "VMC"
    if n.startswith("CAN"):    return "Candor"
    if n.startswith("TOP"):    return "Topeka"
    return "Other"


def compute_group_status(devices: list, alarm_device_set: set) -> dict:
    """
    Given a list of group devices and a set of device names currently in alarm,
    return {status, alert_count, worst_sev_num, location}.

    status: 'critical' | 'warning' | 'minor' | 'clear'
    """
    worst_sev = 5
    alert_count = 0
    loc_votes = {"Topeka": 0, "Candor": 0, "VMC": 0, "Other": 0}

    for d in devices:
        name = (d.get("display_name") or "")
        loc_votes[detect_location(name)] += 1
        sn = d.get("status_num", 5)
        if name.upper() in alarm_device_set:
            alert_count += 1
            if sn < worst_sev:
                worst_sev = sn

    location = max(loc_votes, key=loc_votes.get)
    if loc_votes[location] == 0:
        location = "Unknown"

    if worst_sev <= 1:   status = "critical"
    elif worst_sev <= 2: status = "critical"
    elif worst_sev <= 3: status = "warning"
    elif worst_sev <= 4: status = "minor"
    else:                status = "clear"

    return {"status": status, "alert_count": alert_count,
            "worst_sev_num": worst_sev, "location": location}


def get_unclassified_devices(alarms: list, criticality_map: dict) -> list:
    """
    Given a list of active alarms and the criticality map, return devices
    that are generating alerts but aren't in the criticality registry.
    """
    from collections import defaultdict
    device_stats: dict = defaultdict(lambda: {"alarm_count": 0, "worst_severity": "Clear", "worst_severity_num": 99})

    for alarm in alarms:
        name = (alarm.get("device_name") or "").strip()
        if not name:
            continue
        if name.upper() in criticality_map:
            continue
        stats = device_stats[name]
        stats["alarm_count"] += 1
        sev_num = alarm.get("severity_num", 99)
        if sev_num < stats["worst_severity_num"]:
            stats["worst_severity_num"] = sev_num
            stats["worst_severity"] = alarm.get("severity", "Unknown")

    return sorted(
        [{"device_name": k, **v} for k, v in device_stats.items()],
        key=lambda x: (x["worst_severity_num"], -x["alarm_count"])
    )
