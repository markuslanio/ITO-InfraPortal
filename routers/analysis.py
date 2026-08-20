import os
import json
import re
import time
import logging
import httpx
from anthropic import Anthropic, APIStatusError
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
client = Anthropic(
    api_key=os.getenv("CLAUDE_API_KEY"),
    http_client=httpx.Client(verify=False, timeout=120.0),
)

APPLIANCE_PATTERNS = [
    'nsx', 'vcenter', 'hcx', 'vrealize', 'vrops', 'vrli', 'vcloud',
    'zscaler', 'zpa', 'zpa-connector', 'zpa-service', 'zpas',
    'aws-storage-gateway', 'aws-datasync', 'aws-storage', 'storage-gateway',
    'datasync', 'aws-gateway',
    'veeam', 'veeamdb',
    'nessus', 'tenable', 'nodezero', 'securitycenter', 'tenableweb',
    'canary', 'virtualcanary',
    'opendns', 'datadog', 'expel',
    'vcls', 'hcx_cloud', 'hcx-cloud',
    'topvmprxy', 'vmprxy', 'vmprxyapp', 'vmcusevmprxy',
    'vropsdata', 'topvrli', 'vrli',
    'sunapp', 'gpsr', 'automation-smc',
    'nsxt', 'nsxmanager',
    'topnascv', 'nascv',
    'topehcmd', 'ehcmd',
    'topautomtapp', 'automtapp',
    'cisco', 'meraki', 'checkpoint',
    'palo', 'fortinet', 'juniper',
    'f5', 'bigip', 'netscaler',
    'infoblox', 'bluecoat', 'ironport',
    'avamar', 'networker', 'commvault', 'rubrik', 'cohesity',
    'solarwinds', 'nagios', 'zabbix', 'prtg',
    'topvmgwapp', 'vmgwapp', 'vcgwapp', 'topvcgwapp',
    'lna_zpa', 'lna-zpa', 'canzpaedge', 'zpaedge',
    'setopcsr1000v', 'setopcsr',
    'topwso2', 'wso2',
    'topdellome', 'dellome', 'topdellomivv',
    'topsfmnode', 'sfmnode',
    'topnps', 'setopocum', 'ocum',
    'setopsat',
    'tophcxmgr', 'hcxmgr',
    'toplansweep', 'lansweep',
    'gpsript',
    'smyopman', 'opmancent', 'opmdb', 'opmprb',
    'smycrmjen',
    'topdigisc', 'digics',
    'vmcusewsonecon', 'wsonecon',
    'vmcecone',
]

VDI_PATTERNS = [
    'topctxvdi', 'ctxvdi',
    'pveaaxd', 'dveaaxd',
    'vmcevdibot', 'vmctxvdibot',
]

CITRIX_SERVER_PATTERNS = [
    'vmcectxsrv', 'topctxccp', 'topctxccapp',
    'topctxcclmi', 'topctxaclmi', 'topctxalumi',
    'topctxadev', 'topctxdst', 'topctxdev',
    'topctx2019', 'topctxfas', 'topctxccfas',
    'vmcectxfas', 'vmcectxdc', 'vmcectxsf',
    'vmcectxlc', 'vmcectxsql', 'vmcectxdrfs',
    'vmcectxfs', 'vmcusectxcc', 'vmcusectxdc',
    'vmcusectxsf', 'vmcusectxlc', 'vmcusectxsql',
    'vmcusectxdrfs', 'vmcusectxfs',
    'topctxccmi', 'vmcectxwin',
    'topctxxdmi', 'topctxa02p',
]

GRADE_LABELS = {
    "OVERALL":            "Overall Infrastructure Health",
    "CPU_AND_COMPUTE":    "CPU & Compute",
    "STORAGE":            "Storage",
    "VM_ORGANIZATION":    "VM Organization",
    "PATCHING_AND_TOOLS": "Patching & Tools",
    "PATCH_COMPLIANCE":   "Patch Compliance",
    "ALERT_HEALTH":       "Alert Health",
    "ACTIVE_DIRECTORY":   "Active Directory",
    "CERTIFICATE_HEALTH": "Certificates",
    "CITRIX_HEALTH":      "Citrix Health",
}


# ── Claude API helper with retry ──────────────────────────────────────────────

def _call_claude(model: str, max_tokens: int, messages: list, max_retries: int = 3) -> str:
    """
    Call the Claude API with automatic retry on transient errors:
      - 500 Internal Server Error (Anthropic backend issue)
      - 529 Overloaded (Anthropic capacity issue)
    Raises on non-retryable errors or after max_retries exhausted.
    """
    delays = [5, 15, 30]  # seconds between retries

    for attempt in range(1, max_retries + 1):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=messages,
            )
            return response.content[0].text  # type: ignore[union-attr]

        except APIStatusError as e:
            if e.status_code in (500, 529) and attempt < max_retries:
                delay = delays[attempt - 1]
                logger.warning(
                    "Claude API error %d on attempt %d/%d — retrying in %ds: %s",
                    e.status_code, attempt, max_retries, delay, str(e)
                )
                time.sleep(delay)
            else:
                logger.error("Claude API error %d (non-retryable or max retries reached): %s",
                             e.status_code, str(e))
                raise

        except Exception as e:
            logger.error("Claude API unexpected error on attempt %d: %s", attempt, str(e))
            raise

    raise RuntimeError("Claude API call failed after all retries")


# ── VM classification helpers ─────────────────────────────────────────────────

def get_vm_category(name):
    if not name:
        return "unknown"
    n = name.lower()
    for p in VDI_PATTERNS:
        if p in n: return "vdi"
    for p in CITRIX_SERVER_PATTERNS:
        if p in n: return "citrix"
    for p in APPLIANCE_PATTERNS:
        if p in n: return "appliance"
    return "server"


def is_appliance(name):
    return get_vm_category(name) in ("appliance", "vdi")


def get_server_tier(name):
    if not name:
        return {"tier": 4, "label": "Unknown", "color": "gray"}
    cat = get_vm_category(name)
    if cat == "appliance":
        return {"tier": 5, "label": "Appliance", "color": "gray"}
    if cat == "vdi":
        return {"tier": 6, "label": "VDI", "color": "gray"}
    if cat == "citrix":
        return {"tier": 1, "label": "Citrix Server", "color": "purple"}
    u = name.upper().split("\\")[-1]
    if re.search(r'\d{2}P$', u) or re.search(r'[A-Z]P$', u):
        return {"tier": 1, "label": "Production", "color": "red"}
    if re.search(r'\d{2}Q$', u) or re.search(r'[A-Z]Q$', u) or 'QA' in u:
        return {"tier": 2, "label": "QA", "color": "orange"}
    if re.search(r'\d{2}[DUT]$', u) or re.search(r'[A-Z][DUT]$', u):
        return {"tier": 3, "label": "Dev/Test", "color": "blue"}
    return {"tier": 4, "label": "Unknown", "color": "gray"}


def check_disk_threshold(storage_vms, threshold_pct=15):
    low = []
    for vm in storage_vms:
        for drive in vm.get("drives", []):
            if drive.get("pct_free", 100) <= threshold_pct:
                low.append({
                    "vm_name":     vm.get("name"),
                    "environment": vm.get("environment"),
                    "drive":       drive.get("letter"),
                    "capacity_gb": drive.get("capacity_gb"),
                    "free_gb":     drive.get("free_gb"),
                    "pct_free":    drive.get("pct_free"),
                })
    return low


def get_critical_unacked_hours(alarms, hours=4):
    return [a for a in alarms
            if a.get("severity") in ["Critical", "Trouble"]
            and not a.get("acknowledged")]


# ── Master image helpers ──────────────────────────────────────────────────────

def _is_master_image_by_name(vm_name):
    if not vm_name:
        return False
    n = vm_name.upper().split("\\")[-1]
    if re.search(r'(XDMI|CTXMI|XAMI|XDGMI)', n):
        return True
    if re.search(r'^(TOP|VMCE|AWS|CAN)[A-Z0-9]+MI\d{2}[PQDUTR]?$', n):
        return True
    return False


def _build_master_image_lookup(citrix_data):
    if not citrix_data or citrix_data.get("error"):
        return set(), {}
    lookup = {}
    for img in citrix_data.get("master_images", []):
        short = img.get("hostname_lower", "")
        if short:
            lookup[short] = img
    return set(lookup.keys()), lookup


def _flag_master_images(vms, master_image_hostnames, master_image_lookup):
    flagged = []
    seen = set()
    for vm in vms:
        name  = vm.get("name", "")
        short = name.lower().split(".")[0]
        if short in seen:
            continue
        img_info     = master_image_lookup.get(short, {})
        from_catalog = short in master_image_hostnames
        from_name    = _is_master_image_by_name(name)
        if from_catalog or from_name:
            seen.add(short)
            flagged.append({
                "vm_name":      name,
                "environment":  vm.get("environment"),
                "catalog":      img_info.get("catalog_name"),
                "zone":         img_info.get("zone"),
                "provisioning": img_info.get("provisioning"),
                "tier":         get_server_tier(name)["label"],
                "detected_by":  ("catalog+name" if (from_catalog and from_name)
                                 else ("catalog" if from_catalog else "name")),
            })
    return flagged


# ── Lens analysis helper ──────────────────────────────────────────────────────

def _build_lens_section(alerts_ai=None, vmware_ai=None, citrix_ai=None,
                         ad_ai=None, assets_ai=None) -> dict:
    """
    Extract the compact, signal-rich parts of each focused lens analysis
    to include in the main analysis prompt without blowing up token count.
    Each lens result is expected to have: grade, summary, patterns, recommendations.
    Returns a dict with present keys only — None lenses are omitted.
    """
    def _extract(result):
        if not result or not isinstance(result, dict):
            return None
        return {
            "grade":           result.get("grade"),
            "summary":         result.get("summary"),
            "patterns":        (result.get("patterns") or [])[:5],
            "recommendations": (result.get("recommendations") or [])[:5],
        }

    section = {}
    for key, val in [("alerts", alerts_ai), ("vmware", vmware_ai),
                     ("citrix", citrix_ai), ("ad", ad_ai), ("assets", assets_ai)]:
        extracted = _extract(val)
        if extracted:
            section[key] = extracted
    return section


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_infrastructure(vms, hosts, untagged_vms, storage_data,
                            alarms=None, recurring_alerts=None,
                            disk_trends=None, powered_off_vms=None,
                            ad_data=None, cert_data=None, citrix_data=None,
                            lansweeper_data=None,
                            alerts_ai_analysis=None,
                            vmware_ai_analysis=None,
                            citrix_ai_analysis=None,
                            ad_ai_analysis=None,
                            assets_ai_analysis=None):

    citrix_machine_set = {}
    if citrix_data and not citrix_data.get("error"):
        try:
            from routers.citrix import get_citrix_machine_name_set
            citrix_machine_set = get_citrix_machine_name_set()
        except Exception:
            pass

    master_image_hostnames, master_image_lookup = _build_master_image_lookup(citrix_data)

    powered_on        = [v for v in vms if v.get("power_state") == "POWERED_ON"]
    powered_off       = [v for v in vms if v.get("power_state") != "POWERED_ON"]
    eol_vms           = [v for v in vms if v.get("eol")]
    tools_outdated    = [v for v in vms if v.get("tools_upgrade_needed")]
    maintenance_hosts = [h for h in hosts if h.get("maintenance_mode")]
    low_disk          = check_disk_threshold(storage_data)
    urgent_alerts     = get_critical_unacked_hours(alarms or [], hours=4)
    recurring         = recurring_alerts or []
    trends            = disk_trends or []

    low_disk_real = [
        d for d in low_disk
        if d.get("vm_name", "").lower().split(".")[0] not in master_image_hostnames
    ]

    tier_breakdown = {"Production": 0, "QA": 0, "Dev/Test": 0,
                      "Citrix Server": 0, "Appliance": 0, "VDI": 0, "Unknown": 0}
    prod_eol = []
    prod_low_disk = []
    prod_tools_outdated = []
    prod_untagged = []

    for vm in vms:
        label = get_server_tier(vm.get("name"))["label"]
        tier_breakdown[label] = tier_breakdown.get(label, 0) + 1

    for vm in eol_vms:
        if get_server_tier(vm.get("name"))["tier"] <= 2:
            prod_eol.append(vm)
    for vm in tools_outdated:
        if get_server_tier(vm.get("name"))["tier"] <= 2:
            prod_tools_outdated.append(vm)
    for vm in untagged_vms:
        if get_server_tier(vm.get("name"))["tier"] <= 2:
            prod_untagged.append(vm)
    for d in low_disk_real:
        if get_server_tier(d.get("vm_name", ""))["tier"] <= 2:
            prod_low_disk.append(d)

    real_vms      = [v for v in vms if get_server_tier(v.get("name"))["tier"] < 5]
    prod_vms      = [v for v in vms if get_server_tier(v.get("name"))["tier"] == 1]
    citrix_vms    = [v for v in vms if get_server_tier(v.get("name"))["label"] == "Citrix Server"]
    qa_vms        = [v for v in vms if get_server_tier(v.get("name"))["tier"] == 2]
    dev_vms       = [v for v in vms if get_server_tier(v.get("name"))["tier"] == 3]
    appliance_vms = [v for v in vms if get_server_tier(v.get("name"))["tier"] >= 5]

    master_image_vms = _flag_master_images(vms, master_image_hostnames, master_image_lookup)

    env_breakdown = {}
    for vm in vms:
        env = vm.get("environment", "Unknown")
        if env not in env_breakdown:
            env_breakdown[env] = {"total": 0, "powered_on": 0, "powered_off": 0}
        env_breakdown[env]["total"] += 1
        if vm.get("power_state") == "POWERED_ON":
            env_breakdown[env]["powered_on"] += 1
        else:
            env_breakdown[env]["powered_off"] += 1

    # AD section
    ad_section = {}
    if ad_data and not ad_data.get("error"):
        s   = ad_data.get("summary", {})
        gpo = ad_data.get("gpo_health", {})
        ad_section = {
            "user_health": {
                "total_users":       s.get("total_users"),
                "active_users":      s.get("active_users"),
                "stale_users":       s.get("stale_users"),
                "pwd_never_expires": s.get("pwd_never_expires"),
            },
            "privileged_access": {
                "domain_admins":     s.get("domain_admin_count"),
                "enterprise_admins": s.get("enterprise_admin_count"),
                "disabled_admins":   ad_data.get("privileged_accounts", {}).get("disabled_admins", []),
                "service_admins":    ad_data.get("privileged_accounts", {}).get("service_admins", []),
            },
            "password_policy_issues": ad_data.get("password_policy_issues", []),
            "gpo_health": {
                "total_gpos":      gpo.get("total_gpos"),
                "orphaned":        gpo.get("orphaned"),
                "disabled":        gpo.get("disabled"),
                "stale_2yr":       gpo.get("stale"),
                "linked_disabled": gpo.get("linked_disabled"),
                "recommendations": [r["text"] for r in gpo.get("recommendations", [])],
            },
            "stale_computers": ad_data.get("stale_computers", {}),
        }

    # Cert section
    cert_section = {}
    if cert_data and not cert_data.get("error"):
        cs = cert_data.get("summary", {})
        dc_expired = [c for c in cert_data.get("dc_kerberos_certs", [])
                      if c.get("status") == "expired"]
        cert_section = {
            "total_issued":        cs.get("total_issued"),
            "expired":             cs.get("expired"),
            "expiring_30_days":    cs.get("expiring_30"),
            "expiring_60_days":    cs.get("expiring_60"),
            "manual_likely":       cs.get("manual_likely"),
            "review_needed":       cs.get("review_needed"),
            "dc_kerberos_expired": [c.get("dc_name") for c in dc_expired],
            "critical_expiring":   [{"subject": c.get("subject"),
                                     "days": c.get("days_remaining"),
                                     "dc": c.get("dc_name")}
                                    for c in cert_data.get("critical_expiring", [])],
        }

    # Citrix section
    citrix_section = {}
    if citrix_data and not citrix_data.get("error"):
        dg_issues = []
        for dg in citrix_data.get("delivery_groups", []):
            total = dg.get("total_machines", 0)
            unreg = dg.get("desktops_unregistered", 0)
            pct   = (unreg / total * 100) if total > 0 else 0
            if pct >= 20:
                dg_issues.append({
                    "name": dg.get("name"),
                    "unregistered": unreg,
                    "total": total,
                    "pct_unregistered": round(pct, 1),
                })

        agent_versions  = citrix_data.get("agent_versions", {})
        latest_ver      = max(agent_versions.keys(), default="Unknown") if agent_versions else "Unknown"
        outdated_agents = {v: c for v, c in agent_versions.items()
                           if v != latest_ver and v != "Unknown"}

        vmware_by_name = {}
        for vm in vms:
            short = vm.get("name", "").lower().split(".")[0]
            if short:
                vmware_by_name[short] = vm

        ad_stale_names = set()
        if ad_data and not ad_data.get("error"):
            sc = ad_data.get("stale_computers", {})
            for c in sc.get("top_stale_regular", []):
                ad_stale_names.add(c.get("name", "").lower())
            for c in sc.get("zombie_detail", []):
                ad_stale_names.add(c.get("name", "").lower())

        unregistered_powered_on    = []
        unregistered_powered_off   = []
        unregistered_not_in_vmware = []
        zombie_machines            = []

        for m in citrix_data.get("problem_machines", {}).get("unregistered", []):
            short  = m.get("name", "").lower()
            vm_rec = vmware_by_name.get(short)
            entry  = {**m}
            if vm_rec:
                entry["vmware_power"] = vm_rec.get("power_state")
                entry["vmware_env"]   = vm_rec.get("environment")
                if vm_rec.get("power_state") == "POWERED_ON":
                    unregistered_powered_on.append(entry)
                else:
                    unregistered_powered_off.append(entry)
            else:
                entry["vmware_power"] = "not_found"
                unregistered_not_in_vmware.append(entry)
            if short in ad_stale_names:
                zombie_machines.append(entry)

        citrix_vdi_count    = sum(1 for v in citrix_machine_set.values() if v.get("is_vdi"))
        citrix_xenapp_count = sum(1 for v in citrix_machine_set.values()
                                   if not v.get("is_vdi") and not v.get("is_master_image"))

        citrix_section = {
            "total_machines":          citrix_data.get("total_machines"),
            "registered":              citrix_data.get("registered"),
            "unregistered":            citrix_data.get("unregistered"),
            "in_maintenance":          citrix_data.get("in_maintenance"),
            "image_out_of_date":       citrix_data.get("image_out_of_date"),
            "active_sessions":         citrix_data.get("active_sessions"),
            "disconnected_sessions":   citrix_data.get("disconnected_sessions"),
            "total_delivery_groups":   citrix_data.get("total_delivery_groups"),
            "total_catalogs":          citrix_data.get("total_catalogs"),
            "broken_catalogs":         citrix_data.get("broken_catalogs"),
            "upgrade_available":       citrix_data.get("upgrade_available"),
            "agent_versions":          agent_versions,
            "outdated_agents":         outdated_agents,
            "delivery_group_issues":   dg_issues,
            "master_images":           citrix_data.get("master_images", []),
            "master_images_in_vmware": master_image_vms,
            "vdi_machine_count":       citrix_vdi_count,
            "xenapp_machine_count":    citrix_xenapp_count,
            "problem_machines":        citrix_data.get("problem_machines", {}),
            "cross_reference": {
                "unregistered_powered_on":    unregistered_powered_on[:20],
                "unregistered_powered_off":   unregistered_powered_off[:20],
                "unregistered_not_in_vmware": unregistered_not_in_vmware[:20],
                "zombie_machines":            zombie_machines[:20],
                "summary": {
                    "real_problems":    len(unregistered_powered_on),
                    "expected_offline": len(unregistered_powered_off),
                    "orphans":          len(unregistered_not_in_vmware),
                    "zombies":          len(zombie_machines),
                },
            },
        }

    # Lansweeper / patch compliance section
    patch_section = {}
    if lansweeper_data and not lansweeper_data.get("error"):
        ph = lansweeper_data.get("patch_health", {})
        patch_section = {
            "patch_pct":      ph.get("patch_pct"),
            "patched":        ph.get("patched"),
            "unpatched":      ph.get("unpatched"),
            "unknown":        ph.get("unknown"),
            "eol_count":      lansweeper_data.get("asset_counts", {}).get("eol_count"),
            "not_seen_30d":   lansweeper_data.get("asset_counts", {}).get("not_seen_30d"),
            "not_seen_90d":   lansweeper_data.get("asset_counts", {}).get("not_seen_90d"),
            "eol_breakdown":  lansweeper_data.get("eol_breakdown", {}),
            "top_unpatched":  lansweeper_data.get("top_unpatched", [])[:10],
            "top_eol":        lansweeper_data.get("top_eol", [])[:10],
            "os_breakdown":   lansweeper_data.get("os_breakdown", {}),
        }

    data_payload = {
        "summary": {
            "total_vms":                       len(vms),
            "real_servers":                    len(real_vms),
            "production_servers":              len(prod_vms),
            "citrix_servers":                  len(citrix_vms),
            "qa_servers":                      len(qa_vms),
            "dev_test_servers":                len(dev_vms),
            "appliances_and_vdi_excluded":     len(appliance_vms),
            "powered_on_vms":                  len(powered_on),
            "powered_off_vms":                 len(powered_off),
            "total_hosts":                     len(hosts),
            "hosts_in_maintenance":            len(maintenance_hosts),
            "untagged_vms":                    len(untagged_vms),
            "eol_vms":                         len(eol_vms),
            "eol_production_or_qa":            len(prod_eol),
            "tools_outdated":                  len(tools_outdated),
            "tools_outdated_production_or_qa": len(prod_tools_outdated),
            "low_disk_vms":                    len(low_disk_real),
            "low_disk_production_or_qa":       len(prod_low_disk),
            "urgent_alerts":                   len(urgent_alerts),
            "recurring_alerts":                len(recurring),
            "master_image_vms_identified":     len(master_image_vms),
        },
        "server_tiers":          tier_breakdown,
        "environment_breakdown": env_breakdown,
        "eol_vms":               [{"name": v.get("name"), "os": v.get("os_name"),
                                    "eol": v.get("eol", {}).get("eol"),
                                    "environment": v.get("environment"),
                                    "tier": get_server_tier(v.get("name"))["label"]}
                                   for v in eol_vms[:20]],
        "tools_outdated":        [{"name": v.get("name"), "version": v.get("tools_version"),
                                    "tier": get_server_tier(v.get("name"))["label"]}
                                   for v in tools_outdated[:20]],
        "low_disk_vms":          low_disk_real[:20],
        "low_disk_production":   prod_low_disk[:10],
        "powered_off_long":      (powered_off_vms or [])[:20],
        "master_image_vms":      master_image_vms,
        "urgent_alerts":         [{"device": a.get("device_name"),
                                    "severity": a.get("severity"),
                                    "event": a.get("event_type"),
                                    "message": a.get("message"),
                                    "time": a.get("time")}
                                   for a in urgent_alerts[:20]],
        "recurring_alerts":      [{"device": a.get("device_name"),
                                    "event": a.get("event_type"),
                                    "occurrences": a.get("occurrence_count"),
                                    "severity": a.get("severity")}
                                   for a in recurring[:10]],
        "maintenance_hosts":     [{"name": h.get("name"),
                                    "environment": h.get("environment")}
                                   for h in maintenance_hosts],
        "disk_trends":           [{"vm": t.get("vm_name"), "disk": t.get("disk_label"),
                                    "history_points": len(t.get("history", [])),
                                    "latest_gb": t["history"][-1]["capacity_gb"]
                                                 if t.get("history") else None}
                                   for t in trends[:10]],
        "production_concerns": {
            "eol_production_vms":        [{"name": v.get("name"),
                                            "os": v.get("os_name"),
                                            "eol": v.get("eol", {}).get("eol")}
                                           for v in prod_eol[:10]],
            "low_disk_production_vms":   [{"name": v.get("vm_name"),
                                            "drive": v.get("drive"),
                                            "pct_free": v.get("pct_free")}
                                           for v in prod_low_disk[:10]],
            "tools_outdated_production": [{"name": v.get("name"),
                                            "version": v.get("tools_version")}
                                           for v in prod_tools_outdated[:10]],
            "untagged_production_vms":   [v.get("name") for v in prod_untagged[:10]],
        },
        "active_directory":  ad_section,
        "certificates":      cert_section,
        "citrix":            citrix_section,
        "patch_compliance":  patch_section,
        "focused_analyses":  _build_lens_section(
                                 alerts_ai_analysis,
                                 vmware_ai_analysis,
                                 citrix_ai_analysis,
                                 ad_ai_analysis,
                                 assets_ai_analysis),
    }

    prompt = (
        "You are an expert infrastructure analyst reviewing the Zinnia environment.\n\n"
        "FOCUSED PAGE ANALYSES (pre-digested inputs — high confidence):\n"
        "The focused_analyses section contains results from dedicated per-page AI analyses "
        "that ran against the full raw data for each domain. These are high-signal inputs — "
        "weight them heavily when grading the relevant areas:\n"
        "- focused_analyses.alerts  → informs ALERT_HEALTH grade\n"
        "- focused_analyses.vmware  → informs CPU_AND_COMPUTE, STORAGE, VM_ORGANIZATION, PATCHING_AND_TOOLS\n"
        "- focused_analyses.citrix  → informs CITRIX_HEALTH grade\n"
        "- focused_analyses.ad      → informs ACTIVE_DIRECTORY grade\n"
        "- focused_analyses.assets  → informs PATCH_COMPLIANCE grade\n"
        "If a lens grade differs from what the raw numbers alone suggest, trust the lens — "
        "it had access to more detail. If a lens is absent (null), fall back to raw data only.\n\n"
        "IMPORTANT - SERVER NAMING CONVENTION:\n"
        "- Ending in P (01P, 02P etc) = PRODUCTION - treat all issues as CRITICAL\n"
        "- Ending in Q (01Q, 02Q etc) or containing QA = QA/Staging - MEDIUM priority\n"
        "- Ending in D, U, or T = Dev/Test - LOWER priority, equal weight\n"
        "- Citrix XenApp servers (topctxccp, vmcectxsrv etc) = treat as PRODUCTION importance\n"
        "- VDI machines and infrastructure appliances have been EXCLUDED from disk/EOL analysis\n\n"
        "CITRIX MASTER IMAGE AWARENESS:\n"
        "The 'master_image_vms' list contains VMware VMs that are Citrix master images "
        "(detected from Citrix Cloud catalog metadata AND naming convention — MI in name "
        "e.g. TOPCTXXDMI01P). These are TEMPLATE VMs, NOT live servers. Key rules:\n"
        "- Disk space on master images IS critical — a full disk prevents MCS provisioning "
        "and causes catalog-wide outages (this has happened in this environment before)\n"
        "- Master images powered off = NORMAL. Do not flag.\n"
        "- EOL OS on a master image = ALL machines in that catalog inherit the issue\n"
        "- Master images stale in AD = EXPECTED. They are excluded from stale computer reports.\n"
        "- If a master image appears in low_disk_production, flag it as IMMEDIATE ACTION\n\n"
        "CITRIX THREE-WAY CROSS-REFERENCE (Citrix Cloud + VMware + AD):\n"
        "The citrix.cross_reference section contains pre-computed cross-references:\n"
        "- unregistered_powered_on: Citrix unregistered BUT VMware powered ON -> REAL problems\n"
        "- unregistered_powered_off: Citrix unregistered AND VMware powered off -> EXPECTED\n"
        "- unregistered_not_in_vmware: not found in VMware -> ORPHAN records\n"
        "- zombie_machines: Citrix unregistered AND stale in AD -> true zombies\n"
        "Use cross_reference.summary.real_problems as a key signal for CITRIX_HEALTH grade.\n\n"
        "STALE COMPUTERS CONTEXT:\n"
        "Zombie machines (stale AD + Citrix unregistered + still powered on) are high priority.\n\n"
        "GRADING GUIDANCE:\n"
        "Weight production issues 3x more heavily than QA, 5x more than Dev/Test.\n"
        "For ACTIVE_DIRECTORY grade: consider stale users, privileged account hygiene, "
        "password policy strength, GPO health, and zombie machine count.\n"
        "For CERTIFICATE_HEALTH grade: consider expired certs, certs expiring within 30 days, "
        "DC Kerberos cert status, and manual/unmanaged certs. "
        "An expired DC Kerberos cert should immediately drop the cert grade to C or lower.\n"
        "For PATCH_COMPLIANCE grade: use the patch_compliance section. Consider patch_pct "
        "(% of assets seen within 30 days and active), EOL asset count, assets not seen in 90+ days, "
        "and the top_unpatched list. Below 70% patch_pct = D or lower. EOL assets on production "
        "hostnames should be flagged as critical.\n"
        "For CITRIX_HEALTH grade: consider unregistered machine %, broken catalogs, "
        "active vs disconnected session ratio, agent version spread, image-out-of-date count, "
        "delivery groups with >20% unregistered machines, and cross_reference.summary.real_problems.\n\n"
        "FORMAT YOUR RESPONSE EXACTLY AS FOLLOWS:\n\n"
        "[EXECUTIVE_SUMMARY]\n"
        "3-4 sentences covering overall health with specific focus on production environment.\n\n"
        "[GRADES]\n"
        "OVERALL: (A-F) - one line explanation\n"
        "CPU_AND_COMPUTE: (A-F) - one line explanation\n"
        "STORAGE: (A-F) - one line explanation\n"
        "VM_ORGANIZATION: (A-F) - one line explanation\n"
        "PATCHING_AND_TOOLS: (A-F) - one line explanation\n"
        "PATCH_COMPLIANCE: (A-F) - one line explanation\n"
        "ALERT_HEALTH: (A-F) - one line explanation\n"
        "ACTIVE_DIRECTORY: (A-F) - one line explanation\n"
        "CERTIFICATE_HEALTH: (A-F) - one line explanation\n"
        "CITRIX_HEALTH: (A-F) - one line explanation\n\n"
        "[IMMEDIATE_ACTIONS]\n"
        "Up to 5 PRODUCTION issues needing attention RIGHT NOW. "
        "Include any expired DC Kerberos certs, critical cert expirations, "
        "Citrix master image disk space issues, and real unregistered machines. Be specific.\n\n"
        "[WARNINGS]\n"
        "Up to 5 concerning issues that are not immediately critical.\n\n"
        "[RECOMMENDATIONS]\n"
        "Up to 5 longer term improvements prioritized by impact.\n\n"
        "[ALERT_ANALYSIS]\n"
        "Which alerts are false alarms vs real issues? "
        "Which recurring alerts suggest systemic problems?\n\n"
        "[TRENDS]\n"
        "Based on historical data, what trends are emerging? "
        "What preventative actions should be taken?\n\n"
        "Infrastructure Data:\n"
        + json.dumps(data_payload, indent=2)
    )

    return _call_claude(
        model="claude-opus-4-5",
        max_tokens=2500,
        messages=[{"role": "user", "content": prompt}],
    )


# ── Grade deep dives ──────────────────────────────────────────────────────────

def generate_grade_deepdives(analysis_text, grades):
    """
    Given the full analysis text and parsed grades dict, makes a single Claude
    API call returning a dict of deep dives keyed by grade name.
    """
    grade_summary = "\n".join(
        f"  {k}: {v.get('letter','?')} - {v.get('note','')}"
        for k, v in grades.items()
    )

    prompt = (
        "You are an expert infrastructure analyst. You have just completed a full analysis "
        "of the Zinnia infrastructure and assigned the following grades:\n\n"
        + grade_summary
        + "\n\nHere is the full analysis you wrote:\n\n"
        + analysis_text
        + "\n\nNow generate a detailed deep dive for EACH grade. For each grade explain WHY "
        "it received that letter (referencing specific data points from the analysis), what "
        "the top 5 specific actionable steps are to raise the grade, and 1-2 things going well.\n\n"
        "IMPORTANT: Respond ONLY with a valid JSON object. No preamble, no markdown, no "
        "code fences. The JSON must have this exact structure:\n"
        '{\n'
        '  "OVERALL": {\n'
        '    "why": "3-4 sentence explanation referencing specific data points",\n'
        '    "top5": ["Action 1", "Action 2", "Action 3", "Action 4", "Action 5"],\n'
        '    "positive": "1-2 sentences on what is going well"\n'
        '  },\n'
        '  "CPU_AND_COMPUTE": { "why": "...", "top5": [...], "positive": "..." },\n'
        '  "STORAGE": { "why": "...", "top5": [...], "positive": "..." },\n'
        '  "VM_ORGANIZATION": { "why": "...", "top5": [...], "positive": "..." },\n'
        '  "PATCHING_AND_TOOLS": { "why": "...", "top5": [...], "positive": "..." },\n'
        '  "PATCH_COMPLIANCE": { "why": "...", "top5": [...], "positive": "..." },\n'
        '  "ALERT_HEALTH": { "why": "...", "top5": [...], "positive": "..." },\n'
        '  "ACTIVE_DIRECTORY": { "why": "...", "top5": [...], "positive": "..." },\n'
        '  "CERTIFICATE_HEALTH": { "why": "...", "top5": [...], "positive": "..." },\n'
        '  "CITRIX_HEALTH": { "why": "...", "top5": [...], "positive": "..." }\n'
        '}\n\n'
        "Be specific — reference actual server names, counts, and percentages from the analysis. "
        "Each top5 action should name the specific thing to fix, not generic advice."
    )

    raw = _call_claude(
        model="claude-opus-4-5",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw.strip())

    try:
        deepdives = json.loads(raw)
    except json.JSONDecodeError:
        deepdives = {}

    for key, label in GRADE_LABELS.items():
        if key in deepdives:
            deepdives[key]["label"]  = label
            deepdives[key]["letter"] = grades.get(key, {}).get("letter", "?")
            deepdives[key]["note"]   = grades.get(key, {}).get("note", "")
        else:
            deepdives[key] = {
                "label":    label,
                "letter":   grades.get(key, {}).get("letter", "?"),
                "note":     grades.get(key, {}).get("note", ""),
                "why":      "Deep dive not available for this grade.",
                "top5":     [],
                "positive": "",
            }

    return deepdives