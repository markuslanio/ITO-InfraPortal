import logging
import re
import threading
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime, timedelta
from routers import meraki

# ── Job metadata ──────────────────────────────────────────────────────────────

JOB_LABELS = {
    "job_basic_vms":                  "VMware — Basic VM list",
    "job_basic_hosts":                "VMware — Basic host list",
    "job_detailed_vms":               "VMware — Detailed VMs",
    "job_disk_snapshots":             "VMware — Disk snapshots",
    "job_untagged_vms":               "VMware — Untagged VMs",
    "job_detailed_hosts":             "VMware — Detailed hosts",
    "job_opmanager_alerts":           "Monitoring — Alerts",
    "job_opmanager_devices":          "Monitoring — Devices",
    "job_jira_prefetch":              "Jira — Ticket prefetch",
    "job_ad_summary":                 "Active Directory — Summary",
    "job_ad_reports":                 "Active Directory — Detail reports",
    "job_ad_gpo":                     "Active Directory — GPO analysis",
    "job_citrix_summary":             "Citrix — Summary",
    "job_citrix_power_unknown_check": "Citrix — Power Unknown check",
    "job_lansweeper_summary":         "Lansweeper — Asset summary",
    "job_lansweeper_patch":           "Lansweeper — Patch status",
    "job_lansweeper_assets":          "Lansweeper — Asset list",
    "job_meraki_refresh":             "Network — Meraki refresh",
    "job_ai_analysis":                "System — AI Analysis",
    "job_jira_intelligence":          "System — Jira Intelligence",
    "job_findings":                   "System — Findings engine",
    "job_entra_refresh":              "System — Entra / M365",
}

JOB_GROUPS = {
    "job_basic_vms":                  "VMware",
    "job_basic_hosts":                "VMware",
    "job_detailed_vms":               "VMware",
    "job_disk_snapshots":             "VMware",
    "job_untagged_vms":               "VMware",
    "job_detailed_hosts":             "VMware",
    "job_opmanager_alerts":           "Monitoring",
    "job_opmanager_devices":          "Monitoring",
    "job_jira_prefetch":              "Jira",
    "job_ad_summary":                 "Active Directory",
    "job_ad_reports":                 "Active Directory",
    "job_ad_gpo":                     "Active Directory",
    "job_citrix_summary":             "Citrix",
    "job_citrix_power_unknown_check": "Citrix",
    "job_lansweeper_summary":         "Lansweeper",
    "job_lansweeper_patch":           "Lansweeper",
    "job_lansweeper_assets":          "Lansweeper",
    "job_meraki_refresh":             "Network",
    "job_ai_analysis":                "System",
    "job_jira_intelligence":          "System",
    "job_findings":                   "System",
    "job_entra_refresh":              "System",
}

GROUP_ORDER = ["VMware", "Citrix", "Active Directory", "Monitoring", "Jira", "Lansweeper", "Network", "System"]

JOB_DEFAULTS = {
    "job_basic_vms":                  {"type": "interval", "minutes": 30},
    "job_basic_hosts":                {"type": "interval", "minutes": 30},
    "job_detailed_vms":               {"type": "interval", "minutes": 120},
    "job_disk_snapshots":             {"type": "interval", "minutes": 120},
    "job_untagged_vms":               {"type": "interval", "minutes": 240},
    "job_detailed_hosts":             {"type": "interval", "minutes": 120},
    "job_opmanager_alerts":           {"type": "interval", "minutes": 5},
    "job_opmanager_devices":          {"type": "interval", "minutes": 15},
    "job_jira_prefetch":              {"type": "interval", "minutes": 30},
    "job_ad_summary":                 {"type": "interval", "minutes": 240},
    "job_ad_reports":                 {"type": "interval", "minutes": 360},
    "job_ad_gpo":                     {"type": "cron",     "cron": "Daily 03:00"},
    "job_citrix_summary":             {"type": "interval", "minutes": 60},
    "job_citrix_power_unknown_check": {"type": "interval", "minutes": 15},
    "job_lansweeper_summary":         {"type": "interval", "minutes": 360},
    "job_lansweeper_patch":           {"type": "interval", "minutes": 360},
    "job_lansweeper_assets":          {"type": "interval", "minutes": 360},
    "job_meraki_refresh":             {"type": "interval", "minutes": 15},
    "job_ai_analysis":                {"type": "cron",     "cron": "Daily 06:00"},
    "job_jira_intelligence":          {"type": "cron",     "cron": "Daily 07:00"},
    "job_findings":                   {"type": "interval", "minutes": 15},
    "job_entra_refresh":              {"type": "interval", "minutes": 60},
}


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

# ── Job run history ───────────────────────────────────────────────────────────
# Keyed by job id. Each entry: {last_run, last_status, last_error, run_count}

_job_history: dict = {}

def _record_run(job_id: str, success: bool, error: str = None):
    prev = _job_history.get(job_id, {})
    _job_history[job_id] = {
        "last_run":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "last_status": "ok" if success else "error",
        "last_error":  error,
        "run_count":   prev.get("run_count", 0) + 1,
    }

# ── VMware jobs ───────────────────────────────────────────────────────────────

def job_basic_vms():
    try:
        logger.info("Scheduler: Refreshing basic VM list...")
        from routers.vmware import get_all_vms
        get_all_vms(force_refresh=True)
        logger.info("Scheduler: Basic VM list updated.")
        _record_run("job_basic_vms", True)
    except Exception as e:
        _record_run("job_basic_vms", False, str(e))
        logger.error("Scheduler: VM list error: " + str(e))

def job_basic_hosts():
    try:
        logger.info("Scheduler: Refreshing basic host list...")
        from routers.vmware import get_all_hosts
        get_all_hosts(force_refresh=True)
        logger.info("Scheduler: Basic host list updated.")
        _record_run("job_basic_hosts", True)
    except Exception as e:
        _record_run("job_basic_hosts", False, str(e))
        logger.error("Scheduler: Host list error: " + str(e))

def job_detailed_vms():
    try:
        logger.info("Scheduler: Refreshing detailed VM data...")
        from routers.vmware import stream_detailed_vms
        for _ in stream_detailed_vms(force_refresh=True):
            pass
        logger.info("Scheduler: Detailed VM data updated.")
        _record_run("job_detailed_vms", True)
    except Exception as e:
        _record_run("job_detailed_vms", False, str(e))
        logger.error("Scheduler: Detailed VM error: " + str(e))

def job_disk_snapshots():
    try:
        logger.info("Scheduler: Refreshing disk snapshots...")
        from routers.vmware import stream_vm_storage
        for _ in stream_vm_storage(force_refresh=True):
            pass
        logger.info("Scheduler: Disk snapshots updated.")
        _record_run("job_disk_snapshots", True)
    except Exception as e:
        _record_run("job_disk_snapshots", False, str(e))
        logger.error("Scheduler: Disk snapshot error: " + str(e))

def job_untagged_vms():
    try:
        logger.info("Scheduler: Refreshing untagged VM check...")
        from routers.vmware import stream_untagged_vms
        for _ in stream_untagged_vms(force_refresh=True):
            pass
        logger.info("Scheduler: Untagged VM check updated.")
        _record_run("job_untagged_vms", True)
    except Exception as e:
        _record_run("job_untagged_vms", False, str(e))
        logger.error("Scheduler: Untagged VM error: " + str(e))

def job_detailed_hosts():
    try:
        logger.info("Scheduler: Refreshing detailed host data...")
        from routers.vmware_deep import stream_detailed_hosts
        for _ in stream_detailed_hosts(force_refresh=True):
            pass
        logger.info("Scheduler: Detailed host data updated.")
        _record_run("job_detailed_hosts", True)
    except Exception as e:
        _record_run("job_detailed_hosts", False, str(e))
        logger.error("Scheduler: Detailed host error: " + str(e))

# ── OpManager jobs ────────────────────────────────────────────────────────────

def job_opmanager_alerts():
    try:
        logger.info("Scheduler: Refreshing OpManager alerts...")
        from routers.opmanager import get_alarms
        from routers.database import save_alert_history
        alarms, _ = get_alarms(force_refresh=True)
        save_alert_history(alarms)
        logger.info("Scheduler: OpManager alerts updated. Count: " + str(len(alarms)))
        _record_run("job_opmanager_alerts", True)
    except Exception as e:
        _record_run("job_opmanager_alerts", False, str(e))
        logger.error("Scheduler: OpManager alerts error: " + str(e))

def job_opmanager_devices():
    try:
        logger.info("Scheduler: Refreshing OpManager devices...")
        from routers.opmanager import get_devices
        from routers.cache import cache as _cache
        get_devices(force_refresh=True)
        # Invalidate derived named-groups cache so it rebuilds from fresh device data
        _cache.invalidate("opm_named_groups")
        logger.info("Scheduler: OpManager devices updated.")
        _record_run("job_opmanager_devices", True)
    except Exception as e:
        _record_run("job_opmanager_devices", False, str(e))
        logger.error("Scheduler: OpManager devices error: " + str(e))

# ── Jira prefetch job ─────────────────────────────────────────────────────────

def job_jira_prefetch(alarms=None):
    """
    Fetch ALL open ITSD tickets in one bulk call and populate the search cache.
    Replaces the old per-device search loop that caused Atlassian rate limiting.
    The alarms parameter is kept for API compatibility but is no longer used
    for searching — it's only used to count matched devices for the log line.
    """
    try:
        from routers import jira

        count = jira.bulk_prefetch_all_open_tickets()

        # Count how many active alert devices have a matching cached ticket
        from routers.opmanager import get_alarms
        if alarms is None:
            alarms, _ = get_alarms()

        devices = set()
        for a in alarms:
            if a.get("severity") == "Clear":
                continue
            dev = a.get("device_name") or ""
            short = dev if _IP_RE.match(dev) else dev.split(".")[0]
            if not short or _IP_RE.match(short) or short.upper().startswith("IP-"):
                continue
            devices.add(short.upper())

        found = sum(1 for d in devices if jira._search_cache.get(d, {}).get("tickets"))
        logger.info(
            "Scheduler: Jira prefetch complete. %d ticket(s) fetched. %d/%d device(s) have open tickets.",
            count, found, len(devices)
        )
        _record_run("job_jira_prefetch", True)

    except Exception as e:
        _record_run("job_jira_prefetch", False, str(e))
        logger.error("Scheduler: Jira prefetch error: %s", str(e))

# ── Active Directory jobs ─────────────────────────────────────────────────────

def job_ad_summary():
    try:
        logger.info("Scheduler: Refreshing AD summary...")
        from routers.active_directory import get_ad_summary
        get_ad_summary(force_refresh=True)
        logger.info("Scheduler: AD summary updated.")
        _record_run("job_ad_summary", True)
    except Exception as e:
        _record_run("job_ad_summary", False, str(e))
        logger.error("Scheduler: AD summary error: " + str(e))

def job_ad_gpo_analysis():
    try:
        logger.info("Scheduler: Refreshing GPO analysis...")
        from routers.active_directory import get_gpo_analysis
        get_gpo_analysis(force_refresh=True)
        logger.info("Scheduler: GPO analysis updated.")
        _record_run("job_ad_gpo", True)
    except Exception as e:
        _record_run("job_ad_gpo", False, str(e))
        logger.error("Scheduler: GPO analysis error: " + str(e))

def job_ad_reports():
    try:
        logger.info("Scheduler: Refreshing AD detail reports...")
        from routers.active_directory import (
            get_all_computers_with_ou,
            get_stale_users, get_pwd_never_expires,
            get_domain_admins, get_empty_groups, get_stale_computers
        )
        get_all_computers_with_ou(force_refresh=True)
        get_stale_users(force_refresh=True)
        get_pwd_never_expires(force_refresh=True)
        get_domain_admins(force_refresh=True)
        get_empty_groups(force_refresh=True)
        get_stale_computers(force_refresh=True)
        logger.info("Scheduler: AD detail reports updated.")
        _record_run("job_ad_reports", True)
    except Exception as e:
        _record_run("job_ad_reports", False, str(e))
        logger.error("Scheduler: AD reports error: " + str(e))

# ── Citrix jobs ───────────────────────────────────────────────────────────────

def job_citrix_summary():
    try:
        logger.info("Scheduler: Refreshing Citrix summary...")
        from routers.citrix import get_citrix_summary
        data, _ = get_citrix_summary(force_refresh=True)
        logger.info("Scheduler: Citrix updated. Machines: %d, Sessions: %d",
                    data["total_machines"], data["active_sessions"])
        _record_run("job_citrix_summary", True)
    except Exception as e:
        _record_run("job_citrix_summary", False, str(e))
        logger.error("Scheduler: Citrix job failed: %s", str(e))


def job_citrix_power_unknown_check():
    """
    Runs every 15 minutes. Checks ALL Citrix machines (VDI + XenApp) for
    Unknown power state and fires Slack + email notifications to the relevant
    teams for any machines newly in that state.

    Team routing:
      WORKSPA-*  → Citrix + AWS + Wintel
      All others → Citrix + VMware + Wintel

    XenApp servers with unknown power state are flagged as higher impact
    (multiple concurrent users affected) in both the Slack and email alerts.

    Deduplication: only notifies when machines ENTER the unknown state.
    Clears the alert when machines recover so re-entry triggers a new alert.
    """
    try:
        logger.info("Scheduler: Checking Citrix machine power states for unknowns...")
        from routers.citrix import get_citrix_machines
        from routers.notifications import check_and_notify_vdi_power_unknown

        # Pass ALL machines — both VDI (single-session) and XenApp (multi-session)
        machines_raw, _ = get_citrix_machines(force_refresh=False)
        if not machines_raw:
            logger.info("Scheduler: No Citrix machine data cached yet — skipping power check.")
            _record_run("job_citrix_power_unknown_check", True)
            return

        result = check_and_notify_vdi_power_unknown(machines_raw)

        logger.info(
            "Scheduler: Power check complete. New unknowns: %d, Recovered: %d, Notified teams: %s",
            result["new_unknowns"],
            result["recovered"],
            ", ".join(result["notified_teams"]) or "none",
        )
        _record_run("job_citrix_power_unknown_check", True)
    except Exception as e:
        _record_run("job_citrix_power_unknown_check", False, str(e))
        logger.error("Scheduler: Citrix power unknown check failed: %s", str(e))

# ── Lansweeper jobs ───────────────────────────────────────────────────────────

def job_lansweeper_summary():
    try:
        logger.info("Scheduler: Refreshing Lansweeper asset summary...")
        from routers.lansweeper import get_asset_summary
        get_asset_summary(force_refresh=True)
        logger.info("Scheduler: Lansweeper asset summary updated.")
        _record_run("job_lansweeper_summary", True)
    except Exception as e:
        _record_run("job_lansweeper_summary", False, str(e))
        logger.error("Scheduler: Lansweeper asset summary error: %s", str(e))

def job_lansweeper_patch():
    try:
        logger.info("Scheduler: Refreshing Lansweeper patch status...")
        from routers.lansweeper import get_patch_status
        get_patch_status(force_refresh=True)
        logger.info("Scheduler: Lansweeper patch status updated.")
        _record_run("job_lansweeper_patch", True)
    except Exception as e:
        _record_run("job_lansweeper_patch", False, str(e))
        logger.error("Scheduler: Lansweeper patch status error: %s", str(e))

def job_lansweeper_assets():
    """
    Fetch the full Lansweeper asset list, warm the in-memory cache,
    and persist to DB so the assets page is fast after app pool recycles.
    """
    try:
        logger.info("Scheduler: Refreshing Lansweeper asset list...")
        from routers.lansweeper import _fetch_all_assets, _basic, _os_group, _days_ago, _EOL_OS
        from routers.cache import cache
        from routers.database import save_lansweeper_assets

        fields = [
            "assetBasicInfo.name", "assetBasicInfo.type", "assetBasicInfo.typeGroup",
            "assetBasicInfo.ipAddress", "assetBasicInfo.domain",
            "assetBasicInfo.firstSeen", "assetBasicInfo.lastSeen",
            "assetBasicInfo.scannerTypes",
            "operatingSystem.name",
            "assetCustom.stateName", "assetCustom.manufacturer", "assetCustom.model",
        ]
        raw = _fetch_all_assets(fields)
        assets = []
        for item in raw:
            b = _basic(item)
            os_name = (item.get("operatingSystem") or {}).get("name", "")
            og = _os_group(b.get("type"), os_name)
            assets.append({
                "name":            b.get("name"),
                "ip":              b.get("ipAddress"),
                "type":            b.get("typeGroup") or b.get("type"),
                "os":              og,
                "domain":          b.get("domain"),
                "state":           (item.get("assetCustom") or {}).get("stateName"),
                "manufacturer":    (item.get("assetCustom") or {}).get("manufacturer"),
                "model":           (item.get("assetCustom") or {}).get("model"),
                "last_seen":       b.get("lastSeen"),
                "first_seen":      b.get("firstSeen"),
                "days_since_seen": _days_ago(b.get("lastSeen")),
                "scanner_types":   b.get("scannerTypes") or [],
                "is_eol":          og in _EOL_OS,
            })

        cache.set("ls_asset_list", assets)
        save_lansweeper_assets(assets)
        logger.info("Scheduler: Lansweeper asset list updated. %d assets.", len(assets))
        _record_run("job_lansweeper_assets", True)
    except Exception as e:
        _record_run("job_lansweeper_assets", False, str(e))
        logger.error("Scheduler: Lansweeper asset list error: %s", str(e))

# ── Meraki job ────────────────────────────────────────────────────────────────

def job_meraki_refresh():
    """Refresh all Meraki caches. Runs on startup + every 15 min."""
    try:
        logger.info("Scheduler: Refreshing Meraki data...")
        meraki.job_meraki_refresh()
        _record_run("job_meraki_refresh", True)
    except Exception as e:
        _record_run("job_meraki_refresh", False, str(e))
        logger.error("Scheduler: Meraki refresh error: %s", str(e))

# ── AI Analysis job ───────────────────────────────────────────────────────────

def job_ai_analysis():
    try:
        logger.info("Scheduler: Running daily AI analysis...")
        from routers.vmware import get_all_vms, get_all_hosts
        from routers.analysis import analyze_infrastructure
        from routers.cache import cache
        from routers.database import (
            get_recurring_alerts, get_disk_trends,
            get_powered_off_vms, save_vm_snapshot,
            save_disk_snapshot, save_analysis
        )
        from routers.opmanager import get_alarms
        from routers.active_directory import get_ad_analysis_for_ai
        from routers.ca_analysis import get_ca_analysis_for_ai
        from routers.lansweeper import get_lansweeper_analysis_for_ai

        vms, _, _   = get_all_vms()
        hosts, _, _ = get_all_hosts()

        untagged_data, _ = cache.get("untagged_vms")
        untagged = untagged_data["vms"] if untagged_data else []

        storage_data, _ = cache.get("vm_storage")
        storage = storage_data["vms"] if storage_data else []

        detailed_data, _ = cache.get("detailed_vms")
        detailed_vms = detailed_data["vms"] if detailed_data else vms

        alarms, _ = get_alarms()

        if detailed_vms:
            save_vm_snapshot(detailed_vms)
        if storage:
            save_disk_snapshot(storage)

        recurring   = get_recurring_alerts(min_occurrences=3)
        trends      = get_disk_trends()
        powered_off = get_powered_off_vms(days=30)

        ad_data         = get_ad_analysis_for_ai()
        cert_data       = get_ca_analysis_for_ai()
        lansweeper_data = get_lansweeper_analysis_for_ai()

        analysis = analyze_infrastructure(
            detailed_vms, hosts, untagged, storage,
            alarms=alarms,
            recurring_alerts=recurring,
            disk_trends=trends,
            powered_off_vms=powered_off,
            ad_data=ad_data,
            cert_data=cert_data,
            lansweeper_data=lansweeper_data,
        )

        cache.set("last_analysis", {"text": analysis})
        save_analysis(analysis)
        logger.info("Scheduler: Daily AI analysis complete.")
        _record_run("job_ai_analysis", True)
    except Exception as e:
        _record_run("job_ai_analysis", False, str(e))
        logger.error("Scheduler: AI analysis error: " + str(e))

# ── Entra / Microsoft 365 job ─────────────────────────────────────────────────

def job_entra_refresh():
    try:
        logger.info("Scheduler: Refreshing Entra / M365 data...")
        from routers.entra import refresh_all
        results = refresh_all()
        logger.info("Scheduler: Entra refresh complete: %s", results)
        _record_run("job_entra_refresh", True)
    except Exception as e:
        _record_run("job_entra_refresh", False, str(e))
        logger.error("Scheduler: Entra refresh error: %s", str(e))


# ── Findings engine job ───────────────────────────────────────────────────────

def job_findings():
    try:
        from routers.findings import refresh_findings
        count = refresh_findings()
        logger.info("Scheduler: findings refreshed — %d findings", count)
        _record_run("job_findings", True)
    except Exception as e:
        _record_run("job_findings", False, str(e))
        logger.error("Scheduler: findings error: %s", str(e))


# ── Jira Intelligence job ─────────────────────────────────────────────────────

def job_jira_intelligence():
    try:
        from routers.jira_intelligence import run_jira_intelligence
        run_jira_intelligence()
        _record_run("job_jira_intelligence", True)
    except Exception as e:
        _record_run("job_jira_intelligence", False, str(e))
        logger.error("Scheduler: Jira intelligence error: %s", str(e))

# ── Job function map (built after all functions are defined) ──────────────────

_JOB_FUNCS: dict = {}

def _init_job_funcs():
    _JOB_FUNCS.update({
        "job_basic_vms":                  job_basic_vms,
        "job_basic_hosts":                job_basic_hosts,
        "job_detailed_vms":               job_detailed_vms,
        "job_disk_snapshots":             job_disk_snapshots,
        "job_untagged_vms":               job_untagged_vms,
        "job_detailed_hosts":             job_detailed_hosts,
        "job_opmanager_alerts":           job_opmanager_alerts,
        "job_opmanager_devices":          job_opmanager_devices,
        "job_jira_prefetch":              job_jira_prefetch,
        "job_ad_summary":                 job_ad_summary,
        "job_ad_reports":                 job_ad_reports,
        "job_ad_gpo_analysis":            job_ad_gpo_analysis,
        "job_ad_gpo":                     job_ad_gpo_analysis,
        "job_citrix_summary":             job_citrix_summary,
        "job_citrix_power_unknown_check": job_citrix_power_unknown_check,
        "job_lansweeper_summary":         job_lansweeper_summary,
        "job_lansweeper_patch":           job_lansweeper_patch,
        "job_lansweeper_assets":          job_lansweeper_assets,
        "job_meraki_refresh":             job_meraki_refresh,
        "job_ai_analysis":                job_ai_analysis,
        "job_jira_intelligence":          job_jira_intelligence,
        "job_findings":                   job_findings,
        "job_entra_refresh":              job_entra_refresh,
    })


def run_job_now(job_id: str) -> bool:
    if not _JOB_FUNCS:
        _init_job_funcs()
    func = _JOB_FUNCS.get(job_id)
    if not func:
        return False
    threading.Thread(target=func, daemon=True).start()
    return True


def set_job_paused(job_id: str, paused: bool) -> bool:
    try:
        if paused:
            scheduler.pause_job(job_id)
        else:
            scheduler.resume_job(job_id)
        return True
    except Exception as e:
        logger.warning("set_job_paused %s paused=%s failed: %s", job_id, paused, e)
        return False


def set_job_interval(job_id: str, minutes: int) -> bool:
    default = JOB_DEFAULTS.get(job_id, {})
    if default.get("type") != "interval":
        return False
    try:
        scheduler.reschedule_job(job_id, trigger=IntervalTrigger(minutes=minutes))
        return True
    except Exception as e:
        logger.warning("set_job_interval %s → %d min failed: %s", job_id, minutes, e)
        return False


def get_trigger_info(job) -> dict:
    try:
        cls = type(job.trigger).__name__
        if "Interval" in cls:
            mins = int(job.trigger.interval.total_seconds() / 60)
            return {"type": "interval", "minutes": mins}
        elif "Cron" in cls:
            return {"type": "cron", "spec": str(job.trigger)}
    except Exception:
        pass
    return {"type": "unknown"}


# ── Scheduler startup ─────────────────────────────────────────────────────────

def start_scheduler():
    # Initialise notification state (loads DB-persisted alert dedup table)
    try:
        from routers.notifications import init_notifications
        init_notifications()
    except Exception as e:
        logger.warning("Scheduler: notification init failed (non-fatal) — %s", str(e))

    # Stagger every interval job's first run so their cycles never permanently
    # realign on the same second — without this, jobs added back-to-back all
    # inherit ~the same start_date and collide at every common interval multiple
    # forever (e.g. 30-min jobs colliding every 30 min, 6h jobs every 6h), which
    # piles up concurrent SQLite writers and trips the busy_timeout.
    _stagger_base = datetime.now()
    _stagger_step = iter(timedelta(seconds=25 * n) for n in range(100))
    def _staggered():
        return _stagger_base + next(_stagger_step)

    # VMware
    scheduler.add_job(job_basic_vms,      IntervalTrigger(minutes=30), id="job_basic_vms",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_basic_hosts,    IntervalTrigger(minutes=30), id="job_basic_hosts",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_detailed_vms,   IntervalTrigger(hours=2),    id="job_detailed_vms",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_disk_snapshots, IntervalTrigger(hours=2),    id="job_disk_snapshots",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_untagged_vms,   IntervalTrigger(hours=4),    id="job_untagged_vms",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_detailed_hosts, IntervalTrigger(hours=2),    id="job_detailed_hosts",
                      replace_existing=True, next_run_time=_staggered())

    # OpManager
    scheduler.add_job(job_opmanager_alerts,  IntervalTrigger(minutes=5),  id="job_opmanager_alerts",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_opmanager_devices, IntervalTrigger(minutes=15), id="job_opmanager_devices",
                      replace_existing=True, next_run_time=_staggered())

    # Jira — bulk fetch every 30 min (was 10 min per-device, caused rate limiting)
    # Also fires near-immediately on startup to warm the cache
    scheduler.add_job(job_jira_prefetch, IntervalTrigger(minutes=30), id="job_jira_prefetch",
                      replace_existing=True, next_run_time=_staggered())

    # Active Directory
    scheduler.add_job(job_ad_summary,      IntervalTrigger(hours=4),      id="job_ad_summary",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_ad_reports,      IntervalTrigger(hours=6),      id="job_ad_reports",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_ad_gpo_analysis, CronTrigger(hour=3, minute=0), id="job_ad_gpo",     replace_existing=True)

    # Citrix — summary runs near-immediately on startup to warm cache
    # Power unknown check runs every 15 min (no immediate run — waits for Citrix cache to populate first)
    scheduler.add_job(job_citrix_summary, IntervalTrigger(hours=1), id="job_citrix_summary",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_citrix_power_unknown_check, IntervalTrigger(minutes=15),
                      id="job_citrix_power_unknown_check", replace_existing=True, next_run_time=_staggered())

    # Lansweeper — summary/patch every 6h, full asset list every 6h (all run near-startup to warm cache)
    scheduler.add_job(job_lansweeper_summary, IntervalTrigger(hours=6), id="job_lansweeper_summary",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_lansweeper_patch,   IntervalTrigger(hours=6), id="job_lansweeper_patch",
                      replace_existing=True, next_run_time=_staggered())
    scheduler.add_job(job_lansweeper_assets,  IntervalTrigger(hours=6), id="job_lansweeper_assets",
                      replace_existing=True, next_run_time=_staggered())

    # Meraki — runs near-immediately on startup, then every 15 min
    scheduler.add_job(job_meraki_refresh, IntervalTrigger(minutes=15), id="job_meraki_refresh",
                      replace_existing=True, next_run_time=_staggered())

    # AI Analysis — daily at 6am
    scheduler.add_job(job_ai_analysis, CronTrigger(hour=6, minute=0), id="job_ai_analysis", replace_existing=True)

    # Jira Intelligence — daily at 7am (after AI analysis, after overnight ticket activity)
    scheduler.add_job(job_jira_intelligence, CronTrigger(hour=7, minute=0), id="job_jira_intelligence", replace_existing=True)

    # Findings engine — every 15 min, runs near-immediately on startup
    scheduler.add_job(job_findings, IntervalTrigger(minutes=15), id="job_findings",
                      replace_existing=True, next_run_time=_staggered())

    # Entra / M365 — every hour
    scheduler.add_job(job_entra_refresh, IntervalTrigger(hours=1), id="job_entra_refresh",
                      replace_existing=True, next_run_time=_staggered())

    # Build the job function map now that all functions exist
    _init_job_funcs()

    # Apply DB config overrides (pause disabled jobs, override intervals)
    try:
        from routers.database import get_scheduler_config
        db_config = get_scheduler_config()
        for jid, cfg in db_config.items():
            if not cfg["enabled"]:
                try: scheduler.pause_job(jid)
                except Exception: pass
            if cfg["interval_minutes"] is not None and JOB_DEFAULTS.get(jid, {}).get("type") == "interval":
                try: scheduler.reschedule_job(jid, trigger=IntervalTrigger(minutes=cfg["interval_minutes"]))
                except Exception as e: logger.warning("DB interval override failed for %s: %s", jid, e)
    except Exception as e:
        logger.warning("Scheduler: DB config overrides failed (non-fatal): %s", str(e))

    scheduler.start()
    logger.info("Scheduler started. All background jobs active.")