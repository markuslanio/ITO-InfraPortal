"""
Alert hygiene reports for the NOC — surfaces old/stale alarms and likely
misconfigured-threshold noise so the team can clean up OpManager's alert list
instead of triaging the same junk alerts every day.

Core idea: a Critical alert should mean something is actually down. If nothing
is down and we still see red, it's one of:
  - the device was decommissioned but never removed from OpManager
  - the specific monitor's threshold is wrong (device is fine, one check isn't)
  - the check is flapping (fires/clears repeatedly instead of staying resolved)
"""
import time
import re
import logging

log = logging.getLogger(__name__)

_DECOMMISSIONED_STATES = ("decommission", "retired", "disposed")


def _short_name(name: str) -> str:
    """Match the frontend's shortDeviceName(): strip domain suffix from
    hostnames but leave IPs alone, then normalize case for lookups."""
    name = (name or "").strip()
    if not name:
        return ""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", name):
        return name
    return name.split(".")[0].upper()


def _age_days(epoch_seconds) -> float:
    if not epoch_seconds:
        return 0.0
    return round((time.time() - epoch_seconds) / 86400, 1)


def _age_bucket(age_days: float) -> str:
    if age_days >= 90:
        return "90d+"
    if age_days >= 30:
        return "30-90d"
    if age_days >= 7:
        return "7-30d"
    return "<7d"


def _build_lookup_maps():
    """Build the cross-reference maps shared by all reports: live devices,
    Lansweeper assets, and alert_history — each keyed by short device name."""
    from routers.opmanager import get_devices
    from routers.database import load_lansweeper_assets, get_alert_history_map

    devices_by_name = {}
    try:
        devices, _ = get_devices()
        for d in (devices or []):
            key = _short_name(d.get("display_name"))
            if key:
                devices_by_name[key] = d
    except Exception as e:
        log.warning("alert_reports: get_devices failed: %s", e)

    ls_by_name = {}
    try:
        assets, _ = load_lansweeper_assets()
        for a in (assets or []):
            key = _short_name(a.get("name"))
            if key:
                ls_by_name[key] = a
    except Exception as e:
        log.warning("alert_reports: load_lansweeper_assets failed: %s", e)

    history_map = {}
    try:
        history_map = get_alert_history_map()
    except Exception as e:
        log.warning("alert_reports: get_alert_history_map failed: %s", e)

    return devices_by_name, ls_by_name, history_map


def _tag_alarm(alarm, hist, devices_by_name, ls_by_name, flapping_pairs) -> list[str]:
    tags = []
    key = _short_name(alarm.get("device_name"))
    device = devices_by_name.get(key)
    ls_asset = ls_by_name.get(key)
    age_days = _age_days(hist.get("first_seen")) if hist else 0.0
    sev_num = alarm.get("severity_num") or 5

    if not device:
        tags.append("orphaned_device")
    elif ls_asset:
        state = (ls_asset.get("state") or "").lower()
        days_unseen = ls_asset.get("days_since_seen")
        if any(s in state for s in _DECOMMISSIONED_STATES) or (days_unseen and days_unseen > 30):
            tags.append("likely_decommissioned")

    if device and sev_num <= 2 and (device.get("status_num") or 5) >= 4:
        # This specific alarm is Critical/Trouble but OpManager's own rollup
        # status for the device is Service-Down-or-better (i.e. not driven by
        # this alarm) — the device is fine, this one monitor's threshold isn't.
        tags.append("critical_but_device_up")

    if age_days >= 30 and not alarm.get("acknowledged") and sev_num <= 2:
        tags.append("aging_unacked_critical")

    pair_key = (alarm.get("device_name"), alarm.get("event_type"))
    if flapping_pairs.get(pair_key):
        tags.append("flapping_threshold")

    return tags


def build_stale_alerts_report(min_age_days: int = 7) -> list[dict]:
    from routers.opmanager import get_alarms
    from routers.database import get_flapping_pairs

    alarms, _ = get_alarms()
    devices_by_name, ls_by_name, history_map = _build_lookup_maps()
    flapping_pairs = get_flapping_pairs(days=max(min_age_days, 30))

    rows = []
    for a in alarms:
        if a.get("severity") == "Clear":
            continue
        hist = history_map.get(a.get("alarm_id"), {})
        first_seen = hist.get("first_seen")
        age_days = _age_days(first_seen)
        if age_days < min_age_days:
            continue
        tags = _tag_alarm(a, hist, devices_by_name, ls_by_name, flapping_pairs)
        rows.append({
            **a,
            "age_days":        age_days,
            "age_bucket":      _age_bucket(age_days),
            "occurrence_count": hist.get("occurrence_count", 1),
            "first_seen":      first_seen,
            "tags":            tags,
        })
    rows.sort(key=lambda r: r["age_days"], reverse=True)
    return rows


def build_critical_vs_device_up_report() -> list[dict]:
    """Alarms rated Critical/Trouble where the device's own OpManager status
    is not driven by this alarm — i.e. the box is up, one check is wrong."""
    from routers.opmanager import get_alarms

    alarms, _ = get_alarms()
    devices_by_name, ls_by_name, history_map = _build_lookup_maps()

    rows = []
    for a in alarms:
        sev_num = a.get("severity_num") or 5
        if sev_num > 2:
            continue
        key = _short_name(a.get("device_name"))
        device = devices_by_name.get(key)
        if not device or (device.get("status_num") or 5) < 4:
            continue
        hist = history_map.get(a.get("alarm_id"), {})
        rows.append({
            **a,
            "device_status":     device.get("status"),
            "device_status_num": device.get("status_num"),
            "age_days":          _age_days(hist.get("first_seen")),
            "occurrence_count":  hist.get("occurrence_count", 1),
        })
    rows.sort(key=lambda r: r["age_days"], reverse=True)
    return rows


def build_noisy_alert_types_report(days: int = 30) -> list[dict]:
    from routers.database import get_noisy_alert_types

    rows = get_noisy_alert_types(days=days)
    for r in rows:
        r["span_days"] = days
    return rows


def build_recurring_alerts_report(days: int = 90, min_occurrences: int = 3) -> list[dict]:
    """Groups from the ack/clear action log (what the NOC has actually had to touch
    repeatedly) — the raw 'what keeps coming back' data set that the AI analysis
    explains. Reuses the same evidence signals as the stale-alerts tagging."""
    from routers.database import get_recurring_action_groups, get_flapping_pairs

    groups = get_recurring_action_groups(days=days, min_occurrences=min_occurrences)
    devices_by_name, ls_by_name, _ = _build_lookup_maps()
    flapping_pairs = get_flapping_pairs(days=days, min_incidents=min_occurrences)

    rows = []
    for g in groups:
        key = _short_name(g["device_name"])
        device = devices_by_name.get(key)
        ls_asset = ls_by_name.get(key)
        tags = []
        if not device:
            tags.append("orphaned_device")
        elif ls_asset:
            state = (ls_asset.get("state") or "").lower()
            days_unseen = ls_asset.get("days_since_seen")
            if any(s in state for s in _DECOMMISSIONED_STATES) or (days_unseen and days_unseen > 30):
                tags.append("likely_decommissioned")
        if flapping_pairs.get((g["device_name"], g["event_type"])):
            tags.append("flapping_threshold")
        rows.append({
            **g,
            "span_days":          round((g["last_action"] - g["first_action"]) / 86400, 1),
            "device_status":      (device or {}).get("status"),
            "days_since_seen_ls": (ls_asset or {}).get("days_since_seen"),
            "tags":               tags,
        })
    return rows


def build_chronic_red_devices_report(days: int = 30, min_red_ratio: float = 0.9) -> list[dict]:
    from routers.database import get_chronic_red_devices

    devices_by_name, ls_by_name, _ = _build_lookup_maps()
    rows = []
    for r in get_chronic_red_devices(days=days):
        red_ratio = (r["red_poll_hits"] / r["poll_hits"]) if r["poll_hits"] else 0
        span_days = _age_days(r["first_seen"])
        if red_ratio < min_red_ratio or span_days < 7:
            continue
        key = _short_name(r["device_name"])
        device = devices_by_name.get(key)
        ls_asset = ls_by_name.get(key)
        rows.append({
            **r,
            "red_ratio":   round(red_ratio * 100, 1),
            "span_days":   span_days,
            "age_bucket":  _age_bucket(span_days),
            "orphaned":    device is None,
            "days_since_seen_ls": (ls_asset or {}).get("days_since_seen"),
        })
    rows.sort(key=lambda r: r["red_ratio"], reverse=True)
    return rows
