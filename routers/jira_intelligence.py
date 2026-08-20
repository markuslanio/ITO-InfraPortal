"""
routers/jira_intelligence.py — Jira cross-project intelligence analysis.

Fetches 90 days of tickets from ITSD, TASI, and ITO, computes aggregated
statistics, cross-correlates patterns, and synthesizes findings via Claude.

Called by job_jira_intelligence() in scheduler.py (daily at 7am).
Also triggered manually via POST /infraportal/api/jira-intelligence/run.
"""
import json
import logging
import os
import re
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta

import httpx
from anthropic import Anthropic, APIStatusError

logger = logging.getLogger(__name__)

_client = None
_running = False
_run_lock = threading.Lock()


def _get_client():
    global _client
    if _client is None:
        _client = Anthropic(
            api_key=os.getenv("CLAUDE_API_KEY"),
            http_client=httpx.Client(verify=False, timeout=120.0),
        )
    return _client


def is_running() -> bool:
    return _running


def compute_stats_for_period(days: int) -> dict | None:
    """Compute stats from cached DB tickets for a given lookback period (no AI synthesis).
    ITSD/TASI use strict creation-date filter; ITO always shows full open project list."""
    from routers.database import load_jira_tickets_period, load_jira_tickets
    itsd = load_jira_tickets_period("ITSD", days)
    tasi = load_jira_tickets_period("TASI", days)
    ito  = load_jira_tickets("ITO", days=90)
    if not (itsd or tasi or ito):
        return None
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "period_days":  days,
        "counts":       {"itsd": len(itsd), "tasi": len(tasi), "ito": len(ito)},
        "itsd":         _itsd_stats(itsd),
        "tasi":         _tasi_stats(tasi),
        "ito":          _ito_stats(ito),
        "correlations": _correlations(itsd, tasi, ito),
    }


def trigger_background() -> bool:
    """Start analysis in a background thread. Returns False if already running."""
    if _running:
        return False
    t = threading.Thread(target=run_jira_intelligence, daemon=True)
    t.start()
    return True


def run_jira_intelligence() -> dict:
    """
    Main entry point — fetch, compute, synthesize, store.
    Thread-safe: if already running returns immediately.
    """
    global _running
    with _run_lock:
        if _running:
            return {"status": "already_running"}
        _running = True
    try:
        return _run()
    finally:
        with _run_lock:
            _running = False


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def _run() -> dict:
    from routers import jira as jira_mod
    from routers.database import upsert_jira_tickets, save_jira_intelligence

    logger.info("Jira intelligence: fetching tickets from all three projects...")
    try:
        itsd = jira_mod.fetch_itsd_tickets(days=90)
    except Exception as e:
        logger.error("Jira intelligence: ITSD fetch failed: %s", e)
        itsd = []
    try:
        tasi = jira_mod.fetch_tasi_tickets(days=90)
    except Exception as e:
        logger.error("Jira intelligence: TASI fetch failed: %s", e)
        tasi = []
    try:
        ito = jira_mod.fetch_ito_tickets(days=90)
    except Exception as e:
        logger.error("Jira intelligence: ITO fetch failed: %s", e)
        ito = []

    upsert_jira_tickets(itsd + tasi + ito)
    logger.info("Jira intelligence: stored %d total tickets (ITSD=%d TASI=%d ITO=%d)",
                len(itsd) + len(tasi) + len(ito), len(itsd), len(tasi), len(ito))

    stats = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "period_days":  90,
        "counts":       {"itsd": len(itsd), "tasi": len(tasi), "ito": len(ito)},
        "itsd":         _itsd_stats(itsd),
        "tasi":         _tasi_stats(tasi),
        "ito":          _ito_stats(ito),
        "correlations": _correlations(itsd, tasi, ito),
    }

    logger.info("Jira intelligence: running AI synthesis...")
    try:
        narrative = _synthesize(stats)
    except Exception as e:
        logger.error("Jira intelligence: synthesis failed: %s", e)
        narrative = f"AI synthesis unavailable: {e}"

    result = {
        "stats":        stats,
        "narrative":    narrative,
        "generated_at": stats["generated_at"],
    }
    save_jira_intelligence(json.dumps(result), narrative[:2000])
    logger.info("Jira intelligence: complete")
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _week_label(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts[:10]).strftime("%Y-W%W")
    except Exception:
        return "unknown"


def _days_since(ts: str) -> int:
    try:
        return (datetime.now() - datetime.fromisoformat(ts[:10])).days
    except Exception:
        return 0


def _resolve_hours(created: str, resolved: str) -> float | None:
    try:
        c = datetime.fromisoformat(created[:19])
        r = datetime.fromisoformat(resolved[:19])
        h = (r - c).total_seconds() / 3600
        return round(h, 1) if h >= 0 else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ITSD statistics
# ---------------------------------------------------------------------------

def _itsd_stats(tickets: list) -> dict:
    if not tickets:
        return {"total": 0}

    open_t   = [t for t in tickets if t["status_category"] != "Done"]
    closed_t = [t for t in tickets if t["status_category"] == "Done"]

    weekly = Counter(_week_label(t["created"]) for t in tickets)
    last12 = sorted(weekly)[-12:]

    by_sev    = Counter(t["severity"] or "Not Set" for t in tickets)
    by_source = Counter(t["source"]   or "Unknown" for t in tickets)
    by_team   = Counter(t["team"]     or "Unassigned" for t in tickets if t.get("team"))
    by_op_cat = Counter(t["operational_category"] or "Uncategorized" for t in tickets)

    device_counts: Counter = Counter()
    for t in tickets:
        sn = (t.get("server_name") or "").split(".")[0].strip().upper()
        if sn and len(sn) >= 3:
            device_counts[sn] += 1

    res_by_pri: dict[str, list] = defaultdict(list)
    for t in closed_t:
        if t.get("resolved") and t.get("created"):
            h = _resolve_hours(t["created"], t["resolved"])
            if h is not None:
                res_by_pri[t["priority"] or "None"].append(h)

    stuck = sorted(
        [{"key": t["key"], "summary": t["summary"][:80],
          "days_open": _days_since(t["created"]),
          "team": t["team"], "severity": t["severity"]}
         for t in open_t if _days_since(t["created"]) > 30],
        key=lambda x: -x["days_open"]
    )

    mon_count = sum(1 for t in tickets if "monitor" in (t.get("source") or "").lower())

    sev12 = [{"key": t["key"], "summary": t["summary"][:80],
               "status": t["status"], "severity": t["severity"],
               "created": t["created"][:10]}
             for t in tickets if t.get("severity") in ("Sev-1", "Sev-2")]

    return {
        "total":                   len(tickets),
        "open":                    len(open_t),
        "resolved_90d":            len(closed_t),
        "weekly_volume":           [{"week": w, "count": weekly[w]} for w in last12],
        "by_severity":             dict(by_sev.most_common()),
        "by_source":               dict(by_source.most_common()),
        "by_team":                 dict(by_team.most_common(10)),
        "by_operational_category": dict(by_op_cat.most_common(10)),
        "top_devices":             [{"device": d, "count": c} for d, c in device_counts.most_common(20)],
        "avg_resolution_hours":    {p: round(sum(v) / len(v), 1) for p, v in res_by_pri.items() if v},
        "stuck_tickets":           stuck[:15],
        "monitoring_sourced_pct":  round(100 * mon_count / len(tickets), 1),
        "sev1_sev2":               sev12[:10],
    }


# ---------------------------------------------------------------------------
# ITSD team trend (still-open snapshot over time)
# ---------------------------------------------------------------------------

def compute_itsd_team_trend(weeks: int = 8) -> dict:
    """Still-open ITSD ticket count per team, snapshotted at each of the last `weeks` week-boundaries."""
    from routers.database import load_jira_tickets
    tickets = load_jira_tickets("ITSD", days=max(90, weeks * 7 + 14))
    return _itsd_team_trend(tickets, weeks=weeks)


def _parse_date(ts):
    try:
        return datetime.fromisoformat(ts[:10]).date()
    except Exception:
        return None


def _itsd_team_trend(tickets: list, weeks: int) -> dict:
    parsed = []
    for t in tickets:
        c = _parse_date(t.get("created"))
        if not c:
            continue
        r = _parse_date(t.get("resolved")) if t.get("resolved") else None
        parsed.append((t.get("team") or "", c, r))

    team_names = sorted({team for team, _, _ in parsed if team and team.startswith("ITO")})
    today = datetime.now().date()
    points = [today - timedelta(weeks=w) for w in range(weeks - 1, -1, -1)]  # oldest → newest
    labels = [p.strftime("%b %d") for p in points]

    all_series = []
    by_team = {name: [] for name in team_names}
    for point in points:
        open_at_point = [(team, c, r) for team, c, r in parsed if c <= point and (r is None or r > point)]
        all_series.append(len(open_at_point))
        for name in team_names:
            by_team[name].append(sum(1 for team, _, _ in open_at_point if team == name))

    return {"labels": labels, "all_teams": all_series, "by_team": by_team, "teams": team_names}


# ---------------------------------------------------------------------------
# ITO closed-project trend (Epics resolved per bucket)
# ---------------------------------------------------------------------------

def compute_ito_closed_trend(bucket_weeks: int = 2, num_buckets: int = 4) -> dict:
    """Count of ITO Epics resolved within each `bucket_weeks`-wide window, most recent last."""
    from routers.database import load_jira_tickets
    tickets = load_jira_tickets("ITO", days=bucket_weeks * num_buckets * 7 + 30)
    return _ito_closed_trend(tickets, bucket_weeks=bucket_weeks, num_buckets=num_buckets)


def _ito_closed_trend(tickets: list, bucket_weeks: int, num_buckets: int) -> dict:
    epics = [t for t in tickets
             if t.get("issue_type") == "Epic" and t.get("status_category") == "Done" and t.get("resolved")]

    today = datetime.now().date()
    buckets = []  # (start, end) oldest → newest
    for i in range(num_buckets - 1, -1, -1):
        end = today - timedelta(weeks=i * bucket_weeks)
        start = end - timedelta(weeks=bucket_weeks)
        buckets.append((start, end))

    labels = [f"{s.strftime('%b %d')}–{e.strftime('%b %d')}" for s, e in buckets]
    counts = []
    for start, end in buckets:
        n = sum(1 for t in epics if (lambda d: d and start < d <= end)(_parse_date(t["resolved"])))
        counts.append(n)

    return {"labels": labels, "counts": counts}


# ---------------------------------------------------------------------------
# TASI statistics
# ---------------------------------------------------------------------------

def _tasi_stats(tickets: list) -> dict:
    if not tickets:
        return {"total": 0}

    weekly = Counter(_week_label(t["created"]) for t in tickets)
    last12 = sorted(weekly)[-12:]

    by_group  = Counter(t["resource_group"] or "Unknown" for t in tickets)
    by_env    = Counter(t["environment"]    or "Unknown" for t in tickets)
    by_type   = Counter(t["tas_type"]       or "Unknown" for t in tickets)
    by_status = Counter(t["status"]                      for t in tickets)

    rolled_back = [{"key": t["key"], "summary": t["summary"][:80],
                    "resource_group": t["resource_group"]}
                   for t in tickets if "rolled" in (t["status"] or "").lower()]

    emergency = sorted(
        [{"key": t["key"], "summary": t["summary"][:80],
          "resource_group": t["resource_group"], "environment": t["environment"],
          "created": t["created"][:10]}
         for t in tickets if t.get("tas_type") == "eTAS"],
        key=lambda x: x["created"], reverse=True
    )

    prod = [t for t in tickets if (t.get("environment") or "") == "Production"]
    prod_by_group = Counter(t["resource_group"] or "Unknown" for t in prod)

    durations = []
    for t in tickets:
        if t.get("tas_start") and t.get("tas_end"):
            try:
                s = datetime.fromisoformat(t["tas_start"][:19])
                e = datetime.fromisoformat(t["tas_end"][:19])
                h = (e - s).total_seconds() / 3600
                if 0 < h < 48:
                    durations.append(h)
            except Exception:
                pass

    return {
        "total":                   len(tickets),
        "weekly_volume":           [{"week": w, "count": weekly[w]} for w in last12],
        "by_resource_group":       dict(by_group.most_common()),
        "by_environment":          dict(by_env.most_common()),
        "by_type":                 dict(by_type.most_common()),
        "by_status":               dict(by_status.most_common()),
        "rolled_back_count":       len(rolled_back),
        "rolled_back":             rolled_back,
        "emergency_count":         len(emergency),
        "emergency_changes":       emergency[:10],
        "production_by_group":     dict(prod_by_group.most_common()),
        "avg_change_window_hours": round(sum(durations) / len(durations), 1) if durations else None,
    }


# ---------------------------------------------------------------------------
# ITO statistics
# ---------------------------------------------------------------------------

def _ito_stats(tickets: list) -> dict:
    if not tickets:
        return {"total": 0}

    today  = datetime.now().date()
    epics  = [t for t in tickets if t["issue_type"] == "Epic"]
    tasks  = [t for t in tickets if t["issue_type"] == "Task"]

    open_epics = [t for t in epics if t["status_category"] != "Done"]
    by_status  = Counter(t["status"] for t in epics)

    by_objective: Counter = Counter()
    for t in epics:
        for obj in re.split(r",\s*", t.get("objective") or ""):
            if obj.strip():
                by_objective[obj.strip()] += 1

    overdue = sorted(
        [{"key": t["key"], "summary": t["summary"][:80],
          "due": t["due_date"], "status": t["status"], "team": t["team"],
          "days_overdue": (today - datetime.fromisoformat(t["due_date"]).date()).days}
         for t in open_epics
         if t.get("due_date") and
         (lambda d: d < today)(datetime.fromisoformat(t["due_date"]).date())],
        key=lambda x: -x["days_overdue"]
    )

    stalled = sorted(
        [{"key": t["key"], "summary": t["summary"][:80],
          "status": t["status"], "team": t["team"],
          "days_stalled": _days_since(t["updated"])}
         for t in open_epics if _days_since(t["updated"]) > 30],
        key=lambda x: -x["days_stalled"]
    )

    blocked = [{"key": t["key"], "summary": t["summary"][:80], "team": t["team"]}
               for t in epics if t["status"] == "Blocked"]

    recent_done = [{"key": t["key"], "summary": t["summary"][:80], "team": t["team"]}
                   for t in epics
                   if t["status_category"] == "Done"
                   and t.get("resolved") and _days_since(t["resolved"]) < 30]

    return {
        "total_epics":        len(epics),
        "open_epics":         len(open_epics),
        "total_tasks":        len(tasks),
        "by_status":          dict(by_status.most_common()),
        "by_objective":       dict(by_objective.most_common()),
        "overdue_count":      len(overdue),
        "overdue_epics":      overdue[:10],
        "stalled_count":      len(stalled),
        "stalled_epics":      stalled[:10],
        "blocked_count":      len(blocked),
        "blocked_epics":      blocked[:10],
        "recent_completions": recent_done[:10],
    }


# ---------------------------------------------------------------------------
# Cross-project correlations
# ---------------------------------------------------------------------------

def _correlations(itsd: list, tasi: list, ito: list) -> dict:

    # ── 1. TASI Production changes that preceded ITSD incident spikes ─────────
    tasi_to_itsd = []
    for change in tasi:
        if (change.get("environment") or "") != "Production" or not change.get("tas_end"):
            continue
        try:
            change_end = datetime.fromisoformat(change["tas_end"][:19])
        except Exception:
            continue

        window_end = change_end + timedelta(days=7)

        keywords: set[str] = set()
        for src in [change.get("systems") or "", change.get("hardware_names") or "",
                    change.get("resource_group") or "", change.get("summary") or ""]:
            for word in re.split(r"[\s,/\-]+", src):
                w = word.strip().upper()
                if len(w) >= 4 and not w.isdigit():
                    keywords.add(w)

        related = []
        for inc in itsd:
            try:
                inc_dt = datetime.fromisoformat(inc["created"][:19])
            except Exception:
                continue
            if not (change_end <= inc_dt <= window_end):
                continue
            inc_text = " ".join([inc.get("summary") or "", inc.get("server_name") or "",
                                  inc.get("systems") or ""]).upper()
            if any(kw in inc_text for kw in keywords):
                related.append({"key": inc["key"], "summary": inc["summary"][:60]})

        if related:
            tasi_to_itsd.append({
                "change_key":        change["key"],
                "change_summary":    change["summary"][:80],
                "resource_group":    change["resource_group"],
                "change_date":       (change["tas_end"] or "")[:10],
                "incident_count":    len(related),
                "related_incidents": related[:5],
            })

    tasi_to_itsd.sort(key=lambda x: -x["incident_count"])

    # ── 2. Chronic devices with >3 ITSD tickets and no ITO Epic covering them ─
    device_counts: Counter = Counter()
    for t in itsd:
        sn = (t.get("server_name") or "").split(".")[0].strip().upper()
        if sn and len(sn) >= 3:
            device_counts[sn] += 1

    ito_text = " ".join(t.get("summary") or "" for t in ito).upper()
    chronic_untracked = [
        {"device": dev, "ticket_count": cnt}
        for dev, cnt in device_counts.most_common(50)
        if cnt >= 3 and dev not in ito_text
    ]

    # ── 3. High-volume ITSD categories with no ITO objective covering them ────
    op_counts = Counter(t["operational_category"] for t in itsd if t.get("operational_category"))
    ito_obj_text = " ".join(t.get("objective") or "" for t in ito).lower()

    # Simple keyword mapping from operational category to ITO objective themes
    category_keywords = {
        "Break/Fix":       ["fixing issues", "tech debt"],
        "Account Request": ["active directory", "account", "email/ad"],
        "Server Change":   ["upgrade", "infrastructure", "windows"],
        "VM Request":      ["vmware", "cloud", "infrastructure"],
        "Connectivity":    ["network", "networking"],
        "Configuration":   ["upgrade", "streamline", "tech debt"],
    }
    category_gaps = []
    for cat, count in op_counts.most_common(15):
        if count < 5:
            continue
        root = (cat.split(" > ")[0] if " > " in cat else cat).strip()
        kws  = category_keywords.get(root, [root.lower()])
        if not any(kw in ito_obj_text for kw in kws):
            category_gaps.append({"category": cat, "ticket_count": count})

    return {
        "tasi_to_itsd":      tasi_to_itsd[:10],
        "chronic_untracked": chronic_untracked[:15],
        "category_gaps":     category_gaps[:10],
    }


# ---------------------------------------------------------------------------
# Claude synthesis
# ---------------------------------------------------------------------------

def _synthesize(stats: dict) -> str:
    itsd = stats["itsd"]
    tasi = stats["tasi"]
    ito  = stats["ito"]
    corr = stats["correlations"]

    payload = {
        "period": f"Last {stats['period_days']} days as of {stats['generated_at']}",
        "itsd": {
            "total": itsd.get("total", 0),
            "open":  itsd.get("open", 0),
            "monitoring_sourced_pct": itsd.get("monitoring_sourced_pct"),
            "sev1_sev2_count":        len(itsd.get("sev1_sev2", [])),
            "stuck_over_30d":         len(itsd.get("stuck_tickets", [])),
            "by_severity":            itsd.get("by_severity", {}),
            "by_source":              dict(list((itsd.get("by_source") or {}).items())[:5]),
            "top_teams":              dict(list((itsd.get("by_team") or {}).items())[:5]),
            "top_op_categories":      dict(list((itsd.get("by_operational_category") or {}).items())[:6]),
            "top_10_devices":         (itsd.get("top_devices") or [])[:10],
            "avg_resolution_hours":   itsd.get("avg_resolution_hours", {}),
            "stuck_sample":           (itsd.get("stuck_tickets") or [])[:5],
            "sev1_sev2_sample":       (itsd.get("sev1_sev2") or [])[:5],
            "weekly_trend":           (itsd.get("weekly_volume") or [])[-8:],
        },
        "tasi": {
            "total":                tasi.get("total", 0),
            "emergency_count":      tasi.get("emergency_count", 0),
            "rollback_count":       tasi.get("rolled_back_count", 0),
            "avg_change_window_hrs": tasi.get("avg_change_window_hours"),
            "by_resource_group":    tasi.get("by_resource_group", {}),
            "by_environment":       tasi.get("by_environment", {}),
            "by_type":              tasi.get("by_type", {}),
            "production_by_group":  tasi.get("production_by_group", {}),
            "emergency_sample":     (tasi.get("emergency_changes") or [])[:5],
            "rollback_sample":      (tasi.get("rolled_back") or []),
            "weekly_trend":         (tasi.get("weekly_volume") or [])[-8:],
        },
        "ito": {
            "open_epics":    ito.get("open_epics", 0),
            "overdue_count": ito.get("overdue_count", 0),
            "stalled_count": ito.get("stalled_count", 0),
            "blocked_count": ito.get("blocked_count", 0),
            "by_status":     ito.get("by_status", {}),
            "by_objective":  ito.get("by_objective", {}),
            "overdue_sample": (ito.get("overdue_epics") or [])[:5],
            "stalled_sample": (ito.get("stalled_epics") or [])[:5],
        },
        "correlations": {
            "changes_linked_to_incidents":    len(corr.get("tasi_to_itsd", [])),
            "chronic_devices_without_project": len(corr.get("chronic_untracked", [])),
            "incident_categories_without_project": len(corr.get("category_gaps", [])),
            "change_incident_sample":  (corr.get("tasi_to_itsd") or [])[:3],
            "chronic_device_sample":   (corr.get("chronic_untracked") or [])[:10],
            "gap_sample":              (corr.get("category_gaps") or [])[:5],
        },
    }

    prompt = (
        "You are the infrastructure intelligence analyst for Zinnia's IT Operations team. "
        "You have processed 90 days of ticket data across three Jira projects:\n"
        "- ITSD: IT Service Desk incidents (reactive — something broke)\n"
        "- TASI: Infrastructure change records (planned maintenance and deployments)\n"
        "- ITO: IT Operations projects (Epics and Tasks for ongoing work)\n\n"
        "Analyze the pre-computed statistics below and write a structured intelligence report "
        "with exactly these sections:\n\n"
        "## Headline Findings\n"
        "3-5 bullet points — the most important things happening right now.\n\n"
        "## Recurring Problems\n"
        "Which devices, categories, or teams keep generating incidents. Name specifics.\n\n"
        "## Change Risk Patterns\n"
        "What TASI change activity looks risky or correlates with incident spikes.\n\n"
        "## Tracking Gaps\n"
        "Problems being handled reactively in ITSD that should have an ITO project. "
        "Name the devices or categories and estimate the scale.\n\n"
        "## ITO Project Health\n"
        "Overdue, stalled, or blocked work that needs leadership attention.\n\n"
        "## What's Working\n"
        "Positive signals — improving trends, good resolution times, clean areas, "
        "recently completed projects.\n\n"
        "Rules: Be specific — reference ticket keys, device names, counts, and percentages. "
        "Each section: 3-6 concise bullet points. Infrastructure engineers will act on this.\n\n"
        "Data:\n" + json.dumps(payload, indent=2)
    )

    client = _get_client()
    delays = [5, 15, 30]
    for attempt in range(1, 4):
        try:
            resp = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text
        except APIStatusError as e:
            if e.status_code in (500, 529) and attempt < 3:
                time.sleep(delays[attempt - 1])
            else:
                raise
    raise RuntimeError("Claude synthesis failed after retries")
