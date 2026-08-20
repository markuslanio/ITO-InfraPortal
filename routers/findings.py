"""
routers/findings.py — Portal intelligence findings engine.

Reads from existing caches and SQLite tables to detect pre-failure and
actionable conditions across all integrated systems. Writes to the
portal_findings table. Called every 15 min by job_findings() in scheduler.py.
"""
import json
import logging
import time
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

SEV_CRITICAL = 1
SEV_WARNING  = 2
SEV_INFO     = 3

SYSTEM_URLS = {
    "VMware":     "/infraportal/vmware",
    "Network":    "/infraportal/network",
    "Auth":       "/infraportal/active-directory",
    "Citrix":     "/infraportal/citrix",
    "Certs":      "/infraportal/certificates",
    "Monitoring": "/infraportal/alerts",
    "Assets":     "/infraportal/assets",
    "Jira":       "/infraportal/jira-intelligence",
}


def refresh_findings() -> int:
    """Regenerate all findings from current cache/DB state. Returns count."""
    from routers.database import save_findings
    findings = []
    for fn in (_vmware_findings, _opmanager_findings, _cert_findings,
               _jira_findings, _ad_findings, _lansweeper_findings, _meraki_findings):
        try:
            findings.extend(fn())
        except Exception as e:
            logger.error("findings: %s failed: %s", fn.__name__, e)
    save_findings(findings)
    logger.info("findings: refreshed — %d total", len(findings))
    return len(findings)


def compute_system_health(findings: list) -> dict:
    """
    Return dict of system → status string for the health strip.
    Status: 'critical', 'warning', 'ok', 'unknown'
    """
    systems = list(SYSTEM_URLS.keys())
    health = {s: "unknown" for s in systems}
    seen = set()
    for f in findings:
        sys = f.get("system")
        if sys not in health:
            continue
        seen.add(sys)
        current = health[sys]
        sev = f.get("severity", SEV_INFO)
        if sev == SEV_CRITICAL:
            health[sys] = "critical"
        elif sev == SEV_WARNING and current != "critical":
            health[sys] = "warning"
        elif current == "unknown":
            health[sys] = "ok"
    for s in seen:
        if health[s] == "unknown":
            health[s] = "ok"
    # Systems with no findings but a known cache → mark ok
    from routers.cache import cache
    cache_keys = {
        "VMware": "vm_storage", "Network": None, "Auth": "ad_summary",
        "Citrix": "citrix_summary", "Certs": "ca_expiring",
        "Monitoring": "opm_alarms", "Assets": "ls_asset_summary",
    }
    for sys, key in cache_keys.items():
        if health[sys] == "unknown" and key:
            data, _ = cache.get(key)
            if data is not None:
                health[sys] = "ok"
    # Meraki special case
    if health["Network"] == "unknown":
        try:
            from routers import meraki as meraki_mod
            nets = meraki_mod.get_networks()
            if nets:
                health["Network"] = "ok"
        except Exception:
            pass
    return health


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _f(severity, system, category, title, detail, action_url=None, meta=None):
    return {
        "severity":   severity,
        "system":     system,
        "category":   category,
        "title":      title,
        "detail":     detail or "",
        "action_url": action_url or SYSTEM_URLS.get(system, ""),
        "meta_json":  json.dumps(meta or {}),
        "created_at": int(time.time()),
    }


def _age_str(ts_str: str) -> str:
    try:
        dt = datetime.fromisoformat(ts_str[:19])
        hours = int((datetime.now() - dt).total_seconds() / 3600)
        if hours < 1:
            return "< 1h ago"
        if hours < 24:
            return f"{hours}h ago"
        return f"{hours // 24}d ago"
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# VMware — disk utilisation on VMs and datastores
# ---------------------------------------------------------------------------

def _vmware_findings():
    findings = []
    from routers.cache import cache

    storage, _ = cache.get("vm_storage")
    if storage:
        vms = storage.get("vms") or (storage if isinstance(storage, list) else [])
        critical_vms = []
        warning_vms  = []
        for vm in vms:
            pct_free = vm.get("pct_free")
            if pct_free is None:
                continue
            pct_used = round(100 - pct_free, 1)
            if pct_used >= 90:
                critical_vms.append((pct_used, vm))
            elif pct_used >= 80:
                warning_vms.append((pct_used, vm))

        # Individual critical entries (top 10 worst)
        for pct_used, vm in sorted(critical_vms, key=lambda x: -x[0])[:10]:
            pct_free = round(100 - pct_used, 1)
            name = vm.get("name") or vm.get("vm_name") or "Unknown VM"
            findings.append(_f(SEV_CRITICAL, "VMware", "disk",
                f"{name} — disk at {pct_used}%",
                f"Only {pct_free}% free · immediate action needed",
                meta={"vm_name": name, "pct_used": pct_used, "pct_free": pct_free,
                      "used_gb": vm.get("used_gb"), "capacity_gb": vm.get("capacity_gb")}
            ))
        if len(critical_vms) > 10:
            findings.append(_f(SEV_CRITICAL, "VMware", "disk",
                f"{len(critical_vms) - 10} more VMs above 90% disk usage",
                "Review VMware storage tab for full list",
            ))

        # Summary warning for 80–90%
        if warning_vms:
            names = ", ".join(vm.get("name") or "?" for _, vm in warning_vms[:3])
            findings.append(_f(SEV_WARNING, "VMware", "disk",
                f"{len(warning_vms)} VM{'s' if len(warning_vms) != 1 else ''} between 80–90% disk usage",
                f"{names}{'...' if len(warning_vms) > 3 else ''}",
                meta={"count": len(warning_vms),
                      "vms": [{"name": vm.get("name"), "pct_used": round(100-(vm.get("pct_free") or 0),1)}
                               for _, vm in warning_vms[:15]]}
            ))

    datastores, _ = cache.get("vm_datastores")
    if datastores:
        dss = datastores.get("datastores") or (datastores if isinstance(datastores, list) else [])
        for ds in dss:
            pct_free = ds.get("pct_free")
            if pct_free is None:
                continue
            pct_used = round(100 - pct_free, 1)
            name = ds.get("name") or "Unknown datastore"
            if pct_used >= 85:
                sev = SEV_CRITICAL if pct_used >= 92 else SEV_WARNING
                findings.append(_f(sev, "VMware", "datastore",
                    f"Datastore {name} — {pct_used}% full",
                    f"{pct_free:.1f}% free · affects all VMs on this datastore",
                    meta={"name": name, "pct_used": pct_used, "pct_free": round(pct_free, 1),
                          "capacity_gb": ds.get("capacity_gb"), "free_gb": ds.get("free_gb")}
                ))
    return findings


# ---------------------------------------------------------------------------
# OpManager — unacknowledged Critical / Service Down alerts
# ---------------------------------------------------------------------------

def _opmanager_findings():
    findings = []
    from routers.cache import cache
    data, _ = cache.get("opm_alarms")
    if not data:
        return findings
    alarms = data if isinstance(data, list) else data.get("alarms", [])
    active = [a for a in alarms if not a.get("acknowledged")
              and (a.get("severity_num") or 5) <= 2]
    for alarm in active[:10]:
        device  = alarm.get("device_name") or alarm.get("displayName") or "Unknown"
        sev_lbl = alarm.get("severity", "Critical")
        msg     = (alarm.get("message") or alarm.get("eventType") or "")[:120]
        sev     = SEV_CRITICAL if (alarm.get("severity_num") or 5) <= 1 else SEV_WARNING
        findings.append(_f(sev, "Monitoring", "alert",
            f"{device} — {sev_lbl}",
            msg or "Active alert, not acknowledged",
            meta={"device": device, "severity": sev_lbl, "message": msg,
                  "alarm_id": alarm.get("alarm_id"), "time": alarm.get("time")}
        ))
    return findings


# ---------------------------------------------------------------------------
# Certificates — expiring within 30 days
# ---------------------------------------------------------------------------

def _cert_findings():
    findings = []
    from routers.cache import cache
    data, _ = cache.get("ca_expiring")
    if not data:
        return findings
    certs = data if isinstance(data, list) else data.get("certs", [])

    urgent   = []   # <= 14 days (individual)
    soon     = []   # 15-30 days (summarised)
    expired  = []   # <= 0 days  (summarised)

    for cert in certs:
        days = cert.get("days_remaining")
        if days is None:
            continue
        if days <= 0:
            expired.append(cert)
        elif days <= 14:
            urgent.append(cert)
        elif days <= 30:
            soon.append(cert)

    # Individual entries for the most urgent (expiring ≤ 14 days) — top 10
    for cert in sorted(urgent, key=lambda c: c.get("days_remaining", 0))[:10]:
        days    = cert["days_remaining"]
        subject = cert.get("subject") or "Unknown"
        expiry  = (cert.get("expiry") or "")[:10]
        findings.append(_f(SEV_CRITICAL, "Certs", "expiring",
            f"Certificate expires in {days} day{'s' if days != 1 else ''}: {subject}",
            f"Expires {expiry} · renew immediately",
            meta={"subject": subject, "days_remaining": days, "expiry": expiry}
        ))
    if len(urgent) > 10:
        findings.append(_f(SEV_CRITICAL, "Certs", "expiring",
            f"{len(urgent) - 10} more certificates expiring within 14 days",
            "Review certificate page for full list",
        ))

    # Summary for 15-30 day window
    if soon:
        sample = ", ".join(c.get("subject") or "?" for c in soon[:3])
        findings.append(_f(SEV_WARNING, "Certs", "expiring",
            f"{len(soon)} certificate{'s' if len(soon) != 1 else ''} expiring in 15–30 days",
            f"{sample}{'...' if len(soon) > 3 else ''}",
            meta={"count": len(soon), "sample": [c.get("subject") for c in soon[:10]]}
        ))

    # Summary for expired
    if expired:
        sample = ", ".join(c.get("subject") or "?" for c in expired[:3])
        sev = SEV_CRITICAL if len(expired) > 5 else SEV_WARNING
        findings.append(_f(sev, "Certs", "expired",
            f"{len(expired)} expired certificate{'s' if len(expired) != 1 else ''} on record",
            f"{sample}{'...' if len(expired) > 3 else ''} · likely auto-enrolled or decommissioned",
            meta={"count": len(expired), "sample": [c.get("subject") for c in expired[:10]]}
        ))

    return findings


# ---------------------------------------------------------------------------
# Jira — open Sev-1/2 incidents + recent production changes
# ---------------------------------------------------------------------------

def _jira_findings():
    findings = []
    try:
        from routers.database import get_conn
        conn = get_conn()
        try:
            now = datetime.now()

            # Open Sev-1 / Sev-2
            rows = conn.execute("""
                SELECT key, summary, severity, status, created, team, server_name
                FROM jira_tickets
                WHERE project='ITSD' AND status_category != 'Done'
                  AND severity IN ('Sev-1','Sev-2')
                ORDER BY severity ASC, created ASC
                LIMIT 10
            """).fetchall()
            for row in rows:
                r   = dict(row)
                sev = SEV_CRITICAL if r["severity"] == "Sev-1" else SEV_WARNING
                age = _age_str(r["created"]) if r.get("created") else ""
                findings.append(_f(sev, "Jira", "incident",
                    f"{r['key']} — {(r['summary'] or '')[:70]}",
                    f"{r['severity']} · {r.get('status','')} · {age} · {r.get('team') or 'Unassigned'}",
                    action_url=f"https://zinnia.atlassian.net/browse/{r['key']}",
                    meta=dict(r)
                ))

            # Recent TASI production changes last 48h still in flight
            cutoff = (now - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%S")
            rows = conn.execute("""
                SELECT key, summary, resource_group, environment, tas_end, status
                FROM jira_tickets
                WHERE project='TASI' AND environment='Production'
                  AND created >= ? AND status_category != 'Done'
                ORDER BY created DESC LIMIT 5
            """, (cutoff,)).fetchall()
            for row in rows:
                r = dict(row)
                findings.append(_f(SEV_INFO, "Jira", "change",
                    f"{r['key']} — production change in progress",
                    f"{(r['summary'] or '')[:80]} · {r.get('resource_group') or ''}",
                    action_url=f"https://zinnia.atlassian.net/browse/{r['key']}",
                    meta=dict(r)
                ))
        finally:
            conn.close()
    except Exception as e:
        logger.warning("findings: jira query failed: %s", e)
    return findings


# ---------------------------------------------------------------------------
# Active Directory — stale computers and risky account settings
# ---------------------------------------------------------------------------

def _ad_findings():
    findings = []
    from routers.cache import cache
    data, _ = cache.get("ad_summary")
    if not data:
        return findings

    stale_c  = data.get("stale_computers") or 0
    pwd_nexp = data.get("pwd_never_expires") or 0

    if stale_c > 50:
        sev = SEV_CRITICAL if stale_c > 200 else SEV_WARNING
        findings.append(_f(sev, "Auth", "ad_stale",
            f"{stale_c} stale computer accounts in AD",
            "Inactive 90+ days — clean up to reduce attack surface",
            meta={"stale_computers": stale_c}
        ))
    if pwd_nexp > 100:
        findings.append(_f(SEV_WARNING, "Auth", "ad_policy",
            f"{pwd_nexp} accounts with password never expires",
            "High count without rotation policy — review service accounts",
            meta={"pwd_never_expires": pwd_nexp}
        ))
    return findings


# ---------------------------------------------------------------------------
# Lansweeper — unpatched servers and EOL assets
# ---------------------------------------------------------------------------

def _lansweeper_findings():
    findings = []
    from routers.cache import cache

    patch, _ = cache.get("ls_patch_status")
    if patch:
        unpatched = patch.get("unpatched") or 0
        total     = patch.get("total") or 1
        if unpatched > 0:
            pct = round(100 * unpatched / total, 1)
            sev = SEV_CRITICAL if pct > 25 else SEV_WARNING
            findings.append(_f(sev, "Assets", "patch",
                f"{unpatched} unpatched servers ({pct}% of fleet)",
                "Systems without current patches may carry critical CVE exposure",
                meta={"unpatched": unpatched, "total": total, "pct": pct,
                      "unpatched_list": (patch.get("unpatched_list") or [])[:10]}
            ))

    summary, _ = cache.get("ls_asset_summary")
    if summary:
        eol = summary.get("eol_count") or 0
        if eol > 0:
            sev = SEV_CRITICAL if eol > 10 else SEV_WARNING
            findings.append(_f(sev, "Assets", "eol",
                f"{eol} end-of-life operating systems detected",
                "EOL systems receive no security patches — upgrade or decommission",
                meta={"eol_count": eol}
            ))
    return findings


# ---------------------------------------------------------------------------
# Meraki — degraded or offline networks
# ---------------------------------------------------------------------------

def _meraki_findings():
    findings = []
    try:
        from routers import meraki as meraki_mod
        networks = meraki_mod.get_networks()
        if not networks:
            return findings
        for net in networks:
            health = net.get("health") or "unknown"
            name   = net.get("name") or "Unknown"
            uplinks_active = net.get("uplinks_active") or 0
            uplinks_total  = net.get("uplinks_total") or "?"
            if health == "offline":
                findings.append(_f(SEV_CRITICAL, "Network", "connectivity",
                    f"Network OFFLINE: {name}",
                    "All uplinks down — devices on this network unreachable",
                    meta={"network": name, "id": net.get("id"), "health": health}
                ))
            elif health == "degraded":
                findings.append(_f(SEV_WARNING, "Network", "connectivity",
                    f"Network degraded: {name}",
                    f"{uplinks_active}/{uplinks_total} uplinks active",
                    meta={"network": name, "id": net.get("id"),
                          "uplinks_active": uplinks_active, "uplinks_total": uplinks_total}
                ))
    except Exception as e:
        logger.debug("findings: meraki skipped: %s", e)
    return findings
