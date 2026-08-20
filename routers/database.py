import sqlite3
import os
import json
import time
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "portal.db")

def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)   # wait up to 30s instead of failing instantly
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")        # WAL allows concurrent reads during writes
    conn.execute("PRAGMA synchronous=NORMAL")      # safe with WAL, faster than FULL
    conn.execute("PRAGMA busy_timeout=30000")      # belt-and-suspenders: 30s busy timeout
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS vm_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_date TEXT NOT NULL,
            vm_id TEXT NOT NULL,
            name TEXT,
            environment TEXT,
            power_state TEXT,
            os_name TEXT,
            ip_address TEXT,
            cpu_count INTEGER,
            nic_count INTEGER,
            tools_version TEXT,
            tools_upgrade_needed INTEGER,
            eol_status TEXT,
            created_at INTEGER
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS host_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_date TEXT NOT NULL,
            host_id TEXT,
            name TEXT,
            environment TEXT,
            power_state TEXT,
            esxi_version TEXT,
            build_number TEXT,
            cpu_model TEXT,
            cpu_cores INTEGER,
            memory_gb REAL,
            vm_count INTEGER,
            uptime TEXT,
            maintenance_mode INTEGER,
            created_at INTEGER
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS disk_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_date TEXT NOT NULL,
            vm_id TEXT NOT NULL,
            vm_name TEXT,
            environment TEXT,
            disk_label TEXT,
            capacity_gb REAL,
            created_at INTEGER
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alarm_id TEXT NOT NULL,
            device_name TEXT,
            ip_address TEXT,
            category TEXT,
            event_type TEXT,
            message TEXT,
            severity TEXT,
            severity_num INTEGER,
            acknowledged INTEGER,
            first_seen INTEGER,
            last_seen INTEGER,
            occurrence_count INTEGER DEFAULT 1
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_alert_history_alarm_id ON alert_history(alarm_id)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS alert_action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alarm_id TEXT,
            device_name TEXT,
            category TEXT,
            event_type TEXT,
            severity TEXT,
            message TEXT,
            action TEXT NOT NULL,
            actor TEXT,
            created_at INTEGER NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_alert_action_log_device_event ON alert_action_log(device_name, event_type)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS cache_store (
            key TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_text TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS lansweeper_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assets_json TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS asset_overrides (
            device_name TEXT PRIMARY KEY,
            flag        TEXT NOT NULL DEFAULT 'unimportant',
            reason      TEXT,
            set_by      TEXT,
            set_at      INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS jira_teams (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            sort_order  INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS jira_tickets (
            key                   TEXT PRIMARY KEY,
            project               TEXT NOT NULL,
            issue_type            TEXT,
            summary               TEXT,
            status                TEXT,
            status_category       TEXT,
            priority              TEXT,
            created               TEXT,
            updated               TEXT,
            resolved              TEXT,
            reporter              TEXT,
            assignee              TEXT,
            team                  TEXT,
            severity              TEXT,
            urgency               TEXT,
            impact                TEXT,
            source                TEXT,
            server_name           TEXT,
            systems               TEXT,
            product_category      TEXT,
            operational_category  TEXT,
            tas_type              TEXT,
            risk_impact           TEXT,
            resource_group        TEXT,
            environment           TEXT,
            hardware_names        TEXT,
            tas_start             TEXT,
            tas_end               TEXT,
            objective             TEXT,
            t_shirt_size          TEXT,
            due_date              TEXT,
            parent_key            TEXT,
            latest_update         TEXT,
            fetched_at            TEXT DEFAULT (datetime('now'))
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_jira_tickets_project ON jira_tickets(project)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_jira_tickets_created ON jira_tickets(created)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS jira_intelligence (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_json TEXT NOT NULL,
            summary_text  TEXT,
            created_at    INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS portal_findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            severity    INTEGER NOT NULL,
            system      TEXT NOT NULL,
            category    TEXT NOT NULL,
            title       TEXT NOT NULL,
            detail      TEXT,
            action_url  TEXT,
            meta_json   TEXT,
            created_at  INTEGER NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON portal_findings(severity)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS scheduler_config (
            job_id           TEXT PRIMARY KEY,
            enabled          INTEGER NOT NULL DEFAULT 1,
            interval_minutes INTEGER,
            updated_at       INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_widgets (
            user_email  TEXT PRIMARY KEY,
            widget_ids  TEXT NOT NULL,
            updated_at  INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS asset_criticality (
            device_name         TEXT PRIMARY KEY COLLATE NOCASE,
            tier                TEXT NOT NULL DEFAULT 'P3',
            service_description TEXT,
            blast_radius        TEXT,
            owner_team          TEXT,
            escalation_slack    TEXT,
            escalation_email    TEXT,
            dependencies        TEXT,
            is_singleton        INTEGER NOT NULL DEFAULT 0,
            notes               TEXT,
            set_by              TEXT,
            created_at          INTEGER NOT NULL,
            updated_at          INTEGER NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_criticality_tier ON asset_criticality(tier)")

    c.execute("""
        CREATE TABLE IF NOT EXISTS criticality_groups (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name          TEXT NOT NULL,
            match_type          TEXT NOT NULL DEFAULT 'prefix',
            match_value         TEXT NOT NULL,
            default_tier        TEXT NOT NULL DEFAULT 'P3',
            owner_team          TEXT,
            escalation_slack    TEXT,
            escalation_email    TEXT,
            is_singleton        INTEGER NOT NULL DEFAULT 0,
            service_description TEXT,
            blast_radius        TEXT,
            notes               TEXT,
            excluded_devices    TEXT NOT NULL DEFAULT '[]',
            created_at          INTEGER NOT NULL,
            updated_at          INTEGER NOT NULL
        )
    """)
    # Migrate existing tables that predate the excluded_devices column
    try:
        c.execute("ALTER TABLE criticality_groups ADD COLUMN excluded_devices TEXT NOT NULL DEFAULT '[]'")
    except Exception:
        pass  # column already exists
    try:
        c.execute("ALTER TABLE criticality_groups ADD COLUMN environment TEXT NOT NULL DEFAULT 'Non-Prod'")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE asset_criticality ADD COLUMN environment TEXT NOT NULL DEFAULT 'Non-Prod'")
    except Exception:
        pass
    # Migrate legacy environment values to Prod / Non-Prod
    c.execute("""
        UPDATE criticality_groups
        SET environment = 'Non-Prod'
        WHERE environment NOT IN ('Prod', 'Non-Prod')
    """)
    try:
        c.execute("ALTER TABLE criticality_groups ADD COLUMN opm_group_name TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE criticality_groups ADD COLUMN group_category TEXT NOT NULL DEFAULT 'App'")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE criticality_groups ADD COLUMN location_id INTEGER")
    except Exception:
        pass
    try:
        # NULL = last sync found the linked OPM group; non-NULL = epoch timestamp of
        # when it was first noticed missing (OPM is the source of truth for groups —
        # if OPM no longer has this group, we flag it rather than silently zeroing
        # out membership that might just be a transient lookup failure).
        c.execute("ALTER TABLE criticality_groups ADD COLUMN opm_sync_missing_since INTEGER")
    except Exception:
        pass

    c.execute("""
        CREATE TABLE IF NOT EXISTS device_group_members (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id    INTEGER NOT NULL,
            device_name TEXT    NOT NULL COLLATE NOCASE,
            source      TEXT    NOT NULL DEFAULT 'manual',
            added_at    INTEGER NOT NULL,
            UNIQUE(group_id, device_name)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_dgm_group ON device_group_members(group_id)")

    # Seed default groups if they don't already exist (checked by match_value)
    import time as _time
    now = int(_time.time())
    _default_groups = [
        {
            "group_name":          "10.204.40.x Servers",
            "match_type":          "contains",
            "match_value":         "10.204.40.",
            "default_tier":        "P3",
            "owner_team":          "Wintel",
            "service_description": "Windows servers in the 10.204.40.0/24 subnet",
            "blast_radius":        "Affects services hosted on this subnet",
            "notes":               "Auto-seeded — use AI Draft to refine tier and team",
        },
        {
            "group_name":          "AWS EC2 Instances",
            "match_type":          "suffix",
            "match_value":         ".ec2.internal",
            "default_tier":        "P3",
            "owner_team":          "AWS",
            "service_description": "AWS EC2 instances with internal DNS names",
            "blast_radius":        "Affects workloads running in the AWS environment",
            "notes":               "Auto-seeded — use AI Draft to refine tier and team",
        },
        {
            "group_name":          "VMC/AWS 10.220.x Servers",
            "match_type":          "contains",
            "match_value":         "10.220.",
            "default_tier":        "P3",
            "owner_team":          "AWS",
            "service_description": "Servers in the 10.220.0.0/16 VMC/AWS address space",
            "blast_radius":        "Affects cloud-hosted services in the VMC environment",
            "notes":               "Auto-seeded — use AI Draft to refine tier and team",
        },
    ]
    # Log of match_values already seeded once, so deleting a default group doesn't
    # cause it to be re-inserted on the next restart (match_value alone can't tell
    # "never seeded" apart from "seeded then deliberately removed").
    c.execute("""
        CREATE TABLE IF NOT EXISTS criticality_group_seed_log (
            match_value TEXT PRIMARY KEY,
            seeded_at   INTEGER NOT NULL
        )
    """)
    existing_values = {r[0] for r in c.execute(
        "SELECT match_value FROM criticality_groups"
    ).fetchall()}
    already_seeded = {r[0] for r in c.execute(
        "SELECT match_value FROM criticality_group_seed_log"
    ).fetchall()}
    for g in _default_groups:
        if g["match_value"] in existing_values or g["match_value"] in already_seeded:
            continue
        c.execute("""
            INSERT INTO criticality_groups
                (group_name, match_type, match_value, default_tier,
                 owner_team, escalation_slack, escalation_email,
                 is_singleton, service_description, blast_radius,
                 notes, excluded_devices, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            g["group_name"], g["match_type"], g["match_value"],
            g["default_tier"], g["owner_team"], "", "", 0,
            g["service_description"], g["blast_radius"],
            g["notes"], "[]", now, now,
        ))
        c.execute(
            "INSERT INTO criticality_group_seed_log (match_value, seeded_at) VALUES (?, ?)",
            (g["match_value"], now),
        )

    c.execute("""
        CREATE TABLE IF NOT EXISTS topology_locations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            lat         REAL NOT NULL DEFAULT 0,
            lng         REAL NOT NULL DEFAULT 0,
            description TEXT NOT NULL DEFAULT '',
            opm_groups  TEXT NOT NULL DEFAULT '[]',
            created_at  INTEGER NOT NULL,
            updated_at  INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS group_dependencies (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            from_group   TEXT NOT NULL,
            to_group     TEXT NOT NULL,
            dep_type     TEXT NOT NULL DEFAULT 'application',
            confidence   TEXT NOT NULL DEFAULT 'medium',
            ai_suggested INTEGER NOT NULL DEFAULT 0,
            notes        TEXT NOT NULL DEFAULT '',
            created_at   INTEGER NOT NULL,
            UNIQUE(from_group, to_group)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS opm_group_names (
            name       TEXT PRIMARY KEY COLLATE NOCASE,
            created_at INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS server_env_overrides (
            server_name TEXT PRIMARY KEY COLLATE NOCASE,
            environment TEXT NOT NULL,
            set_by      TEXT,
            set_at      INTEGER NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS lookup_lists (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            list_key    TEXT NOT NULL,
            value       TEXT NOT NULL,
            sort_order  INTEGER DEFAULT 0,
            created_at  TEXT DEFAULT (datetime('now')),
            UNIQUE(list_key, value)
        )
    """)

    # Seed the Owner Team list once, from the values that used to be hardcoded
    # in criticality.html, so existing installs don't lose their options.
    has_owner_teams = c.execute(
        "SELECT COUNT(*) FROM lookup_lists WHERE list_key = 'owner_teams'"
    ).fetchone()[0]
    if not has_owner_teams:
        default_teams = ["Wintel", "Citrix", "VMware", "Network", "Linux", "DBA",
                          "O365 / Entra", "Security", "AWS", "Storage", "Other"]
        for i, team in enumerate(default_teams):
            c.execute(
                "INSERT OR IGNORE INTO lookup_lists (list_key, value, sort_order) VALUES (?, ?, ?)",
                ("owner_teams", team, i)
            )

    conn.commit()
    conn.close()

def save_cache(key, data):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO cache_store (key, data, timestamp)
            VALUES (?, ?, ?)
        """, (key, json.dumps(data), int(time.time())))
        conn.commit()
    finally:
        conn.close()

def load_cache(key):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT data, timestamp FROM cache_store WHERE key = ?", (key,))
        row = c.fetchone()
        if row:
            return json.loads(row["data"]), row["timestamp"]
        return None, None
    finally:
        conn.close()

def save_vm_snapshot(vms):
    conn = get_conn()
    try:
        c = conn.cursor()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        c.execute("DELETE FROM vm_snapshots WHERE snapshot_date = ?", (today,))
        for vm in vms:
            eol = vm.get("eol")
            eol_status = eol["label"] if eol else None
            c.execute("""
                INSERT INTO vm_snapshots
                (snapshot_date, vm_id, name, environment, power_state, os_name,
                 ip_address, cpu_count, nic_count, tools_version, tools_upgrade_needed,
                 eol_status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                today,
                vm.get("vm_id", vm.get("vm", "")),
                vm.get("name"), vm.get("environment"), vm.get("power_state"),
                vm.get("os_name"), vm.get("ip_address"), vm.get("cpu_count"),
                vm.get("nic_count"), vm.get("tools_version"),
                1 if vm.get("tools_upgrade_needed") else 0,
                eol_status, int(time.time())
            ))
        conn.commit()
    finally:
        conn.close()

def save_disk_snapshot(storage_vms):
    conn = get_conn()
    try:
        c = conn.cursor()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        c.execute("DELETE FROM disk_snapshots WHERE snapshot_date = ?", (today,))
        for vm in storage_vms:
            for drive in vm.get("drives", []):
                c.execute("""
                    INSERT INTO disk_snapshots
                    (snapshot_date, vm_id, vm_name, environment, disk_label, capacity_gb, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    today, vm.get("vm_id", ""), vm.get("name"),
                    vm.get("environment"), drive.get("letter"),
                    drive.get("free_gb"), int(time.time())
                ))
        conn.commit()
    finally:
        conn.close()

def save_alert_history(alarms):
    conn = get_conn()
    try:
        c = conn.cursor()
        now = int(time.time())
        for alarm in alarms:
            alarm_id = alarm.get("alarm_id")
            c.execute(
                "SELECT id, occurrence_count FROM alert_history WHERE alarm_id = ?",
                (alarm_id,)
            )
            existing = c.fetchone()
            if existing:
                c.execute("""
                    UPDATE alert_history
                    SET last_seen = ?, occurrence_count = occurrence_count + 1,
                        severity = ?, acknowledged = ?
                    WHERE alarm_id = ?
                """, (now, alarm.get("severity"),
                      1 if alarm.get("acknowledged") else 0, alarm_id))
            else:
                c.execute("""
                    INSERT INTO alert_history
                    (alarm_id, device_name, ip_address, category, event_type, message,
                     severity, severity_num, acknowledged, first_seen, last_seen, occurrence_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """, (
                    alarm_id, alarm.get("device_name"), alarm.get("ip_address"),
                    alarm.get("category"), alarm.get("event_type"), alarm.get("message"),
                    alarm.get("severity"), alarm.get("severity_num"),
                    1 if alarm.get("acknowledged") else 0, now, now
                ))
        conn.commit()
    finally:
        conn.close()

def get_disk_trends(days=30):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT vm_name, environment, disk_label, capacity_gb, snapshot_date
            FROM disk_snapshots
            ORDER BY vm_name, disk_label, snapshot_date
        """)
        rows = c.fetchall()
        trends = {}
        for row in rows:
            key = row["vm_name"] + "|" + row["disk_label"]
            if key not in trends:
                trends[key] = {
                    "vm_name":     row["vm_name"],
                    "environment": row["environment"],
                    "disk_label":  row["disk_label"],
                    "history":     []
                }
            trends[key]["history"].append({
                "date":        row["snapshot_date"],
                "capacity_gb": row["capacity_gb"]
            })
        return list(trends.values())
    finally:
        conn.close()

def get_recurring_alerts(min_occurrences=3):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT * FROM alert_history
            WHERE occurrence_count >= ?
            ORDER BY occurrence_count DESC
        """, (min_occurrences,))
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()

def log_alert_action(alarm_id, device_name, category, event_type, severity, message, action, actor):
    """Record one ack/clear action against an alarm, for the recurring-alerts report.
    Snapshotting device/category/event_type/severity/message here (rather than joining
    back to alert_history later) means the log stays correct even after the alarm itself
    ages out of OpManager's own history."""
    conn = get_conn()
    try:
        conn.execute("""
            INSERT INTO alert_action_log
            (alarm_id, device_name, category, event_type, severity, message, action, actor, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (str(alarm_id), device_name, category, event_type, severity, message,
              action, actor, int(time.time())))
        conn.commit()
    finally:
        conn.close()


def get_recurring_action_groups(days=90, min_occurrences=3):
    """Group the action log by (device_name, event_type) to find alerts the NOC keeps
    having to ack/clear over and over — the raw signal the Recurring Alerts report and
    its AI analysis are built from."""
    conn = get_conn()
    try:
        cutoff = int(time.time()) - days * 86400
        rows = conn.execute("""
            SELECT * FROM alert_action_log
            WHERE created_at >= ? AND device_name IS NOT NULL AND device_name != ''
            ORDER BY device_name, event_type, created_at
        """, (cutoff,)).fetchall()

        groups: dict[tuple, dict] = {}
        for r in rows:
            key = (r["device_name"], r["event_type"])
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "device_name": r["device_name"], "event_type": r["event_type"],
                    "category": r["category"], "action_count": 0,
                    "acknowledge_count": 0, "clear_count": 0,
                    "first_action": r["created_at"], "last_action": r["created_at"],
                    "sample_messages": [], "actors": set(),
                }
            g["action_count"] += 1
            g[f"{r['action']}_count"] = g.get(f"{r['action']}_count", 0) + 1
            g["last_action"] = r["created_at"]
            if r["message"] and r["message"] not in g["sample_messages"] and len(g["sample_messages"]) < 3:
                g["sample_messages"].append(r["message"])
            if r["actor"]:
                g["actors"].add(r["actor"])

        result = [g for g in groups.values() if g["action_count"] >= min_occurrences]
        for g in result:
            g["actors"] = sorted(g["actors"])
        result.sort(key=lambda g: g["action_count"], reverse=True)
        return result
    finally:
        conn.close()


def get_alert_history_map():
    """Return {alarm_id: row_dict} for every alarm ever polled — used to enrich
    live alarms with true first_seen/occurrence_count (listAlarms itself only
    carries modTime, which updates on every re-poll and isn't a real age)."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM alert_history").fetchall()
        return {r["alarm_id"]: dict(r) for r in rows}
    finally:
        conn.close()


def get_noisy_alert_types(days=30):
    """Aggregate alert_history by category/event_type to find the checks that
    generate the most distinct alarm instances (flapping/noise) vs. the most
    total poll-hits (persistence), over the lookback window."""
    conn = get_conn()
    try:
        cutoff = int(time.time()) - days * 86400
        rows = conn.execute("""
            SELECT category, event_type,
                   COUNT(*)                AS incident_count,
                   SUM(occurrence_count)    AS poll_hits,
                   COUNT(DISTINCT device_name) AS device_count,
                   MAX(last_seen)           AS most_recent
            FROM alert_history
            WHERE first_seen >= ?
            GROUP BY category, event_type
            ORDER BY incident_count DESC
        """, (cutoff,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_chronic_red_devices(days=30):
    """Aggregate alert_history by device to find devices that have spent most
    of the lookback window in a non-Clear state — either a real outage nobody
    is chasing, or a monitor that structurally never reports Clear."""
    conn = get_conn()
    try:
        cutoff = int(time.time()) - days * 86400
        rows = conn.execute("""
            SELECT device_name,
                   COUNT(*)                                                       AS incident_count,
                   SUM(occurrence_count)                                          AS poll_hits,
                   SUM(CASE WHEN severity != 'Clear' THEN occurrence_count ELSE 0 END) AS red_poll_hits,
                   MIN(first_seen)                                                AS first_seen,
                   MAX(last_seen)                                                 AS last_seen
            FROM alert_history
            WHERE last_seen >= ? AND device_name IS NOT NULL AND device_name != ''
            GROUP BY device_name
            HAVING poll_hits > 0
            ORDER BY (red_poll_hits * 1.0 / poll_hits) DESC, poll_hits DESC
        """, (cutoff,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_flapping_pairs(days=30, min_incidents=5):
    """Return {(device_name, event_type): incident_count} for device/check
    combos that have generated many separate alarm instances in the window —
    the signature of a threshold sitting right at the noise floor."""
    conn = get_conn()
    try:
        cutoff = int(time.time()) - days * 86400
        rows = conn.execute("""
            SELECT device_name, event_type, COUNT(*) AS incident_count
            FROM alert_history
            WHERE first_seen >= ? AND device_name IS NOT NULL
            GROUP BY device_name, event_type
            HAVING COUNT(*) >= ?
        """, (cutoff, min_incidents)).fetchall()
        return {(r["device_name"], r["event_type"]): r["incident_count"] for r in rows}
    finally:
        conn.close()


def get_powered_off_vms(days=30):
    conn = get_conn()
    try:
        c = conn.cursor()
        cutoff = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        c.execute("""
            SELECT DISTINCT vm_id, name, environment, os_name
            FROM vm_snapshots
            WHERE power_state = 'POWERED_OFF'
            AND snapshot_date >= date(?, '-' || ? || ' days')
            GROUP BY vm_id
            HAVING COUNT(*) >= ?
        """, (cutoff, days, max(1, days // 2)))
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()

def save_analysis(text):
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT INTO analysis_history (analysis_text, created_at)
            VALUES (?, ?)
        """, (text, int(time.time())))
        conn.commit()
    finally:
        conn.close()

def load_latest_analysis():
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT analysis_text, created_at FROM analysis_history
            ORDER BY created_at DESC LIMIT 1
        """)
        row = c.fetchone()
        if row:
            return row["analysis_text"], row["created_at"]
        return None, None
    finally:
        conn.close()

def save_lansweeper_assets(assets):
    """Persist the full asset list to DB so it survives app pool recycles."""
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM lansweeper_assets")
        c.execute("""
            INSERT INTO lansweeper_assets (assets_json, created_at)
            VALUES (?, ?)
        """, (json.dumps(assets), int(time.time())))
        conn.commit()
    finally:
        conn.close()

def load_lansweeper_assets():
    """Load the persisted asset list. Returns (assets, timestamp) or (None, None)."""
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT assets_json, created_at FROM lansweeper_assets
            ORDER BY created_at DESC LIMIT 1
        """)
        row = c.fetchone()
        if row:
            return json.loads(row["assets_json"]), row["created_at"]
        return None, None
    finally:
        conn.close()

def save_asset_override(device_name, flag="unimportant", reason=None, set_by=None):
    """Mark a device with a flag (e.g. 'unimportant') to suppress it from views."""
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO asset_overrides (device_name, flag, reason, set_by, set_at)
            VALUES (?, ?, ?, ?, ?)
        """, (device_name, flag, reason, set_by, int(time.time())))
        conn.commit()
    finally:
        conn.close()

def delete_asset_override(device_name):
    """Remove an override, restoring normal display for this device."""
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM asset_overrides WHERE device_name = ?", (device_name,))
        conn.commit()
    finally:
        conn.close()

def get_asset_override(device_name):
    """Return the override row for a device, or None if not overridden."""
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM asset_overrides WHERE device_name = ?", (device_name,))
        row = c.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def list_asset_overrides():
    """Return all overrides as a list of dicts."""
    conn = get_conn()
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM asset_overrides ORDER BY set_at DESC")
        return [dict(row) for row in c.fetchall()]
    finally:
        conn.close()

# ── Jira Tickets (intelligence store) ────────────────────────────────────────

def upsert_jira_tickets(tickets: list) -> None:
    if not tickets:
        return
    conn = get_conn()
    try:
        conn.executemany("""
            INSERT OR REPLACE INTO jira_tickets (
                key, project, issue_type, summary, status, status_category, priority,
                created, updated, resolved, reporter, assignee, team,
                severity, urgency, impact, source, server_name, systems,
                product_category, operational_category,
                tas_type, risk_impact, resource_group, environment, hardware_names,
                tas_start, tas_end,
                objective, t_shirt_size, due_date, parent_key, latest_update,
                fetched_at
            ) VALUES (
                :key, :project, :issue_type, :summary, :status, :status_category, :priority,
                :created, :updated, :resolved, :reporter, :assignee, :team,
                :severity, :urgency, :impact, :source, :server_name, :systems,
                :product_category, :operational_category,
                :tas_type, :risk_impact, :resource_group, :environment, :hardware_names,
                :tas_start, :tas_end,
                :objective, :t_shirt_size, :due_date, :parent_key, :latest_update,
                datetime('now')
            )
        """, tickets)
        conn.commit()
    finally:
        conn.close()


def load_jira_tickets(project: str = None, days: int = 90) -> list:
    from datetime import timedelta
    conn = get_conn()
    try:
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        if project:
            rows = conn.execute(
                """SELECT * FROM jira_tickets
                   WHERE project = ? AND (created >= ? OR resolved IS NULL)
                   ORDER BY created DESC""",
                (project, cutoff)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM jira_tickets
                   WHERE created >= ? OR resolved IS NULL
                   ORDER BY created DESC""",
                (cutoff,)
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def save_jira_intelligence(analysis_json: str, summary_text: str) -> None:
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO jira_intelligence (analysis_json, summary_text, created_at) VALUES (?, ?, ?)",
            (analysis_json, summary_text, int(time.time()))
        )
        conn.execute(
            """DELETE FROM jira_intelligence WHERE id NOT IN (
               SELECT id FROM jira_intelligence ORDER BY created_at DESC LIMIT 10)"""
        )
        conn.commit()
    finally:
        conn.close()


def load_jira_tickets_period(project: str, days: int) -> list:
    """Load tickets strictly by creation date — used for meeting period views."""
    from datetime import timedelta
    conn = get_conn()
    try:
        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        rows = conn.execute(
            "SELECT * FROM jira_tickets WHERE project = ? AND created >= ? ORDER BY created DESC",
            (project, cutoff)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def load_latest_jira_intelligence() -> dict | None:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT analysis_json, summary_text, created_at FROM jira_intelligence ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ── Portal Findings ──────────────────────────────────────────────────────────

def save_findings(findings: list) -> None:
    """Replace all portal_findings with a fresh list."""
    conn = get_conn()
    try:
        conn.execute("DELETE FROM portal_findings")
        if findings:
            conn.executemany("""
                INSERT INTO portal_findings
                    (severity, system, category, title, detail, action_url, meta_json, created_at)
                VALUES
                    (:severity, :system, :category, :title, :detail, :action_url, :meta_json, :created_at)
            """, findings)
        conn.commit()
    finally:
        conn.close()


def load_findings() -> list:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, severity, system, category, title, detail, action_url, meta_json, created_at"
            " FROM portal_findings ORDER BY severity ASC, created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_findings_age() -> int | None:
    """Returns Unix timestamp of last findings refresh, or None."""
    conn = get_conn()
    try:
        row = conn.execute("SELECT MAX(created_at) FROM portal_findings").fetchone()
        return row[0] if row else None
    finally:
        conn.close()


# ── Jira Teams ────────────────────────────────────────────────────────────────

def list_jira_teams() -> list[dict]:
    """Return all stored Jira teams, ordered by sort_order then name."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, name, sort_order FROM jira_teams ORDER BY sort_order, name"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def save_jira_team(team_id: str, name: str, sort_order: int = 0) -> bool:
    """Insert or update a team. Returns True on success."""
    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO jira_teams (id, name, sort_order)
            VALUES (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET name=excluded.name, sort_order=excluded.sort_order
            """,
            (team_id.strip(), name.strip(), sort_order),
        )
        conn.commit()
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"save_jira_team failed: {e}")
        return False
    finally:
        conn.close()

def delete_jira_team(team_id: str) -> bool:
    """Delete a team by ID. Returns True on success."""
    conn = get_conn()
    try:
        conn.execute("DELETE FROM jira_teams WHERE id = ?", (team_id,))
        conn.commit()
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"delete_jira_team failed: {e}")
        return False
    finally:
        conn.close()

# ── Lookup lists (generic, admin-editable dropdown options) ──────────────────

def list_lookup_values(list_key: str) -> list[dict]:
    """Return all values for a lookup list, ordered by sort_order then value."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, value, sort_order FROM lookup_lists WHERE list_key = ? ORDER BY sort_order, value",
            (list_key,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def add_lookup_value(list_key: str, value: str) -> bool:
    """Add a new value to a lookup list. Returns True on success (False if duplicate)."""
    conn = get_conn()
    try:
        next_order = conn.execute(
            "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM lookup_lists WHERE list_key = ?",
            (list_key,)
        ).fetchone()[0]
        conn.execute(
            "INSERT INTO lookup_lists (list_key, value, sort_order) VALUES (?, ?, ?)",
            (list_key, value.strip(), next_order)
        )
        conn.commit()
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"add_lookup_value failed: {e}")
        return False
    finally:
        conn.close()

def delete_lookup_value(value_id: int) -> bool:
    """Delete a lookup list value by its row id."""
    conn = get_conn()
    try:
        conn.execute("DELETE FROM lookup_lists WHERE id = ?", (value_id,))
        conn.commit()
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"delete_lookup_value failed: {e}")
        return False
    finally:
        conn.close()

def reorder_lookup_values(list_key: str, ordered_ids: list[int]) -> bool:
    """Update sort_order for a list of lookup value ids in the given order."""
    conn = get_conn()
    try:
        for i, vid in enumerate(ordered_ids):
            conn.execute(
                "UPDATE lookup_lists SET sort_order = ? WHERE id = ? AND list_key = ?",
                (i, vid, list_key)
            )
        conn.commit()
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"reorder_lookup_values failed: {e}")
        return False
    finally:
        conn.close()


# ── Scheduler config ─────────────────────────────────────────────────────────

def get_scheduler_config() -> dict:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT job_id, enabled, interval_minutes FROM scheduler_config"
        ).fetchall()
        return {r["job_id"]: {"enabled": bool(r["enabled"]), "interval_minutes": r["interval_minutes"]} for r in rows}
    finally:
        conn.close()


def upsert_scheduler_config(job_id: str, enabled=None, interval_minutes=None) -> None:
    conn = get_conn()
    try:
        existing = conn.execute(
            "SELECT enabled, interval_minutes FROM scheduler_config WHERE job_id = ?", (job_id,)
        ).fetchone()
        if existing:
            new_enabled = (1 if enabled else 0) if enabled is not None else existing["enabled"]
            new_interval = interval_minutes if interval_minutes is not None else existing["interval_minutes"]
        else:
            new_enabled = (1 if enabled else 0) if enabled is not None else 1
            new_interval = interval_minutes
        conn.execute(
            "INSERT OR REPLACE INTO scheduler_config (job_id, enabled, interval_minutes, updated_at) VALUES (?, ?, ?, ?)",
            (job_id, new_enabled, new_interval, int(time.time()))
        )
        conn.commit()
    finally:
        conn.close()


# ── User widgets ──────────────────────────────────────────────────────────────

def get_user_widgets(user_email: str) -> list | None:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT widget_ids FROM user_widgets WHERE user_email = ?", (user_email,)
        ).fetchone()
        return json.loads(row["widget_ids"]) if row else None
    finally:
        conn.close()


def save_user_widgets(user_email: str, widget_ids: list) -> None:
    conn = get_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO user_widgets (user_email, widget_ids, updated_at) VALUES (?, ?, ?)",
            (user_email, json.dumps(widget_ids), int(time.time()))
        )
        conn.commit()
    finally:
        conn.close()


def reorder_jira_teams(ordered_ids: list[str]) -> bool:
    """Update sort_order for a list of team IDs in the given order."""
    conn = get_conn()
    try:
        for i, tid in enumerate(ordered_ids):
            conn.execute(
                "UPDATE jira_teams SET sort_order = ? WHERE id = ?", (i, tid)
            )
        conn.commit()
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"reorder_jira_teams failed: {e}")
        return False
    finally:
        conn.close()

# ── Asset Criticality Registry ────────────────────────────────────────────────

def list_criticality() -> list[dict]:
    """Return all criticality entries ordered by tier then device name."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM asset_criticality ORDER BY "
            "CASE tier WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END, device_name"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_criticality(device_name: str) -> "dict | None":
    """Return the criticality entry for a device, or None."""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM asset_criticality WHERE device_name = ? COLLATE NOCASE",
            (device_name,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def upsert_criticality(
    device_name: str,
    tier: str,
    service_description: str = None,
    blast_radius: str = None,
    owner_team: str = None,
    escalation_slack: str = None,
    escalation_email: str = None,
    dependencies: str = None,
    is_singleton: bool = False,
    notes: str = None,
    set_by: str = None,
) -> bool:
    """Insert or update a criticality entry. Returns True on success."""
    conn = get_conn()
    try:
        now = int(time.time())
        existing = conn.execute(
            "SELECT created_at FROM asset_criticality WHERE device_name = ? COLLATE NOCASE",
            (device_name,)
        ).fetchone()
        created_at = existing["created_at"] if existing else now
        conn.execute("""
            INSERT OR REPLACE INTO asset_criticality
                (device_name, tier, service_description, blast_radius, owner_team,
                 escalation_slack, escalation_email, dependencies,
                 is_singleton, notes, set_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_name.strip(), tier,
            service_description, blast_radius, owner_team,
            escalation_slack, escalation_email, dependencies,
            1 if is_singleton else 0, notes, set_by,
            created_at, now
        ))
        conn.commit()
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"upsert_criticality failed: {e}")
        return False
    finally:
        conn.close()


def delete_criticality(device_name: str) -> bool:
    """Delete a criticality entry. Returns True on success."""
    conn = get_conn()
    try:
        conn.execute(
            "DELETE FROM asset_criticality WHERE device_name = ? COLLATE NOCASE",
            (device_name,)
        )
        conn.commit()
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"delete_criticality failed: {e}")
        return False
    finally:
        conn.close()


def bulk_delete_criticality(device_names: list) -> int:
    """Delete multiple criticality entries. Returns count of rows deleted."""
    if not device_names:
        return 0
    conn = get_conn()
    try:
        placeholders = ",".join("?" for _ in device_names)
        cur = conn.execute(
            f"DELETE FROM asset_criticality WHERE device_name IN ({placeholders}) COLLATE NOCASE",
            device_names,
        )
        conn.commit()
        return cur.rowcount
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"bulk_delete_criticality failed: {e}")
        return 0
    finally:
        conn.close()


def get_criticality_map() -> dict:
    """Return {DEVICE_NAME_UPPER: row_dict} for fast alert enrichment lookups."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM asset_criticality").fetchall()
        return {dict(r)["device_name"].upper(): dict(r) for r in rows}
    finally:
        conn.close()


# ── Criticality Groups ────────────────────────────────────────────────────────

def list_criticality_groups() -> list[dict]:
    import json as _json
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM criticality_groups ORDER BY group_name COLLATE NOCASE"
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["excluded_devices"] = _json.loads(d.get("excluded_devices") or "[]")
            except Exception:
                d["excluded_devices"] = []
            result.append(d)
        return result
    finally:
        conn.close()


def compute_all_blast_radii() -> dict[str, list[str]]:
    """Return {group_name: [groups_that_depend_on_it, ...]} via reverse BFS on group_dependencies."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT from_group, to_group FROM group_dependencies").fetchall()
    finally:
        conn.close()
    # dependents[X] = all groups that directly depend on X
    dependents: dict[str, list[str]] = {}
    all_groups: set[str] = set()
    for row in rows:
        fg, tg = row[0], row[1]
        dependents.setdefault(tg, []).append(fg)
        all_groups.update([fg, tg])
    # BFS from each group to find transitive dependents
    result: dict[str, list[str]] = {}
    for g in all_groups:
        visited: set[str] = set()
        queue = [g]
        while queue:
            cur = queue.pop(0)
            for dep in dependents.get(cur, []):
                if dep not in visited:
                    visited.add(dep)
                    queue.append(dep)
        if visited:
            result[g] = sorted(visited)
    return result


def upsert_criticality_group(data: dict) -> int:
    """Insert or update a criticality group. Returns the row id."""
    import time as _time
    import json as _json
    conn = get_conn()
    try:
        now = int(_time.time())
        gid = data.get("id")
        excl = _json.dumps(data.get("excluded_devices") or [])
        cat = data.get("group_category", "App") or "App"
        # Technology and Geographic groups are always Prod
        env = "Prod" if cat in ("Technology", "Geographic") else (data.get("environment", "Non-Prod") or "Non-Prod")
        loc_id = data.get("location_id") or None
        if loc_id is not None:
            try:
                loc_id = int(loc_id)
            except (ValueError, TypeError):
                loc_id = None
        if gid:
            conn.execute("""
                UPDATE criticality_groups SET
                    group_name=?, match_type=?, match_value=?, default_tier=?,
                    owner_team=?, escalation_slack=?, escalation_email=?,
                    is_singleton=?, service_description=?, blast_radius=?, notes=?,
                    excluded_devices=?, opm_group_name=?, group_category=?, environment=?,
                    location_id=?, updated_at=?
                WHERE id=?
            """, (
                data.get("group_name",""), data.get("match_type","prefix"),
                data.get("match_value",""), data.get("default_tier","P3"),
                data.get("owner_team",""), data.get("escalation_slack",""),
                data.get("escalation_email",""), int(bool(data.get("is_singleton"))),
                data.get("service_description",""), data.get("blast_radius",""),
                data.get("notes",""), excl, data.get("opm_group_name",""),
                cat, env, loc_id, now, gid
            ))
        else:
            cur = conn.execute("""
                INSERT INTO criticality_groups
                    (group_name, match_type, match_value, default_tier,
                     owner_team, escalation_slack, escalation_email,
                     is_singleton, service_description, blast_radius, notes,
                     excluded_devices, opm_group_name, group_category, environment,
                     location_id, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                data.get("group_name",""), data.get("match_type","prefix"),
                data.get("match_value",""), data.get("default_tier","P3"),
                data.get("owner_team",""), data.get("escalation_slack",""),
                data.get("escalation_email",""), int(bool(data.get("is_singleton"))),
                data.get("service_description",""), data.get("blast_radius",""),
                data.get("notes",""), excl, data.get("opm_group_name",""),
                cat, env, loc_id, now, now
            ))
            gid = cur.lastrowid
        conn.commit()
        return gid
    finally:
        conn.close()


def delete_criticality_group(gid: int) -> bool:
    conn = get_conn()
    try:
        conn.execute("DELETE FROM device_group_members WHERE group_id=?", (gid,))
        conn.execute("DELETE FROM criticality_groups WHERE id=?", (gid,))
        conn.commit()
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"delete_criticality_group failed: {e}")
        return False
    finally:
        conn.close()


def match_device_to_groups(device_name: str, groups: list[dict]) -> list[dict]:
    """Return any groups whose pattern matches the given device name."""
    n = device_name.upper()
    matched = []
    for g in groups:
        v = (g.get("match_value") or "").upper()
        if not v:
            continue  # empty match_value would match everything — skip
        mt = g.get("match_type", "prefix")
        if mt == "prefix"    and n.startswith(v): matched.append(g)
        elif mt == "suffix"  and n.endswith(v):   matched.append(g)
        elif mt == "contains" and v in n:         matched.append(g)
        elif mt == "exact"   and n == v:          matched.append(g)
    return matched


# ── Device Group Members (explicit membership) ────────────────────────────────

def list_group_members(group_id: int) -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT device_name, source, added_at FROM device_group_members "
            "WHERE group_id=? ORDER BY device_name COLLATE NOCASE",
            (group_id,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_group_members(group_id: int, device_names: list, source: str = "manual") -> int:
    """Insert devices into device_group_members, ignoring duplicates. Returns count inserted."""
    import time as _time
    conn = get_conn()
    try:
        now = int(_time.time())
        added = 0
        for name in device_names:
            name = name.strip()
            if not name:
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO device_group_members (group_id, device_name, source, added_at) "
                "VALUES (?,?,?,?)",
                (group_id, name, source, now)
            )
            added += cur.rowcount
        conn.commit()
        return added
    finally:
        conn.close()


def remove_group_member(group_id: int, device_name: str) -> bool:
    conn = get_conn()
    try:
        conn.execute(
            "DELETE FROM device_group_members WHERE group_id=? AND device_name=? COLLATE NOCASE",
            (group_id, device_name)
        )
        conn.commit()
        return True
    finally:
        conn.close()


def clear_opm_members(group_id: int) -> int:
    """Remove all OPM-sourced members to allow a clean re-sync. Returns count removed."""
    conn = get_conn()
    try:
        cur = conn.execute(
            "DELETE FROM device_group_members WHERE group_id=? AND source='opm'",
            (group_id,)
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def set_opm_sync_status(group_id: int, found: bool) -> None:
    """Record whether the linked OPM group was located during the last sync attempt.
    Clears the missing flag as soon as it's found again; sets it (preserving the
    original "since" timestamp on repeat misses) the moment it isn't found anywhere."""
    import time as _time
    conn = get_conn()
    try:
        if found:
            conn.execute(
                "UPDATE criticality_groups SET opm_sync_missing_since = NULL WHERE id=?",
                (group_id,)
            )
        else:
            conn.execute(
                "UPDATE criticality_groups SET opm_sync_missing_since = COALESCE(opm_sync_missing_since, ?) WHERE id=?",
                (int(_time.time()), group_id)
            )
        conn.commit()
    finally:
        conn.close()


def get_member_counts() -> dict[int, int]:
    """Return {group_id: member_count} for all groups in one query."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT group_id, COUNT(*) FROM device_group_members GROUP BY group_id"
        ).fetchall()
        return {r[0]: r[1] for r in rows}
    finally:
        conn.close()


# ── Group Dependencies ────────────────────────────────────────────────────────

def list_group_dependencies() -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM group_dependencies ORDER BY dep_type, from_group"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_group_dependency(from_group: str, to_group: str,
                          dep_type: str = "application",
                          confidence: str = "medium",
                          ai_suggested: bool = False,
                          notes: str = "") -> int | None:
    conn = get_conn()
    try:
        cur = conn.execute("""
            INSERT OR IGNORE INTO group_dependencies
                (from_group, to_group, dep_type, confidence, ai_suggested, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (from_group, to_group, dep_type, confidence,
               1 if ai_suggested else 0, notes or "", int(time.time())))
        conn.commit()
        return cur.lastrowid if cur.rowcount else None
    finally:
        conn.close()


def delete_group_dependency(dep_id: int) -> bool:
    conn = get_conn()
    try:
        conn.execute("DELETE FROM group_dependencies WHERE id=?", (dep_id,))
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


# ── Topology Locations ────────────────────────────────────────────────────────

def list_locations() -> list[dict]:
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM topology_locations ORDER BY name").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["opm_groups"] = json.loads(d.get("opm_groups") or "[]")
            except Exception:
                d["opm_groups"] = []
            result.append(d)
        return result
    finally:
        conn.close()


def upsert_location(data: dict) -> int:
    conn = get_conn()
    try:
        now = int(time.time())
        lid = data.get("id")
        groups_json = json.dumps(data.get("opm_groups") or [])
        if lid:
            conn.execute("""
                UPDATE topology_locations SET
                    name=?, lat=?, lng=?, description=?, opm_groups=?, updated_at=?
                WHERE id=?
            """, (data.get("name",""), float(data.get("lat",0)), float(data.get("lng",0)),
                   data.get("description",""), groups_json, now, lid))
        else:
            cur = conn.execute("""
                INSERT OR REPLACE INTO topology_locations
                    (name, lat, lng, description, opm_groups, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?)
            """, (data.get("name",""), float(data.get("lat",0)), float(data.get("lng",0)),
                   data.get("description",""), groups_json, now, now))
            lid = cur.lastrowid
        conn.commit()
        return lid
    finally:
        conn.close()


def delete_location(loc_id: int) -> bool:
    conn = get_conn()
    try:
        conn.execute("DELETE FROM topology_locations WHERE id=?", (loc_id,))
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()


def bulk_add_dependencies(deps: list[dict]) -> int:
    """Insert AI-suggested dependencies, skipping duplicates. Returns count added."""
    conn = get_conn()
    try:
        now = int(time.time())
        count = 0
        for d in deps:
            cur = conn.execute("""
                INSERT OR IGNORE INTO group_dependencies
                    (from_group, to_group, dep_type, confidence, ai_suggested, notes, created_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
            """, (d.get("from_group",""), d.get("to_group",""),
                   d.get("dep_type","application"), d.get("confidence","medium"),
                   d.get("notes",""), now))
            count += cur.rowcount
        conn.commit()
        return count
    finally:
        conn.close()


# ── OPM Group Names (user-maintained) ────────────────────────────────────────

def list_opm_group_names() -> list[str]:
    conn = get_conn()
    try:
        rows = conn.execute("SELECT name FROM opm_group_names ORDER BY name COLLATE NOCASE").fetchall()
        return [r[0] for r in rows]
    finally:
        conn.close()


def add_opm_group_name(name: str) -> bool:
    conn = get_conn()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO opm_group_names (name, created_at) VALUES (?, ?)",
            (name.strip(), int(time.time()))
        )
        conn.commit()
        return True
    finally:
        conn.close()


def delete_opm_group_name(name: str) -> bool:
    conn = get_conn()
    try:
        conn.execute("DELETE FROM opm_group_names WHERE name=? COLLATE NOCASE", (name,))
        conn.commit()
        return True
    finally:
        conn.close()


# ── Server Environment Overrides ──────────────────────────────────────────────

def get_share_audit_env_overrides() -> dict:
    """Return {server_name_upper: environment} for all manual overrides."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT server_name, environment FROM server_env_overrides"
        ).fetchall()
        return {r["server_name"].upper(): r["environment"] for r in rows}
    finally:
        conn.close()


def set_share_audit_env_override(server_name: str, environment: str,
                                  set_by: str = None) -> bool:
    conn = get_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO server_env_overrides "
            "(server_name, environment, set_by, set_at) VALUES (?, ?, ?, ?)",
            (server_name.strip(), environment, set_by, int(time.time()))
        )
        conn.commit()
        return True
    except Exception as e:
        import logging as _logging
        _logging.getLogger(__name__).error("set_share_audit_env_override: %s", e)
        return False
    finally:
        conn.close()


def delete_share_audit_env_override(server_name: str) -> bool:
    conn = get_conn()
    try:
        conn.execute(
            "DELETE FROM server_env_overrides WHERE server_name = ? COLLATE NOCASE",
            (server_name,)
        )
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        conn.close()
