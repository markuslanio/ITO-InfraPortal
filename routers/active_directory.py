import os
import datetime
import re
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from dotenv import load_dotenv
from routers.cache import cache

load_dotenv()

DC_HOST  = os.getenv("AD_HOST")
USERNAME = os.getenv("AD_DOMAIN") + "\\" + os.getenv("AD_USER")
PASSWORD = os.getenv("AD_PASSWORD")
BASE_DN  = os.getenv("AD_BASE_DN")
GPO_BASE = "CN=Policies,CN=System," + BASE_DN

# ── connection ────────────────────────────────────────────────────────────────

def get_conn():
    server = Server(DC_HOST, get_info=ALL)
    return Connection(server, user=USERNAME, password=PASSWORD,
                      authentication=NTLM, auto_bind=True)

# ── paged search helpers ──────────────────────────────────────────────────────

def paged_count(conn, search_filter):
    entries = conn.extend.standard.paged_search(
        search_base=BASE_DN,
        search_filter=search_filter,
        attributes=['cn'],
        paged_size=500,
        generator=True
    )
    return sum(1 for e in entries if e.get('type') == 'searchResEntry')

def paged_search(conn, search_filter, attributes, base=None):
    return list(conn.extend.standard.paged_search(
        search_base=base or BASE_DN,
        search_filter=search_filter,
        attributes=attributes,
        paged_size=500,
        generator=False
    ))

def attr(entry, key, default=''):
    if entry.get('type') != 'searchResEntry':
        return default
    val = entry.get('attributes', {}).get(key, default)
    if val is None:
        return default
    if isinstance(val, list):
        return str(val[0]) if val else default
    return str(val)

def get_ft_from_entry(entry, key):
    val = entry.get('attributes', {}).get(key, 0)
    if not val:
        return None
    if isinstance(val, datetime.datetime):
        return val.replace(tzinfo=None)
    return filetime_to_dt(val)

# ── time helpers ──────────────────────────────────────────────────────────────

def filetime_to_dt(ft):
    if not ft or ft == 0 or ft == 9223372036854775807:
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(ft) // 10)
    except Exception:
        return None

def days_ago(dt):
    if not dt:
        return None
    return (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - dt).days

def ft_threshold(days_back):
    now    = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    cutoff = now - datetime.timedelta(days=days_back)
    return int((cutoff - datetime.datetime(1601, 1, 1)).total_seconds() * 10_000_000)

# ── summary ───────────────────────────────────────────────────────────────────

def get_ad_summary(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ad_summary")
        if data is not None:
            return data, ts

    conn  = get_conn()
    ft_90 = ft_threshold(90)

    total_users       = paged_count(conn, '(&(objectClass=user)(objectCategory=person))')
    disabled_users    = paged_count(conn,
        '(&(objectClass=user)(objectCategory=person)'
        '(userAccountControl:1.2.840.113556.1.4.803:=2))')
    pwd_never_expires = paged_count(conn,
        '(&(objectClass=user)(objectCategory=person)'
        '(userAccountControl:1.2.840.113556.1.4.803:=65536)'
        '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
    stale_users       = paged_count(conn,
        f'(&(objectClass=user)(objectCategory=person)'
        f'(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        f'(lastLogonTimestamp<={ft_90}))')
    total_groups      = paged_count(conn, '(objectClass=group)')
    empty_groups      = paged_count(conn, '(&(objectClass=group)(!(member=*)))')
    total_computers   = paged_count(conn, '(objectClass=computer)')
    stale_computers   = paged_count(conn,
        f'(&(objectClass=computer)(lastLogonTimestamp<={ft_90}))')

    conn.search(BASE_DN, '(&(objectClass=group)(cn=Domain Admins))',
                attributes=['member'])
    domain_admin_count = len(
        conn.entries[0].member.values
        if conn.entries and conn.entries[0].member else [])

    conn.search(BASE_DN, '(&(objectClass=group)(cn=Enterprise Admins))',
                attributes=['member'])
    enterprise_admin_count = len(
        conn.entries[0].member.values
        if conn.entries and conn.entries[0].member else [])

    conn.search(BASE_DN, '(objectClass=domainDNS)',
                attributes=['minPwdLength', 'pwdHistoryLength',
                            'maxPwdAge', 'lockoutThreshold'])
    pwd_policy = {}
    if conn.entries:
        e = conn.entries[0]
        pwd_policy = {
            "min_length":        int(e.minPwdLength.value)     if e.minPwdLength     else 0,
            "history":           int(e.pwdHistoryLength.value) if e.pwdHistoryLength else 0,
            "lockout_threshold": int(e.lockoutThreshold.value) if e.lockoutThreshold else 0,
        }

    gpo_summary = _get_gpo_quick_counts(conn)
    conn.unbind()

    result = {
        "total_users":            total_users,
        "disabled_users":         disabled_users,
        "active_users":           total_users - disabled_users,
        "pwd_never_expires":      pwd_never_expires,
        "stale_users":            stale_users,
        "total_groups":           total_groups,
        "empty_groups":           empty_groups,
        "total_computers":        total_computers,
        "stale_computers":        stale_computers,
        "domain_admin_count":     domain_admin_count,
        "enterprise_admin_count": enterprise_admin_count,
        "pwd_policy":             pwd_policy,
        "gpo_summary":            gpo_summary,
    }
    cache.set("ad_summary", result)
    _, ts = cache.get("ad_summary")
    return result, ts

# ── user reports ──────────────────────────────────────────────────────────────

def get_stale_users(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ad_stale_users")
        if data is not None:
            return data, ts

    conn  = get_conn()
    ft_90 = ft_threshold(90)
    entries = paged_search(conn,
        f'(&(objectClass=user)(objectCategory=person)'
        f'(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        f'(lastLogonTimestamp<={ft_90}))',
        attributes=['cn', 'sAMAccountName', 'lastLogonTimestamp',
                    'department', 'title'])
    users = []
    for e in entries:
        if e.get('type') != 'searchResEntry':
            continue
        dt = get_ft_from_entry(e, 'lastLogonTimestamp')
        users.append({
            "name":          attr(e, 'cn'),
            "username":      attr(e, 'sAMAccountName'),
            "last_login":    dt.strftime("%Y-%m-%d") if dt else "Never",
            "days_inactive": days_ago(dt) if dt else 999,
            "department":    attr(e, 'department'),
            "title":         attr(e, 'title'),
        })
    users.sort(key=lambda x: x["days_inactive"], reverse=True)
    conn.unbind()
    cache.set("ad_stale_users", users)
    _, ts = cache.get("ad_stale_users")
    return users, ts

def get_pwd_never_expires(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ad_pwd_never_expires")
        if data is not None:
            return data, ts

    conn = get_conn()
    entries = paged_search(conn,
        '(&(objectClass=user)(objectCategory=person)'
        '(userAccountControl:1.2.840.113556.1.4.803:=65536)'
        '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
        attributes=['cn', 'sAMAccountName', 'department',
                    'title', 'lastLogonTimestamp'])
    users = []
    for e in entries:
        if e.get('type') != 'searchResEntry':
            continue
        dt = get_ft_from_entry(e, 'lastLogonTimestamp')
        users.append({
            "name":       attr(e, 'cn'),
            "username":   attr(e, 'sAMAccountName'),
            "last_login": dt.strftime("%Y-%m-%d") if dt else "Never",
            "department": attr(e, 'department'),
            "title":      attr(e, 'title'),
        })
    conn.unbind()
    cache.set("ad_pwd_never_expires", users)
    _, ts = cache.get("ad_pwd_never_expires")
    return users, ts

def get_domain_admins(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ad_domain_admins")
        if data is not None:
            return data, ts

    conn       = get_conn()
    by_username = {}

    for group_cn in ["Domain Admins", "Enterprise Admins"]:
        conn.search(
            BASE_DN,
            f'(&(objectClass=group)(cn={group_cn}))',
            attributes=['member', 'distinguishedName'],
            search_scope='SUBTREE',
            size_limit=0
        )

        if not conn.entries:
            # Fallback: try forest root derived from BASE_DN
            parts    = BASE_DN.upper().split(',')
            dc_parts = [p for p in parts if p.startswith('DC=')]
            if len(dc_parts) > 2:
                forest_root = ','.join(dc_parts[-2:])
                conn.search(
                    forest_root,
                    f'(&(objectClass=group)(cn={group_cn}))',
                    attributes=['member', 'distinguishedName'],
                    search_scope='SUBTREE',
                    size_limit=0
                )

        if not conn.entries:
            continue

        members = conn.entries[0].member.values if conn.entries[0].member else []

        for member_dn in members:
            # Search with the member DN as the base in BASE scope — this avoids
            # any filter-escaping issues with DNs that contain commas e.g.
            # CN=Choudhary\, Milan (DA),OU=...
            entries = list(conn.extend.standard.paged_search(
                search_base=member_dn,
                search_filter='(objectClass=*)',
                search_scope='BASE',
                attributes=['cn', 'sAMAccountName', 'title', 'department',
                            'userAccountControl', 'lastLogonTimestamp'],
                paged_size=1,
                generator=False
            ))
            if not entries:
                continue

            e = entries[0]
            if e.get('type') != 'searchResEntry':
                continue

            username = attr(e, 'sAMAccountName')
            if not username:
                continue

            dt  = get_ft_from_entry(e, 'lastLogonTimestamp')
            uac = int(attr(e, 'userAccountControl') or 0)
            cn  = attr(e, 'cn')
            svc = ('service' in cn.lower() or
                   'svc'     in username.lower() or
                   'svc'     in cn.lower() or
                   username.lower().startswith('ser'))

            if username not in by_username:
                by_username[username] = {
                    "name":               cn,
                    "username":           username,
                    "title":              attr(e, 'title'),
                    "department":         attr(e, 'department'),
                    "last_login":         dt.strftime("%Y-%m-%d") if dt else "Never",
                    "groups":             [group_cn],
                    "group":              group_cn,
                    "is_service_account": svc,
                    "is_disabled":        bool(uac & 2),
                }
            else:
                # User is in multiple groups — track all, promote to EA if applicable
                by_username[username]["groups"].append(group_cn)
                if group_cn == "Enterprise Admins":
                    by_username[username]["group"] = "Enterprise Admins"

    conn.unbind()
    admins = list(by_username.values())
    cache.set("ad_domain_admins", admins)
    _, ts = cache.get("ad_domain_admins")
    return admins, ts

def get_empty_groups(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ad_empty_groups")
        if data is not None:
            return data, ts

    conn    = get_conn()
    entries = paged_search(conn,
        '(&(objectClass=group)(!(member=*)))',
        attributes=['cn', 'description', 'whenCreated'])
    groups = [{
        "name":        attr(e, 'cn'),
        "description": attr(e, 'description'),
        "created":     attr(e, 'whenCreated')[:10],
    } for e in entries if e.get('type') == 'searchResEntry']
    conn.unbind()
    cache.set("ad_empty_groups", groups)
    _, ts = cache.get("ad_empty_groups")
    return groups, ts


def get_stale_computers(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ad_stale_computers")
        if data is not None:
            return data, ts

    conn  = get_conn()
    ft_90 = ft_threshold(90)
    entries = paged_search(conn,
        f'(&(objectClass=computer)(lastLogonTimestamp<={ft_90}))',
        attributes=['cn', 'lastLogonTimestamp',
                    'operatingSystem', 'operatingSystemVersion'])
    computers = []
    for e in entries:
        if e.get('type') != 'searchResEntry':
            continue
        dt = get_ft_from_entry(e, 'lastLogonTimestamp')
        computers.append({
            "name":          attr(e, 'cn'),
            "last_login":    dt.strftime("%Y-%m-%d") if dt else "Never",
            "days_inactive": days_ago(dt) if dt else 999,
            "os":            attr(e, 'operatingSystem'),
            "os_version":    attr(e, 'operatingSystemVersion'),
        })
    computers.sort(key=lambda x: x["days_inactive"], reverse=True)
    conn.unbind()

    # ── Citrix cross-reference ────────────────────────────────────────────────
    # Tag each stale computer with its Citrix context and filter out master images.
    # Master images (e.g. TOPCTXXDMI01P) are snapshot-based templates — they are
    # intentionally not domain-active and should never appear as stale computers.
    try:
        from routers.citrix import get_citrix_machine_name_set
        citrix_machines = get_citrix_machine_name_set()
    except Exception:
        citrix_machines = {}

    enriched = []
    for c in computers:
        short = c["name"].lower()
        ctx   = citrix_machines.get(short, {})

        # Skip master images entirely — they are not live computers
        if ctx.get("is_master_image") or _is_master_image_by_name(c["name"]):
            continue

        c["citrix_managed"]        = bool(ctx)
        c["citrix_catalog"]        = ctx.get("catalog_name")
        c["citrix_delivery_group"] = ctx.get("delivery_group_name")
        c["citrix_is_vdi"]         = ctx.get("is_vdi", False)
        c["citrix_reg_state"]      = ctx.get("registration_state")  # Registered/Unregistered
        c["citrix_power_state"]    = ctx.get("power_state")          # On/Off/Suspended
        enriched.append(c)

    cache.set("ad_stale_computers", enriched)
    _, ts = cache.get("ad_stale_computers")
    return enriched, ts


def _is_master_image_by_name(name):
    """Mirror of analysis.py helper — kept local to avoid circular imports."""
    if not name:
        return False
    n = name.upper().split("\\")[-1]
    if re.search(r'(XDMI|CTXMI|XAMI|XDGMI)', n):
        return True
    if re.search(r'^(TOP|VMCE|AWS|CAN)[A-Z0-9]+MI\d{2}[PQDUTR]?$', n):
        return True
    return False


def _parse_ou_path(dn):
    """Extract OU path from a Distinguished Name, e.g.
    'CN=TOPDC01P,OU=Domain Controllers,DC=zinnia,DC=com' → 'Domain Controllers'
    Returns a list of OU names (innermost first) and the full path string."""
    if not dn:
        return [], ''
    parts = [p.strip() for p in dn.split(',')]
    ous = [p[3:] for p in parts if p.upper().startswith('OU=')]
    path = ' / '.join(reversed(ous)) if ous else ''
    return ous, path


_ENV_OU_KEYWORDS = {
    'Production': ['production', 'prod', 'servers', 'domain controllers', 'infrastructure'],
    'QA':         ['qa', 'quality'],
    'Staging':    ['staging', 'stage', 'uat', 'pre-prod', 'preprod'],
    'Dev':        ['dev', 'development', 'sandbox'],
    'Test':       ['test', 'testing'],
}

def _infer_env_from_ou(ous):
    for ou in ous:
        ou_lower = ou.lower()
        for env, keywords in _ENV_OU_KEYWORDS.items():
            if any(kw in ou_lower for kw in keywords):
                return env
    return 'Unknown'


def get_all_computers_with_ou(force_refresh=False):
    """Fetch all AD computer accounts with OU path and environment hint.
    Cached for 4 hours — used by the merged inventory endpoint."""
    if not force_refresh:
        data, ts = cache.get("ad_all_computers_ou")
        if data is not None:
            return data, ts

    try:
        conn = get_conn()
    except Exception:
        return [], None

    entries = paged_search(conn,
        '(objectClass=computer)',
        attributes=['cn', 'distinguishedName', 'operatingSystem',
                    'operatingSystemVersion', 'lastLogonTimestamp', 'description'])
    conn.unbind()

    computers = []
    for e in entries:
        if e.get('type') != 'searchResEntry':
            continue
        dn   = attr(e, 'distinguishedName')
        name = attr(e, 'cn')
        if not name:
            continue
        ous, ou_path = _parse_ou_path(dn)
        env = _infer_env_from_ou(ous)
        dt  = get_ft_from_entry(e, 'lastLogonTimestamp')
        computers.append({
            "name":        name,
            "dn":          dn,
            "ou_path":     ou_path,
            "ou_list":     ous,
            "environment": env,
            "os":          attr(e, 'operatingSystem'),
            "os_version":  attr(e, 'operatingSystemVersion'),
            "description": attr(e, 'description'),
            "last_login":  dt.strftime("%Y-%m-%d") if dt else None,
        })

    computers.sort(key=lambda x: x["name"].lower())
    cache.set("ad_all_computers_ou", computers)
    _, ts = cache.get("ad_all_computers_ou")
    return computers, ts


# ── GPO analysis ──────────────────────────────────────────────────────────────

def _get_gpo_quick_counts(conn):
    try:
        conn.search(GPO_BASE,
                    '(objectClass=groupPolicyContainer)',
                    attributes=['cn', 'flags', 'whenChanged'],
                    search_scope=SUBTREE, size_limit=0)
        total    = len(conn.entries)
        disabled = sum(1 for e in conn.entries
                       if e.flags and int(e.flags.value) in (1, 2, 3))
        two_years_ago = datetime.datetime.utcnow() - datetime.timedelta(days=730)
        stale = 0
        for e in conn.entries:
            if e.whenChanged:
                try:
                    changed = datetime.datetime.strptime(
                        str(e.whenChanged.value)[:19], "%Y-%m-%d %H:%M:%S")
                    if changed < two_years_ago:
                        stale += 1
                except Exception:
                    pass
        return {"total": total, "disabled": disabled, "stale_2yr": stale}
    except Exception:
        return {"total": 0, "disabled": 0, "stale_2yr": 0}

def _get_all_gpo_links(conn):
    links = {}
    conn.search(BASE_DN, '(gPLink=*)',
                attributes=['distinguishedName', 'gPLink'],
                search_scope=SUBTREE, size_limit=0)
    for e in conn.entries:
        raw_link = str(e.gPLink.value) if e.gPLink else ""
        guids    = re.findall(r'\{([A-Fa-f0-9\-]+)\}', raw_link)
        if guids:
            links[str(e.distinguishedName)] = guids
    return links

def get_gpo_analysis(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ad_gpo_analysis")
        if data is not None:
            return data, ts

    conn          = get_conn()
    two_years_ago = datetime.datetime.utcnow() - datetime.timedelta(days=730)

    conn.search(GPO_BASE,
                '(objectClass=groupPolicyContainer)',
                attributes=['cn', 'displayName', 'flags',
                            'whenChanged', 'whenCreated', 'versionNumber'],
                search_scope=SUBTREE, size_limit=0)

    all_gpos = {}
    for e in conn.entries:
        guid  = str(e.cn).strip('{}').upper()
        flags = int(e.flags.value) if e.flags else 0

        changed_dt = None
        try:
            changed_dt = datetime.datetime.strptime(
                str(e.whenChanged.value)[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

        created_dt = None
        try:
            created_dt = datetime.datetime.strptime(
                str(e.whenCreated.value)[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

        all_gpos[guid] = {
            "guid":              guid,
            "name":              str(e.displayName) if e.displayName else str(e.cn),
            "flags":             flags,
            "user_disabled":     bool(flags & 1),
            "computer_disabled": bool(flags & 2),
            "all_disabled":      flags == 3,
            "last_modified":     changed_dt.strftime("%Y-%m-%d") if changed_dt else "Unknown",
            "created":           created_dt.strftime("%Y-%m-%d") if created_dt else "Unknown",
            "stale":             changed_dt < two_years_ago if changed_dt else False,
            "linked_to":         [],
            "link_count":        0,
        }

    gpo_links    = _get_all_gpo_links(conn)
    linked_guids = set()

    for ou_dn, guids in gpo_links.items():
        for guid in guids:
            g = guid.upper()
            linked_guids.add(g)
            if g in all_gpos:
                all_gpos[g]["linked_to"].append(ou_dn)
                all_gpos[g]["link_count"] += 1

    orphaned        = []
    empty_disabled  = []
    stale           = []
    linked_disabled = []

    for gpo in all_gpos.values():
        is_linked = gpo["guid"] in linked_guids
        if not is_linked:
            orphaned.append(gpo)
        if gpo["all_disabled"]:
            empty_disabled.append(gpo)
        if gpo["stale"]:
            stale.append(gpo)
        if is_linked and (gpo["all_disabled"] or
                          gpo["user_disabled"] or
                          gpo["computer_disabled"]):
            linked_disabled.append(gpo)

    name_groups = {}
    for gpo in all_gpos.values():
        key = re.sub(r'[\s\-_]+', ' ',
              re.sub(r'\d+', '',
              re.sub(r'(copy|new|old|backup|test|v\d+)$', '',
                     gpo["name"].lower()))).strip()
        name_groups.setdefault(key, []).append(gpo["name"])

    duplicate_names = [
        {"pattern": k, "gpo_names": v, "count": len(v)}
        for k, v in name_groups.items() if len(v) > 1
    ]

    ou_complexity = sorted(
        [{"ou": ou, "gpo_count": len(guids)}
         for ou, guids in gpo_links.items()],
        key=lambda x: x["gpo_count"], reverse=True
    )[:15]

    conn.unbind()

    result = {
        "total_gpos":            len(all_gpos),
        "linked_gpos":           len(linked_guids),
        "orphaned_count":        len(orphaned),
        "disabled_count":        len(empty_disabled),
        "stale_count":           len(stale),
        "linked_disabled_count": len(linked_disabled),
        "duplicate_groups":      len(duplicate_names),
        "orphaned":              sorted(orphaned, key=lambda x: x["last_modified"], reverse=True),
        "empty_disabled":        empty_disabled,
        "stale":                 sorted(stale, key=lambda x: x["last_modified"]),
        "linked_disabled":       linked_disabled,
        "duplicate_names":       sorted(duplicate_names, key=lambda x: x["count"], reverse=True),
        "ou_complexity":         ou_complexity,
        "recommendations":       _gpo_recommendations(
                                     len(orphaned), len(empty_disabled),
                                     len(stale), len(linked_disabled),
                                     len(duplicate_names), ou_complexity),
    }
    cache.set("ad_gpo_analysis", result)
    _, ts = cache.get("ad_gpo_analysis")
    return result, ts

def _gpo_recommendations(orphaned, disabled, stale, linked_disabled,
                          duplicates, ou_complexity):
    recs = []
    if orphaned > 0:
        recs.append({"severity": "warning",
                     "text": f"{orphaned} orphaned GPO(s) not linked to any OU. "
                             f"Review and delete if no longer needed."})
    if linked_disabled > 0:
        recs.append({"severity": "warning",
                     "text": f"{linked_disabled} GPO(s) are linked but partially or fully "
                             f"disabled — overhead without effect. Unlink or delete."})
    if disabled > 0:
        recs.append({"severity": "info",
                     "text": f"{disabled} GPO(s) have all settings disabled. "
                             f"Consider deleting rather than leaving disabled."})
    if stale > 0:
        recs.append({"severity": "info",
                     "text": f"{stale} GPO(s) not modified in over 2 years. "
                             f"Review whether they are still relevant."})
    if duplicates > 0:
        recs.append({"severity": "info",
                     "text": f"{duplicates} group(s) of GPOs have similar names "
                             f"suggesting redundancy. Consider consolidating."})
    if ou_complexity and ou_complexity[0]["gpo_count"] >= 10:
        top = ou_complexity[0]
        recs.append({"severity": "warning",
                     "text": f"OU '{top['ou'].split(',')[0]}' has {top['gpo_count']} GPOs "
                             f"linked — complexity hotspot. Consider consolidating."})
    return recs

# ── AI analysis helper ────────────────────────────────────────────────────────

def get_ad_analysis_for_ai():
    try:
        summary, _ = get_ad_summary()
        stale_u, _ = get_stale_users()
        admins, _  = get_domain_admins()
        gpo, _     = get_gpo_analysis()
        stale_c, _ = get_stale_computers()
        pp         = summary.get("pwd_policy", {})

        pp_issues = []
        if pp.get("min_length", 0) < 12:
            pp_issues.append(f"Min password length is {pp.get('min_length')} (recommend 12+)")
        if pp.get("history", 0) < 10:
            pp_issues.append(f"Password history is {pp.get('history')} (recommend 10+)")
        if pp.get("lockout_threshold", 0) == 0:
            pp_issues.append("No account lockout threshold set")
        elif pp.get("lockout_threshold", 0) > 10:
            pp_issues.append(f"Lockout threshold is {pp.get('lockout_threshold')} (recommend ≤10)")

        disabled_admins = [a for a in admins if a.get("is_disabled")]
        svc_admins      = [a for a in admins if a.get("is_service_account")]

        # Stale computers broken out by type for AI context
        stale_citrix_vdi      = [c for c in stale_c if c.get("citrix_is_vdi")]
        stale_citrix_xenapp   = [c for c in stale_c if c.get("citrix_managed") and not c.get("citrix_is_vdi")]
        stale_citrix_unreg    = [c for c in stale_c if c.get("citrix_managed")
                                  and c.get("citrix_reg_state") == "Unregistered"]
        stale_regular         = [c for c in stale_c if not c.get("citrix_managed")]
        # Zombies: Citrix-managed, unregistered, AND stale in AD — worth calling out
        zombies = [c for c in stale_c
                   if c.get("citrix_managed")
                   and c.get("citrix_reg_state") == "Unregistered"
                   and c.get("citrix_power_state") not in ("Off", "Suspended", None)]

        return {
            "summary": {
                "total_users":            summary.get("total_users"),
                "active_users":           summary.get("active_users"),
                "disabled_users":         summary.get("disabled_users"),
                "stale_users":            summary.get("stale_users"),
                "pwd_never_expires":      summary.get("pwd_never_expires"),
                "domain_admin_count":     summary.get("domain_admin_count"),
                "enterprise_admin_count": summary.get("enterprise_admin_count"),
                "empty_groups":           summary.get("empty_groups"),
                "stale_computers":        len(stale_c),
            },
            "password_policy":        pp,
            "password_policy_issues": pp_issues,
            "privileged_accounts": {
                "total_admins":    len(admins),
                "disabled_admins": [a["username"] for a in disabled_admins],
                "service_admins":  [a["username"] for a in svc_admins],
            },
            "gpo_health": {
                "total_gpos":        gpo.get("total_gpos"),
                "orphaned":          gpo.get("orphaned_count"),
                "disabled":          gpo.get("disabled_count"),
                "stale":             gpo.get("stale_count"),
                "linked_disabled":   gpo.get("linked_disabled_count"),
                "duplicate_groups":  gpo.get("duplicate_groups"),
                "top_complexity_ou": gpo.get("ou_complexity", [{}])[0],
                "recommendations":   gpo.get("recommendations", []),
            },
            "stale_computers": {
                "total":               len(stale_c),
                "regular_servers":     len(stale_regular),
                "citrix_vdi":          len(stale_citrix_vdi),
                "citrix_xenapp":       len(stale_citrix_xenapp),
                "citrix_unregistered": len(stale_citrix_unreg),
                "zombie_machines":     len(zombies),
                "zombie_detail":       [{"name": z["name"], "days_inactive": z["days_inactive"],
                                         "catalog": z.get("citrix_catalog"),
                                         "citrix_power": z.get("citrix_power_state")}
                                        for z in zombies[:10]],
                "top_stale_regular":   [{"name": c["name"], "days": c["days_inactive"], "os": c["os"]}
                                        for c in stale_regular[:10]],
            },
            "top_stale_users": stale_u[:10],
        }
    except Exception as e:
        return {"error": str(e)}