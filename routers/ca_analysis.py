import os
import subprocess
import datetime
import csv
import io
import json as _json
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from dotenv import load_dotenv
from routers.cache import cache

load_dotenv()

DC_HOST   = os.getenv("AD_HOST")
USERNAME  = os.getenv("AD_DOMAIN") + "\\" + os.getenv("AD_USER")
PASSWORD  = os.getenv("AD_PASSWORD")
BASE_DN   = os.getenv("AD_BASE_DN")
CA_HOST   = os.getenv("CA_HOST")
CA_NAME   = os.getenv("CA_NAME")
DC_CERT_SCAN_PATH = os.getenv("DC_CERT_SCAN_PATH", r"\\SETOPCA02P\CertScan\dc_certs.json")

EXPIRY_CRITICAL = 30
EXPIRY_WARNING  = 60
EXPIRY_NOTICE   = 90

# How far back to pull issued certs from the CA. Without this, Get-IssuedRequest
# walks the CA's entire lifetime history — mostly auto-enrolled machine/DC/workstation
# renewals from years ago — which is what was blowing past the 900s WinRM timeout.
# Certs still valid are always included regardless of this cutoff; this only drops
# ones that expired before it.
CERT_SCAN_LOOKBACK_DAYS = 180

# ── Critical servers ──────────────────────────────────────────────────────────
CRITICAL_SERVERS = [
    # Domain Controllers
    "AWSEASTDC1", "AWSEASTDC2", "AWSWESTDC1",
    "CANDC01P", "CANDC02P",
    "SETOPDC01P", "SETOPDC02P",
    # Certificate Authority
    "SETOPCA02P",
    # ADFS
    "SETOPADFS01P", "SETOPADFS02P",
    # Citrix FAS — Topeka, VMC, AWS
    "TOPCTXCCFAS01P", "TOPCTXCCFAS02P",
    "VMCECTXFAS01P",  "VMCECTXFAS02P",
    "AWSCTXFAS01P",   "AWSCTXFAS02P",
]

# Server → human-readable role (used in AI prompt and watch list display)
SERVER_ROLES = {
    "AWSEASTDC1":    "Domain Controller (AWS East)",
    "AWSEASTDC2":    "Domain Controller (AWS East)",
    "AWSWESTDC1":    "Domain Controller (AWS West)",
    "CANDC01P":      "Domain Controller (Candor India)",
    "CANDC02P":      "Domain Controller (Candor India)",
    "SETOPDC01P":    "Domain Controller (Topeka)",
    "SETOPDC02P":    "Domain Controller (Topeka)",
    "SETOPCA02P":    "Certificate Authority",
    "SETOPADFS01P":  "ADFS Server",
    "SETOPADFS02P":  "ADFS Server",
    "TOPCTXCCFAS01P":"Citrix FAS (Topeka)",
    "TOPCTXCCFAS02P":"Citrix FAS (Topeka)",
    "VMCECTXFAS01P": "Citrix FAS (VMC)",
    "VMCECTXFAS02P": "Citrix FAS (VMC)",
    "AWSCTXFAS01P":  "Citrix FAS (AWS)",
    "AWSCTXFAS02P":  "Citrix FAS (AWS)",
}

AUTO_ENROLL_KEYWORDS = [
    "machine", "computer", "domaincontroller", "domain controller",
    "domaincontrollerauthentication", "domain controller authentication",
    "kerberosauthentication", "kerberos authentication",
    "workstationauthentication", "workstation authentication"
]

MANUAL_KEYWORDS = [
    "webserver", "web server", "citrix", "fas", "iis",
    "serverauth", "server auth", "ldaps", "ssl", "tls", "federation"
]

SERVICE_SUBJECT_KEYWORDS = [
    "citrix", "fas", "federation", "ldap", "ldaps", "web", "ssl", "tls"
]

# ── DC list ───────────────────────────────────────────────────────────────────
DC_LIST = [
    {"name": "CANDC01P",   "fqdn": "CANDC01P.sbl.com",   "reachable": True},
    {"name": "SETOPDC01P", "fqdn": "SETOPDC01P.sbl.com", "reachable": True},
    {"name": "SETOPDC02P", "fqdn": "SETOPDC02P.sbl.com", "reachable": True},
    {"name": "AWSEASTDC1", "fqdn": "AWSEASTDC1.sbl.com", "reachable": False},
    {"name": "AWSEASTDC2", "fqdn": "AWSEASTDC2.sbl.com", "reachable": False},
    {"name": "AWSWESTDC1", "fqdn": "AWSWESTDC1.sbl.com", "reachable": False},
]

# ── helpers ───────────────────────────────────────────────────────────────────

def contains_any(text, patterns):
    if not text:
        return False
    t = text.lower()
    return any(p.lower() in t for p in patterns)

def days_until(dt):
    if not dt:
        return None
    if isinstance(dt, str):
        for fmt in ("%m/%d/%Y %I:%M %p", "%m/%d/%Y %H:%M",
                    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.datetime.strptime(dt.strip(), fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return (dt - datetime.datetime.utcnow()).days

def expiry_status(days):
    if days is None:             return "unknown"
    if days < 0:                 return "expired"
    if days <= EXPIRY_CRITICAL:  return "critical"
    if days <= EXPIRY_WARNING:   return "warning"
    if days <= EXPIRY_NOTICE:    return "notice"
    return "ok"

def resolve_critical_server(common_name, requester):
    found = []
    for text in [common_name or "", requester or ""]:
        for srv in CRITICAL_SERVERS:
            if srv.upper() in text.upper():
                found.append(srv.upper())
    return "; ".join(sorted(set(found)))

def classify_cert(requester, template, common_name, related_server):
    requester_is_machine = bool(
        requester and (requester.strip().endswith("$") or
                       ("\\" in requester and requester.split("\\")[-1].endswith("$")))
    )
    is_auto     = contains_any(template, AUTO_ENROLL_KEYWORDS)
    is_manual   = contains_any(template, MANUAL_KEYWORDS)
    is_critical = bool(related_server)
    subj_svc    = contains_any(common_name, SERVICE_SUBJECT_KEYWORDS)

    if is_auto and requester_is_machine and not is_manual:
        return "AutoEnrollLikely"
    if is_manual and not requester_is_machine:
        return "ManualLikely"
    if is_manual and is_critical:
        return "ManualLikely"
    if subj_svc and is_critical:
        return "ManualLikely"
    if requester_is_machine and is_critical and is_auto:
        return "AutoEnrollLikely"
    if requester_is_machine and not is_manual and not subj_svc:
        return "AutoEnrollLikely"
    return "ReviewNeeded"

# ── LDAP connection ───────────────────────────────────────────────────────────

def get_conn():
    server = Server(DC_HOST, get_info=ALL)
    return Connection(server, user=USERNAME, password=PASSWORD,
                      authentication=NTLM, auto_bind=True)

# ── PSPKI remote execution ────────────────────────────────────────────────────

PS_SCRIPT = r"""
param($CAHost, $CAName, $NotAfterCutoff)
Import-Module PSPKI -Force -ErrorAction Stop

$ca = Get-CertificationAuthority |
      Where-Object { $_.DisplayName -eq $CAName } |
      Select-Object -First 1

if ($null -eq $ca) { throw "CA not found: $CAName on $CAHost" }

$properties = @(
    "RequestID","RequesterName","CommonName",
    "CertificateTemplate","NotBefore","NotAfter",
    "SerialNumber","CertificateHash"
)

# Only pull certs that are still valid or expired within the lookback window —
# excludes years of superseded auto-enroll renewals without touching classification.
$restriction = "NotAfter -ge $NotAfterCutoff"

$rows = New-Object System.Collections.Generic.List[object]
$page = 1
while ($true) {
    $batch = @($ca | Get-IssuedRequest -Page $page -PageSize 1000 -Property $properties -Filter $restriction)
    if ($batch.Count -eq 0) { break }
    foreach ($r in $batch) {
        $na = $null
        try { $na = $r.NotAfter } catch {}
        $days = $null
        if ($na) {
            try { $days = [int][math]::Floor(($na - (Get-Date)).TotalDays) } catch {}
        }
        $rows.Add([pscustomobject]@{
            RequestID           = [string]$r.RequestID
            RequesterName       = [string]$r.RequesterName
            CommonName          = [string]$r.CommonName
            CertificateTemplate = [string]$r.CertificateTemplate
            NotBefore           = if ($r.NotBefore) { $r.NotBefore.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            NotAfter            = if ($na) { $na.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            DaysRemaining       = if ($days -ne $null) { $days } else { "" }
            SerialNumber        = [string]$r.SerialNumber
            Thumbprint          = [string]$r.CertificateHash
        })
    }
    if ($batch.Count -lt 1000) { break }
    $page++
}
$rows | ConvertTo-Csv -NoTypeInformation
"""

def run_pspki_remote(timeout=900):
    """
    Runs the PSPKI cert query on the CA server via WinRM.
    Builds credentials from AD_USER / AD_DOMAIN / AD_PASSWORD env vars.
    Writes a temp .ps1 file so the full Security module loads correctly —
    inline ConvertTo-SecureString fails in constrained IIS/uvicorn sessions.
    """
    import tempfile, uuid, os as _os

    user     = f"{_os.getenv('AD_DOMAIN', '')}\\{_os.getenv('AD_USER', '')}"
    password = _os.getenv("AD_PASSWORD", "")
    cutoff   = (datetime.datetime.utcnow() - datetime.timedelta(days=CERT_SCAN_LOOKBACK_DAYS)).strftime("%m/%d/%Y")

    # Write a temp script file — avoids inline one-liner module loading issues
    script_id   = uuid.uuid4().hex[:8]
    script_path = _os.path.join(tempfile.gettempdir(), f"infraportal_certscan_{script_id}.ps1")

    wrapper = f"""
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

$pw   = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{user}', $pw)

$sopts = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
Invoke-Command -ComputerName '{CA_HOST}' -Credential $cred `
    -SessionOption $sopts `
    -Authentication Negotiate `
    -ScriptBlock {{
{PS_SCRIPT}
}} -ArgumentList '{CA_HOST}','{CA_NAME}','{cutoff}'
"""

    # Pin PSModulePath to the built-in system module locations only. The
    # ambient PSModulePath includes a OneDrive-synced user modules folder as
    # its first entry — if that folder is mid-sync/unavailable, PowerShell's
    # module resolution can throw "command found but module could not be
    # loaded" instead of just skipping it. Skipping it entirely avoids the
    # flakiness (and avoids resolving modules from a writable synced folder).
    env = dict(os.environ)
    env["PSModulePath"] = ";".join([
        r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
        r"C:\Program Files\WindowsPowerShell\Modules",
    ])

    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(wrapper)

        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile",
             "-WindowStyle", "Hidden",
             "-ExecutionPolicy", "Bypass",
             "-File", script_path],
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,   # blocks interactive credential prompts
            creationflags=0x08000000,   # CREATE_NO_WINDOW — suppresses console window
            env=env
        )
        if result.returncode != 0 and not result.stdout.strip():
            raise RuntimeError(f"PowerShell error: {result.stderr.strip()[:500]}")
        return list(csv.DictReader(io.StringIO(result.stdout)))
    finally:
        try: _os.remove(script_path)
        except: pass

# ── LDAP cert queries ─────────────────────────────────────────────────────────

def get_user_certs_from_ldap():
    conn = get_conn()
    conn.search(BASE_DN,
                "(&(objectClass=user)(objectCategory=person)(userCertificate=*))",
                attributes=["cn", "sAMAccountName", "userCertificate", "department", "title"],
                search_scope=SUBTREE, size_limit=0)
    results = []
    for e in conn.entries:
        certs = e.userCertificate.values if e.userCertificate else []
        for raw in certs:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                c = x509.load_der_x509_certificate(bytes(raw), default_backend())
                expiry = c.not_valid_after_utc.replace(tzinfo=None)
                d = days_until(expiry)
                results.append({
                    "subject":         str(e.cn),
                    "username":        str(e.sAMAccountName),
                    "department":      str(e.department) if e.department else "",
                    "title":           str(e.title) if e.title else "",
                    "expiry":          expiry.strftime("%Y-%m-%d"),
                    "days_remaining":  d,
                    "status":          expiry_status(d),
                    "issuer":          c.issuer.rfc4514_string(),
                    "serial":          format(c.serial_number, "x").upper(),
                    "key_size":        c.public_key().key_size
                                       if hasattr(c.public_key(), "key_size") else None,
                    "cert_type":       "User",
                    "template":        "",
                    "classification":  "UserCert",
                    "critical_server": "",
                })
            except Exception:
                pass
    conn.unbind()
    return results

def get_machine_certs_from_ldap():
    conn = get_conn()
    conn.search(BASE_DN,
                "(&(objectClass=computer)(userCertificate=*))",
                attributes=["cn", "userCertificate", "operatingSystem"],
                search_scope=SUBTREE, size_limit=0)
    results = []
    for e in conn.entries:
        certs = e.userCertificate.values if e.userCertificate else []
        for raw in certs:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                c = x509.load_der_x509_certificate(bytes(raw), default_backend())
                expiry = c.not_valid_after_utc.replace(tzinfo=None)
                d = days_until(expiry)
                results.append({
                    "subject":         str(e.cn),
                    "os":              str(e.operatingSystem) if e.operatingSystem else "",
                    "expiry":          expiry.strftime("%Y-%m-%d"),
                    "days_remaining":  d,
                    "status":          expiry_status(d),
                    "issuer":          c.issuer.rfc4514_string(),
                    "serial":          format(c.serial_number, "x").upper(),
                    "key_size":        c.public_key().key_size
                                       if hasattr(c.public_key(), "key_size") else None,
                    "cert_type":       "Machine",
                    "template":        "",
                    "classification":  "MachineCert",
                    "critical_server": "",
                })
            except Exception:
                pass
    conn.unbind()
    return results

# ── DC discovery ──────────────────────────────────────────────────────────────

def get_domain_controllers():
    try:
        conn = get_conn()
        conn.search(BASE_DN,
                    "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
                    attributes=["cn", "dNSHostName", "operatingSystem"],
                    search_scope=SUBTREE, size_limit=0)
        ldap_dcs = {str(e.cn).upper() for e in conn.entries}
        conn.unbind()
    except Exception:
        ldap_dcs = set()

    known = {dc["name"].upper() for dc in DC_LIST}
    merged = list(DC_LIST)
    for name in ldap_dcs:
        if name not in known:
            merged.append({"name": name, "fqdn": f"{name}.sbl.com", "reachable": None})
    return merged

# ── enrichment ────────────────────────────────────────────────────────────────

def enrich_cert(row):
    requester = row.get("RequesterName", "")
    template  = row.get("CertificateTemplate", "")
    cn        = row.get("CommonName", "")
    not_after = row.get("NotAfter", "")
    days_str  = row.get("DaysRemaining", "")
    try:
        days = int(days_str) if days_str != "" else None
    except ValueError:
        days = None
    related        = resolve_critical_server(cn, requester)
    classification = classify_cert(requester, template, cn, related)
    return {
        "request_id":      row.get("RequestID", ""),
        "subject":         cn,
        "requester":       requester,
        "template":        template,
        "not_before":      row.get("NotBefore", ""),
        "expiry":          not_after[:10] if not_after else "",
        "days_remaining":  days,
        "status":          expiry_status(days),
        "serial":          row.get("SerialNumber", ""),
        "thumbprint":      row.get("Thumbprint", ""),
        "critical_server": related,
        "is_critical":     bool(related),
        "classification":  classification,
        "cert_type":       "Server/Service",
    }

# ── public API functions ──────────────────────────────────────────────────────

def get_all_issued(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ca_all_issued")
        if data is not None:
            return data, ts
    raw      = run_pspki_remote()
    enriched = sorted([enrich_cert(r) for r in raw],
                      key=lambda x: x.get("days_remaining") or 9999)
    cache.set("ca_all_issued", enriched)
    _, ts = cache.get("ca_all_issued")
    return enriched, ts

def get_expiring_certs(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ca_expiring")
        if data is not None:
            return data, ts
    # Reuse the underlying CA export if it's already cached — don't trigger a second
    # full WinRM/PSPKI scan just because this derived view is being force-refreshed.
    all_certs, _ = get_all_issued(force_refresh=False)
    user_c  = get_user_certs_from_ldap()
    mach_c  = get_machine_certs_from_ldap()
    expiring = [c for c in all_certs
                if c.get("days_remaining") is not None
                and c["days_remaining"] <= EXPIRY_NOTICE]
    expiring += [c for c in user_c + mach_c
                 if c.get("days_remaining") is not None
                 and c["days_remaining"] <= EXPIRY_NOTICE]
    expiring.sort(key=lambda x: x.get("days_remaining") or 9999)
    cache.set("ca_expiring", expiring)
    _, ts = cache.get("ca_expiring")
    return expiring, ts

def get_manual_certs(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ca_manual")
        if data is not None:
            return data, ts
    # Reuse the underlying CA export if it's already cached — see get_expiring_certs.
    all_certs, _ = get_all_issued(force_refresh=False)
    manual = sorted([c for c in all_certs
                     if c.get("classification") in ("ManualLikely", "ReviewNeeded")],
                    key=lambda x: x.get("days_remaining") or 9999)
    cache.set("ca_manual", manual)
    _, ts = cache.get("ca_manual")
    return manual, ts

def get_cert_summary(force_refresh=False):
    if not force_refresh:
        data, ts = cache.get("ca_summary")
        if data is not None:
            return data, ts
    # Reuse the underlying CA export if it's already cached — see get_expiring_certs.
    all_certs, _ = get_all_issued(force_refresh=False)
    user_c  = get_user_certs_from_ldap()
    mach_c  = get_machine_certs_from_ldap()
    expired = expiring_30 = expiring_60 = expiring_90 = 0
    manual  = review = auto = critical = 0
    template_counts = {}
    for c in all_certs:
        d = c.get("days_remaining")
        if d is not None:
            if d < 0:       expired     += 1
            elif d <= 30:   expiring_30 += 1
            elif d <= 60:   expiring_60 += 1
            elif d <= 90:   expiring_90 += 1
        cls = c.get("classification", "")
        if cls == "ManualLikely":       manual   += 1
        elif cls == "ReviewNeeded":     review   += 1
        elif cls == "AutoEnrollLikely": auto     += 1
        if c.get("is_critical"):        critical += 1
        t = c.get("template") or "(blank)"
        template_counts[t] = template_counts.get(t, 0) + 1
    result = {
        "total_issued":       len(all_certs),
        "expired":            expired,
        "expiring_30":        expiring_30,
        "expiring_60":        expiring_60,
        "expiring_90":        expiring_90,
        "manual_likely":      manual,
        "review_needed":      review,
        "auto_enroll_likely": auto,
        "critical_server":    critical,
        "user_certs":         len(user_c),
        "machine_certs":      len(mach_c),
        "template_breakdown": sorted(template_counts.items(),
                                     key=lambda x: x[1], reverse=True)[:15],
    }
    cache.set("ca_summary", result)
    _, ts = cache.get("ca_summary")
    return result, ts

def get_dc_kerberos_certs(force_refresh=False):
    """
    Read DC Kerberos cert data from the JSON file written by the
    scheduled task on the CA server. Accessed via the CertScan network share.
    """
    if not force_refresh:
        data, ts = cache.get("ca_dc_certs")
        if data is not None:
            return data, ts

    results = []
    try:
        with open(DC_CERT_SCAN_PATH, "r", encoding="utf-8-sig") as f:
            raw = _json.load(f)

        for c in raw.get("certs", []):
            expiry_str = c.get("expiry") or ""
            dt = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    dt = datetime.datetime.strptime(expiry_str.strip(), fmt)
                    break
                except (ValueError, AttributeError):
                    continue
            d         = c.get("days_remaining")
            if d is None and dt:
                d = days_until(dt)
            reachable = c.get("reachable", True)
            error     = c.get("error") or None
            results.append({
                "dc_name":         c.get("dc_name", ""),
                "subject":         c.get("subject") or "—",
                "issuer":          c.get("issuer") or "—",
                "expiry":          dt.strftime("%Y-%m-%d") if dt else "—",
                "days_remaining":  d,
                "status":          expiry_status(d) if reachable and not error else "unknown",
                "thumbprint":      c.get("thumbprint") or "—",
                "eku":             c.get("eku") or "—",
                "reachable":       reachable,
                "error":           error,
                "scan_time":       c.get("scan_time", raw.get("scan_time", "")),
            })

    except FileNotFoundError:
        results.append({
            "dc_name": "ALL DCs", "subject": "—", "issuer": "—",
            "expiry": "—", "days_remaining": None, "status": "unknown",
            "thumbprint": "—", "eku": "—", "reachable": False,
            "error": f"Scan file not found: {DC_CERT_SCAN_PATH}. "
                     f"Run ScanDCCerts.ps1 on the CA server first.",
            "scan_time": "",
        })
    except Exception as ex:
        results.append({
            "dc_name": "ALL DCs", "subject": "—", "issuer": "—",
            "expiry": "—", "days_remaining": None, "status": "unknown",
            "thumbprint": "—", "eku": "—", "reachable": False,
            "error": f"Error reading scan file: {str(ex)[:200]}",
            "scan_time": "",
        })

    results.sort(key=lambda x: (
        1 if not x.get("reachable") and x.get("subject") == "—" else 0,
        x.get("days_remaining") if x.get("days_remaining") is not None else 9999
    ))
    cache.set("ca_dc_certs", results)
    _, ts = cache.get("ca_dc_certs")
    return results, ts

def get_ca_analysis_for_ai():
    """Structured summary for AI Analysis."""
    try:
        summary,   _ = get_cert_summary()
        manual,    _ = get_manual_certs()
        expiring,  _ = get_expiring_certs()
        dc_certs,  _ = get_dc_kerberos_certs()
        return {
            "summary":           summary,
            "manual_likely":     manual[:50],
            "expiring_soon":     expiring[:50],
            "critical_expiring": [c for c in expiring if c.get("is_critical")],
            "expired_deployed":  [c for c in expiring if c.get("status") == "expired"],
            "dc_kerberos_certs": dc_certs,
        }
    except Exception as e:
        return {"error": str(e)}


def get_cert_watchlist_for_ai():
    """
    Returns a filtered cert set suitable for AI classification.
    Excludes pure noise (AutoEnrollLikely with no critical server match,
    certs expired >365 days) to keep the prompt token-efficient.
    Returns (candidates, dc_certs, summary) tuple.
    """
    try:
        all_certs, _ = get_all_issued()
        dc_certs,  _ = get_dc_kerberos_certs()
        summary,   _ = get_cert_summary()

        candidates = []
        for c in all_certs:
            cls     = c.get("classification", "")
            days    = c.get("days_remaining")
            is_crit = c.get("is_critical", False)

            # Always skip: pure auto-enroll with no critical server, and very old expired
            if cls == "AutoEnrollLikely" and not is_crit:
                continue
            if days is not None and days < -365:
                continue

            # Enrich with role if we know the server
            server = c.get("critical_server", "")
            role   = ""
            if server:
                for srv in server.split(";"):
                    srv = srv.strip()
                    if srv in SERVER_ROLES:
                        role = SERVER_ROLES[srv]
                        break

            candidates.append({
                "subject":        c.get("subject", ""),
                "template":       c.get("template", ""),
                "requester":      c.get("requester", ""),
                "expiry":         c.get("expiry", ""),
                "days_remaining": days,
                "status":         c.get("status", ""),
                "classification": cls,
                "critical_server": server,
                "server_role":    role,
                "thumbprint":     c.get("thumbprint", "")[:16] if c.get("thumbprint") else "",
            })

        # Cap at 80 — sorted so most urgent + critical come first
        candidates.sort(key=lambda x: (
            0 if x.get("critical_server") else 1,
            x.get("days_remaining") if x.get("days_remaining") is not None else 9999
        ))
        return candidates[:80], dc_certs, summary
    except Exception as e:
        return [], [], {"error": str(e)}