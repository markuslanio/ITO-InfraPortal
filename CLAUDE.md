# Zinnia Infrastructure Portal — CLAUDE.md
> Context for Claude Code. Last synced: Day 20.

---

## Project Overview

FastAPI web application running on IIS via uvicorn. Aggregates data from VMware, Citrix, OpManager, Active Directory, Lansweeper, Meraki, Jira, and Certificate Authority into a unified dashboard with AI-powered analysis via Claude.

| | |
|---|---|
| **Dev URL** | `http://localhost:8000/infraportal` |
| **Production URL** | `https://itodash.zinnia.com/infraportal` |
| **Server path** | `C:\InfraPortal` |
| **Dev path** | `C:\Users\lanio\Coding\VMWare Project` |
| **IIS Site / App Pool** | `ITOpsTools` |
| **Python (server)** | `C:\Python313` — fixed, never auto-updates |
| **Python (dev)** | `C:\Users\lanio\AppData\Local\Programs\Python\Python314` (venv) |

**Stack:** Python 3.13/3.14 · FastAPI · Jinja2 · SQLite · APScheduler · Anthropic Claude API

---

## Dev Environment

### Start dev server
```
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Reinstall packages if missing
```
pip install uvicorn fastapi python-dotenv requests anthropic apscheduler openpyxl pyodbc jinja2 python-multipart httpx ldap3 pyVmomi
pip freeze > requirements.txt
```

### Diagnose missing routes
```powershell
python -c "import sys; sys.path.insert(0, '.'); import main; routes = [r.path for r in main.app.routes]; print('\n'.join(r for r in routes if 'keyword' in r))"
```

### Recycle app pool (after server deploy)
```powershell
%windir%\system32\inetsrv\appcmd recycle apppool /apppool.name:"ITOpsTools"
```

---

## ⚠️ Critical Gotchas — Read Before Touching Anything

1. **`main.py` location** — lives in project root ONLY. `routers\main.py` must NOT exist — it intercepts imports and silences new routes. When uploading for editing, always use the server copy (`C:\InfraPortal\main.py`).

2. **Python 3.14 / Jinja2** — `_SafeTemplateCache` must be applied after `Jinja2Templates()`:
   ```python
   templates.env.cache = _SafeTemplateCache()
   ```

3. **CSS theming** — uses `body.light-mode` class, NOT `data-theme="light"`. Never use hardcoded hex colors. Always use the 14 CSS variables (see CSS section below).

4. **Every API endpoint** uses lazy imports inside try/except — prevents a single module failure from crashing the entire app.

5. **Fire-and-forget pattern** for long-running operations (AI analysis, VDI report) — return `{status:"running"}` immediately, background thread does the work, frontend polls a `/status` endpoint.

6. **Corporate SSL proxy** — `verify=False` + `urllib3.disable_warnings` on all MS Graph and Anthropic API calls.

7. **`REDIRECT_URI`** must be read at call time, not module import.

8. **Entra group membership** — use `/me/transitiveMemberOf` (not `memberOf`) for nested group support. Paginate with `$top=999` + `@odata.nextLink`.

9. **Azure client secret** — was exposed in chat Day 13, rotated 2026-05-21. Keep `.env` on dev and server in sync after any future rotation.

10. **VMC proxy** — `NO_PROXY` env var set at module load + `proxies={"https":None}` on VMC requests.

---

## Project Structure

```
C:\Users\lanio\Coding\VMWare Project\
├── main.py                  # FastAPI app entry point — all routes registered here
├── run.py                   # IIS/uvicorn launcher — never modify carelessly
├── .env                     # Secrets — never commit
├── requirements.txt
├── routers/
│   ├── auth.py              # Azure AD SSO + RBAC
│   ├── analysis.py          # Claude AI infrastructure analysis
│   ├── vmware.py            # vCenter REST API (3 environments)
│   ├── vmware_deep.py       # pyVmomi legacy (retained)
│   ├── citrix.py            # Citrix Cloud API
│   ├── citrix_apps.py       # Citrix App Manager (4-step clone wizard)
│   ├── vdi_cost.py          # VDI Cost Estimation Report
│   ├── config.py            # Admin config: scheduler + env vars
│   ├── notifications.py     # Citrix Power Unknown alerts (Slack + email)
│   ├── opmanager.py         # ManageEngine OpManager
│   ├── active_directory.py  # AD via ldap3
│   ├── ca_analysis.py       # Certificate Authority
│   ├── jira.py              # Jira Cloud
│   ├── lansweeper.py        # Lansweeper SQL via pyodbc → TOPINFRADB01P
│   ├── meraki.py            # Cisco Meraki Dashboard API
│   ├── scheduler.py         # APScheduler — 22 background jobs
│   ├── cache.py             # In-memory cache with timestamps
│   └── database.py          # SQLite WAL mode, 30s timeout
├── templates/
│   ├── base.html            # Navbar, theming, dark/light toggle, floating AI chat
│   ├── dashboard.html       # Grade cards + deep dive modal
│   ├── vmware.html          # VMs/Hosts/Untagged/Disk/Datastores/Snapshots/AI tabs
│   ├── alerts.html          # OpManager alerts + Jira badges + AI Insights tab
│   ├── citrix.html          # Citrix Cloud + VDI Cost Report button
│   ├── citrix_app_manager.html
│   ├── vdi_cost.html        # 5 tabs: All/By Manager/By Dept/Cost/Cleanup
│   ├── active_directory.html
│   ├── assets.html          # Lansweeper assets + Mark Unimportant
│   ├── certificates.html
│   ├── network.html         # Meraki
│   ├── analysis.html        # AI Analysis grades
│   ├── config.html          # Admin: Scheduler + Environment tabs
│   └── my_dashboard.html    # Coming Soon placeholder
└── static/
    ├── tableutils.js        # SmartTable: sortable/filterable/exportable
    ├── tableutils.css
    └── favicon.svg          # Three Zinnia petals (red/orange/yellow) on black
```

---

## SQLite Tables

| Table | Purpose |
|-------|---------|
| `alert_history` | Historical alert records |
| `analysis_history` | Saved AI analysis results |
| `vm_snapshots` | VM snapshot trend tracking |
| `disk_snapshots` | Disk usage trend tracking |
| `asset_overrides` | "Mark Unimportant" flags |
| `lansweeper_assets` | Cached asset list (survives restarts) |
| `clone_jobs` | Citrix App Manager clone job records |
| `vdi_alert_state` | Citrix power unknown deduplication state |
| `scheduler_config` | Per-job interval/enabled overrides from Config page |

---

## Scheduler Jobs (22 total)

Intervals configurable at runtime via `/infraportal/config` — no restart needed.

| Job | Interval | Purpose |
|-----|----------|---------|
| `job_basic_vms` | 30 min | Basic VM list |
| `job_basic_hosts` | 30 min | Basic host list |
| `job_detailed_vms` | 2 hr | Full VM details |
| `job_disk_snapshots` | 1 hr | VM disk space |
| `job_untagged_vms` | 4 hr | Untagged VM check |
| `job_detailed_hosts` | 2 hr | Full host details |
| `job_opmanager_alerts` | 5 min | Alert refresh |
| `job_opmanager_devices` | 1 hr | Device list |
| `job_jira_prefetch` | 30 min | Ticket cache warm |
| `job_ad_summary` | 1 hr | AD summary |
| `job_ad_reports` | 4 hr | AD detail reports |
| `job_ad_gpo_analysis` | 4 hr | GPO analysis |
| `job_cert_summary` | 6 hr | Cert summary |
| `job_cert_expiring` | 6 hr | Expiring certs |
| `job_cert_dc_certs` | 6 hr | DC Kerberos certs |
| `job_citrix_summary` | 1 hr | Citrix summary |
| `job_citrix_power_unknown_check` | 15 min | Power unknown notifications |
| `job_lansweeper_summary` | 6 hr | Asset summary |
| `job_lansweeper_patch` | 6 hr | Patch status |
| `job_lansweeper_assets` | 6 hr | Full asset list |
| `job_meraki_refresh` | 15 min | Meraki data |
| `job_ai_analysis` | 24 hr | Scheduled AI analysis |

---

## Open Bugs

| # | Issue | Fix |
|---|-------|-----|
| **43** | VMC Snapshots inaccessible — TCP 902 blocked by NSX for server subnet | Add port 902 to the second NSX rule that already allows `10.220.11.74` → vCenter on 443. vCenter IP `10.7.224.4` is not in covered subnets. Verify: `Test-NetConnection -ComputerName vcenter.sddc-34-238-206-207.vmwarevmc.com -Port 902` |

---

## CSS Variables — All Templates Must Use These

> `body.light-mode` class (NOT `data-theme="light"`). Never use hardcoded hex.

| Variable | Dark | Light | Usage |
|---|---|---|---|
| `--bg` | `#1a1a2e` | `#f5f5f3` | Page / body background |
| `--bg2` | `#16213e` | `#ffffff` | Cards, panels, navbar, tab bars |
| `--bg3` | `#0d1117` | `#f1efe8` | Inputs, table headers, darker surfaces |
| `--surface` | `#2a2a4a` | `#e8e6df` | Hover / pressed states |
| `--border` | `#444466` | `#d3d1c7` | All borders |
| `--text` | `#ffffff` | `#1a1a18` | Primary text |
| `--text2` | `#cccccc` | `#3a3a38` | Secondary / body text |
| `--text3` | `#aaaaaa` | `#5f5e5a` | Muted labels, nav links |
| `--text4` | `#888888` | `#888780` | Placeholders, timestamps |
| `--accent` | `#0f9b8e` | `#0a7a70` | Teal brand accent |
| `--accent-dark` | `#0d8a7e` | `#086b62` | Accent hover |
| `--danger` | `#ff4444` | `#cc2222` | Errors, critical alerts |
| `--warning` | `#ffaa00` | `#996600` | Warnings, amber |
| `--success` | `#22cc66` | `#2a7a2a` | Success, green |

**Status color pattern:**
```css
background: rgba(255,68,68,.10);  color: var(--danger);  border: 1px solid rgba(255,68,68,.30);
background: rgba(255,170,0,.10);  color: var(--warning); border: 1px solid rgba(255,170,0,.30);
background: rgba(34,204,102,.10); color: var(--success); border: 1px solid rgba(34,204,102,.30);
background: rgba(15,155,142,.10); color: var(--accent);  border: 1px solid rgba(15,155,142,.30);
```

---

## Azure App Registration

| Field | Value |
|---|---|
| **App name** | Zinnia Infrastructure Portal |
| **Client ID** | `86cd9ecf-4a17-454f-b69d-87bc4484e2f1` |
| **Tenant ID** | `c0d9a159-18ab-4c31-a5a5-f4d0b805de7d` |
| **Redirect URIs** | `https://itodash.zinnia.com/infraportal/auth/callback` + `http://localhost:8000/infraportal/auth/callback` |
| **Token config** | Groups claim enabled (Security groups) |
| **API permissions** | `User.Read` (Delegated), `GroupMember.Read.All` (App), `User.Read.All` (App) |

---

## .env Variables Reference

```
AZURE_CLIENT_ID=86cd9ecf-4a17-454f-b69d-87bc4484e2f1
AZURE_TENANT_ID=c0d9a159-18ab-4c31-a5a5-f4d0b805de7d
AZURE_CLIENT_SECRET=<rotated 2026-05-21>
AZURE_REDIRECT_URI=https://itodash.zinnia.com/infraportal/auth/callback
ENTRA_DEFAULT_DOMAIN=zinnia.com

GROUP_ADMIN=5b2f6312-5e67-426b-9bbc-4f2f5f946be7
GROUP_GENERAL=5a40a5e5-f26e-4269-a4cb-4f6a56cee393
GROUP_VMWARE=bb53132b-09b1-4dfb-b715-a486d0c2774c
GROUP_CITRIX=933f504e-a287-465e-bf85-72dd5ba33873
GROUP_NETWORK=bcd7ed0d-7b7b-4c06-85d0-788298946288

VCENTER_HOST=<Topeka vCenter>
VMC_HOST=vcenter.sddc-34-238-206-207.vmwarevmc.com
CANDOR_HOST=<Candor India vCenter>

SMTP_HOST=outlook.sbl.com
SMTP_PORT=25
SMTP_FROM=Citrix_Alerts@zinnia.com
SMTP_TLS=none

SLACK_WEBHOOK_CITRIX / VMWARE / AWS / WINTEL
NOTIFY_EMAIL_CITRIX=citrix-team@zinnia.com
NOTIFY_EMAIL_VMWARE=vmware-team@zinnia.com
NOTIFY_EMAIL_AWS=aws-team@zinnia.com
NOTIFY_EMAIL_WINTEL=wintel-team@zinnia.com

JIRA_HELPDESK_PROJECT=ITSD
JIRA_PROJECT_PROJECT=ITO
JIRA_TASI_PROJECT=TASI
```

---

## Jira Projects

| Key | Name | Type | Purpose |
|-----|------|------|---------|
| **ITSD** | IT Service Desk | service_desk | Reactive incidents — something is broken now |
| **ITO** | IT Operations | software | Projects — Epics + Tasks for multi-sprint systemic work |
| **TASI** | TAS Infrastructure | software | Planned infrastructure changes with CAB approval workflow |

> TAS (application changes) and TASSD are not used by infrastructure teams — ignore them.

### TASI Required Fields (smart change ticket creation)
`summary`, `description`, `reporter`, `customfield_15736` (TAS Type: TAS/rTAS/eTAS),
`customfield_15381` (Risk/Impact: High/Moderate/Low), `customfield_15243` (System(s)),
`customfield_15215` (Client/s), `customfield_15855` (Infrastructure Resource Group),
`customfield_15811` (System Environment: Production/QA/Development/Other),
`customfield_15792` (Hardware/Server/Database/Schema Name), `customfield_15812` (Rollback Plan),
`customfield_15769` (TAS Start Time), `customfield_15770` (TAS End Time),
`customfield_15790` (FTEV Start Date/Time), `customfield_15791` (FTEV End Date/Time),
`customfield_15817` (TAS Already Deployed?: Yes/No)

### Infrastructure Resource Group → Portal Domain Mapping
| TASI Resource Group | Portal Router |
|---|---|
| VMWare | routers/vmware.py |
| Citrix | routers/citrix.py |
| Active Directory | routers/active_directory.py |
| Network | routers/meraki.py |
| Windows / Workstations | routers/lansweeper.py |
| Monitoring | routers/opmanager.py |
| Security | routers/ca_analysis.py |

### ITSD Smart Incident Key Fields
`customfield_15955` (AI Rationale), `customfield_15833` (Severity: Sev-1→Sev-5),
`customfield_15828` (Urgency), `customfield_15829` (Impact),
`customfield_15845` (Source — use "Monitoring systems"),
`customfield_16047` (Server Name), `customfield_15243` (System(s)),
`customfield_16054` (Product categorization), `customfield_16055` (Operational categorization),
`customfield_11600` (Team), `customfield_15997` (Workgroup)

### ITO Epic Key Fields
`customfield_16256` (Objective), `customfield_15786` (ITO Lead),
`customfield_16267` (T-Shirt Size: XS/S/M/L/XL/XXL),
`customfield_16981` (IODM Selected Services: Infrastructure/Networking/Cloud-AWS/etc.),
`customfield_18070` (RACI Accountable), `customfield_18071` (RACI Consulted),
`customfield_18072` (RACI Informed), `customfield_16456` (Latest Update),
`customfield_15204` (Start date), `duedate` (Due date)

---

## Deployment Checklist (Next Push to Server)

1. Copy changed files to `C:\InfraPortal\`
2. Confirm `routers\main.py` does **NOT** exist
3. Recycle app pool: `%windir%\system32\inetsrv\appcmd recycle apppool /apppool.name:"ITOpsTools"`
4. Log in as admin → verify affected pages load
5. Confirm dev and server `.env` have the same (rotated 2026-05-21) client secret

---

## What's Done vs. Still To Do

### Immediate / Carry Forward
- [ ] Fix Bug #43 — Add port 902 to NSX rule for `10.7.224.4`
- [x] Rotate Azure client secret — done 2026-05-21

### AI / Analysis
- [ ] Wire `alerts_ai_analysis`, `vmware_ai_analysis`, `citrix_ai_analysis` into `analyze_infrastructure()` as pre-digested inputs
- [ ] AI Lens for AD, Assets, Certificates, Network pages
- [ ] Asset modal — on-demand AI diagnosis per device
- [ ] Floating AI chat widget (site-wide, lower-right) — spec in Day 16 handoff
- [ ] Jira: create ticket from AI analysis action items
- [ ] Jira: ticket status badges on Analysis page
- [ ] Jira: team selection in create modal (DB-stored pairs)
- [ ] Jira: ITO Epics & Tasks scaffold from AI deep dive

### Integrations
- [ ] vROps integration
- [ ] Entra / O365 / Exchange (mailbox health, MFA status)
- [ ] Veeam backup health
- [ ] AWS EC2 via boto3
- [ ] Checkpoint firewalls
- [ ] Proofpoint
- [ ] Slack — general outbound notifications (datastore warnings, critical alerts)
- [ ] Alert grouping by application stack

### UI
- [ ] Full CSS variable pass across remaining templates (vmware, alerts, AD, assets, certs, network, analysis, dashboard)
- [ ] UI overhaul plan from Day 16 — stat strips, tab consolidation, unified badge palette, section accordions
- [ ] My Dashboard — save AI queries, pin metrics, custom widgets
- [ ] Reports page + custom report builder
- [ ] Scheduled email reports
- [ ] Grade history over time

### Security / Infra
- [ ] `.env` protection — Windows Env Vars or Azure Key Vault
- [ ] Logging — better structured error visibility

---

## Data Flow

```
Browser → IIS → run.py → uvicorn → main.py → routers/*.py → cache.py → external API / SQLite
                                            ↘ templates/*.html (Jinja2)
                                            ↘ analysis.py → Anthropic API
```

- **Scheduler** warms cache in background threads on configured intervals
- **SSE Streaming** for long VMware fetches — `EventSource` consuming `data: {...}\n\n`
- **Fire-and-forget** for AI analysis + VDI report — polls `/api/*/status`
