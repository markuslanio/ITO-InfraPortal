# Zinnia Infrastructure Portal — CLAUDE.md
> Context for Claude Code. Last synced: 2026-08-28, after the sidebar/IA redesign (branch `ui-redesign`, not yet merged to `main`).

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

1. **`main.py` location** — lives in project root ONLY. `routers\main.py` must NOT exist — it intercepts imports and silences new routes. When uploading for editing, always use the server copy (`C:\InfraPortal\main.py`). (`routers/main.py.bak-stale` is the already-neutralized old copy — inert, harmless, ignore it.)

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

11. **Adding a sidebar nav item** touches three places, not one: the `<a>` in `base.html` (with its `active_page == '...'` highlight check and, if it should be gated, a `user_groups` condition), the route's `_ctx(request, user, "...")` call in `main.py` (the active_page string must match what the nav checks for — a prior mismatch here silently broke highlighting on the App Cloner page), and if it's config rather than something to consume, it belongs in Admin regardless of how related it looks to a nearby feature (see Navigation Structure below).

---

## Project Structure

```
C:\Users\lanio\Coding\VMWare Project\
├── main.py                  # FastAPI app entry point — all routes registered here
├── run.py                   # IIS/uvicorn launcher — never modify carelessly
├── .env                     # Secrets — never commit
├── requirements.txt
├── routers/
│   ├── auth.py                # Azure AD SSO + RBAC
│   ├── analysis.py            # Claude AI infrastructure analysis — feeds the Dashboard's AI Analysis section
│   ├── findings.py            # Portal-wide findings engine (pre-failure/actionable conditions), feeds Dashboard
│   ├── vmware.py               # vCenter REST API (3 environments)
│   ├── vmware_deep.py          # pyVmomi legacy (retained)
│   ├── citrix.py                # Citrix Cloud API — machines, sessions, delivery groups, catalogs, logoff
│   ├── citrix_apps.py           # Citrix App Manager (4-step clone wizard)
│   ├── vdi_cost.py              # VDI Cost Estimation Report
│   ├── criticality.py           # NOC Page Config backend — device criticality, groups, dependencies, AI-assist
│   ├── settings.py              # .env editor + IIS app pool recycle (was config.py — renamed)
│   ├── notifications.py         # Citrix Power Unknown alerts (Slack + email)
│   ├── opmanager.py             # ManageEngine OpManager
│   ├── alert_reports.py         # Alert hygiene reports — stale/noisy OpManager alarms
│   ├── active_directory.py      # AD via ldap3
│   ├── entra.py                 # Microsoft Entra ID / M365 via Graph API
│   ├── ca_analysis.py           # Certificate Authority data collection — page removed, jobs/data still live
│   ├── jira.py                  # Jira Cloud
│   ├── jira_intelligence.py     # Cross-project Jira trend analysis (ITSD/TASI/ITO)
│   ├── soc_report.py            # SOC audit report generator (TASI compliance)
│   ├── share_audit.py           # SMB share/permission audit for AD-joined servers
│   ├── lansweeper.py            # Lansweeper SQL via pyodbc → TOPINFRADB01P
│   ├── meraki.py                # Cisco Meraki Dashboard API
│   ├── scheduler.py             # APScheduler — 25 background jobs
│   ├── cache.py                 # In-memory cache with timestamps
│   └── database.py              # SQLite WAL mode, 30s timeout
├── templates/
│   ├── base.html               # Collapsible sidebar (NOC/Infra/Directory/Utils/Admin), theming, floating AI chat
│   ├── dashboard.html          # Root page — live system-health tiles + merged AI Analysis section
│   ├── vmware.html             # VMs/Hosts/Untagged/Disk/Datastores/Snapshots/AI tabs
│   ├── alerts.html             # OpManager alerts + Jira badges + AI Insights tab (the NOC "Alerts" page)
│   ├── noc.html                 # NOC wallboard — world map, TV mode, root-cause callouts (the "Wallboard" page)
│   ├── citrix.html               # Citrix Cloud + Needs Attention triage panel
│   ├── citrix_app_manager.html   # App Cloner (Utils)
│   ├── vdi_cost.html             # 5 tabs: All/By Manager/By Dept/Cost/Cleanup (Utils)
│   ├── active_directory.html
│   ├── entra.html                 # Entra / M365 (Directory)
│   ├── assets.html                # Lansweeper assets + Mark Unimportant (Infra)
│   ├── network.html               # Meraki (Infra)
│   ├── jira_intelligence.html     # Jira Intel (Utils)
│   ├── soc_reports.html           # SOC Reports (Utils)
│   ├── my_dashboard.html          # Personal drag-and-drop widget dashboard, per-user saved layout (Utils)
│   ├── settings.html              # Admin: Scheduler / Jira Teams / Environment tabs, flat Admin nav items
│   ├── _criticality_content.html  # Included by settings.html — NOC Page Config (OPM Groups/Dependencies/
│   │                               # Locations/Device Groups first; Registry/Inventory deprioritized after)
│   ├── unauthorized.html          # Auth error page
│   └── (orphaned, not referenced by any route — candidates for deletion, left alone pending confirmation)
│       criticality.html, jira_config.html, scheduler.html, login.html
└── static/
    ├── tableutils.js        # SmartTable: sortable/filterable/exportable
    ├── tableutils.css
    └── favicon.svg          # Three Zinnia petals (red/orange/yellow) on black
```

**Removed in the UI redesign:** `templates/certificates.html` and `templates/analysis.html` are gone. `/certificates` and `/analysis` (and their `/infraportal/...` equivalents) now redirect to `/infraportal/` so old bookmarks don't 404. Certificate Authority data collection itself (`ca_analysis.py`, the `job_cert_*` scheduler jobs, the `findings.py` Certs finding generator) was deliberately left running — only the dedicated page and its nav/dashboard surfaces were retired.

---

## Navigation Structure (sidebar, `templates/base.html`)

Replaced the old horizontal top navbar. Consumption (what NOC/helpdesk/engineers look at) and configuration (Admin) are deliberately kept apart — see the design principle below.

| Group | Contents | Notes |
|---|---|---|
| *(top, ungrouped)* | Dashboard | Root page (`/`) — live system-health tiles + AI Analysis section. Also reachable via the logo. |
| **NOC** | Alerts, Wallboard | Alerts = OpManager/Jira triage list (`alerts.html`). Wallboard = the big-screen map/TV-mode display (`noc.html`), renamed here to stop colliding with "Alerts" on the meaning of "NOC." |
| **Infra** | VMware, Citrix, Network, Assets | Group-gated per item (`GROUP_VMWARE`/`GROUP_CITRIX`/`GROUP_NETWORK` or admin). Assets has no group gate today. |
| **Directory** | Active Directory, Entra / M365 | |
| **Utils** | Jira Intel, SOC Reports, Citrix App Cloner (admin-gated), VDI Cost Report, My Dashboard | Occasional-use tools and personal space — not daily NOC operations, not portal configuration. |
| **Admin** (whole group gated to `GROUP_ADMIN`) | Scheduler, Jira Teams, NOC Page Config, Environment | Flat menu items, each deep-linking into `settings.html` via a `#fragment` (`#scheduler`, `#jira`, `#criticality`, `#env`) rather than separate pages — `stSwitchTab()` in settings.html reads `location.hash` on load. |

**Design principle established this pass:** anything a NOC/helpdesk/engineering user *consumes* lives in NOC/Infra/Directory/Utils; anything that *configures how the portal behaves* lives in Admin, regardless of how closely related it looks. NOC Page Config (dependency mapping, device tiering) is a good example — it drives the NOC Wallboard/Alerts pages but lives in Admin because the NOC team doesn't edit it directly.

**Two independent collapse mechanisms**, both in `base.html`'s inline script:
- Per-section collapse (NOC/Infra/Directory/Utils/Admin headers) — starts collapsed each login, remembered via `sessionStorage` (`navgroup_<name>`) for the rest of that browser session only. Toggle: `v2ToggleGroup()`.
- Whole-sidebar icon-rail collapse — persists indefinitely via `localStorage` (`infraportal-sidebar-collapsed`), same pattern as the existing theme toggle. Toggle: `v2ToggleSidebar()`.

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
| `scheduler_config` | Per-job interval/enabled overrides from Admin → Scheduler |
| `user_widgets` | My Dashboard per-user saved widget layout |
| `asset_criticality` | NOC Page Config → Registry — per-device tier/team/blast-radius/escalation records |
| `criticality_groups` | NOC Page Config → Device Groups — pattern/membership definitions (not the same rows as `asset_criticality`) |
| `device_group_members` | NOC Page Config → Device Groups — explicit (non-pattern-matched) group membership |
| `lookup_lists` | Admin-editable dropdown values — today just `owner_teams`, managed via the "Manage Owner Teams" modal on Device Groups |
| `portal_findings` | Cross-system findings written by `findings.py`, feeds Dashboard tiles/drawer |

*(This table isn't necessarily exhaustive of every table in `database.py` — it covers what's directly relevant to features touched or discovered during the UI redesign.)*

---

## Scheduler Jobs (25 total)

Intervals configurable at runtime via the Admin → Scheduler menu item (`/infraportal/settings#scheduler`) — no restart needed.

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
| `job_ai_analysis` | 24 hr | Scheduled AI analysis (feeds Dashboard's AI Analysis section) |
| `job_jira_intelligence` | — | Jira cross-project trend analysis (Jira Intel page) |
| `job_findings` | 15 min | Portal findings engine — writes `portal_findings`, feeds Dashboard tiles |
| `job_entra_refresh` | — | Entra ID / M365 data via Graph API |

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
| `--bg2` | `#16213e` | `#ffffff` | Cards, panels, sidebar, tab bars |
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

## Git Workflow

Repo is on GitHub (`markuslanio/ITO-InfraPortal`), `main` tracks `origin/main`. For any change of meaningful size (more than a one-line fix): work on a feature branch, not directly on `main` — `main` should stay in a known-good, deployable state at all times, since deployment is a manual file copy rather than a git pull on the server (see Deployment Checklist above), so there's no automatic way to "roll back production" from a git revert alone.

- `git checkout -b <branch-name>` before starting.
- Commit at each logical milestone with a clear message — not one giant commit — so a specific problem can be found/reverted without touching everything else.
- Push the branch to `origin` early and often; it's the off-machine backup, not just a final step.
- Before merging a branch that will be deployed, tag current `main` first (`git tag pre-<change-name>`) so there's a named fallback point to re-copy from if the new code has a problem in production after go-live.
- Merge to `main` (locally or via a PR — a PR is worth it even solo for a large change, since it gives a single clean before/after diff) only once the branch has been tested on the dev server.
- `__pycache__/` and `*.pyc` are gitignored — don't re-add compiled bytecode to tracking.

The UI/IA redesign (sidebar nav, Dashboard/Analysis merge, Citrix triage panel, NOC Page Config consolidation, Certificates removal, My Dashboard relocation) happened entirely on `ui-redesign`, one commit per milestone — see its commit history for the reasoning behind each change in more detail than this file carries.

---

## What's Done vs. Still To Do

### Immediate / Carry Forward
- [ ] Merge `ui-redesign` branch to `main` and deploy (see Git Workflow above) — details of what's on the branch are in the UI section below and the Navigation Structure section above
- [ ] Fix Bug #43 — Add port 902 to NSX rule for `10.7.224.4`
- [x] Rotate Azure client secret — done 2026-05-21

### AI / Analysis
- [ ] Wire `alerts_ai_analysis`, `vmware_ai_analysis`, `citrix_ai_analysis` into `analyze_infrastructure()` as pre-digested inputs
- [ ] AI Lens for AD, Assets, Network pages
- [ ] Asset modal — on-demand AI diagnosis per device
- [x] Floating AI chat widget (site-wide, lower-right) — done, `base.html`
- [x] AI Analysis merged into the Dashboard (was a standalone `/analysis` page) — grade cards, deep-dive modal, Immediate Actions/Warnings/Alert Analysis/Trends/Recommendations as accordions. Certificates grade dropped.
- [ ] Jira: create ticket from AI analysis action items
- [ ] Jira: ticket status badges on Jira Intel page
- [ ] Jira: team selection in create modal (DB-stored pairs)
- [ ] Jira: ITO Epics & Tasks scaffold from AI deep dive

### Integrations
- [ ] vROps integration
- [x] Entra / O365 (licenses, users, groups, mailbox usage, risky users, Conditional Access) — `routers/entra.py`, `entra.html`, still no Exchange mailbox *health* specifically
- [ ] Veeam backup health
- [ ] AWS EC2 via boto3
- [ ] Checkpoint firewalls
- [ ] Proofpoint
- [ ] Slack — general outbound notifications (datastore warnings, critical alerts) — Citrix Power Unknown already does Slack+email via `notifications.py`
- [ ] Alert grouping by application stack

### UI
- [ ] Full CSS variable pass across remaining templates
- [x] Sidebar/IA redesign (this file's Navigation Structure section) — collapsible sections, NOC/Infra/Directory/Utils/Admin grouping, consumption vs. configuration separation
- [x] Citrix Needs Attention panel — surfaces unregistered/maintenance/faulted/unexpectedly-off machines without digging into tabs; session logoff already existed and works
- [x] NOC Page Config consolidation — Lookup Lists folded in, Device Groups reordered ahead of Registry/Inventory, "+ Register on an already-registered device" data-loss bug fixed
- [ ] Citrix write actions (Power On, Exit Maintenance) — deliberately deferred; would need new Citrix Cloud API calls against production VDI/XenApp infra, revisit as its own scoped piece of work
- [ ] My Dashboard — it's *not* a stub (see Project Structure) — already supports save/pin/arrange of ~10 live widgets with per-user layout; remaining gap is "save AI queries" specifically
- [ ] Reports page + custom report builder
- [ ] Scheduled email reports
- [ ] Grade history over time
- [ ] Delete or repurpose orphaned templates: `criticality.html`, `jira_config.html`, `scheduler.html`, `login.html` (unreferenced by any route — found during the redesign, left in place pending a decision)

### Security / Infra
- [ ] `.env` protection — Windows Env Vars or Azure Key Vault
- [ ] Logging — better structured error visibility

---

## Data Flow

```
Browser → IIS → run.py → uvicorn → main.py → routers/*.py → cache.py → external API / SQLite
                                            ↘ templates/*.html (Jinja2)
                                            ↘ analysis.py → Anthropic API (rendered in Dashboard's AI Analysis section)
```

- **Scheduler** warms cache in background threads on configured intervals
- **SSE Streaming** for long VMware fetches — `EventSource` consuming `data: {...}\n\n`
- **Fire-and-forget** for AI analysis + VDI report — polls `/api/*/status`
