# Zinnia Infrastructure Portal

Internal NOC/monitoring and infrastructure dashboard for Zinnia IT Operations. Aggregates live data from VMware, Citrix, OpManager, Active Directory, Entra ID/M365, Lansweeper, Meraki, and Jira into one portal, with Claude-powered AI analysis layered on top.

> Internal tool — proprietary, not for external distribution.

## What it does

- **NOC** — live OpManager/Jira alert triage, plus a big-screen wallboard (world map + app/tech topology, TV mode) for the physical NOC display.
- **Infrastructure monitoring** — VMware (3 environments), Citrix Cloud (sessions, machines, delivery groups, a "Needs Attention" triage panel for machines that are unregistered/faulted/unexpectedly off), Meraki networks, and Lansweeper-tracked assets.
- **Directory** — Active Directory health and Entra ID / Microsoft 365 (licenses, users, groups, mailbox usage, risky users, Conditional Access).
- **AI Analysis** — an on-demand Claude-generated infrastructure review (letter grades per subsystem, executive summary, prioritized actions) built into the Dashboard, plus a site-wide floating chat for ad-hoc questions about current infrastructure state.
- **Utils** — cross-project Jira trend analysis, SOC/TASI compliance reports, a Citrix published-app clone wizard, a VDI cost estimator, and a personal drag-and-drop widget dashboard.
- **Admin** — background job scheduling (25 jobs on configurable intervals), Jira team mappings, NOC device criticality/dependency/tiering config, and a masked `.env` editor with automatic IIS app pool recycle on save.

## Stack

Python 3.13/3.14 · FastAPI · Jinja2 · SQLite (WAL mode) · APScheduler · Anthropic Claude API · ldap3 · pyVmomi · IIS + uvicorn

## Getting started (dev)

```bash
pip install -r requirements.txt
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Then open `http://localhost:8000/infraportal`. You'll need a `.env` file with Azure AD SSO credentials and the various integration endpoints/credentials configured — see `CLAUDE.md` for the full variable reference (not committed; ask an existing maintainer for a copy).

## Project layout

```
main.py           FastAPI app entry point — all routes registered here
run.py            IIS/uvicorn launcher
routers/          One module per integration (VMware, Citrix, AD, Entra, Jira, Meraki, Lansweeper, scheduler, etc.)
templates/        Jinja2 templates — collapsible sidebar shell in base.html
static/           JS/CSS shared across pages (SmartTable, favicon)
```

## Documentation

**[`CLAUDE.md`](./CLAUDE.md)** is the authoritative technical reference for this repo — dev environment setup, critical gotchas, full router/template map, SQLite schema, scheduler job list, CSS conventions, Jira field mappings, deployment checklist, and git workflow. Read it before making non-trivial changes.

## Deployment

Deployment is a manual file copy to the IIS server (`C:\InfraPortal`) followed by an app pool recycle — there's no CI/CD pipeline and no `git pull` on the server. See the Deployment Checklist in `CLAUDE.md` for the exact steps, and the Git Workflow section for how branches/tags are used to keep a safe rollback point before each production push.
