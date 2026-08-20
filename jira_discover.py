"""
jira_discover.py — One-shot Jira project schema discovery.

Run from the project root (venv activated):
    python jira_discover.py

Writes jira_schema.json to the project root.
Safe — read-only, no writes to Jira.
"""

import json
import os
import sys
import requests
from requests.auth import HTTPBasicAuth

# ── Load .env manually (avoid requiring python-dotenv to be installed) ────────
def _load_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_env()

BASE_URL = os.getenv("JIRA_BASE_URL", "").rstrip("/")
EMAIL    = os.getenv("JIRA_EMAIL", "")
TOKEN    = os.getenv("JIRA_API_TOKEN", "")
VERIFY   = False   # Corporate SSL proxy

if not all([BASE_URL, EMAIL, TOKEN]):
    sys.exit("ERROR: JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN must be set in .env")

AUTH    = HTTPBasicAuth(EMAIL, TOKEN)
HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

TARGET_PROJECTS = ["ITSD", "ITO", "TASI"]   # adjust if TASi key differs


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def get(path, params=None):
    r = requests.get(f"{BASE_URL}/rest/api/3{path}",
                     auth=AUTH, headers=HEADERS, params=params,
                     timeout=15, verify=VERIFY)
    if not r.ok:
        return {"_error": r.status_code, "_body": r.text[:500]}
    return r.json()


def post(path, payload):
    r = requests.post(f"{BASE_URL}/rest/api/3{path}",
                      auth=AUTH, headers=HEADERS, json=payload,
                      timeout=15, verify=VERIFY)
    if not r.ok:
        return {"_error": r.status_code, "_body": r.text[:500]}
    return r.json()


# ── Step 1: Discover all projects — find TASi key ────────────────────────────

def discover_projects():
    print("  Fetching all projects...")
    data = get("/project/search", params={"maxResults": 100})
    if "_error" in data:
        print(f"  WARNING: project list failed: {data}")
        return []
    projects = []
    for p in data.get("values", []):
        projects.append({
            "key":        p.get("key"),
            "name":       p.get("name"),
            "type":       p.get("projectTypeKey"),
            "style":      p.get("style"),
            "id":         p.get("id"),
        })
    return projects


# ── Step 2: All fields — maps customfield_XXXXX → human name ─────────────────

def discover_all_fields():
    print("  Fetching global field list...")
    fields = get("/field")
    if isinstance(fields, dict) and "_error" in fields:
        print(f"  WARNING: field list failed: {fields}")
        return {}
    field_map = {}
    for f in fields:
        fid   = f.get("id", "")
        name  = f.get("name", "")
        schema = f.get("schema", {})
        field_map[fid] = {
            "name":      name,
            "type":      schema.get("type", ""),
            "custom":    fid.startswith("customfield_"),
            "clause":    f.get("clauseNames", []),
        }
    return field_map


# ── Step 3: Issue types + fields per project ──────────────────────────────────

def discover_project_schema(project_key):
    print(f"  Fetching issue types for {project_key}...")
    it_data = get(f"/issue/createmeta/{project_key}/issuetypes")
    if "_error" in it_data:
        return {"_error": it_data}

    issue_types = {}
    for it in it_data.get("issueTypes", []):
        it_id   = it.get("id")
        it_name = it.get("name")
        print(f"    Issue type: {it_name} ({it_id})")

        fields_data = get(
            f"/issue/createmeta/{project_key}/issuetypes/{it_id}",
            params={"maxResults": 200}
        )

        fields_out = {}
        if not isinstance(fields_data, dict) or "_error" in fields_data:
            fields_out["_error"] = fields_data
        else:
            raw = fields_data.get("fields", fields_data)
            if isinstance(raw, dict):
                raw = list(raw.values())
            for f in raw:
                if not isinstance(f, dict):
                    continue
                fid  = f.get("fieldId") or f.get("key", "")
                fname = f.get("name", "")
                allowed = f.get("allowedValues", [])
                fields_out[fid] = {
                    "name":          fname,
                    "required":      f.get("required", False),
                    "schema":        f.get("schema", {}),
                    "hasAllowed":    len(allowed) > 0,
                    "allowedValues": [
                        {"id": a.get("id"), "name": a.get("name") or a.get("value")}
                        for a in allowed[:30]
                    ],
                    "autoCompleteUrl": f.get("autoCompleteUrl"),
                }

        issue_types[it_name] = {
            "id":     it_id,
            "fields": fields_out,
        }

    return issue_types


# ── Step 4: Sample tickets — 3 per project, all fields ───────────────────────

def sample_tickets(project_key, count=3):
    print(f"  Fetching {count} sample tickets from {project_key}...")
    data = post("/search/jql", {
        "jql":        f"project = {project_key} ORDER BY updated DESC",
        "maxResults": count,
        "fields":     ["*all"],
    })
    if "_error" in data:
        return {"_error": data}

    samples = []
    for issue in data.get("issues", []):
        fields = issue.get("fields", {})
        # Strip null/empty fields to keep output readable
        populated = {}
        for k, v in fields.items():
            if v is None:
                continue
            if isinstance(v, list) and len(v) == 0:
                continue
            if isinstance(v, str) and v.strip() == "":
                continue
            populated[k] = v
        samples.append({
            "key":    issue["key"],
            "fields": populated,
        })
    return samples


# ── Step 5: Statuses per project ──────────────────────────────────────────────

def discover_statuses(project_key):
    print(f"  Fetching statuses for {project_key}...")
    data = get(f"/project/{project_key}/statuses")
    if "_error" in data:
        return data
    out = {}
    for it in data:
        it_name = it.get("name", "unknown")
        out[it_name] = [
            {"id": s.get("id"), "name": s.get("name"), "category": s.get("statusCategory", {}).get("name")}
            for s in it.get("statuses", [])
        ]
    return out


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=== Jira Discovery ===\n")
    result = {}

    print("[1/5] Listing all projects...")
    result["all_projects"] = discover_projects()
    found_keys = {p["key"] for p in result["all_projects"]}
    print(f"      Found {len(result['all_projects'])} projects. Keys: {sorted(found_keys)}\n")

    # Warn if TASi key is different
    for key in TARGET_PROJECTS:
        if key not in found_keys:
            print(f"  WARNING: '{key}' not found in project list. Check exact key above.\n")

    print("[2/5] Mapping all field IDs to names...")
    result["field_map"] = discover_all_fields()
    custom_count = sum(1 for v in result["field_map"].values() if v["custom"])
    print(f"      {len(result['field_map'])} total fields ({custom_count} custom)\n")

    result["projects"] = {}
    for key in TARGET_PROJECTS:
        if key not in found_keys:
            print(f"  SKIPPING {key} — not found\n")
            continue

        print(f"[3-5/{len(TARGET_PROJECTS)}] Inspecting project: {key}")
        result["projects"][key] = {}

        print(f"  Issue types + fields...")
        result["projects"][key]["schema"] = discover_project_schema(key)

        print(f"  Statuses...")
        result["projects"][key]["statuses"] = discover_statuses(key)

        print(f"  Sample tickets (3 most recent)...")
        result["projects"][key]["samples"] = sample_tickets(key, count=3)
        print()

    # Enrich sample ticket fields with human names
    print("[+] Annotating sample ticket fields with human-readable names...")
    fm = result["field_map"]
    for key, proj in result["projects"].items():
        for sample in proj.get("samples", []):
            if "_error" in sample:
                continue
            annotated = {}
            for fid, fval in sample.get("fields", {}).items():
                human = fm.get(fid, {}).get("name", fid)
                annotated[f"{fid} ({human})"] = fval
            sample["fields_annotated"] = annotated

    out_path = "jira_schema.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\n=== Done. Schema written to {out_path} ===")
    print("\nQuick summary:")
    for key, proj in result["projects"].items():
        schema = proj.get("schema", {})
        if "_error" not in schema:
            print(f"  {key}: {list(schema.keys())}")
        samples = proj.get("samples", [])
        if isinstance(samples, list):
            print(f"       {len(samples)} sample ticket(s): {[s['key'] for s in samples if 'key' in s]}")
    print("\nShare jira_schema.json to map the smart-ticket field templates.")


if __name__ == "__main__":
    main()
