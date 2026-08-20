import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TOKEN   = "lsp_eyJwYXQiOiJrWkJVL1VlS0FlUW5VTzNsa0VtTCIsInNpdGVfcmVnaW9uIjp7ImIwMzViZGExLTc0NmMtNGZiOS04NTU1LWFmMjQ4MDg2YTQ2YiI6ImV1In1900830894519"
SITE_ID = "b035bda1-746c-4fb9-8555-af248086a46b"
GRAPHQL_URL = "https://api.lansweeper.com/api/v2/graphql"

def gql(query, variables=None):
    body = {"query": query}
    if variables:
        body["variables"] = variables
    resp = requests.post(
        GRAPHQL_URL,
        headers={"Authorization": f"Token {TOKEN}", "Content-Type": "application/json"},
        json=body, timeout=15, verify=False
    )
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"raw": resp.text[:300]}

def type_name(t):
    if not t: return "?"
    return t.get("name") or type_name(t.get("ofType"))

def introspect(type_name_str):
    _, data = gql(f"""
    query {{
      __type(name: "{type_name_str}") {{
        kind
        inputFields {{ name type {{ name kind ofType {{ name kind ofType {{ name kind }} }} }} }}
        fields      {{ name type {{ name kind ofType {{ name kind ofType {{ name kind }} }} }} }}
        enumValues  {{ name }}
      }}
    }}
    """)
    return (data.get("data") or {}).get("__type") or {}

if __name__ == "__main__":
    print("=" * 60)

    # 1 — Find exact arg types on assetResources via Site type
    print("\n[1] Site.assetResources arguments:")
    _, data = gql("""
    query {
      __type(name: "Site") {
        fields {
          name
          args {
            name
            type { name kind ofType { name kind ofType { name kind } } }
          }
        }
      }
    }
    """)
    fields = ((data.get("data") or {}).get("__type") or {}).get("fields") or []
    for f in fields:
        if f["name"] == "assetResources":
            print(f"  Field: assetResources")
            for arg in (f.get("args") or []):
                print(f"     arg: {arg['name']} → {type_name(arg['type'])}")

    # 2 — Introspect each arg type we found
    print("\n[2] Introspecting pagination-related types:")
    for type_str in ["AssetsPage", "Pagination", "AssetsPagination",
                     "AssetsPaginationInput", "PaginationInput",
                     "AssetsResourcePagination", "ResourcePagination"]:
        t = introspect(type_str)
        if t:
            kind = t.get("kind")
            if kind == "ENUM":
                vals = [e["name"] for e in (t.get("enumValues") or [])]
                print(f"     {type_str} (ENUM): {vals}")
            elif kind == "INPUT_OBJECT":
                fields = t.get("inputFields") or []
                print(f"     {type_str} (INPUT): {[f['name'] for f in fields]}")
                for f in fields:
                    print(f"       - {f['name']} : {type_name(f['type'])}")
            elif kind == "OBJECT":
                fields = t.get("fields") or []
                print(f"     {type_str} (OBJECT): {[f['name'] for f in fields]}")

    # 3 — Try the working query from our test session to confirm token still works
    print("\n[3] Sanity check — 2 assets no pagination object:")
    _, data = gql("""
    query($id: ID!) {
      site(id: $id) {
        assetResources(
          fields: ["assetBasicInfo.name", "assetBasicInfo.ipAddress"]
          pagination: { limit: 2, page: FIRST }
        ) {
          total
          items
        }
      }
    }
    """, {"id": SITE_ID})
    ar = ((data.get("data") or {}).get("site") or {}).get("assetResources") or {}
    print(f"     [{_[0] if False else 200}] total={ar.get('total')} items={len(ar.get('items') or [])}")
    print(f"     raw pagination block: {json.dumps(data.get('data'))[:300]}")

    print("\n" + "=" * 60)