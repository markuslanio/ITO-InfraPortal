from dotenv import load_dotenv
import os, requests, json

load_dotenv()

CLIENT_ID     = os.getenv("CITRIX_CLIENT_ID")
CLIENT_SECRET = os.getenv("CITRIX_CLIENT_SECRET")
CUSTOMER_ID   = os.getenv("CITRIX_CUSTOMER_ID")

# Auth
r = requests.post(
    f"https://api.cloud.com/cctrustoauth2/{CUSTOMER_ID}/tokens/clients",
    headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
    data={"grant_type": "client_credentials", "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}
)
token = r.json()["access_token"]

session = requests.Session()
session.headers.update({
    "Authorization": f"CwsAuth Bearer={token}",
    "Citrix-CustomerId": CUSTOMER_ID,
    "Accept": "application/json"
})

SITE_ID = "4d60e6f7-1b21-4c6a-8400-c2c87c234ad2"

# Delivery group detail
try:
    r = session.get(f"https://api-us.cloud.com/cvadapis/{SITE_ID}/DeliveryGroups?limit=1")
    dgs = r.json().get("Items", [])
    dg_id = dgs[0]["Id"]
    r2 = session.get(f"https://api-us.cloud.com/cvadapis/{SITE_ID}/DeliveryGroups/{dg_id}")
    print("=== DELIVERY GROUP DETAIL ===")
    print(json.dumps(r2.json(), indent=2))
except Exception as e:
    print(f"DG detail error: {e}")

# Machine catalogs
try:
    r = session.get(f"https://api-us.cloud.com/cvadapis/{SITE_ID}/MachineCatalogs")
    print(f"\n=== MACHINE CATALOGS === status: {r.status_code}")
    print(json.dumps(r.json(), indent=2))
except Exception as e:
    print(f"Catalogs error: {e}")

# Sample machines
try:
    r = session.get(f"https://api-us.cloud.com/cvadapis/{SITE_ID}/Machines?limit=2")
    print(f"\n=== SAMPLE MACHINES === status: {r.status_code}")
    print(json.dumps(r.json(), indent=2))
except Exception as e:
    print(f"Machines error: {e}")

# Sessions
try:
    r = session.get(f"https://api-us.cloud.com/cvadapis/{SITE_ID}/Sessions?limit=2")
    print(f"\n=== SESSIONS === status: {r.status_code}")
    print(json.dumps(r.json(), indent=2))
except Exception as e:
    print(f"Sessions error: {e}")
