import requests

API_KEY = "2fd4bd0ee5133510ad0b06af382b330fc5a9178b"

resp = requests.get(
    "https://api.meraki.com/api/v1/organizations",
    headers={"X-Cisco-Meraki-API-Key": API_KEY},
    verify=False
)
print(resp.status_code)
print(resp.json())

import requests

API_KEY = "2fd4bd0ee5133510ad0b06af382b330fc5a9178b"
ORGS = {
    "SE2": "634524",
    "Policygenius": "624874448297656685"
}

for org_name, org_id in ORGS.items():
    print(f"\n=== {org_name} ===")
    resp = requests.get(
        f"https://api.meraki.com/api/v1/organizations/{org_id}/networks",
        headers={"X-Cisco-Meraki-API-Key": API_KEY},
        verify=False
    )
    networks = resp.json()
    for n in networks:
        print(f"  {n['id']} | {n['name']} | {n['productTypes']}")


from dotenv import load_dotenv
import os

load_dotenv()
key = os.getenv("MERAKI_API_KEY", "")
print(f"Key loaded: '{key[:6]}...' ({len(key)} chars)" if key else "ERROR: Key is empty!")