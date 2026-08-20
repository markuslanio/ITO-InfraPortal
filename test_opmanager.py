import requests
import os
import urllib3
import json
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

host = os.getenv("OPMANAGER_HOST")
port = os.getenv("OPMANAGER_PORT")
api_key = os.getenv("OPMANAGER_API_KEY")

base_url = "https://" + host + ":" + port + "/api/json"

def get(endpoint):
    r = requests.get(base_url + endpoint + "?apiKey=" + api_key, verify=False, timeout=10)
    print("---")
    print("ENDPOINT:", endpoint)
    print("STATUS:", r.status_code)
    try:
        data = r.json()
        print("RESPONSE:", json.dumps(data, indent=2)[:600])
    except:
        print("RESPONSE:", r.text[:300])

get("/alarm/listAlarms?apiKey=" + api_key + "&severity=1")
get("/alarm/listAlarms?apiKey=" + api_key + "&severity=2")
get("/alarm/listAlarms?apiKey=" + api_key + "&status=1")
get("/device/listDevices?apiKey=" + api_key + "&status=2")
get("/device/getAlarmsForDevice")
