from routers.vmware import get_session_token, ENVIRONMENTS, get_vms
import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

env = ENVIRONMENTS['topeka']
token = get_session_token(env['host'], env['user'], env['password'], env['verify_ssl'])
headers = {'vmware-api-session-id': token}

vms = get_vms('topeka')
powered_on = [v for v in vms if v.get('power_state') == 'POWERED_ON']

print("Testing first 5 powered on VMs for filesystem data:")
tested = 0
for vm in powered_on:
    if tested >= 5:
        break
    r = requests.get(
        'https://' + env['host'] + '/api/vcenter/vm/' + vm['vm'] + '/guest/local-filesystem',
        headers=headers,
        verify=False
    )
    print('---')
    print('VM:', vm['name'])
    print('STATUS:', r.status_code)
    if r.status_code == 200:
        print('RESPONSE:', json.dumps(r.json(), indent=2)[:600])
    else:
        print('RESPONSE:', r.text[:200])
    tested += 1
