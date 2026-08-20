import os
from dotenv import load_dotenv
load_dotenv()

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

DC_HOST  = os.getenv("AD_HOST")
USERNAME = os.getenv("AD_DOMAIN") + "\\" + os.getenv("AD_USER")
PASSWORD = os.getenv("AD_PASSWORD")
BASE_DN  = os.getenv("AD_BASE_DN")

print("BASE_DN:", BASE_DN)

server = Server(DC_HOST, get_info=ALL)
conn = Connection(server, user=USERNAME, password=PASSWORD, authentication=NTLM, auto_bind=True)

for group_cn in ["Domain Admins", "Enterprise Admins"]:
    print(f"\n--- Searching for: {group_cn} ---")
    conn.search(BASE_DN, f'(&(objectClass=group)(cn={group_cn}))',
                attributes=['member', 'distinguishedName'],
                search_scope=SUBTREE, size_limit=0)
    print(f"Entries found: {len(conn.entries)}")
    for e in conn.entries:
        print(f"  DN: {e.distinguishedName}")
        members = e.member.values if e.member else []
        print(f"  Members: {len(members)}")
        for m in members[:3]:
            print(f"    - {m}")

conn.unbind()