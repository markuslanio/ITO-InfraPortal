from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
from ldap3.utils.conv import escape_filter_chars
import os
import datetime
from dotenv import load_dotenv

load_dotenv()

DC_HOST = os.getenv("AD_HOST")
USERNAME = os.getenv("AD_DOMAIN") + "\\" + os.getenv("AD_USER")
PASSWORD = os.getenv("AD_PASSWORD")
BASE_DN = os.getenv("AD_BASE_DN")

server = Server(DC_HOST, get_info=ALL)
conn = Connection(server, user=USERNAME, password=PASSWORD, authentication=NTLM, auto_bind=True)

def filetime_to_dt(ft):
    if not ft or ft == 0 or ft == 9223372036854775807:
        return None
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(ft) // 10)
    except:
        return None

def days_ago(dt):
    if not dt:
        return None
    return (datetime.datetime.utcnow() - dt).days

print("=== STALE USERS (no login > 90 days) ===")
ninety_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=90)
ft_90 = int((ninety_days_ago - datetime.datetime(1601, 1, 1)).total_seconds() * 10000000)
conn.search(BASE_DN,
    '(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogon<=' + str(ft_90) + '))',
    attributes=['cn', 'sAMAccountName', 'lastLogon'],
    size_limit=5)
print("Sample stale active users:", len(conn.entries))
for e in conn.entries[:3]:
    dt = filetime_to_dt(e.lastLogon.value if e.lastLogon else 0)
    print(" -", e.cn, "| Last login:", dt)

print("\n=== DISABLED USERS ===")
conn.search(BASE_DN,
    '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=2))',
    attributes=['cn', 'sAMAccountName'],
    size_limit=5)
print("Sample disabled users:", len(conn.entries))

print("\n=== PASSWORD NEVER EXPIRES ===")
conn.search(BASE_DN,
    '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
    attributes=['cn', 'sAMAccountName'],
    size_limit=5)
print("Sample password never expires:", len(conn.entries))
for e in conn.entries[:3]:
    print(" -", e.cn)

print("\n=== EMPTY GROUPS ===")
conn.search(BASE_DN,
    '(&(objectClass=group)(!(member=*)))',
    attributes=['cn', 'groupType'],
    size_limit=5)
print("Sample empty groups:", len(conn.entries))
for e in conn.entries[:3]:
    print(" -", e.cn)

print("\n=== STALE COMPUTERS (no login > 90 days) ===")
conn.search(BASE_DN,
    '(&(objectClass=computer)(lastLogon<=' + str(ft_90) + '))',
    attributes=['cn', 'lastLogon', 'operatingSystem'],
    size_limit=5)
print("Sample stale computers:", len(conn.entries))
for e in conn.entries[:3]:
    dt = filetime_to_dt(e.lastLogon.value if e.lastLogon else 0)
    print(" -", e.cn, "| Last login:", dt)

print("\n=== DOMAIN ADMINS ===")
conn.search(BASE_DN,
    '(&(objectClass=group)(cn=Domain Admins))',
    attributes=['member'])
if conn.entries:
    print("Domain Admin count:", len(conn.entries[0].member.values if conn.entries[0].member else []))

print("\n=== PASSWORD POLICY ===")
conn.search(BASE_DN,
    '(objectClass=domainDNS)',
    attributes=['minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'lockoutThreshold'])
if conn.entries:
    e = conn.entries[0]
    print("Min password length:", e.minPwdLength)
    print("Password history:", e.pwdHistoryLength)
    print("Lockout threshold:", e.lockoutThreshold)

conn.unbind()
print("\nDone!")
