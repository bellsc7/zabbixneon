import os
import requests
import json

ZABBIX_URL = "http://192.168.1.25/zabbix/api_jsonrpc.php"
ZABBIX_USER = "Admin"
ZABBIX_PASS = "zabbix"

def request(method, params, auth=None):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
        "auth": auth
    }
    try:
        resp = requests.post(ZABBIX_URL, json=payload)
        return resp.json().get("result")
    except Exception as e:
        print(f"Error: {e}")
        return None

auth = request("user.login", {"username": ZABBIX_USER, "password": ZABBIX_PASS})

target_host = "AP04-IT"

print(f"\n--- Debugging Status for: {target_host} ---")

# Get Host Availability Fields
hosts = request("host.get", {
    "output": ["hostid", "name", "available", "snmp_available", "jmx_available", "ipmi_available", "error", "snmp_error"], 
    "search": {"name": target_host}
}, auth)

if not hosts:
    print("Host not found")
    exit()

h = hosts[0]
print("Host Data:")
print(f"  available (Agent): {h.get('available')}")
print(f"  snmp_available: {h.get('snmp_available')}")
print(f"  jmx_available: {h.get('jmx_available')}")
print(f"  ipmi_available: {h.get('ipmi_available')}")
print(f"  error: {h.get('error')}")
print(f"  snmp_error: {h.get('snmp_error')}")

host_id = h['hostid']

# Check for Ping Items
print("\nChecking Ping Items:")
items = request("item.get", {
    "output": ["key_", "name", "lastvalue", "units"],
    "hostids": host_id,
    "search": {"key_": ["icmpping", "icmppingsec", "agent.ping"]},
    "searchByAny": True
}, auth)

if items:
    for i in items:
        print(f"  [{i['key_']}] {i['name']}: {i['lastvalue']}")
else:
    print("  No ping items found.")
