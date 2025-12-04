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

print(f"\n--- Debugging Unifi AP: {target_host} ---")

hosts = request("host.get", {"output": ["hostid", "name"], "search": {"name": target_host}}, auth)
if not hosts:
    print("Host not found")
    exit()

host_id = hosts[0]['hostid']

# Keys from screenshot + generic memory search
keys_to_check = [
    "cpuLoad.0",
    "laLoad.1",
    "unifiIfRxBytes.1",
    "unifiIfTxBytes.1",
    "sysDesc.0",
    "unifiApSystemVersion.0",
    "mem", # Wildcard search for memory
    "free" # Wildcard search for free memory
]

print(f"Host ID: {host_id}")

# 1. Check specific keys
print("\nChecking specific keys...")
items = request("item.get", {
    "output": ["key_", "name", "lastvalue", "units"],
    "hostids": host_id,
    "search": {"key_": keys_to_check},
    "searchByAny": True
}, auth)

if items:
    for i in items:
        print(f"  [{i['key_']}] {i['name']}: {i['lastvalue']} ({i['units']})")
else:
    print("  No items found matching keys.")

# 2. Search for all items to find memory if missed
print("\nListing all items (first 50)...")
all_items = request("item.get", {
    "output": ["key_", "name", "lastvalue"],
    "hostids": host_id,
    "limit": 50
}, auth)

for i in all_items:
    # Print only if not already printed or looks interesting
    if "mem" in i['key_'].lower() or "cpu" in i['key_'].lower() or "load" in i['key_'].lower():
         print(f"  [ALL] [{i['key_']}] {i['name']}: {i['lastvalue']}")
