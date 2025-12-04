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

print(f"\n--- Debugging Unifi Extra: {target_host} ---")

hosts = request("host.get", {
    "output": ["hostid", "name"],
    "search": {"name": target_host}
}, auth)

if not hosts:
    print("Host not found")
    exit()

host_id = hosts[0]['hostid']

# 1. Search for Client Count keys (unifiVapNumStations)
print("\nChecking Client Count keys (unifiVapNumStations)...")
items = request("item.get", {
    "output": ["key_", "name", "lastvalue"],
    "hostids": host_id,
    "search": {"key_": "unifiVapNumStations"},
    "searchByAny": True
}, auth)

if items:
    total_clients = 0
    for i in items:
        print(f"  [{i['key_']}] {i['name']}: {i['lastvalue']}")
        try:
            total_clients += int(i['lastvalue'])
        except:
            pass
    print(f"  >> TOTAL CLIENTS: {total_clients}")
else:
    print("  No client count items found.")

# 2. Check Model and Channel Utilization
print("\nChecking Model and Channel Utilization...")
keys_to_check = [
    "unifiApSystemModel.0",
    "unifiRadioCuTotal.1",
    "unifiRadioCuTotal.2"
]

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
    print("  No extra items found.")
