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
host_name = "PACIFICA-DB"
hosts = request("host.get", {"output": ["hostid", "name"], "search": {"name": host_name}}, auth)
host_id = hosts[0]['hostid']

print(f"Host: {host_name} ({host_id})")

# Search for the specific keys from the screenshot
target_keys = ["Disk Reads/sec", "Disk Writes/sec"]

print("\n--- Verifying Specific Keys ---")
for k in target_keys:
    print(f"Searching for key substring: {k}")
    items = request("item.get", {
        "output": ["itemid", "key_", "name", "lastvalue"],
        "hostids": host_id,
        "search": {"key_": k},
        "limit": 5
    }, auth)
    
    if items:
        for i in items:
            print(f"  FOUND: {i['key_']} | Last: {i['lastvalue']}")
    else:
        print("  NOT FOUND")
