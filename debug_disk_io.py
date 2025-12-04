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

# 1. Login
auth = request("user.login", {"username": ZABBIX_USER, "password": ZABBIX_PASS})

# 2. Get Host
hosts = request("host.get", {"output": ["hostid", "name"], "search": {"name": "PACIFICA-DB"}}, auth)
if not hosts:
    print("Host not found")
    exit()

host = hosts[0]
print(f"Host: {host['name']} (ID: {host['hostid']})")

# 3. Search for Disk I/O Keys
print("\n--- Searching for Disk I/O Keys ---")
keys_to_search = ["Disk Read Bytes", "Disk Write Bytes", "vfs.dev.read", "vfs.dev.write", "vmware.vm.disk.read", "vmware.vm.disk.write"]

for k in keys_to_search:
    print(f"Searching: {k}")
    items = request("item.get", {
        "output": ["itemid", "key_", "name", "lastvalue"],
        "hostids": host['hostid'],
        "search": {"key_": k},
        "limit": 5
    }, auth)
    
    if items:
        for item in items:
            print(f"  FOUND: {item['key_']} | {item['name']} | Last: {item['lastvalue']}")
    else:
        # Try searching by name if key search fails (sometimes keys are perf_counter...)
        items_by_name = request("item.get", {
            "output": ["itemid", "key_", "name", "lastvalue"],
            "hostids": host['hostid'],
            "search": {"name": k},
            "limit": 5
        }, auth)
        if items_by_name:
             for item in items_by_name:
                print(f"  FOUND (by Name): {item['key_']} | {item['name']} | Last: {item['lastvalue']}")
