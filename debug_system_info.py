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

# Test Hosts: Windows and Linux
target_hosts = ["PACIFICA-DB", "Zabbix Server"]

print("\n--- Searching for System Info Keys ---")

for host_name in target_hosts:
    print(f"\nHost: {host_name}")
    hosts = request("host.get", {"output": ["hostid", "name"], "search": {"name": host_name}}, auth)
    if not hosts:
        print("  Host not found")
        continue
        
    host_id = hosts[0]['hostid']
    
    # Search for relevant keys
    search_keys = ["system.sw.os", "system.uname", "system.hw.serial", "system.cpu", "vm.version", "kernel"]
    
    items = request("item.get", {
        "output": ["key_", "name", "lastvalue"],
        "hostids": host_id,
        "search": {"key_": search_keys},
        "searchByAny": True
    }, auth)
    
    if items:
        for i in items:
            # Filter for relevant info
            k = i['key_']
            if any(x in k for x in ['os', 'uname', 'serial', 'model', 'version']):
                print(f"  [{k}] {i['name']}: {i['lastvalue'][:100] if i['lastvalue'] else 'None'}")
    else:
        print("  No system items found")
