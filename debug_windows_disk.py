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

# Target Windows Host
host_name = "PACIFICA-DB"
hosts = request("host.get", {"output": ["hostid", "name"], "search": {"name": host_name}}, auth)
if not hosts:
    print(f"Host {host_name} not found")
    exit()

host_id = hosts[0]['hostid']
print(f"Host: {host_name} ({host_id})")

# Simulate backend logic
target_keys_read = ['Disk Read Bytes/sec', 'vfs.dev.read.rate', 'vmware.vm.disk.read']

print("\n--- Simulating Backend Search Logic ---")
for key_pattern in target_keys_read:
    search_params = {"key_": key_pattern}
    if "Bytes/sec" in key_pattern:
        search_params = {"name": key_pattern}
    
    print(f"Searching for: {key_pattern} (Params: {search_params})")
    
    items = request("item.get", {
        "output": ["itemid", "key_", "value_type", "lastvalue", "name"],
        "hostids": host_id,
        "search": search_params,
        "limit": 20
    }, auth)
    
    if items:
        print(f"  Found {len(items)} items.")
        for i in items:
            print(f"    ID: {i['itemid']} | Key: {i['key_']} | Name: {i['name']} | Type: {i['value_type']} | Last: {i['lastvalue']}")
            
            # Try fetching history for the first one
            hist_type = 0 if int(i['value_type']) == 0 else 3
            history = request("history.get", {
                "output": "extend",
                "history": hist_type,
                "itemids": i['itemid'],
                "sortfield": "clock",
                "sortorder": "DESC",
                "limit": 5
            }, auth)
            print(f"    History Count: {len(history) if history else 0}")
            if history:
                print(f"      Latest: {history[0]['value']} @ {history[0]['clock']}")
    else:
        print("  No items found.")
