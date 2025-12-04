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

# Try searching by Key with wildcard
print("\n--- Searching by Key Wildcard ---")
keys = ["perf_counter_en*", "perf_counter*"]
for k in keys:
    print(f"Search Key: {k}")
    items = request("item.get", {
        "output": ["itemid", "key_", "name", "lastvalue"],
        "hostids": host_id,
        "search": {"key_": k},
        "searchWildcardsEnabled": True,
        "limit": 50
    }, auth)
    
    if items:
        # Filter for Disk Read/Write
        relevant = [i for i in items if "Disk Read Bytes" in i['name'] or "Disk Write Bytes" in i['name']]
        for i in relevant:
            print(f"  MATCH: {i['key_']} | {i['name']} | Last: {i['lastvalue']}")
