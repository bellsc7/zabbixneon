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
target_hosts = ["PACIFICA-DB", "Zabbix Server"]

print("\n--- Checking Host Inventory ---")

for host_name in target_hosts:
    print(f"\nHost: {host_name}")
    hosts = request("host.get", {
        "output": ["hostid", "name"], 
        "search": {"name": host_name},
        "selectInventory": ["os", "serialno_a", "hardware", "software"] # Fetch specific inventory fields
    }, auth)
    
    if hosts:
        h = hosts[0]
        inv = h.get('inventory', {})
        if inv:
            print(f"  OS: {inv.get('os')}")
            print(f"  Serial: {inv.get('serialno_a')}")
            print(f"  Hardware: {inv.get('hardware')}")
            print(f"  Software: {inv.get('software')}")
        else:
            print("  No inventory data found (Inventory might be disabled)")
