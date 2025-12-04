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
print(f"Auth Token: {auth}")

# 2. Get Host
hosts = request("host.get", {"output": ["hostid", "name"], "search": {"name": "PACIFICA-DB"}}, auth)
if not hosts:
    print("Host not found")
    exit()

host = hosts[0]
print(f"Host: {host['name']} (ID: {host['hostid']})")

# 3. List Items
print("\n--- Listing Items (First 100) ---")
items = request("item.get", {
    "output": ["itemid", "key_", "name", "lastvalue"],
    "hostids": host['hostid'],
    "limit": 100,
    "sortfield": "name"
}, auth)

for item in items:
    print(f"Key: {item['key_']} | Name: {item['name']} | Last: {item['lastvalue']}")
