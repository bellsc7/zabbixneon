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
    resp = requests.post(ZABBIX_URL, json=payload)
    return resp.json().get("result")

# 1. Login
auth = request("user.login", {"username": ZABBIX_USER, "password": ZABBIX_PASS})
print(f"Auth: {auth}")

# 2. Get Host ID
hosts = request("host.get", {"output": ["hostid", "name"]}, auth)
print(f"Found {len(hosts)} hosts:")
target_host_id = None
for h in hosts:
    print(f"ID: {h['hostid']}, Name: {h['name']}")
    if "ad2" in h['name']:
        target_host_id = h['hostid']

if not target_host_id:
    print("Target host not found")
    exit()

host_id = target_host_id
print(f"Selected Host ID: {host_id}")

# 3. Get Disk Items
items = request("item.get", {
    "output": ["itemid", "key_", "name", "lastvalue"],
    "hostids": host_id,
    "search": {"key_": "vfs.fs.size"},
    "sortfield": "key_"
}, auth)

print(f"Found {len(items)} items:")
for item in items:
    print(f"Key: {item['key_']}, Name: {item['name']}, Last Value: {item['lastvalue']}")
