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

# Windows Host
win_host = "PACIFICA-DB"
# Linux Host
linux_host = "Zabbix Server"

print("\n--- Checking Specific Hardware Keys ---")

# Windows WMI Checks
print(f"\nChecking Windows ({win_host})...")
hosts = request("host.get", {"output": ["hostid"], "search": {"name": win_host}}, auth)
if hosts:
    hid = hosts[0]['hostid']
    keys = [
        "wmi.get[root/cimv2,Select SerialNumber from Win32_BIOS]",
        "wmi.get[root/cimv2,Select Name from Win32_Processor]",
        "system.uname"
    ]
    items = request("item.get", {
        "output": ["key_", "lastvalue"],
        "hostids": hid,
        "search": {"key_": keys},
        "searchByAny": True
    }, auth)
    for i in items:
        print(f"  {i['key_']}: {i['lastvalue']}")

# Linux Checks
print(f"\nChecking Linux ({linux_host})...")
hosts = request("host.get", {"output": ["hostid"], "search": {"name": linux_host}}, auth)
if hosts:
    hid = hosts[0]['hostid']
    keys = [
        "system.cpu.model",
        "system.hw.serial",
        "system.sw.os",
        "system.uname"
    ]
    items = request("item.get", {
        "output": ["key_", "lastvalue"],
        "hostids": hid,
        "search": {"key_": keys},
        "searchByAny": True
    }, auth)
    for i in items:
        print(f"  {i['key_']}: {i['lastvalue']}")
