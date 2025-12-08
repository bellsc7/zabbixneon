import os
import httpx
import asyncio
import json
from typing import List, Optional, Any, Dict, Union
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Configuration with Defaults
ZABBIX_URL = os.getenv("ZABBIX_URL", "http://192.168.1.25/zabbix/api_jsonrpc.php")
ZABBIX_USER = os.getenv("ZABBIX_USER", "Admin")
ZABBIX_PASS = os.getenv("ZABBIX_PASS", "zabbix")

class DiskUsage(BaseModel):
    label: str
    usage: float

class Alert(BaseModel):
    description: str
    severity: int

class ServerMetric(BaseModel):
    id: str
    name: str
    ip: str
    type: str
    icon: str
    cpu: Optional[float] = None
    ram: Optional[float] = None
    disks: List[DiskUsage] = []
    latency: Optional[float] = None
    uptime: Optional[int] = None
    uptime_str: Optional[str] = "N/A"
    alerts: List[Alert] = []
    status: str = "unknown"
    os_info: Optional[str] = "N/A"
    serial_number: Optional[str] = "N/A"
    cpu_model: Optional[str] = "N/A"
    kernel_version: Optional[str] = "N/A"
    client_count: Optional[int] = 0
    model: Optional[str] = "N/A"
    sessions: Optional[int] = 0
    wan_in: Optional[float] = 0
    wan_out: Optional[float] = 0
    last_updated: Optional[str] = None

class ZabbixAPI:
    def __init__(self, url, user, password):
        self.url = url
        self.user = user
        self.password = password
        self.auth_token = None
        self.req_id = 1
        self.client = httpx.AsyncClient()

    async def close(self):
        await self.client.aclose()

    async def _request(self, method, params=None):
        current_id = self.req_id
        self.req_id += 1
        
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": current_id,
            "auth": self.auth_token
        }
        
        if method == "user.login":
            payload["auth"] = None
            
        try:
            response = await self.client.post(self.url, json=payload, timeout=30.0)
            response.raise_for_status()
            result = response.json()
            
            if "error" in result:
                raise Exception(f"Zabbix API Error: {result['error']}")
            return result.get("result")
        except httpx.RequestError as e:
            print(f"Request failed: {e}")
            raise

    async def login(self):
        if not self.auth_token:
            self.auth_token = await self._request("user.login", {"username": self.user, "password": self.password})
        return self.auth_token

    async def get_hosts(self):
        return await self._request("host.get", {
            "output": ["hostid", "name", "available", "snmp_available"],
            "selectInterfaces": ["ip"],
            "selectParentTemplates": ["name"]
        })

    async def get_active_triggers(self, host_ids):
        return await self._request("trigger.get", {
            "output": ["description", "priority"],
            "selectHosts": ["hostid", "name"],
            "hostids": host_ids,
            "only_true": True,
            "monitored": True,
            "active": True,
            "sortfield": ["priority"],
            "sortorder": "DESC"
        })

    async def get_items(self, host_id):
        search_keys = [
            "system.cpu", "vm.memory", "vfs.fs.size", "icmppingsec", "icmpping", "agent.ping",
            "vmware.vm.cpu", "vmware.hv.cpu", "vmware.vm.memory", "vmware.hv.memory", "vmware.vm.vfs",
            "cisco.memory", "fgProcessorUsage", "net.if.in", "net.if.out", "system.uptime",
            "unifi.cpu", "unifi.memory", "system.cpu.util", "system.cpu.load", "vm.memory.util", "vm.memory.pused",
            "ifInOctets", "ifOutOctets", "system.uname", "system.sw.os",
            "cpuLoad.0", "unifiIfRxBytes.1", "unifiIfTxBytes.1", "unifiApSystemVersion.0",
            "unifiVapNumStations", "unifiApSystemModel.0", "unifi.ap.users", "dot11AssociatedStationCount",
            "unifi.client.count", "unifi.radio.util", "unifi.radio.channel",
            "sysUpTime.0", "sysUpTimeInstance", "system.uptime[fgSysUpTime.0]",
            "memTotalReal.0", "memTotal.0", "memAvailReal.0", "memFree.0", "memBuffer.0", "memCached.0", "vm.memory.free[0]", "vm.memory.total[0]",
            "fgSysSesCount", "fgSysSesCount.0", "fgSysMemUsage", "fortinet.firewall.sessions", "fgSysSesCount[0]",
            "system.cpu.util[fgSysCpuUsage.0]", "fgProcessorUsage[0]", "vm.memory.util[memoryUsedPercentage.0]", "vm.memory.pused[0]", "fgSysMemUsage[0]"
        ]
        
        return await self._request("item.get", {
            "output": ["hostid", "key_", "lastvalue", "value_type", "units", "name"],
            "hostids": host_id,
            "search": {"key_": search_keys},
            "searchByAny": True,
            "sortfield": "key_"
        })

    async def get_history(self, item_id, time_from=None, time_till=None, history_type=0):
        params = {
            "output": "extend",
            "history": history_type,
            "itemids": item_id,
            "sortfield": "clock",
            "sortorder": "DESC", 
            "limit": 20 
        }
        if time_from:
            params["time_from"] = time_from
        if time_till:
            params["time_till"] = time_till
            
        return await self._request("history.get", params)

zabbix = ZabbixAPI(ZABBIX_URL, ZABBIX_USER, ZABBIX_PASS)

# Global Cache
SERVER_DATA_CACHE: List[ServerMetric] = []

def determine_device_type(host_data):
    templates = [t['name'].lower() for t in host_data.get('parentTemplates', [])]
    name = host_data['name'].lower()
    full_text = " ".join(templates) + " " + name
    
    if "windows" in full_text:
        return "Windows", "fa-brands fa-windows"
    elif "linux" in full_text:
        return "Linux", "fa-brands fa-linux"
    elif "vmware" in full_text:
        return "VMware", "fa-solid fa-cube"
    elif any(k in full_text for k in ['forti', 'palo', 'firewall', 'gate']):
        return "Firewall", "fa-solid fa-shield-halved"
    elif any(k in full_text for k in ['ubiquiti', 'unifi', 'ruckus', 'wifi', 'wlan', 'ap', 'ubqt']):
        return "AP", "fa-solid fa-wifi"
    elif any(k in full_text for k in ['cisco', 'switch', 'sw', 'catalyst', 'hp', 'aruba']):
        return "Switch", "fa-solid fa-network-wired"
    else:
        return "Unknown", "fa-solid fa-server"

def get_metric_value(items_map, keys_priority):
    for key in keys_priority:
        if key in items_map:
            val = items_map[key]
            if val is not None and val != "":
                try:
                    return float(val)
                except ValueError:
                    continue
    return None

def get_percentage_metric(items_map, percentage_keys, used_keys, total_keys):
    val = get_metric_value(items_map, percentage_keys)
    if val is not None:
        return val

    used_val = get_metric_value(items_map, used_keys)
    total_val = get_metric_value(items_map, total_keys)

    if used_val is not None and total_val is not None and total_val > 0:
        return (used_val / total_val) * 100.0
    
    return None

async def process_host(h_data, all_alerts):
    hid = h_data['hostid']
    
    # Fetch Items for this host
    items = await zabbix.get_items(hid)
    
    h_items = {}
    h_items_list = []
    for item in items:
        key = item['key_']
        val = item['lastvalue']
        h_items[key] = val
        h_items_list.append(item)
        
    dev_type, dev_icon = determine_device_type(h_data)
    
    templates = [t['name'].lower() for t in h_data.get('parentTemplates', [])]
    is_ubiquiti = any("ubqt" in t or "unifi" in t for t in templates)
    
    interfaces = h_data.get('interfaces', [])
    ip = interfaces[0]['ip'] if interfaces else "0.0.0.0"
    
    # --- CPU Logic ---
    cpu_pct_keys = [
        'system.cpu.util[fgSysCpuUsage.0]', 'fgProcessorUsage[0]',
        'system.cpu.util', 'system.cpu.util[0]', 'system.cpu.load[percpu,avg1]', 'system.cpu.load[all,avg1]', 
        'unifi.cpu.util', 'vmware.vm.cpu.usage', 'vmware.hv.cpu.usage', 'fgProcessorUsage', 'cpuLoad.0' 
    ]
    if is_ubiquiti:
        cpu_pct_keys = ['cpuLoad.0', 'system.cpu.util[0]', 'system.cpu.load[percpu,avg1]', 'unifi.cpu.util'] + cpu_pct_keys

    cpu_val = get_metric_value(h_items, cpu_pct_keys)
    
    # --- RAM Logic ---
    ram_pct_keys = [
        'vm.memory.util[memoryUsedPercentage.0]', 'vm.memory.pused[0]', 'fgSysMemUsage[0]',
        'vm.memory.size[pused]', 'vm.memory.util', 'vm.memory.util[0]', 'vm.memory.pused[0]',
        'unifi.memory.util', 'vmware.vm.memory.usage', 'vmware.hv.memory.usage', 'fgSysMemUsage'
    ]
    if is_ubiquiti:
        ram_pct_keys = ['vm.memory.util[0]', 'vm.memory.pused[0]', 'unifi.memory.util'] + ram_pct_keys

    ram_used_keys = ['vm.memory.size[used]', 'vm.memory.used[0]', 'vm.memory.pused[0]', 'cisco.memory.used']
    ram_total_keys = ['vm.memory.size[total]', 'vm.memory.total[0]', 'cisco.memory.free']
    
    cisco_used = get_metric_value(h_items, ['cisco.memory.used'])
    cisco_free = get_metric_value(h_items, ['cisco.memory.free'])
    
    ram_val = None
    if cisco_used is not None and cisco_free is not None:
            total = cisco_used + cisco_free
            if total > 0:
                ram_val = (cisco_used / total) * 100.0
    
    if ram_val is None:
        ram_val = get_percentage_metric(h_items, ram_pct_keys, ram_used_keys, ram_total_keys)
    
    if ram_val is None:
        pavail = get_metric_value(h_items, ['vm.memory.size[pavailable]'])
        if pavail is not None:
            ram_val = 100.0 - pavail

    if ram_val is None:
        mem_total_keys = ['vm.memory.total[0]', 'memTotalReal.0', 'memTotal.0']
        mem_free_keys = ['vm.memory.free[0]', 'memAvailReal.0', 'memFree.0', 'memBuffer.0', 'memCached.0']
        mem_total = get_metric_value(h_items, mem_total_keys)
        mem_free = get_metric_value(h_items, mem_free_keys)
        if mem_total and mem_total > 0:
            current_free = mem_free if mem_free is not None else 0
            used = mem_total - current_free
            ram_val = (used / mem_total) * 100.0

    # --- Disk Logic ---
    disks = []
    if dev_type not in ['AP', 'Switch'] and not is_ubiquiti:
        for item in h_items_list:
            key = item['key_']
            if 'vfs.fs.size[' in key and ',pused]' in key:
                try:
                    start = key.index('[') + 1
                    end = key.rindex(',')
                    label = key[start:end]
                    val = item['lastvalue']
                    if val:
                        disks.append(DiskUsage(label=label, usage=float(val)))
                except:
                    pass
            elif 'vmware.vm.vfs.fs.size[' in key and ',pused]' in key:
                    try:
                        start = key.index('[') + 1
                        end = key.rindex(',')
                        label = key[start:end]
                        val = item['lastvalue']
                        if val:
                            disks.append(DiskUsage(label=label, usage=float(val)))
                    except:
                        pass
    
    # --- Latency Logic ---
    latency_val = get_metric_value(h_items, ['icmppingsec'])
    if latency_val is None:
        is_up = get_metric_value(h_items, ['icmpping'])
        if is_up == 1:
            latency_val = 0.1 
    
    if latency_val is not None:
        latency_val = latency_val * 1000.0 
    else:
        ping_val = get_metric_value(h_items, ['agent.ping'])
        if ping_val == 1:
            latency_val = 0.0 

    # --- Uptime Logic ---
    uptime_val = get_metric_value(h_items, ['system.uptime[fgSysUpTime.0]', 'system.uptime', 'sysUpTime.0', 'sysUpTimeInstance'])
    if uptime_val is not None:
        matched_key = None
        for k in ['system.uptime', 'sysUpTime.0', 'sysUpTimeInstance']:
            if k in h_items and h_items[k] is not None:
                matched_key = k
                break
        
        uptime_val = float(uptime_val)
        if matched_key and 'sysUpTime' in matched_key:
            uptime_val = uptime_val / 100.0
        
        uptime_val = int(uptime_val)

    # --- Status Logic ---
    avail_api = h_data.get('available', '0')
    snmp_avail = h_data.get('snmp_available', '0')
    ping_status = get_metric_value(h_items, ['agent.ping', 'icmpping'])
    
    if avail_api == '1' or snmp_avail == '1':
        status = 'online'
    elif avail_api == '2' or snmp_avail == '2':
        status = 'offline'
    else:
        if ping_status == 1:
            status = 'online'
        elif ping_status == 0:
            status = 'offline'
        elif cpu_val is not None or ram_val is not None or uptime_val is not None:
            status = 'online'
        else:
            status = 'unknown'

    # --- System Info Logic ---
    os_info = "N/A"
    serial_number = "N/A"
    cpu_model = "N/A"
    kernel_version = "N/A"

    uname = h_items.get('system.uname')
    sw_os = h_items.get('system.sw.os')
    unifi_ver = h_items.get('unifiApSystemVersion.0')

    if uname:
        if "Windows" in uname:
            os_info = "Windows Server" 
            if "2019" in uname: os_info += " 2019"
            elif "2016" in uname: os_info += " 2016"
            elif "2022" in uname: os_info += " 2022"
            parts = uname.split()
            for p in parts:
                if p.count('.') >= 2:
                    kernel_version = p
                    break
        elif "Linux" in uname:
            os_info = "Linux"
            parts = uname.split()
            if len(parts) > 2:
                kernel_version = parts[2] 
    
    if sw_os and os_info == "Linux":
            if "Ubuntu" in sw_os:
                os_info = "Ubuntu Linux"
    
    if unifi_ver:
        os_info = f"Unifi OS {unifi_ver}"

    # --- Unifi Extra Logic ---
    client_count = 0
    model = "N/A"
    uptime_str = "N/A"

    for item in h_items_list:
        k = item['key_']
        if any(x in k for x in ['unifiVapNumStations', 'unifi.ap.users', 'dot11AssociatedStationCount', 'unifi.client.count']):
            try:
                client_count += int(item['lastvalue'])
            except:
                pass
    
    # Firewall Sessions
    sessions = 0
    sessions_val = get_metric_value(h_items, ['fgSysSesCount[0]', 'fgSysSesCount', 'fgSysSesCount.0', 'fortinet.firewall.sessions'])
    if sessions_val is not None:
        sessions = int(sessions_val)

    # WAN Throughput (FortiGate)
    wan_in = 0.0
    wan_out = 0.0
    if dev_type == 'Firewall':
        for item in h_items_list:
            name = item.get('name', '').lower()
            key = item['key_']
            if 'wan1' in name:
                try:
                    val = float(item['lastvalue'])
                    if key.startswith('net.if.in'):
                        wan_in = val
                    elif key.startswith('net.if.out'):
                        wan_out = val
                except:
                    pass

    model_val = h_items.get('unifiApSystemModel.0')
    if model_val:
        model = model_val
        if cpu_model == "N/A":
            cpu_model = model_val

    if uptime_val:
        days = uptime_val // 86400
        hours = (uptime_val % 86400) // 3600
        minutes = (uptime_val % 3600) // 60
        uptime_str = f"{days}d {hours}h {minutes}m"

    if dev_type == 'AP' or is_ubiquiti:
        disks = []

    return ServerMetric(
        id=hid,
        name=h_data['name'],
        ip=ip,
        type=dev_type,
        icon=dev_icon,
        cpu=round(cpu_val, 2) if cpu_val is not None else None,
        ram=round(ram_val, 2) if ram_val is not None else None,
        disks=disks,
        latency=round(latency_val, 2) if latency_val is not None else None,
        uptime=uptime_val,
        uptime_str=uptime_str,
        alerts=all_alerts.get(hid, []),
        status=status,
        os_info=os_info,
        serial_number=serial_number,
        cpu_model=cpu_model,
        kernel_version=kernel_version,
        client_count=client_count,
        model=model,
        sessions=sessions,
        wan_in=wan_in,
        wan_out=wan_out,
        last_updated=datetime.now().strftime("%H:%M:%S")
    )

async def fetch_all_server_data():
    try:
        await zabbix.login()
        hosts = await zabbix.get_hosts()
        if not hosts:
            return []

        host_map = {h['hostid']: h for h in hosts}
        host_ids = list(host_map.keys())

        triggers = await zabbix.get_active_triggers(host_ids)
        host_problems = {hid: [] for hid in host_ids}
        for t in triggers:
            if int(t['priority']) >= 2: 
                if t.get('hosts'):
                    for h in t['hosts']:
                        hid = h['hostid']
                        if hid in host_problems:
                            host_problems[hid].append(Alert(
                                description=t['description'],
                                severity=int(t['priority'])
                            ))

        tasks = [process_host(h_data, host_problems) for h_data in hosts]
        results = await asyncio.gather(*tasks)
        return results
    except Exception as e:
        print(f"Fetch Error: {e}")
        return []

async def data_updater_loop():
    global SERVER_DATA_CACHE
    while True:
        try:
            new_data = await fetch_all_server_data()
            if new_data:
                SERVER_DATA_CACHE = new_data
                print(f"[{datetime.now()}] Cache updated with {len(new_data)} servers.")
        except Exception as e:
            print(f"Error in background loop: {e}")
        
        await asyncio.sleep(5)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    task = asyncio.create_task(data_updater_loop())
    yield
    # Shutdown
    task.cancel()
    await zabbix.close()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/servers", response_model=List[ServerMetric])
async def get_servers():
    return SERVER_DATA_CACHE

@app.get("/api/history/{host_id}")
async def get_history_data(host_id: str, metric: str):
    try:
        await zabbix.login()
        
        target_keys = []
        is_network = False
        is_disk_io = False
        
        if metric == 'cpu':
            target_keys = ['system.cpu.util[fgSysCpuUsage.0]', 'fgProcessorUsage[0]', 'system.cpu.util', 'system.cpu.load[all,avg1]', 'vmware.vm.cpu.usage', 'system.cpu.util[0]', 'system.cpu.load', 'cpuLoad.0']
        elif metric == 'memory':
            target_keys = ['vm.memory.util[memoryUsedPercentage.0]', 'vm.memory.pused[0]', 'fgSysMemUsage[0]', 'vm.memory.util', 'vm.memory.size[pused]', 'vmware.vm.memory.usage']
        elif metric == 'network':
            is_network = True
            target_keys_in = ['net.if.in', 'vmware.vm.net.if.in', 'ifInOctets', 'unifiIfRxBytes.1']
            target_keys_out = ['net.if.out', 'vmware.vm.net.if.out', 'ifOutOctets', 'unifiIfTxBytes.1']
        elif metric == 'disk_io':
            is_disk_io = True
            target_keys_read = ['Disk Reads/sec', 'Disk Read Bytes/sec', 'vfs.dev.read.rate', 'vmware.vm.disk.read']
            target_keys_write = ['Disk Writes/sec', 'Disk Write Bytes/sec', 'vfs.dev.write.rate', 'vmware.vm.disk.write']
        elif metric == 'sessions':
            target_keys = ['fgSysSesCount[0]', 'fgSysSesCount', 'fgSysSesCount.0', 'fortinet.firewall.sessions']
        else:
            target_keys = [metric]

        async def fetch_history_for_keys(keys):
            for key_pattern in keys:
                search_params = {"key_": key_pattern}
                
                items = await zabbix._request("item.get", {
                    "output": ["itemid", "key_", "value_type", "lastvalue", "name", "units"],
                    "hostids": host_id,
                    "search": search_params,
                    "limit": 20 
                })
                
                if items:
                    valid_items = [i for i in items if i.get('lastvalue') is not None]
                    
                    if valid_items:
                        def get_val(i):
                            try:
                                val = float(i['lastvalue'])
                                # Prioritize WAN1 for network metrics
                                if is_network and "wan1" in i.get('name', '').lower():
                                    val += 1e15 
                                return val
                            except:
                                return -1.0
                        
                        valid_items.sort(key=get_val, reverse=True)
                        item = valid_items[0]
                        
                        multiplier = 1.0
                        if "Reads/sec" in item['key_'] or "Writes/sec" in item['key_'] or "r/s" in item.get('units', '').lower() or "w/s" in item.get('units', '').lower():
                            multiplier = 4096.0 
                        
                        hist_type = 0 if int(item['value_type']) == 0 else 3
                        
                        history = await zabbix.get_history(item['itemid'], history_type=hist_type)
                        if history:
                            history.sort(key=lambda x: int(x['clock']))
                            return history, multiplier
            return [], 1.0

        if is_network:
            hist_in, _ = await fetch_history_for_keys(target_keys_in)
            hist_out, _ = await fetch_history_for_keys(target_keys_out)
            
            map_in = {h['clock']: float(h['value']) for h in hist_in}
            map_out = {h['clock']: float(h['value']) for h in hist_out}
            
            all_clocks = sorted(list(set(map_in.keys()) | set(map_out.keys())))
            
            final_rx = [map_in.get(c, 0) for c in all_clocks]
            final_tx = [map_out.get(c, 0) for c in all_clocks]
            
            return {
                "labels": all_clocks,
                "rx": final_rx,
                "tx": final_tx
            }
        elif is_disk_io:
            hist_read, mult_read = await fetch_history_for_keys(target_keys_read)
            hist_write, mult_write = await fetch_history_for_keys(target_keys_write)
            
            map_read = {h['clock']: float(h['value']) * mult_read for h in hist_read}
            map_write = {h['clock']: float(h['value']) * mult_write for h in hist_write}
            
            all_clocks = sorted(list(set(map_read.keys()) | set(map_write.keys())))
            
            final_read = [map_read.get(c, 0) for c in all_clocks]
            final_write = [map_write.get(c, 0) for c in all_clocks]
            
            return {
                "labels": all_clocks,
                "read": final_read,
                "write": final_write
            }
        else:
            history, _ = await fetch_history_for_keys(target_keys)
            labels = [h['clock'] for h in history]
            values = [float(h['value']) for h in history]
            
            return {
                "labels": labels,
                "values": values
            }

    except Exception as e:
        print(f"History Error: {e}")
        if metric == 'network' or metric == 'disk_io':
             return {"labels": [], "rx": [], "tx": [], "read": [], "write": []}
        return {"labels": [], "values": []}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
