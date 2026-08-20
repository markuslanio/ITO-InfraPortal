from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl
import os
import json
from dotenv import load_dotenv
from routers.cache import cache

load_dotenv()

import os as _os, urllib3 as _urllib3
_urllib3.disable_warnings(_urllib3.exceptions.InsecureRequestWarning)
_existing = _os.environ.get("NO_PROXY","")
_vcenter_hosts = ",".join(filter(None,[
    _os.getenv("VCENTER_HOST",""), _os.getenv("VMC_HOST",""), _os.getenv("CANDOR_HOST","")
]))
if _vcenter_hosts:
    _os.environ["NO_PROXY"] = (_existing + "," + _vcenter_hosts).strip(",")

EOL_ESXI = [
    {"match": "6.0.", "label": "ESXi 6.0", "eol": "Mar 2022"},
    {"match": "6.5.", "label": "ESXi 6.5", "eol": "Oct 2022"},
    {"match": "6.7.", "label": "ESXi 6.7", "eol": "Oct 2022"},
]

ENVIRONMENTS = {
    "topeka": {
        "host": os.getenv("VCENTER_HOST"),
        "user": os.getenv("VCENTER_USER"),
        "password": os.getenv("VCENTER_PASSWORD"),
        "verify_ssl": False,
        "label": "Topeka"
    },
    "vmc": {
        "host": os.getenv("VMC_HOST"),
        "user": os.getenv("VMC_USER"),
        "password": os.getenv("VMC_PASSWORD"),
        "verify_ssl": False,
        "label": "VMC on AWS"
    },
    "candor": {
        "host": os.getenv("CANDOR_HOST"),
        "user": os.getenv("CANDOR_USER"),
        "password": os.getenv("CANDOR_PASSWORD"),
        "verify_ssl": False,
        "label": "Candor India"
    }
}

def check_esxi_eol(version):
    if not version:
        return None
    for entry in EOL_ESXI:
        if entry["match"] in version:
            return entry
    return None

def format_uptime(uptime_seconds):
    if not uptime_seconds:
        return None
    days = uptime_seconds // 86400
    hours = (uptime_seconds % 86400) // 3600
    if days > 0:
        return str(days) + "d " + str(hours) + "h"
    return str(hours) + "h"

def get_si(env_key):
    env = ENVIRONMENTS[env_key]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    si = SmartConnect(
        host=env["host"],
        user=env["user"],
        pwd=env["password"],
        sslContext=context
    )
    return si

def get_hosts_deep(env_key):
    env = ENVIRONMENTS[env_key]
    si = get_si(env_key)
    try:
        content = si.RetrieveContent()
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.HostSystem], True
        )
        hosts = []
        for h in container.view:
            try:
                version = h.config.product.version if h.config and h.config.product else None
                build = h.config.product.build if h.config and h.config.product else None
                cpu_model = None
                if h.hardware and h.hardware.cpuPkg:
                    cpu_model = h.hardware.cpuPkg[0].description
                cpu_cores = h.hardware.cpuInfo.numCpuCores if h.hardware and h.hardware.cpuInfo else None
                cpu_packages = h.hardware.cpuInfo.numCpuPackages if h.hardware and h.hardware.cpuInfo else None
                cpu_threads = h.hardware.cpuInfo.numCpuThreads if h.hardware and h.hardware.cpuInfo else None
                memory_gb = round(h.hardware.memorySize / (1024**3), 1) if h.hardware else None
                ip_address = None
                if h.config and h.config.network and h.config.network.vnic:
                    ip_address = h.config.network.vnic[0].spec.ip.ipAddress
                uptime_seconds = h.summary.quickStats.uptime if h.summary and h.summary.quickStats else None
                maintenance_mode = h.runtime.inMaintenanceMode if h.runtime else None
                vm_count = len(h.vm) if h.vm else 0
                hosts.append({
                    "name": h.name,
                    "environment": env["label"],
                    "env_key": env_key,
                    "power_state": str(h.runtime.powerState) if h.runtime else "UNKNOWN",
                    "connection_state": str(h.runtime.connectionState) if h.runtime else "UNKNOWN",
                    "ip_address": ip_address,
                    "esxi_version": version,
                    "build_number": build,
                    "eol": check_esxi_eol(version),
                    "cpu_model": cpu_model,
                    "cpu_cores": cpu_cores,
                    "cpu_packages": cpu_packages,
                    "cpu_threads": cpu_threads,
                    "memory_gb": memory_gb,
                    "uptime": format_uptime(uptime_seconds),
                    "maintenance_mode": maintenance_mode,
                    "vm_count": vm_count
                })
            except Exception as e:
                hosts.append({
                    "name": getattr(h, 'name', 'Unknown'),
                    "environment": env["label"],
                    "env_key": env_key,
                    "error": str(e)
                })
        container.Destroy()
        return hosts
    finally:
        Disconnect(si)

def stream_detailed_hosts(force_refresh=False):
    if not force_refresh:
        data, timestamp = cache.get("detailed_hosts")
        if data is not None:
            age = cache.age_string(timestamp)
            yield "data: " + json.dumps({"type": "cached", "timestamp": age, "count": data["count"], "hosts": data["hosts"]}) + "\n\n"
            return

    all_hosts = []
    env_keys = list(ENVIRONMENTS.keys())
    total_envs = len(env_keys)

    for env_idx, env_key in enumerate(env_keys):
        label = ENVIRONMENTS[env_key]["label"]
        yield "data: " + json.dumps({"type": "progress", "percent": int((env_idx / total_envs) * 100), "current": env_idx, "total": total_envs, "message": "Connecting to " + label + "..."}) + "\n\n"
        try:
            hosts = get_hosts_deep(env_key)
            all_hosts.extend(hosts)
        except Exception as e:
            yield "data: " + json.dumps({"type": "error", "message": label + " error: " + str(e)}) + "\n\n"

    cache.set("detailed_hosts", {"count": len(all_hosts), "hosts": all_hosts})
    _, timestamp = cache.get("detailed_hosts")
    age = cache.age_string(timestamp)
    yield "data: " + json.dumps({"type": "complete", "timestamp": age, "count": len(all_hosts), "hosts": all_hosts}) + "\n\n"