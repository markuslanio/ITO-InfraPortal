import requests
import urllib3
import os
import json
import threading
import time
import logging
logger = logging.getLogger(__name__)
from dotenv import load_dotenv
from routers.cache import cache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Bypass corporate SSL proxy for all vCenter connections
# (proxy intercepts HTTPS and blocks vCenter REST API even with verify=False)
import os as _os
_existing = _os.environ.get("NO_PROXY","")
_vcenter_hosts = ",".join(filter(None,[
    _os.getenv("VCENTER_HOST",""), _os.getenv("VMC_HOST",""), _os.getenv("CANDOR_HOST","")
]))
if _vcenter_hosts:
    _os.environ["NO_PROXY"] = (_existing + "," + _vcenter_hosts).strip(",")

load_dotenv()

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

EOL_OS = [
    {"match": "2008", "label": "Windows Server 2008/R2", "eol": "Jan 2020"},
    {"match": "2012", "label": "Windows Server 2012/R2", "eol": "Oct 2023"},
    {"match": "centos 6", "label": "CentOS 6", "eol": "Nov 2020"},
    {"match": "red hat enterprise linux 6", "label": "RHEL 6", "eol": "Nov 2020"},
    {"match": "rhel 6", "label": "RHEL 6", "eol": "Nov 2020"},
    {"match": "ubuntu 18", "label": "Ubuntu 18.04", "eol": "Apr 2023"},
]

EOL_ESXI = [
    {"match": "6.0.", "label": "ESXi 6.0", "eol": "Mar 2022"},
    {"match": "6.5.", "label": "ESXi 6.5", "eol": "Oct 2022"},
    {"match": "6.7.", "label": "ESXi 6.7", "eol": "Oct 2022"},
]

TOOLS_CURRENT_VERSION = 12000

def check_eol(os_name):
    if not os_name:
        return None
    os_lower = os_name.lower()
    for entry in EOL_OS:
        if entry["match"] in os_lower:
            return entry
    return None

def check_esxi_eol(version):
    if not version:
        return None
    for entry in EOL_ESXI:
        if entry["match"] in version:
            return entry
    return None

def format_uptime(boot_time_str):
    if not boot_time_str:
        return None
    try:
        from datetime import datetime, timezone
        boot_time = datetime.fromisoformat(boot_time_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - boot_time
        days = delta.days
        hours = delta.seconds // 3600
        if days > 0:
            return str(days) + "d " + str(hours) + "h"
        return str(hours) + "h"
    except:
        return None

def get_session_token(host, user, password, verify_ssl=False):
    response = requests.post(
        "https://" + host + "/api/session",
        auth=(user, password),
        verify=verify_ssl,
        proxies={"https": None, "http": None},
        timeout=15
    )
    if response.status_code == 201:
        return response.json()
    else:
        msg = "Login failed for " + host + ": " + str(response.status_code) + " - " + response.text[:200]
        logger.error("vmware get_session_token: " + msg)
        raise Exception(msg)

def get_vms(env_key):
    env = ENVIRONMENTS[env_key]
    token = get_session_token(env["host"], env["user"], env["password"], env["verify_ssl"])
    headers = {"vmware-api-session-id": token}
    response = requests.get(
        "https://" + env["host"] + "/api/vcenter/vm",
        headers=headers,
        verify=env["verify_ssl"],
        proxies={"https": None, "http": None},
        timeout=30
    )
    if response.status_code == 200:
        vms = response.json()
        for vm in vms:
            vm["environment"] = env["label"]
            vm["env_key"] = env_key
        return vms
    else:
        raise Exception("Failed to get VMs: " + str(response.status_code))

def get_all_vms(force_refresh=False):
    if not force_refresh:
        data, timestamp = cache.get("all_vms")
        if data is not None:
            return data["vms"], data["errors"], timestamp
    results = []
    errors = []
    for env_key in ENVIRONMENTS:
        try:
            vms = get_vms(env_key)
            results.extend(vms)
        except Exception as e:
            label = ENVIRONMENTS[env_key]["label"]
            errors.append(label + ": " + str(e))
    cache.set("all_vms", {"vms": results, "errors": errors})
    _, timestamp = cache.get("all_vms")
    return results, errors, timestamp

def get_hosts(env_key):
    env = ENVIRONMENTS[env_key]
    token = get_session_token(env["host"], env["user"], env["password"], env["verify_ssl"])
    headers = {"vmware-api-session-id": token}
    response = requests.get(
        "https://" + env["host"] + "/api/vcenter/host",
        headers=headers,
        verify=env["verify_ssl"],
        proxies={"https": None, "http": None},
        timeout=30
    )
    if response.status_code == 200:
        hosts = response.json()
        for h in hosts:
            h["environment"] = env["label"]
            h["env_key"] = env_key
        return hosts
    else:
        raise Exception("Failed to get hosts: " + str(response.status_code))

def get_all_hosts(force_refresh=False):
    if not force_refresh:
        data, timestamp = cache.get("all_hosts")
        if data is not None:
            return data["hosts"], data["errors"], timestamp
    results = []
    errors = []
    for env_key in ENVIRONMENTS:
        try:
            hosts = get_hosts(env_key)
            results.extend(hosts)
        except Exception as e:
            label = ENVIRONMENTS[env_key]["label"]
            errors.append(label + ": " + str(e))
    cache.set("all_hosts", {"hosts": results, "errors": errors})
    _, timestamp = cache.get("all_hosts")
    return results, errors, timestamp

def get_tokens():
    tokens = {}
    for env_key, env in ENVIRONMENTS.items():
        try:
            tokens[env_key] = get_session_token(env["host"], env["user"], env["password"], env["verify_ssl"])
        except Exception as e:
            logger.error("vmware get_tokens failed for " + env_key + ": " + str(e))
            tokens[env_key] = None
    return tokens

def stream_detailed_hosts(force_refresh=False):
    if not force_refresh:
        data, timestamp = cache.get("detailed_hosts")
        if data is not None:
            age = cache.age_string(timestamp)
            yield "data: " + json.dumps({"type": "cached", "timestamp": age, "count": data["count"], "hosts": data["hosts"]}) + "\n\n"
            return

    all_hosts = []
    for env_key in ENVIRONMENTS:
        try:
            hosts = get_hosts(env_key)
            all_hosts.extend(hosts)
        except Exception as e:
            label = ENVIRONMENTS[env_key]["label"]
            yield "data: " + json.dumps({"type": "error", "message": label + " error: " + str(e)}) + "\n\n"

    all_vms = []
    for env_key in ENVIRONMENTS:
        try:
            vms = get_vms(env_key)
            all_vms.extend(vms)
        except:
            pass

    total = len(all_hosts)
    detailed_hosts = []
    tokens = get_tokens()

    for i, host in enumerate(all_hosts):
        env_key = host.get("env_key")
        env = ENVIRONMENTS[env_key]
        token = tokens.get(env_key)
        if not token:
            continue
        headers = {"vmware-api-session-id": token}

        host_detail = {
            "name": host.get("name"),
            "host_id": host.get("host"),
            "environment": host.get("environment"),
            "power_state": host.get("power_state"),
            "connection_state": host.get("connection_state"),
            "ip_address": None,
            "esxi_version": None,
            "build_number": None,
            "eol": None,
            "cpu_model": None,
            "cpu_count": None,
            "memory_gb": None,
            "vm_count": None,
            "uptime": None,
            "maintenance_mode": None,
            "datastore_count": None
        }

        detail_response = requests.get(
            "https://" + env["host"] + "/api/vcenter/host/" + host["host"],
            headers=headers,
            verify=env["verify_ssl"]
        )
        if detail_response.status_code == 200:
            detail = detail_response.json()
            host_detail["maintenance_mode"] = detail.get("maintenance_mode", False)

        summary_response = requests.get(
            "https://" + env["host"] + "/api/vcenter/host/" + host["host"] + "/summary",
            headers=headers,
            verify=env["verify_ssl"]
        )
        if summary_response.status_code == 200:
            summary = summary_response.json()
            config = summary.get("config", {})
            hardware = summary.get("hardware", {})
            runtime = summary.get("runtime", {})
            host_detail["ip_address"] = config.get("management_ip", None)
            host_detail["esxi_version"] = config.get("vsphere_version", None)
            host_detail["build_number"] = config.get("build", None)
            host_detail["eol"] = check_esxi_eol(host_detail["esxi_version"])
            host_detail["cpu_model"] = hardware.get("cpu_model", None)
            host_detail["cpu_count"] = hardware.get("num_cpu_cores", None)
            memory_bytes = hardware.get("memory_size_MiB", 0)
            host_detail["memory_gb"] = round(memory_bytes / 1024, 1) if memory_bytes else None
            boot_time = runtime.get("boot_time", None)
            host_detail["uptime"] = format_uptime(boot_time)

        vm_count = sum(1 for vm in all_vms if vm.get("env_key") == env_key)
        host_detail["vm_count"] = vm_count

        ds_response = requests.get(
            "https://" + env["host"] + "/api/vcenter/datastore?hosts=" + host["host"],
            headers=headers,
            verify=env["verify_ssl"]
        )
        if ds_response.status_code == 200:
            host_detail["datastore_count"] = len(ds_response.json())

        detailed_hosts.append(host_detail)
        percent = round(((i + 1) / total) * 100)
        yield "data: " + json.dumps({"type": "progress", "percent": percent, "current": i+1, "total": total}) + "\n\n"

    cache.set("detailed_hosts", {"count": len(detailed_hosts), "hosts": detailed_hosts})
    _, timestamp = cache.get("detailed_hosts")
    age = cache.age_string(timestamp)
    yield "data: " + json.dumps({"type": "complete", "timestamp": age, "count": len(detailed_hosts), "hosts": detailed_hosts}) + "\n\n"

def stream_detailed_vms(force_refresh=False):
    if not force_refresh:
        data, timestamp = cache.get("detailed_vms")
        if data is not None:
            age = cache.age_string(timestamp)
            yield "data: " + json.dumps({"type": "cached", "timestamp": age, "count": data["count"], "vms": data["vms"]}) + "\n\n"
            return

    all_vms = []
    for env_key in ENVIRONMENTS:
        try:
            vms = get_vms(env_key)
            all_vms.extend(vms)
        except Exception as e:
            label = ENVIRONMENTS[env_key]["label"]
            yield "data: " + json.dumps({"type": "error", "message": label + " error: " + str(e)}) + "\n\n"

    total = len(all_vms)
    detailed_data = []
    tokens = get_tokens()

    for i, vm in enumerate(all_vms):
        env_key = vm.get("env_key")
        env = ENVIRONMENTS[env_key]
        token = tokens.get(env_key)
        if not token:
            continue
        headers = {"vmware-api-session-id": token}
        vm_detail = {
            "name": vm["name"],
            "vm_id": vm["vm"],
            "environment": vm.get("environment", "Unknown"),
            "env_key": env_key,
            "power_state": vm.get("power_state", "UNKNOWN"),
            "cpu_count": None,
            "nic_count": None,
            "ip_address": None,
            "os_name": None,
            "eol": None,
            "tools_version": None,
            "tools_upgrade_needed": None
        }
        detail_response = requests.get(
            "https://" + env["host"] + "/api/vcenter/vm/" + vm["vm"],
            headers=headers,
            verify=env["verify_ssl"]
        )
        if detail_response.status_code == 200:
            detail = detail_response.json()
            cpu = detail.get("cpu", {})
            vm_detail["cpu_count"] = cpu.get("count", None)
            nics = detail.get("nics", {})
            vm_detail["nic_count"] = len(nics) if nics else 0
            guest = detail.get("guest_OS", None)
            vm_detail["os_name"] = guest
            eol = check_eol(guest)
            vm_detail["eol"] = eol

        guest_response = requests.get(
            "https://" + env["host"] + "/api/vcenter/vm/" + vm["vm"] + "/guest/identity",
            headers=headers,
            verify=env["verify_ssl"]
        )
        if guest_response.status_code == 200:
            guest_info = guest_response.json()
            vm_detail["ip_address"] = guest_info.get("ip_address", None)
            full_os = guest_info.get("full_name", {})
            if isinstance(full_os, dict):
                vm_detail["os_name"] = full_os.get("default_message", vm_detail["os_name"])
            elif isinstance(full_os, str):
                vm_detail["os_name"] = full_os
            eol = check_eol(vm_detail["os_name"])
            vm_detail["eol"] = eol

        tools_response = requests.get(
            "https://" + env["host"] + "/api/vcenter/vm/" + vm["vm"] + "/tools",
            headers=headers,
            verify=env["verify_ssl"]
        )
        if tools_response.status_code == 200:
            tools_info = tools_response.json()
            vm_detail["tools_version"] = tools_info.get("version", None)
            vm_detail["tools_upgrade_needed"] = tools_info.get("version_status", None) in ["UNMANAGED", "TOO_OLD_UNOFFICIAL", "TOO_NEW_UNOFFICIAL", "NOT_INSTALLED"]

        detailed_data.append(vm_detail)
        percent = round(((i + 1) / total) * 100)
        yield "data: " + json.dumps({"type": "progress", "percent": percent, "current": i+1, "total": total}) + "\n\n"

    cache.set("detailed_vms", {"count": len(detailed_data), "vms": detailed_data})
    try:
        from routers.database import save_vm_snapshot
        save_vm_snapshot(detailed_data)
    except Exception as e:
        pass
    _, timestamp = cache.get("detailed_vms")
    age = cache.age_string(timestamp)
    yield "data: " + json.dumps({"type": "complete", "timestamp": age, "count": len(detailed_data), "vms": detailed_data}) + "\n\n"

def stream_untagged_vms(force_refresh=False):
    if not force_refresh:
        data, timestamp = cache.get("untagged_vms")
        if data is not None:
            age = cache.age_string(timestamp)
            yield "data: " + json.dumps({"type": "cached", "timestamp": age, "count": data["count"], "vms": data["vms"]}) + "\n\n"
            return

    all_vms = []
    for env_key in ENVIRONMENTS:
        try:
            vms = get_vms(env_key)
            all_vms.extend(vms)
        except Exception as e:
            label = ENVIRONMENTS[env_key]["label"]
            yield "data: " + json.dumps({"type": "error", "message": label + " error: " + str(e)}) + "\n\n"

    total = len(all_vms)
    untagged = []
    tokens = get_tokens()

    for i, vm in enumerate(all_vms):
        env_key = vm.get("env_key")
        env = ENVIRONMENTS[env_key]
        token = tokens.get(env_key)
        if not token:
            continue
        headers = {"vmware-api-session-id": token}
        tag_response = requests.get(
            "https://" + env["host"] + "/api/cis/tagging/tag-association?object_type=VirtualMachine&object_id=" + vm["vm"],
            headers=headers,
            verify=env["verify_ssl"]
        )
        if tag_response.status_code == 200:
            tags = tag_response.json()
            if len(tags) == 0:
                untagged.append(vm)
        percent = round(((i + 1) / total) * 100)
        yield "data: " + json.dumps({"type": "progress", "percent": percent, "current": i+1, "total": total}) + "\n\n"

    cache.set("untagged_vms", {"count": len(untagged), "vms": untagged})
    _, timestamp = cache.get("untagged_vms")
    age = cache.age_string(timestamp)
    yield "data: " + json.dumps({"type": "complete", "timestamp": age, "count": len(untagged), "vms": untagged}) + "\n\n"

def stream_vm_storage(force_refresh=False):
    if not force_refresh:
        data, timestamp = cache.get("vm_storage")
        if data is not None:
            age = cache.age_string(timestamp)
            yield "data: " + json.dumps({"type": "cached", "timestamp": age, "count": data["count"], "vms": data["vms"]}) + "\n\n"
            return

    all_vms = []
    for env_key in ENVIRONMENTS:
        try:
            vms = get_vms(env_key)
            all_vms.extend(vms)
        except Exception as e:
            label = ENVIRONMENTS[env_key]["label"]
            yield "data: " + json.dumps({"type": "error", "message": label + " error: " + str(e)}) + "\n\n"

    powered_on = [v for v in all_vms if v.get("power_state") == "POWERED_ON"]
    total = len(powered_on)
    storage_data = []
    tokens = get_tokens()

    for i, vm in enumerate(powered_on):
        env_key = vm.get("env_key")
        env = ENVIRONMENTS[env_key]
        token = tokens.get(env_key)
        if not token:
            continue
        headers = {"vmware-api-session-id": token}

        vm_entry = {
            "name": vm["name"],
            "vm_id": vm["vm"],
            "environment": vm.get("environment", "Unknown"),
            "env_key": env_key,
            "power_state": vm.get("power_state", "UNKNOWN"),
            "drives": [],
            "has_low_disk": False
        }

        try:
            fs_response = requests.get(
                "https://" + env["host"] + "/api/vcenter/vm/" + vm["vm"] + "/guest/local-filesystem",
                headers=headers,
                verify=env["verify_ssl"],
                timeout=10
            )
            if fs_response.status_code == 200:
                fs_data = fs_response.json()
                for drive_letter, drive_info in fs_data.items():
                    capacity_bytes = drive_info.get("capacity", 0)
                    free_bytes = drive_info.get("free_space", 0)
                    if capacity_bytes > 0:
                        capacity_gb = round(capacity_bytes / (1024**3), 1)
                        free_gb = round(free_bytes / (1024**3), 1)
                        used_gb = round(capacity_gb - free_gb, 1)
                        pct_free = round((free_bytes / capacity_bytes) * 100, 1)
                        is_low = pct_free <= 15
                        if is_low:
                            vm_entry["has_low_disk"] = True
                        vm_entry["drives"].append({
                            "letter": drive_letter,
                            "filesystem": drive_info.get("filesystem", ""),
                            "capacity_gb": capacity_gb,
                            "free_gb": free_gb,
                            "used_gb": used_gb,
                            "pct_free": pct_free,
                            "is_low": is_low
                        })
                vm_entry["drives"].sort(key=lambda x: x["letter"])
        except Exception:
            pass

        if vm_entry["drives"]:
            storage_data.append(vm_entry)

        percent = round(((i + 1) / total) * 100)
        yield "data: " + json.dumps({"type": "progress", "percent": percent, "current": i+1, "total": total}) + "\n\n"

    low_disk_count = sum(1 for v in storage_data if v.get("has_low_disk"))
    cache.set("vm_storage", {"count": len(storage_data), "vms": storage_data, "low_disk_count": low_disk_count})
    try:
        from routers.database import save_disk_snapshot
        save_disk_snapshot(storage_data)
    except Exception:
        pass
    _, timestamp = cache.get("vm_storage")
    age = cache.age_string(timestamp)
    yield "data: " + json.dumps({"type": "complete", "timestamp": age, "count": len(storage_data), "low_disk_count": low_disk_count, "vms": storage_data}) + "\n\n"


def stream_datastores(force_refresh=False):
    if not force_refresh:
        data, timestamp = cache.get("vm_datastores")
        if data is not None:
            age = cache.age_string(timestamp)
            yield "data: " + json.dumps({"type": "cached", "timestamp": age, "datastores": data["datastores"]}) + "\n\n"
            return

    tokens = get_tokens()
    all_datastores = []

    for env_key in ENVIRONMENTS:
        env = ENVIRONMENTS[env_key]
        token = tokens.get(env_key)
        if not token:
            continue
        headers = {"vmware-api-session-id": token}
        try:
            # Get list of all datastores
            r = requests.get(
                "https://" + env["host"] + "/api/vcenter/datastore",
                headers=headers, verify=env["verify_ssl"], timeout=30
            )
            if r.status_code != 200:
                continue
            ds_list = r.json()
            total = len(ds_list)
            for i, ds in enumerate(ds_list):
                ds_id = ds.get("datastore")
                if not ds_id:
                    continue
                # The list endpoint includes capacity and free_space directly
                cap  = ds.get("capacity", 0) or 0
                free = ds.get("free_space", 0) or 0
                entry = {
                    "datastore_id": ds_id,
                    "name":         ds.get("name", "Unknown"),
                    "type":         ds.get("type", "Unknown"),
                    "environment":  env["label"],
                    "env_key":      env_key,
                    "accessible":   ds.get("accessible", True),
                    "capacity_gb":  round(cap  / (1024**3), 1) if cap  > 0 else None,
                    "free_gb":      round(free / (1024**3), 1) if cap  > 0 else None,
                    "used_gb":      round((cap - free) / (1024**3), 1) if cap > 0 else None,
                    "pct_free":     round((free / cap) * 100, 1) if cap > 0 else None,
                }
                all_datastores.append(entry)
                yield "data: " + json.dumps({"type": "progress", "current": i + 1, "total": total, "message": env["label"] + ": " + entry["name"]}) + "\n\n"
        except Exception as e:
            yield "data: " + json.dumps({"type": "error", "message": env["label"] + " datastore error: " + str(e)}) + "\n\n"

    # Sort by pct_free ascending (most critical first), inaccessible first
    all_datastores.sort(key=lambda x: (
        0 if x.get("accessible") is False else 1,
        x.get("pct_free") if x.get("pct_free") is not None else 999
    ))

    cache.set("vm_datastores", {"datastores": all_datastores})
    _, timestamp = cache.get("vm_datastores")
    age = cache.age_string(timestamp)
    yield "data: " + json.dumps({"type": "complete", "timestamp": age, "datastores": all_datastores}) + "\n\n"


def _infer_tier(vm_name):
    u = vm_name.upper()
    if u.endswith("P") or "P0" in u or "P1" in u or "P2" in u:
        return "Production"
    if u.endswith("Q") or "Q0" in u or "Q1" in u:
        return "QA"
    return "Dev/UAT/Test"


def _flatten_snapshot_tree(snap_list, vm_name, environment):
    """Recursively flatten a pyVmomi snapshot tree into a list of dicts."""
    from datetime import datetime, timezone
    result = []
    for s in snap_list:
        snap = s.snapshot  # ManagedObject reference — not used directly
        created = s.createTime
        age_days = None
        created_str = None
        if created:
            try:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created).days
                created_str = created.isoformat()
            except Exception:
                pass
        # Size: quiesced/memory deltas — pyVmomi doesn't expose size directly
        # but we can note whether memory was included
        result.append({
            "vm_name":     vm_name,
            "environment": environment,
            "name":        s.name or "Unnamed",
            "description": s.description or "",
            "created":     created_str,
            "age_days":    age_days,
            "tier":        _infer_tier(vm_name),
            "size_gb":     None,  # not available via SOAP without additional property
            "memory":      getattr(s, "quiesced", False),
        })
        if s.childSnapshotList:
            result.extend(_flatten_snapshot_tree(s.childSnapshotList, vm_name, environment))
    return result


def stream_snapshots(force_refresh=False):
    if not force_refresh:
        data, timestamp = cache.get("vm_snapshots")
        if data is not None:
            age = cache.age_string(timestamp)
            yield "data: " + json.dumps({"type": "cached", "timestamp": age, "snapshots": data["snapshots"]}) + "\n\n"
            return

    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
    import ssl
    from datetime import datetime, timezone

    all_snapshots = []
    env_count = len(ENVIRONMENTS)

    for idx, env_key in enumerate(ENVIRONMENTS):
        env = ENVIRONMENTS[env_key]
        label = env["label"]
        host = env["host"]
        user = env["user"]
        password = env["password"]
        verify = env.get("verify_ssl", False)

        if not host or not user or not password:
            continue

        yield "data: " + json.dumps({"type": "progress", "current": idx, "total": env_count, "message": "Connecting to " + label + "..."}) + "\n\n"

        try:
            ssl_ctx = ssl.create_default_context()
            if not verify:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

            si = SmartConnect(host=host, user=user, pwd=password, sslContext=ssl_ctx)
            content = si.RetrieveContent()

            # Collect all VMs with snapshots using a property collector
            container = content.viewManager.CreateContainerView(
                content.rootFolder, [vim.VirtualMachine], True
            )
            vms = container.view
            container.Destroy()

            total = len(vms)
            for i, vm in enumerate(vms):
                try:
                    if vm.snapshot and vm.snapshot.rootSnapshotList:
                        snaps = _flatten_snapshot_tree(vm.snapshot.rootSnapshotList, vm.name, label)
                        all_snapshots.extend(snaps)
                except Exception:
                    pass
                if i % 50 == 0:
                    yield "data: " + json.dumps({"type": "progress", "current": i + 1, "total": total, "message": label + ": scanning VMs..."}) + "\n\n"

            Disconnect(si)

        except Exception as e:
            yield "data: " + json.dumps({"type": "error", "message": label + " snapshot error: " + str(e)}) + "\n\n"

    all_snapshots.sort(key=lambda x: x.get("age_days") or 0, reverse=True)

    cache.set("vm_snapshots", {"snapshots": all_snapshots})
    _, timestamp = cache.get("vm_snapshots")
    age = cache.age_string(timestamp)
    yield "data: " + json.dumps({"type": "complete", "timestamp": age, "snapshots": all_snapshots, "total": len(all_snapshots)}) + "\n\n"


def start_background_refresh():
    def refresh_loop():
        while True:
            time.sleep(1800)
            try:
                get_all_vms(force_refresh=True)
            except:
                pass
            try:
                get_all_hosts(force_refresh=True)
            except:
                pass
    t = threading.Thread(target=refresh_loop, daemon=True)
    t.start()