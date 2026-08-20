"""Site Settings — .env editor and IIS app pool recycle helper.

Secrets (PASSWORD/SECRET/TOKEN/KEY) are never round-tripped to the browser in
plaintext. read_env_entries() returns a masked value for those keys; the
front end only sends a key back in write_env_changes() if the admin actually
typed a new value for it.
"""
import os
import re
import time
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(BASE_DIR, ".env")

_SECRET_KEY_RE = re.compile(r"(PASSWORD|SECRET|TOKEN|API_KEY|_KEY|CREDENTIAL)", re.IGNORECASE)


def _is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(key))


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "•" * len(value)
    return "•" * (len(value) - 4) + value[-4:]


def read_env_entries() -> list[dict]:
    """Parse .env and return editable KEY=VALUE entries (comments/blank lines skipped)."""
    if not os.path.exists(ENV_PATH):
        return []
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entries = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key, value = key.strip(), value.strip()
        is_secret = _is_secret_key(key)
        entries.append({
            "key": key,
            "value": "" if is_secret else value,
            "masked": _mask(value) if is_secret else None,
            "is_secret": is_secret,
        })
    return entries


def write_env_changes(changes: dict) -> str:
    """Overwrite the given KEY: value pairs in .env, appending new keys that don't exist yet.
    Backs up the previous file first. Returns the backup path."""
    if not os.path.exists(ENV_PATH):
        raise FileNotFoundError(f".env not found at {ENV_PATH}")
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    backup_path = f"{ENV_PATH}.backup.{int(time.time())}"
    with open(backup_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    seen_keys = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.partition("=")[0].strip()
            if key in changes:
                new_lines.append(f"{key}={changes[key]}\n")
                seen_keys.add(key)
                continue
        new_lines.append(line)

    new_keys = [k for k in changes if k not in seen_keys]
    if new_keys:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        for key in new_keys:
            new_lines.append(f"{key}={changes[key]}\n")

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    return backup_path


def recycle_app_pool(pool_name: str = "ITOpsTools") -> tuple[bool, str]:
    """Recycle the IIS app pool via appcmd. No-op-with-error on non-IIS/dev machines."""
    appcmd = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "system32", "inetsrv", "appcmd.exe")
    if not os.path.exists(appcmd):
        return False, f"appcmd not found at {appcmd} — not running under IIS on this machine"
    try:
        result = subprocess.run(
            [appcmd, "recycle", "apppool", f"/apppool.name:{pool_name}"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return True, (result.stdout or "").strip() or "Recycled"
        return False, (result.stderr or "").strip() or f"appcmd exited with code {result.returncode}"
    except Exception as e:
        return False, str(e)
