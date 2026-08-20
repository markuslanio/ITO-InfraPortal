import sys
sys.path.insert(0, "C:\\Python313\\Lib\\site-packages")

import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# ── Load secrets from web.config appSettings ─────────────────────────────────
# Secrets are stored in <appSettings> in web.config, optionally encrypted
# with aspnet_regiis DPAPI. We read them here and inject into os.environ
# before load_dotenv() runs, so they take priority over .env values.
try:
    import xml.etree.ElementTree as ET
    _web_config = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web.config")
    if os.path.exists(_web_config):
        _tree = ET.parse(_web_config)
        _root = _tree.getroot()
        _app_settings = _root.find("appSettings")
        if _app_settings is not None:
            for _item in _app_settings.findall("add"):
                _key = _item.get("key", "")
                _val = _item.get("value", "")
                if _key and _val and _val != "FILL_IN":
                    os.environ.setdefault(_key, _val)
except Exception as _e:
    pass  # Never block startup over this

import uvicorn
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("run")

port = int(os.environ.get("HTTP_PLATFORM_PORT", "8001"))

MAX_RETRIES = 10
RETRY_DELAY = 5  # seconds

for attempt in range(1, MAX_RETRIES + 1):
    try:
        logger.info(f"Starting uvicorn on port {port} (attempt {attempt})")
        uvicorn.run("main:app", host="127.0.0.1", port=port)
        logger.info("Uvicorn exited cleanly.")
        break
    except OSError as e:
        logger.error(f"Socket error on attempt {attempt}: {e}")
        if attempt < MAX_RETRIES:
            logger.info(f"Retrying in {RETRY_DELAY}s...")
            time.sleep(RETRY_DELAY)
        else:
            logger.error("Max retries reached. Giving up.")
            raise
    except Exception as e:
        logger.error(f"Unexpected error on attempt {attempt}: {e}")
        raise