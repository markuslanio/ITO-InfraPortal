import time
import threading
from routers.database import save_cache, load_cache

class DataCache:
    def __init__(self, ttl_seconds=1800):
        self.ttl = ttl_seconds
        self.lock = threading.Lock()
        self._store = {}

    def get(self, key):
        with self.lock:
            entry = self._store.get(key)
            if entry is not None:
                return entry["data"], entry["timestamp"]
        data, timestamp = load_cache(key)
        if data is not None:
            with self.lock:
                self._store[key] = {"data": data, "timestamp": timestamp}
            return data, timestamp
        return None, None

    def set(self, key, data):
        ts = int(time.time())
        with self.lock:
            self._store[key] = {"data": data, "timestamp": ts}
        save_cache(key, data)

    def is_stale(self, key):
        with self.lock:
            entry = self._store.get(key)
            if entry is None:
                return True
            return (time.time() - entry["timestamp"]) > self.ttl

    def invalidate(self, key):
        with self.lock:
            if key in self._store:
                del self._store[key]

    def age_string(self, timestamp):
        if timestamp is None:
            return "Never"
        age = int(time.time() - timestamp)
        if age < 60:
            return str(age) + " seconds ago"
        elif age < 3600:
            return str(age // 60) + " minutes ago"
        else:
            return str(age // 3600) + " hours ago"

cache = DataCache(ttl_seconds=1800)