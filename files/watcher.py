#!/usr/bin/env python3
"""
ip-sentry watcher

Streams nginx access logs from nginx-gateway-fabric pods via the Kubernetes API.
Detects probing/exploit requests by matching URLs against configured patterns.
Bans source IPs that exceed the hit threshold by writing to the blocklist ConfigMap.
"""
import json
import os
import re
import threading
import time
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from kubernetes import client, config

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

NAMESPACE        = os.environ.get("NAMESPACE", "default")
BLOCKLIST_CM     = os.environ.get("BLOCKLIST_CM", "ip-sentry-blocklist")
NGF_NAMESPACE    = os.environ.get("NGF_NAMESPACE", "nginx-gateway-fabric")
NGF_LABEL        = os.environ.get("NGF_LABEL", "gateway.networking.k8s.io/gateway-name=nginx-public")
NGF_CONTAINER    = os.environ.get("NGF_CONTAINER", "nginx")
_raw_patterns = [p.strip() for p in os.environ.get("PATTERNS", "/wp-admin,/wp-login.php,/.env").split(",") if p.strip()]
PATTERNS = []
for _p in _raw_patterns:
    try:
        PATTERNS.append((re.compile(_p), _p))
    except re.error as e:
        print(f"WARNING: skipping invalid regex pattern {_p!r}: {e}", flush=True)
THRESHOLD                = int(float(os.environ.get("THRESHOLD", "3")))
UNIQUE_PATTERN_THRESHOLD = int(float(os.environ.get("UNIQUE_PATTERN_THRESHOLD", "2")))
WINDOW                   = int(float(os.environ.get("WINDOW_SECONDS", "120")))
BAN_DURATION             = int(float(os.environ.get("BAN_DURATION_SECONDS", "86400")))

_DEFAULT_LOG_REGEX = r'^(\S+) \S+ \S+ \[.+?\] "(?:[A-Z]+) (\S+) \S+" \d+'
# nginx combined log format: IP - user [date] "METHOD /path PROTO" status bytes ...
# Override with LOG_REGEX env var. Group 1 must be the source IP, group 2 the request path.
try:
    LOG_RE = re.compile(os.environ.get("LOG_REGEX", _DEFAULT_LOG_REGEX))
except re.error as e:
    print(f"WARNING: invalid LOG_REGEX, falling back to default: {e}", flush=True)
    LOG_RE = re.compile(_DEFAULT_LOG_REGEX)

hits        = defaultdict(list)  # ip -> [(unix_timestamp, pattern), ...]
hits_lock   = threading.Lock()
banned      = set()
banned_lock = threading.Lock()
cm_lock     = threading.Lock()


def match_pattern(path):
    for compiled, original in PATTERNS:
        if compiled.search(path):
            return original
    return None


def process_line(line):
    m = LOG_RE.match(line)
    if not m:
        return
    ip, path = m.group(1), m.group(2)

    with banned_lock:
        if ip in banned:
            return

    pattern = match_pattern(path)
    if not pattern:
        return

    log.info(f"Probe: {ip} -> {path}")
    now = time.time()
    with hits_lock:
        hits[ip] = [(t, p) for t, p in hits[ip] if now - t < WINDOW]
        hits[ip].append((now, pattern))
        count           = len(hits[ip])
        unique_patterns = len({pattern for _, pattern in hits[ip]})

    should_ban = count >= THRESHOLD
    should_ban = should_ban or (UNIQUE_PATTERN_THRESHOLD > 0 and unique_patterns >= UNIQUE_PATTERN_THRESHOLD)
    if should_ban:
        ban(ip, pattern, count)


def ban(ip, reason, count):
    with banned_lock:
        if ip in banned:
            return
        banned.add(ip)

    now     = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=BAN_DURATION)
    entry   = {
        "banned_at":  now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reason":     reason,
        "hit_count":  count,
    }

    with cm_lock:
        v1 = client.CoreV1Api()
        try:
            cm   = v1.read_namespaced_config_map(BLOCKLIST_CM, NAMESPACE)
            data = json.loads(cm.data.get("blocklist.json", "{}") or "{}")
            data[ip] = entry
            cm.data["blocklist.json"] = json.dumps(data, indent=2)
            v1.replace_namespaced_config_map(BLOCKLIST_CM, NAMESPACE, cm)
            log.info(f"Banned {ip}: {reason} ({count} hits, expires {entry['expires_at']})")
        except Exception as e:
            log.error(f"Failed to write ban for {ip}: {e}")
            with banned_lock:
                banned.discard(ip)


def prune_loop():
    """Periodically remove expired bans from the ConfigMap and in-memory set."""
    while True:
        time.sleep(300)
        try:
            with cm_lock:
                v1   = client.CoreV1Api()
                cm   = v1.read_namespaced_config_map(BLOCKLIST_CM, NAMESPACE)
                data = json.loads(cm.data.get("blocklist.json", "{}") or "{}")
                now  = datetime.now(timezone.utc)

                active, pruned = {}, []
                for ip, info in data.items():
                    exp = datetime.strptime(info["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    if exp > now:
                        active[ip] = info
                    else:
                        pruned.append(ip)

                if pruned:
                    cm.data["blocklist.json"] = json.dumps(active, indent=2)
                    v1.replace_namespaced_config_map(BLOCKLIST_CM, NAMESPACE, cm)
                    with banned_lock:
                        for ip in pruned:
                            banned.discard(ip)
                    log.info(f"Pruned {len(pruned)} expired bans: {pruned}")
        except Exception as e:
            log.error(f"Prune loop error: {e}")


def tail_pod(pod_name):
    """Stream logs from a single NGF pod, retrying on disconnect."""
    v1 = client.CoreV1Api()
    log.info(f"Starting log tail: {pod_name}")
    while True:
        try:
            resp = v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=NGF_NAMESPACE,
                container=NGF_CONTAINER,
                follow=True,
                since_seconds=1,
                _preload_content=False,
            )
            buf = b""
            for chunk in resp.stream(amt=4096, decode_content=True):
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = line.decode("utf-8", errors="replace").strip()
                    if text:
                        process_line(text)
        except Exception as e:
            log.error(f"Log tail error ({pod_name}): {e} — retrying in 15s")
            time.sleep(15)


HEARTBEAT_FILE = "/tmp/healthy"


def pod_watcher():
    """Discover NGF pods and start a tail thread for each running pod."""
    v1      = client.CoreV1Api()
    threads = {}
    while True:
        try:
            pods    = v1.list_namespaced_pod(NGF_NAMESPACE, label_selector=NGF_LABEL)
            running = {p.metadata.name for p in pods.items if p.status.phase == "Running"}
            for name in running:
                t = threads.get(name)
                if t is None or not t.is_alive():
                    t = threading.Thread(target=tail_pod, args=(name,), daemon=True)
                    t.start()
                    threads[name] = t
                    log.info(f"Watching pod: {name}")
            threads = {k: v for k, v in threads.items() if k in running or v.is_alive()}
        except Exception as e:
            log.error(f"Pod watcher error: {e}")
        try:
            with open(HEARTBEAT_FILE, "w") as f:
                f.write(str(time.time()))
        except Exception as e:
            log.warning(f"Failed to write heartbeat: {e}")
        time.sleep(30)


def main():
    config.load_incluster_config()

    try:
        v1   = client.CoreV1Api()
        cm   = v1.read_namespaced_config_map(BLOCKLIST_CM, NAMESPACE)
        data = json.loads(cm.data.get("blocklist.json", "{}") or "{}")
        with banned_lock:
            banned.update(data.keys())
        log.info(f"Loaded {len(data)} existing bans from ConfigMap")
    except Exception as e:
        log.warning(f"Could not preload bans: {e}")

    threading.Thread(target=prune_loop, daemon=True).start()
    pod_watcher()


if __name__ == "__main__":
    main()
