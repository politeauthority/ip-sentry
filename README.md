# K8s IP Sentry v0.0.1

A fail2ban-style IP blocking system for Kubernetes, built around nginx-gateway-fabric. It watches nginx access logs for probing requests (WordPress admin panels, exposed config files, shell injection attempts, etc.) and automatically bans offending IPs at the host iptables level across all cluster nodes.

## Quick Install

```bash
helm upgrade --install --create-namespace -n ip-sentry ip-sentry . -f values-colfax.yaml
```

## Usage
### Remove a Banned IP
To remove a banned IP address edit the `ip-sentry-blocklist` configmap and remove the entry for the IP address you want to unban. This will cause the `ip-enforcer` pods to update ip tables and remove the records for that IP address.

## How it works

```
nginx-gateway-fabric pods
        │ access logs (streamed via K8s API)
        ▼
┌─────────────────┐       writes ban      ┌──────────────────┐
│   ip-watcher    │ ──────────────────▶   │  ip-blocklist    │
│  (Deployment)   │                       │  (ConfigMap)     │
└─────────────────┘                       └──────────────────┘
                                                   │ mounted as volume
                                                   ▼
                                        ┌─────────────────────┐
                                        │    ip-enforcer      │
                                        │    (DaemonSet)      │
                                        │  node 1 / node 2 /  │
                                        │  node 3 ...         │
                                        └─────────────────────┘
                                                   │ iptables DROP rules
                                                   ▼
                                          host network stack
```

### ip-watcher (Deployment)

- Lists all running nginx-gateway-fabric pods via the Kubernetes API and starts a log-streaming thread for each one, handling pod restarts and scaling automatically.
- Parses each line against the nginx combined access log format, extracting the source IP and request path.
- Matches the path against a configurable list of suspicious patterns (e.g. `/wp-admin`, `/.env`, `/xmlrpc.php`).
- Tracks hits per IP in a sliding time window. Once an IP exceeds the configured threshold within that window, it is banned.
- A ban is written as a JSON entry to the `ip-blocklist` ConfigMap, including the ban timestamp, expiry time, triggering pattern, and hit count.
- On startup, existing bans are reloaded from the ConfigMap so state survives pod restarts.
- A background thread runs every 5 minutes to prune expired bans from the ConfigMap.

### ip-blocklist (ConfigMap)

The shared state between the watcher and the enforcer. Format:

```json
{
  "1.2.3.4": {
    "banned_at":  "2026-03-20T10:00:00Z",
    "expires_at": "2026-03-21T10:00:00Z",
    "reason":     "/wp-admin",
    "hit_count":  5
  }
}
```

### ip-enforcer (DaemonSet)

- Runs on every cluster node with `hostNetwork: true` and `privileged: true` so that iptables commands affect the node's real network stack.
- The `ip-blocklist` ConfigMap is mounted as a volume; Kubernetes propagates updates to the volume automatically (within ~60 seconds).
- Every 30 seconds the enforcer reads the blocklist, checks expiry timestamps, and syncs an `IP-BLOCKER` iptables chain:
  - Adds a `DROP` rule for each active ban not yet in the chain.
  - Removes rules for any IP whose ban has expired or was manually removed.
- The `IP-BLOCKER` chain is inserted at the top of both `FORWARD` and `INPUT`. `FORWARD` is what catches web traffic being routed to pods (after kube-proxy DNAT in PREROUTING). `INPUT` additionally blocks the IP from reaching the node itself.

## Technologies

| Component | Technology |
|---|---|
| Ingress / gateway | [nginx-gateway-fabric](https://github.com/nginx/nginx-gateway-fabric) (Gateway API) |
| Log streaming | Kubernetes Python client (`kubernetes` library) |
| Ban state | Kubernetes ConfigMap |
| IP blocking | iptables (`IP-BLOCKER` chain on each node) |
| Enforcer runtime | [nicolaka/netshoot](https://github.com/nicolaka/netshoot) (includes iptables + jq) |
| GitOps deployment | Argo CD via Kustomize |

## Prerequisites

### 1. externalTrafficPolicy: Local on the NGF LoadBalancer

This is the most critical requirement. By default, Kubernetes LoadBalancer services use `externalTrafficPolicy: Cluster`, which SNAT's incoming traffic — nginx sees a node-internal IP as the source, not the real client IP. Banning that node IP would break the cluster.

Set `externalTrafficPolicy: Local` on the nginx-gateway-fabric LoadBalancer service (in `colfax-ops`):

```yaml
spec:
  externalTrafficPolicy: Local
```

With `Local`, the load balancer routes traffic only to nodes running an NGF pod and preserves the original source IP end-to-end.

### 2. Verify NGF pod labels and container name

The watcher targets pods matched by `app.kubernetes.io/name=nginx-gateway` in the `nginx-gateway-fabric-public` namespace and streams the `nginx` container logs (the data-plane container, not the controller).

Confirm these match your deployment:

```bash
kubectl get pods -n nginx-gateway-fabric-public --show-labels
kubectl get pods -n nginx-gateway-fabric-public -o jsonpath='{.items[0].spec.containers[*].name}'
```

Adjust `NGF_LABEL` and `NGF_CONTAINER` in `configmap-config.yaml` if needed.

### 3. nftables compatibility

On nodes using nftables (Ubuntu 20.04+, Debian 10+), verify that iptables-legacy is active and that rules written by the enforcer are actually processed. Check on a node:

```bash
iptables-legacy -L IP-BLOCKER -n
```

## Configuration

All tunable parameters live in `configmap-config.yaml`:

| Key | Default | Description |
|---|---|---|
| `PATTERNS` | `/wp-admin,/wp-login.php,...` | Comma-separated URL substrings that trigger hit counting |
| `THRESHOLD` | `3` | Number of hits within the window before banning |
| `WINDOW_SECONDS` | `120` | Sliding window for hit counting (seconds) |
| `BAN_DURATION_SECONDS` | `86400` | How long a ban lasts (seconds). 86400 = 24h |
| `NGF_NAMESPACE` | `nginx-gateway-fabric-public` | Namespace containing NGF pods |
| `NGF_LABEL` | `app.kubernetes.io/name=nginx-gateway` | Label selector for NGF pods |
| `NGF_CONTAINER` | `nginx` | Container name that writes nginx access logs |

## Operations

### Inspect current bans

```bash
kubectl get cm ip-blocklist -n ip-sentry -o jsonpath='{.data.blocklist\.json}' | jq .
```

### Manually ban an IP

```bash
kubectl patch cm ip-blocklist -n ip-sentry --type merge \
  -p '{"data":{"blocklist.json":"{\"1.2.3.4\":{\"banned_at\":\"2026-03-20T00:00:00Z\",\"expires_at\":\"2026-03-21T00:00:00Z\",\"reason\":\"manual\",\"hit_count\":1}}"}}'
```

### Unban an IP

Edit the ConfigMap and remove the entry. The enforcer will drop the iptables rule within 30 seconds.

```bash
kubectl edit cm ip-blocklist -n ip-sentry
```

### Check enforcer iptables rules on a node

```bash
# From any node or via a debug pod
iptables -L IP-BLOCKER -n -v

# Verify the jump rules exist in both chains
iptables -L FORWARD -n | head -5
iptables -L INPUT -n | head -5
```

### View watcher logs

```bash
kubectl logs -n ip-sentry -l app=ip-watcher -f
```
