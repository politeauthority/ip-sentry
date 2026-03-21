# IP Sentry

A fail2ban style IP blocking system for Kubernetes, built around Kubernetes [Gateway API](https://kubernetes.io/docs/concepts/services-networking/gateway/) and [Nginx Gateway Fabric](https://github.com/nginx/nginx-gateway-fabric). It watches Nginx access logs for probing requests (WordPress admin panels, exposed config files, shell injection attempts, etc.) and bans offending IPs via host iptables rules across all cluster nodes.

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

**ip-watcher** streams access logs from all nginx-gateway-fabric data plane pods via the Kubernetes API. For each request it extracts the source IP and path, checks the path against a configurable list of regex patterns, and tracks hits per IP in a sliding time window. When an IP exceeds the threshold — either total hits or distinct patterns matched — a ban entry is written to the `ip-blocklist` ConfigMap. A background thread prunes expired bans every 5 minutes. State survives watcher restarts by reloading the ConfigMap on startup.

**ip-enforcer** runs on every node with `hostNetwork: true` and `privileged: true`. It mounts the `ip-blocklist` ConfigMap as a volume and every 30 seconds syncs an `IP-BLOCKER` iptables chain: adding DROP rules for active bans and removing rules for expired or deleted entries. Rules are applied to both the `FORWARD` chain (web traffic routed to pods via kube-proxy DNAT) and the `INPUT` chain (direct access to the node itself).

**ip-blocklist** is the shared state between the two components, stored as a JSON object in a ConfigMap:

```json
{
  "1.2.3.4": {
    "banned_at":  "2026-03-20T10:00:00Z",
    "expires_at": "2026-03-21T10:00:00Z",
    "reason":     "^/wp-admin",
    "hit_count":  5
  }
}
```

## Prerequisites

### externalTrafficPolicy: Local

The nginx-gateway-fabric LoadBalancer service must have `externalTrafficPolicy: Local`. Without this, kube-proxy SNATs incoming traffic and Nginx logs a cluster-internal node IP instead of the real client IP — banning it would break the cluster.

```yaml
spec:
  externalTrafficPolicy: Local
```

### iptables-legacy

The enforcer uses `nsenter` to run the host's `iptables-legacy` binary (the same backend kube-proxy uses). On nodes where `iptables` points to the nftables backend, rules written via `iptables-nft` are silently ignored by traffic. Verify enforcement is working after deploy:

```bash
# Run on any cluster node
iptables-legacy -L IP-BLOCKER -n -v
```

## Installation

```bash
helm upgrade --install ip-sentry . \
  --namespace ip-sentry \
  --create-namespace \
  -f values-my-cluster.yaml
```

A minimal override file for a typical nginx-gateway-fabric deployment:

```yaml
ngf:
  namespace: nginx-gateway-fabric
  labelSelector: "gateway.networking.k8s.io/gateway-name=nginx-public"
```

## Values

### `ngf` — nginx-gateway-fabric targeting

| Value | Default | Description |
|---|---|---|
| `ngf.namespace` | `nginx-gateway-fabric` | Namespace where the NGF data plane pods run |
| `ngf.labelSelector` | `gateway.networking.k8s.io/gateway-name=nginx-public` | Label selector used to find the nginx data plane pods. Target the **data plane** pods (not the controller pod) — these are the ones that write access logs |
| `ngf.container` | `nginx` | Container name inside the data plane pods that writes nginx access logs |

To find the correct values for your cluster:

```bash
kubectl get pods -n <ngf-namespace> --show-labels
kubectl get pods -n <ngf-namespace> -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].name}{"\n"}{end}'
```

### `watcher` — log watcher behaviour

| Value | Default | Description |
|---|---|---|
| `watcher.image.repository` | `python` | Watcher container image repository |
| `watcher.image.tag` | `3.12-slim` | Watcher container image tag |
| `watcher.logRegex` | *(nginx combined format)* | Python regex used to parse each nginx access log line. **Group 1 must capture the source IP, group 2 the request path.** Default matches the standard nginx combined log format: `` `^(\S+) \S+ \S+ \[.+?\] "(?:[A-Z]+) (\S+) \S+" \d+` `` |
| `watcher.patterns` | *(see below)* | List of Python regex patterns matched against the request path via `re.search`. Simple strings work as-is; use `^` to anchor to the path root. Patterns are tested against the **extracted path only** (e.g. `/wp-admin`), not the full log line |
| `watcher.threshold` | `3` | Total hits to any pattern(s) within `windowSeconds` before banning |
| `watcher.uniquePatternThreshold` | `2` | Ban if this many **distinct** patterns are matched within `windowSeconds`, regardless of total hit count. Set to `0` to disable. With the default of `2`, an IP hitting `/.git` once and `/.env` once is banned immediately |
| `watcher.windowSeconds` | `120` | Sliding window for hit counting (seconds) |
| `watcher.banDurationSeconds` | `86400` | How long a ban lasts in seconds. `86400` = 24h, `604800` = 7d, `2592000` = 30d |
| `watcher.resources` | *(see values.yaml)* | CPU/memory requests and limits for the watcher pod |
| `watcher.podSecurityContext` | `runAsNonRoot: true`, `runAsUser/Group: 1000`, `seccompProfile: RuntimeDefault` | Pod-level security context |
| `watcher.securityContext` | `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]` | Container-level security context |

Default patterns:

```yaml
# WordPress
- '^/wp-admin'
- '^/wp-login\.php'
- '^/xmlrpc\.php'
# Exposed config / secrets
- '^/\.env'           # matches /.env, /.env.local, /.env.production, etc.
- '^/\.git/'
- '^/\.aws/'
- '^/\.ssh/'
# Database admin panels
- '^/phpmyadmin'
- '^/manager/html'    # Tomcat manager
# Generic PHP shells / scanners
- '^/admin\.php'
- '^/config\.php'
- '^/setup\.php'
- '^/shell\.php'
- '^/eval\.php'
# IoT / router exploits
- '^/boaform/'
```

**Testing patterns:** use only the path portion as the test string in regex101 (e.g. `/wp-admin/login.php`), not the full nginx log line.

### `enforcer` — iptables enforcer behaviour

| Value | Default | Description |
|---|---|---|
| `enforcer.image.repository` | `nicolaka/netshoot` | Enforcer container image repository |
| `enforcer.image.tag` | `v0.13` | Enforcer container image tag |
| `enforcer.intervalSeconds` | `30` | How often the enforcer syncs iptables rules from the blocklist. Combined with Kubernetes ConfigMap volume propagation (~60s), the maximum lag between a ban being written and traffic being dropped is ~90s |
| `enforcer.tolerateControlPlane` | `false` | Set to `true` to also run the enforcer on control plane nodes (adds an `operator: Exists` toleration). Default is worker nodes only |
| `enforcer.tolerations` | `[]` | Additional tolerations for the enforcer DaemonSet, e.g. for nodes with custom taints |
| `enforcer.resources` | *(see values.yaml)* | CPU/memory requests and limits for enforcer pods |
| `enforcer.podSecurityContext` | `seccompProfile: RuntimeDefault` | Pod-level security context. Seccomp is set here because it is overridden by `privileged: true` at the container level |
| `enforcer.securityContext` | `privileged: true`, `readOnlyRootFilesystem: true` | Container-level security context. `privileged` is required for `nsenter` + `iptables-legacy` and cannot be removed |

### Top-level values

| Value | Default | Description |
|---|---|---|
| `imagePullSecrets` | `[]` | Image pull secrets applied to both the watcher and enforcer pods, e.g. for a private registry |
| `serviceAccount.create` | `true` | Whether to create a ServiceAccount for the watcher |
| `serviceAccount.name` | `""` | Override the ServiceAccount name. Defaults to the Helm release fullname |
| `rbac.create` | `true` | Whether to create Roles and RoleBindings. The watcher needs read access to pods and pod logs in the NGF namespace, and read/write access to the blocklist ConfigMap in its own namespace |

## Operations

### Inspect current bans

```bash
kubectl get cm -n ip-sentry ip-sentry-blocklist \
  -o jsonpath='{.data.blocklist\.json}' | jq .
```

### Unban an IP

Edit the ConfigMap and remove the entry. The enforcer drops the iptables rule within `intervalSeconds`.

```bash
kubectl edit cm -n ip-sentry ip-sentry-blocklist
```

### Manually ban an IP

```bash
kubectl patch cm -n ip-sentry ip-sentry-blocklist --type merge \
  -p '{"data":{"blocklist.json":"{\"1.2.3.4\":{\"banned_at\":\"2026-03-20T00:00:00Z\",\"expires_at\":\"2099-01-01T00:00:00Z\",\"reason\":\"manual\",\"hit_count\":1}}"}}'
```

### Verify iptables rules on a node

```bash
# SSH to a node or exec into an enforcer pod
iptables-legacy -L IP-BLOCKER -n -v

# Confirm jump rules exist in both chains
iptables-legacy -L FORWARD -n | head -5
iptables-legacy -L INPUT -n | head -5
```

### View watcher logs

```bash
kubectl logs -n ip-sentry -l app.kubernetes.io/component=watcher -f
```

### View enforcer logs

```bash
kubectl logs -n ip-sentry -l app.kubernetes.io/component=enforcer -f
```

## Road Map

### Import Ban Lists

Create tooling for importing lists of known malicious IPs, so they can be blocked before the probe the cluster.

### Bruteforce Auth

Allow for watching failed login attempts on hosted services and ban an IP after repeated failed attempts.

### More Malicious Probe Patterns

Build out a data set of common application probing urls for users to pick and choose from.
