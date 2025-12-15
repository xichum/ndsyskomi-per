# Background Service Manager

A lightweight, automated background process manager designed for distributed data handling and connection stability in containerized environments.

## 🔧 Service Configuration

The service is configured via Environment Variables. Use the following settings to tune the connection parameters and resource allocation.

### 🌐 Network Interfaces (Ports)

Configure the listening ports for different data transport protocols.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `3000` | **Dashboard / API Port**. Used for health checks and configuration retrieval. |
| `R_PORT` | `9258` | **Primary Sync Port**. Main TCP data channel. (Leave empty to disable). |
| `T_PORT` | *(Optional)* | **Fast Track Port**. UDP-based low latency channel (Requires >64MB RAM). |
| `H_PORT` | *(Optional)* | **High-Throughput Port**. Optimized UDP channel for bulk data (Requires >64MB RAM). |

### 🔒 Security & Validation

Settings for upstream connection verification and handshake masquerading.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `R_SNI` | `www.xxxxx.xcom` | **Target Domain**. The hostname used for TLS handshake verification. |
| `R_DEST` | `...:443` | **Fallback Destination**. Where traffic should be directed if validation fails. |

### 📊 Instance Identity & Telemetry

Manage how this instance is identified in the cluster and where it reports metrics.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `NODE_PREFIX` | `XXXXX` | **Instance Tag**. Friendly name prefix for this node in the cluster map. |
| `KOMARI_HOST` | *(Optional)* | **Metrics Endpoint**. Central server address for system monitoring. |
| `KOMARI_TOKEN`| *(Optional)* | **Access Token**. Authentication key for the metrics server. |

### ⚙️ System Tuning

Advanced resource management for container environments.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CRON_RESTART`| `06:30` | **Maintenance Window**. Daily auto-restart time (UTC+8). Format: `HH:MM`. |
| `MEM_LIMIT` | `512` | **Heap Limit (MB)**.  |
| `CPU_LIMIT` | `0.1` | **Heap Limit (CPU)**.  |
| `RES_CERT_URL` |
| `RES_KEY_URL` |


---

## 📝 Logs
The service includes an automated **Watchdog** process. It periodically checks the integrity of the data processors (every 10s) and performs self-healing if a process hangs.

*   `[sys]` System events and resource usage.
*   `[tls]` Certificate validation status.
*   `[upd]` Core dependency updates.
