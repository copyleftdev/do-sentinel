# do-sentinel

A lightweight, single-binary Linux security metrics agent written in Rust. Collects deep procfs telemetry, kernel hardening state, network forensics, and authentication intelligence — then exposes it all via a Prometheus-compatible endpoint and an embedded real-time analytics dashboard.

**~7 MB binary. ~2 MB RAM. Zero external dependencies at runtime.**

## Features

### Collectors

| Collector | What it gathers |
|---|---|
| **cpu** | Per-CPU mode times, context switches, forks, running/blocked counts |
| **memory** | /proc/meminfo fields, swap, PSI (pressure stall) for cpu/memory/io |
| **disk** | /proc/diskstats I/O counters, filesystem usage via statvfs |
| **network** | Interface rx/tx bytes/packets/errors, TCP state counts, retransmits |
| **loadavg** | 1/5/15 min load averages, thread counts |
| **process** | Top-K processes by CPU: times, RSS, threads, FDs, disk I/O |
| **security** | Kernel hardening sysctls (ASLR, ptrace, kptr, dmesg, modules), network hardening (forwarding, syncookies, rp_filter, redirects), per-process capabilities, seccomp status, entropy, FD limits |
| **connections** | Full TCP/UDP socket table with PID attribution, listening services with bind scope, conntrack entries, unique remote peers |
| **forensics** | Deleted binaries still running, memfd fileless execution, SUID/SGID inventory, /dev/shm contents, suspicious command lines, world-writable files |
| **auth** | SSH failed/accepted logins, brute-force IP detection (>10 failures), failed logins by IP and username, sudo events, active sessions, authorized_keys counts |

### Endpoints

| Path | Description |
|---|---|
| `/metrics` | Prometheus text exposition format |
| `/health` | Simple health check |
| `/boto` | Embedded analytics dashboard (undiscoverable) |
| `/boto/api/metrics` | JSON API for structured metric data |

### Embedded Dashboard

The dashboard is compiled into the binary — no static files to deploy. It features:

- **Security posture score** with animated radial gauge and deduction breakdown
- **Intelligence narrative** — auto-generated English prose describing system state
- **Real-time sparkline charts** for CPU load and memory (ApexCharts)
- **Alert strip** for critical findings (deleted binaries, fileless execution, brute force)
- **5 deep-dive panels**: Intelligence, Network, Forensics, Auth, Deep Inspection
- Auto-refreshes every 10 seconds

## Quick Start

### Build

```bash
cargo build --release
```

The binary is at `target/release/do-sentinel` (~7 MB).

### Run

```bash
# Minimal — metrics only, no persistence
./do-sentinel --no-store

# With local sled database for metric history
./do-sentinel

# With TLS (e.g. Let's Encrypt)
./do-sentinel --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
              --tls-key  /etc/letsencrypt/live/example.com/privkey.pem

# Custom port and bind
./do-sentinel --port 9101 --bind 127.0.0.1
```

### Verify

```bash
# Prometheus metrics
curl http://localhost:9101/metrics | head -20

# JSON API
curl http://localhost:9101/boto/api/metrics | python3 -m json.tool | head

# Dashboard
open http://localhost:9101/boto
```

## CLI Options

```
Usage: do-sentinel [OPTIONS]

Options:
      --port <PORT>            Port [default: 9101]
      --bind <BIND>            Bind address [default: 0.0.0.0]
      --data-dir <DATA_DIR>    Sled data directory [default: /var/lib/do-sentinel]
      --interval <INTERVAL>    Collection interval in seconds [default: 10]
      --top-k <TOP_K>          Top-K processes by CPU [default: 30]
      --no-processes           Disable process collection
      --no-store               Disable sled persistence (serve live metrics only)
      --tls-cert <TLS_CERT>    TLS certificate file (PEM)
      --tls-key <TLS_KEY>      TLS private key file (PEM)
      --debug                  Enable debug logging
  -h, --help                   Print help
```

## Install as systemd Service

```bash
sudo cp target/release/do-sentinel /usr/local/bin/

sudo tee /etc/systemd/system/do-sentinel.service > /dev/null << 'EOF'
[Unit]
Description=do-sentinel security metrics agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/do-sentinel --no-store
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now do-sentinel
```

## Architecture

```
src/
  main.rs              # Async runtime, HTTP server, TLS, JSON API, dashboard serving
  config.rs            # CLI argument parsing (clap)
  store.rs             # Sled embedded DB + Prometheus text formatter
  collector/
    mod.rs             # Collector trait, Metric/Sample types, helper functions
    cpu.rs             # /proc/stat parser
    memory.rs          # /proc/meminfo + /proc/pressure/* parser
    disk.rs            # /proc/diskstats + statvfs
    network.rs         # /proc/net/dev, /proc/net/tcp, /proc/net/snmp
    loadavg.rs         # /proc/loadavg
    process.rs         # /proc/[pid]/stat, status, io, fd
    security.rs        # Kernel sysctls, capabilities, seccomp, entropy
    connections.rs     # Socket tables, listeners, conntrack, peer analysis
    forensics.rs       # Deleted binaries, memfd, SUID, /dev/shm, suspicious cmdlines
    auth.rs            # Auth log parsing, brute force detection, sessions
  dashboard/
    index.html         # Embedded SPA (TailwindCSS + ApexCharts)
```

### Adding a Collector

1. Create `src/collector/my_collector.rs`
2. Implement the `Collector` trait:

```rust
use super::*;

pub struct MyCollector;

impl Collector for MyCollector {
    fn name(&self) -> &'static str { "my_collector" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let mut metrics = Vec::new();
        // Use gauge() or counter() helpers with labels() and sample()
        metrics.push(gauge(
            "sentinel_my_metric",
            "Description of my metric",
            vec![sample(labels(&[("key", "value")]), 42.0)],
        ));
        Ok(metrics)
    }
}
```

3. Add `pub mod my_collector;` to `src/collector/mod.rs`
4. Add `Box::new(collector::my_collector::MyCollector)` to the collectors vec in `main.rs`

## Requirements

- **Linux** (reads from procfs, /proc/net/*, sysctl paths)
- **Rust 1.70+** to build
- Root or appropriate capabilities for full metric collection (process details, auth logs)

## License

MIT
