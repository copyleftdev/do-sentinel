use super::*;
use std::collections::HashMap as StdHashMap;
use std::fs;

pub struct ConnectionsCollector;

impl Collector for ConnectionsCollector {
    fn name(&self) -> &'static str { "connections" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let mut metrics = Vec::new();

        // Build inode→(pid,comm) map from /proc/[pid]/fd
        let inode_map = build_inode_map();

        // --- Full TCP socket table with PID attribution ---
        if let Ok(content) = read_proc_file("/proc/net/tcp") {
            parse_socket_table(&content, "tcp4", &inode_map, &mut metrics);
        }
        if let Ok(content) = read_proc_file("/proc/net/tcp6") {
            parse_socket_table6(&content, "tcp6", &inode_map, &mut metrics);
        }

        // --- Full UDP socket table ---
        if let Ok(content) = read_proc_file("/proc/net/udp") {
            parse_udp_table(&content, "udp4", &inode_map, &mut metrics);
        }
        if let Ok(content) = read_proc_file("/proc/net/udp6") {
            parse_udp_table(&content, "udp6", &inode_map, &mut metrics);
        }

        // --- Listening services inventory ---
        let mut listeners = Vec::new();
        if let Ok(content) = read_proc_file("/proc/net/tcp") {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 10 { continue; }
                if fields[3] != "0A" { continue; } // LISTEN state
                let inode = fields[9];
                let local = decode_addr_v4(fields[1]);
                let (pid, comm) = inode_map.get(inode).cloned().unwrap_or(("?".into(), "?".into()));
                listeners.push((local.0, local.1, pid, comm, "tcp4".to_string()));
            }
        }
        if let Ok(content) = read_proc_file("/proc/net/tcp6") {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 10 { continue; }
                if fields[3] != "0A" { continue; }
                let inode = fields[9];
                let local = decode_addr_v6(fields[1]);
                let (pid, comm) = inode_map.get(inode).cloned().unwrap_or(("?".into(), "?".into()));
                listeners.push((local.0, local.1, pid, comm, "tcp6".to_string()));
            }
        }

        for (addr, port, pid, comm, proto) in &listeners {
            let port_str = port.to_string();
            let bind_scope = if addr == "0.0.0.0" || addr == "::" { "all" } else { "local" };
            metrics.push(gauge(
                "sentinel_listen_socket",
                "Listening TCP socket with process attribution",
                vec![sample(
                    labels(&[
                        ("proto", proto), ("addr", addr), ("port", &port_str),
                        ("pid", pid), ("comm", comm), ("scope", bind_scope),
                    ]),
                    1.0,
                )],
            ));
        }

        metrics.push(gauge(
            "sentinel_listen_sockets_total",
            "Total listening sockets",
            vec![sample(Labels::new(), listeners.len() as f64)],
        ));

        // --- Conntrack table size (firewall state) ---
        if let Ok(content) = read_proc_file("/proc/sys/net/netfilter/nf_conntrack_count") {
            if let Ok(val) = content.trim().parse::<f64>() {
                metrics.push(gauge("sentinel_conntrack_entries", "Active conntrack entries", vec![sample(Labels::new(), val)]));
            }
        }
        if let Ok(content) = read_proc_file("/proc/sys/net/netfilter/nf_conntrack_max") {
            if let Ok(val) = content.trim().parse::<f64>() {
                metrics.push(gauge("sentinel_conntrack_max", "Max conntrack entries", vec![sample(Labels::new(), val)]));
            }
        }

        // --- Unique remote IPs currently connected ---
        let mut remote_ips: StdHashMap<String, f64> = StdHashMap::new();
        if let Ok(content) = read_proc_file("/proc/net/tcp") {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 { continue; }
                if fields[3] != "01" { continue; } // ESTABLISHED
                let (ip, _port) = decode_addr_v4(fields[2]);
                if ip != "0.0.0.0" && ip != "127.0.0.1" {
                    *remote_ips.entry(ip).or_insert(0.0) += 1.0;
                }
            }
        }

        for (ip, count) in &remote_ips {
            metrics.push(gauge(
                "sentinel_remote_peer_connections",
                "Active connections per remote IP",
                vec![sample(labels(&[("remote_ip", ip)]), *count)],
            ));
        }

        metrics.push(gauge(
            "sentinel_unique_remote_peers",
            "Number of unique remote IPs with established connections",
            vec![sample(Labels::new(), remote_ips.len() as f64)],
        ));

        Ok(metrics)
    }
}

fn build_inode_map() -> StdHashMap<String, (String, String)> {
    let mut map = StdHashMap::new();

    for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy().to_string();
        if pid_str.parse::<u32>().is_err() { continue; }

        let comm = fs::read_to_string(format!("/proc/{}/comm", pid_str))
            .unwrap_or_default().trim().to_string();

        let fd_dir = format!("/proc/{}/fd", pid_str);
        for fd_entry in fs::read_dir(&fd_dir).into_iter().flatten().flatten() {
            if let Ok(link) = fs::read_link(fd_entry.path()) {
                let link_str = link.to_string_lossy().to_string();
                if let Some(rest) = link_str.strip_prefix("socket:[") {
                    if let Some(inode) = rest.strip_suffix(']') {
                        map.insert(inode.to_string(), (pid_str.clone(), comm.clone()));
                    }
                }
            }
        }
    }

    map
}

fn decode_addr_v4(hex: &str) -> (String, u16) {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return ("0.0.0.0".into(), 0); }

    let ip_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    if ip_hex.len() == 8 {
        let ip_u32 = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
        let ip = format!("{}.{}.{}.{}",
            ip_u32 & 0xFF, (ip_u32 >> 8) & 0xFF,
            (ip_u32 >> 16) & 0xFF, (ip_u32 >> 24) & 0xFF);
        (ip, port)
    } else {
        ("0.0.0.0".into(), port)
    }
}

fn decode_addr_v6(hex: &str) -> (String, u16) {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 { return ("::".into(), 0); }

    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    let ip_hex = parts[0];

    if ip_hex.len() == 32 {
        // Simplify: check if it's a v4-mapped address
        if ip_hex.starts_with("0000000000000000FFFF0000") || ip_hex.starts_with("0000000000000000ffff0000") {
            let v4_hex = &ip_hex[24..32];
            let ip_u32 = u32::from_str_radix(v4_hex, 16).unwrap_or(0);
            let ip = format!("{}.{}.{}.{}",
                ip_u32 & 0xFF, (ip_u32 >> 8) & 0xFF,
                (ip_u32 >> 16) & 0xFF, (ip_u32 >> 24) & 0xFF);
            return (ip, port);
        }

        // Full IPv6
        let mut segs = Vec::new();
        for i in (0..32).step_by(8) {
            let chunk = &ip_hex[i..i+8];
            let val = u32::from_str_radix(chunk, 16).unwrap_or(0);
            // /proc/net/tcp6 stores each 32-bit word in host byte order (little-endian)
            let swapped = val.swap_bytes();
            segs.push(format!("{:04x}", (swapped >> 16) & 0xFFFF));
            segs.push(format!("{:04x}", swapped & 0xFFFF));
        }
        (segs.join(":"), port)
    } else {
        ("::".into(), port)
    }
}

fn tcp_state_name(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED", "02" => "SYN_SENT", "03" => "SYN_RECV",
        "04" => "FIN_WAIT1", "05" => "FIN_WAIT2", "06" => "TIME_WAIT",
        "07" => "CLOSE", "08" => "CLOSE_WAIT", "09" => "LAST_ACK",
        "0A" => "LISTEN", "0B" => "CLOSING", _ => "UNKNOWN",
    }
}

fn parse_socket_table(content: &str, proto: &str, inode_map: &StdHashMap<String, (String, String)>, metrics: &mut Vec<Metric>) {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 { continue; }

        let state = fields[3];
        if state == "0A" { continue; } // LISTEN handled separately

        let (local_ip, local_port) = decode_addr_v4(fields[1]);
        let (remote_ip, remote_port) = decode_addr_v4(fields[2]);
        let inode = fields[9];
        let (pid, comm) = inode_map.get(inode).cloned().unwrap_or(("?".into(), "?".into()));

        let lp = local_port.to_string();
        let rp = remote_port.to_string();

        metrics.push(gauge(
            "sentinel_tcp_socket",
            "TCP socket with full attribution",
            vec![sample(
                labels(&[
                    ("proto", proto), ("state", tcp_state_name(state)),
                    ("local_ip", &local_ip), ("local_port", &lp),
                    ("remote_ip", &remote_ip), ("remote_port", &rp),
                    ("pid", &pid), ("comm", &comm),
                ]),
                1.0,
            )],
        ));
    }
}

fn parse_socket_table6(content: &str, proto: &str, inode_map: &StdHashMap<String, (String, String)>, metrics: &mut Vec<Metric>) {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 { continue; }

        let state = fields[3];
        if state == "0A" { continue; }

        let (local_ip, local_port) = decode_addr_v6(fields[1]);
        let (remote_ip, remote_port) = decode_addr_v6(fields[2]);
        let inode = fields[9];
        let (pid, comm) = inode_map.get(inode).cloned().unwrap_or(("?".into(), "?".into()));

        let lp = local_port.to_string();
        let rp = remote_port.to_string();

        metrics.push(gauge(
            "sentinel_tcp_socket",
            "TCP socket with full attribution",
            vec![sample(
                labels(&[
                    ("proto", proto), ("state", tcp_state_name(state)),
                    ("local_ip", &local_ip), ("local_port", &lp),
                    ("remote_ip", &remote_ip), ("remote_port", &rp),
                    ("pid", &pid), ("comm", &comm),
                ]),
                1.0,
            )],
        ));
    }
}

fn parse_udp_table(content: &str, proto: &str, inode_map: &StdHashMap<String, (String, String)>, metrics: &mut Vec<Metric>) {
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 { continue; }

        let (local_ip, local_port) = decode_addr_v4(fields[1]);
        let inode = fields[9];
        let (pid, comm) = inode_map.get(inode).cloned().unwrap_or(("?".into(), "?".into()));

        let lp = local_port.to_string();

        metrics.push(gauge(
            "sentinel_udp_socket",
            "UDP socket with process attribution",
            vec![sample(
                labels(&[
                    ("proto", proto), ("local_ip", &local_ip), ("local_port", &lp),
                    ("pid", &pid), ("comm", &comm),
                ]),
                1.0,
            )],
        ));
    }
}
