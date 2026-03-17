use super::*;

pub struct NetworkCollector;

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str { "network" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let content = read_proc_file("/proc/net/dev")?;
        let mut metrics = Vec::new();

        for line in content.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 17 { continue; }

            let iface = parts[0].trim_end_matches(':');
            if iface == "lo" { continue; }

            let l = labels(&[("interface", iface)]);

            // Receive side
            if let Ok(v) = parts[1].parse::<f64>() {
                metrics.push(counter("sentinel_net_receive_bytes_total", "Total bytes received", vec![sample(l.clone(), v)]));
            }
            if let Ok(v) = parts[2].parse::<f64>() {
                metrics.push(counter("sentinel_net_receive_packets_total", "Total packets received", vec![sample(l.clone(), v)]));
            }
            if let Ok(v) = parts[3].parse::<f64>() {
                metrics.push(counter("sentinel_net_receive_errs_total", "Total receive errors", vec![sample(l.clone(), v)]));
            }
            if let Ok(v) = parts[4].parse::<f64>() {
                metrics.push(counter("sentinel_net_receive_drop_total", "Total receive drops", vec![sample(l.clone(), v)]));
            }

            // Transmit side
            if let Ok(v) = parts[9].parse::<f64>() {
                metrics.push(counter("sentinel_net_transmit_bytes_total", "Total bytes transmitted", vec![sample(l.clone(), v)]));
            }
            if let Ok(v) = parts[10].parse::<f64>() {
                metrics.push(counter("sentinel_net_transmit_packets_total", "Total packets transmitted", vec![sample(l.clone(), v)]));
            }
            if let Ok(v) = parts[11].parse::<f64>() {
                metrics.push(counter("sentinel_net_transmit_errs_total", "Total transmit errors", vec![sample(l.clone(), v)]));
            }
            if let Ok(v) = parts[12].parse::<f64>() {
                metrics.push(counter("sentinel_net_transmit_drop_total", "Total transmit drops", vec![sample(l.clone(), v)]));
            }
        }

        // TCP connection states — deeper than do-agent
        if let Ok(tcp) = read_proc_file("/proc/net/tcp") {
            let mut states: HashMap<&str, f64> = HashMap::new();
            for line in tcp.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 { continue; }
                let state_hex = fields[3];
                let state_name = match state_hex {
                    "01" => "ESTABLISHED",
                    "02" => "SYN_SENT",
                    "03" => "SYN_RECV",
                    "04" => "FIN_WAIT1",
                    "05" => "FIN_WAIT2",
                    "06" => "TIME_WAIT",
                    "07" => "CLOSE",
                    "08" => "CLOSE_WAIT",
                    "09" => "LAST_ACK",
                    "0A" => "LISTEN",
                    "0B" => "CLOSING",
                    _ => "UNKNOWN",
                };
                *states.entry(state_name).or_insert(0.0) += 1.0;
            }
            for (state, count) in &states {
                metrics.push(gauge(
                    "sentinel_tcp_connections",
                    "TCP connections by state",
                    vec![sample(labels(&[("state", state)]), *count)],
                ));
            }
        }

        // /proc/net/snmp for TCP retransmits — deeper than do-agent
        if let Ok(snmp) = read_proc_file("/proc/net/snmp") {
            let lines: Vec<&str> = snmp.lines().collect();
            for i in (0..lines.len()).step_by(2) {
                if !lines[i].starts_with("Tcp:") { continue; }
                if i + 1 >= lines.len() { break; }
                let keys: Vec<&str> = lines[i].split_whitespace().collect();
                let vals: Vec<&str> = lines[i + 1].split_whitespace().collect();
                for (j, key) in keys.iter().enumerate() {
                    if j >= vals.len() { break; }
                    match *key {
                        "RetransSegs" => {
                            if let Ok(v) = vals[j].parse::<f64>() {
                                metrics.push(counter("sentinel_tcp_retransmits_total", "TCP retransmitted segments", vec![sample(Labels::new(), v)]));
                            }
                        }
                        "ActiveOpens" => {
                            if let Ok(v) = vals[j].parse::<f64>() {
                                metrics.push(counter("sentinel_tcp_active_opens_total", "TCP active connection opens", vec![sample(Labels::new(), v)]));
                            }
                        }
                        "PassiveOpens" => {
                            if let Ok(v) = vals[j].parse::<f64>() {
                                metrics.push(counter("sentinel_tcp_passive_opens_total", "TCP passive connection opens", vec![sample(Labels::new(), v)]));
                            }
                        }
                        "CurrEstab" => {
                            if let Ok(v) = vals[j].parse::<f64>() {
                                metrics.push(gauge("sentinel_tcp_established", "Current established TCP connections", vec![sample(Labels::new(), v)]));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(metrics)
    }
}
