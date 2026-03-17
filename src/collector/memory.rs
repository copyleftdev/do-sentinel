use super::*;

pub struct MemoryCollector;

impl Collector for MemoryCollector {
    fn name(&self) -> &'static str { "memory" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let content = read_proc_file("/proc/meminfo")?;
        let mut metrics = Vec::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 { continue; }

            let key = parts[0].trim();
            let val_str = parts[1].trim().trim_end_matches(" kB").trim();
            let val_kb: f64 = match val_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let val_bytes = val_kb * 1024.0;

            let (metric_name, help) = match key {
                "MemTotal" => ("sentinel_memory_total_bytes", "Total memory"),
                "MemFree" => ("sentinel_memory_free_bytes", "Free memory"),
                "MemAvailable" => ("sentinel_memory_available_bytes", "Available memory"),
                "Buffers" => ("sentinel_memory_buffers_bytes", "Buffer memory"),
                "Cached" => ("sentinel_memory_cached_bytes", "Cached memory"),
                "SwapTotal" => ("sentinel_swap_total_bytes", "Total swap"),
                "SwapFree" => ("sentinel_swap_free_bytes", "Free swap"),
                "SwapCached" => ("sentinel_swap_cached_bytes", "Cached swap"),
                "Active" => ("sentinel_memory_active_bytes", "Active memory"),
                "Inactive" => ("sentinel_memory_inactive_bytes", "Inactive memory"),
                "Slab" => ("sentinel_memory_slab_bytes", "Slab memory"),
                "SReclaimable" => ("sentinel_memory_sreclaimable_bytes", "Reclaimable slab"),
                "SUnreclaim" => ("sentinel_memory_sunreclaim_bytes", "Unreclaimable slab"),
                "Dirty" => ("sentinel_memory_dirty_bytes", "Dirty pages"),
                "Writeback" => ("sentinel_memory_writeback_bytes", "Writeback pages"),
                "Committed_AS" => ("sentinel_memory_committed_bytes", "Committed memory"),
                _ => continue,
            };

            metrics.push(gauge(metric_name, help, vec![sample(Labels::new(), val_bytes)]));
        }

        // PSI (Pressure Stall Information) — deeper than do-agent
        if let Ok(psi) = read_proc_file("/proc/pressure/memory") {
            parse_psi(&mut metrics, &psi, "memory");
        }
        if let Ok(psi) = read_proc_file("/proc/pressure/cpu") {
            parse_psi(&mut metrics, &psi, "cpu");
        }
        if let Ok(psi) = read_proc_file("/proc/pressure/io") {
            parse_psi(&mut metrics, &psi, "io");
        }

        Ok(metrics)
    }
}

fn parse_psi(metrics: &mut Vec<Metric>, content: &str, resource: &str) {
    for line in content.lines() {
        let stall_type = if line.starts_with("some") {
            "some"
        } else if line.starts_with("full") {
            "full"
        } else {
            continue;
        };

        for part in line.split_whitespace() {
            if let Some(rest) = part.strip_prefix("total=") {
                if let Ok(val) = rest.parse::<f64>() {
                    metrics.push(counter(
                        "sentinel_psi_total_us",
                        "Total PSI stall time in microseconds",
                        vec![sample(
                            labels(&[("resource", resource), ("type", stall_type)]),
                            val,
                        )],
                    ));
                }
            }
            for window in &["avg10", "avg60", "avg300"] {
                if let Some(rest) = part.strip_prefix(&format!("{}=", window)) {
                    if let Ok(val) = rest.parse::<f64>() {
                        metrics.push(gauge(
                            &format!("sentinel_psi_{}", window),
                            &format!("PSI {} average", window),
                            vec![sample(
                                labels(&[("resource", resource), ("type", stall_type)]),
                                val,
                            )],
                        ));
                    }
                }
            }
        }
    }
}
