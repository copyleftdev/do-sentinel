use super::*;

pub struct CpuCollector;

impl Collector for CpuCollector {
    fn name(&self) -> &'static str { "cpu" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let content = read_proc_file("/proc/stat")?;
        let mut metrics = Vec::new();

        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("cpu") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() < 8 { continue; }

                let cpu_id = if rest.starts_with(' ') {
                    "total".to_string()
                } else {
                    let id_end = rest.find(' ').unwrap_or(0);
                    rest[..id_end].to_string()
                };

                let modes = [
                    ("user", 0), ("nice", 1), ("system", 2), ("idle", 3),
                    ("iowait", 4), ("irq", 5), ("softirq", 6), ("steal", 7),
                ];

                // /proc/stat values are in jiffies (USER_HZ, typically 100)
                let offset = if cpu_id == "total" { 0 } else { 1 };
                for (mode, idx) in modes {
                    if let Ok(val) = parts[idx + offset].parse::<f64>() {
                        let jiffies_to_seconds = val / 100.0;
                        metrics.push(counter(
                            "sentinel_cpu_seconds_total",
                            "CPU time in seconds per mode",
                            vec![sample(
                                labels(&[("cpu", &cpu_id), ("mode", mode)]),
                                jiffies_to_seconds,
                            )],
                        ));
                    }
                }
            } else if let Some(rest) = line.strip_prefix("ctxt ") {
                if let Ok(val) = rest.trim().parse::<f64>() {
                    metrics.push(counter(
                        "sentinel_context_switches_total",
                        "Total context switches",
                        vec![sample(Labels::new(), val)],
                    ));
                }
            } else if let Some(rest) = line.strip_prefix("processes ") {
                if let Ok(val) = rest.trim().parse::<f64>() {
                    metrics.push(counter(
                        "sentinel_forks_total",
                        "Total forks",
                        vec![sample(Labels::new(), val)],
                    ));
                }
            } else if let Some(rest) = line.strip_prefix("procs_running ") {
                if let Ok(val) = rest.trim().parse::<f64>() {
                    metrics.push(gauge(
                        "sentinel_procs_running",
                        "Number of running processes",
                        vec![sample(Labels::new(), val)],
                    ));
                }
            } else if let Some(rest) = line.strip_prefix("procs_blocked ") {
                if let Ok(val) = rest.trim().parse::<f64>() {
                    metrics.push(gauge(
                        "sentinel_procs_blocked",
                        "Number of blocked processes",
                        vec![sample(Labels::new(), val)],
                    ));
                }
            }
        }

        Ok(metrics)
    }
}
