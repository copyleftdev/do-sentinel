use super::*;

pub struct LoadAvgCollector;

impl Collector for LoadAvgCollector {
    fn name(&self) -> &'static str { "loadavg" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let content = read_proc_file("/proc/loadavg")?;
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() < 5 {
            return Err("unexpected /proc/loadavg format".into());
        }

        let mut metrics = Vec::new();

        if let Ok(v) = parts[0].parse::<f64>() {
            metrics.push(gauge("sentinel_load1", "1-minute load average", vec![sample(Labels::new(), v)]));
        }
        if let Ok(v) = parts[1].parse::<f64>() {
            metrics.push(gauge("sentinel_load5", "5-minute load average", vec![sample(Labels::new(), v)]));
        }
        if let Ok(v) = parts[2].parse::<f64>() {
            metrics.push(gauge("sentinel_load15", "15-minute load average", vec![sample(Labels::new(), v)]));
        }

        // running/total threads
        if let Some((running, total)) = parts[3].split_once('/') {
            if let Ok(v) = running.parse::<f64>() {
                metrics.push(gauge("sentinel_threads_running", "Running threads", vec![sample(Labels::new(), v)]));
            }
            if let Ok(v) = total.parse::<f64>() {
                metrics.push(gauge("sentinel_threads_total", "Total threads", vec![sample(Labels::new(), v)]));
            }
        }

        Ok(metrics)
    }
}
