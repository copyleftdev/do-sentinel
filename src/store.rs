use crate::collector::{Metric, MetricType, Sample};

pub struct MetricStore {
    db: sled::Db,
}

impl MetricStore {
    pub fn open(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub fn store_metrics(&self, metrics: &[Metric]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut batch = sled::Batch::default();
        let now_ms = chrono::Utc::now().timestamp_millis();

        for metric in metrics {
            for sample in &metric.samples {
                let key = format_key(&metric.name, sample, now_ms);
                let val = sample.value.to_le_bytes();
                batch.insert(key.as_bytes(), &val[..]);
            }
        }

        self.db.apply_batch(batch)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn get_latest(&self, prefix: &str) -> Vec<(String, f64)> {
        let mut results = Vec::new();

        for item in self.db.scan_prefix(prefix.as_bytes()) {
            if let Ok((key, val)) = item {
                let key_str = String::from_utf8_lossy(&key);
                if val.len() == 8 {
                    let value = f64::from_le_bytes(val[..8].try_into().unwrap_or([0u8; 8]));
                    results.push((key_str.to_string(), value));
                }
            }
        }

        results
    }

    #[allow(dead_code)]
    pub fn flush(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.db.flush()?;
        Ok(())
    }
}

fn format_key(name: &str, sample: &Sample, ts_ms: i64) -> String {
    if sample.labels.is_empty() {
        format!("{}@{}", name, ts_ms)
    } else {
        let mut label_parts: Vec<String> = sample.labels.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();
        label_parts.sort();
        format!("{}{{{}}}@{}", name, label_parts.join(","), ts_ms)
    }
}

pub fn format_prometheus(metrics: &[Metric]) -> String {
    let mut out = String::with_capacity(metrics.len() * 128);

    // Group metrics by name to emit HELP/TYPE only once
    let mut seen_names = std::collections::HashSet::new();

    for metric in metrics {
        if seen_names.insert(&metric.name) {
            out.push_str(&format!("# HELP {} {}\n", metric.name, metric.help));
            out.push_str(&format!("# TYPE {} {}\n", metric.name, match metric.metric_type {
                MetricType::Gauge => "gauge",
                MetricType::Counter => "counter",
            }));
        }

        for sample in &metric.samples {
            if sample.labels.is_empty() {
                out.push_str(&format!("{} {}\n", metric.name, format_value(sample.value)));
            } else {
                let mut label_parts: Vec<String> = sample.labels.iter()
                    .map(|(k, v)| format!("{}=\"{}\"", k, v))
                    .collect();
                label_parts.sort();
                out.push_str(&format!("{}{{{}}} {}\n",
                    metric.name,
                    label_parts.join(","),
                    format_value(sample.value),
                ));
            }
        }
    }

    out
}

fn format_value(v: f64) -> String {
    if v == v.floor() && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}
