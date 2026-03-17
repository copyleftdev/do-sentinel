pub mod auth;
pub mod connections;
pub mod cpu;
pub mod disk;
pub mod forensics;
pub mod loadavg;
pub mod memory;
pub mod network;
pub mod process;
pub mod security;

use std::collections::HashMap;

pub type MetricValue = f64;
pub type Labels = HashMap<String, String>;

#[derive(Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub help: String,
    pub metric_type: MetricType,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Clone)]
pub struct Sample {
    pub labels: Labels,
    pub value: MetricValue,
    #[allow(dead_code)]
    pub timestamp_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy)]
pub enum MetricType {
    Gauge,
    Counter,
}

impl MetricType {
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            MetricType::Gauge => "gauge",
            MetricType::Counter => "counter",
        }
    }
}

pub trait Collector: Send + Sync {
    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>>;
    fn name(&self) -> &'static str;
}

pub fn read_proc_file(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(path)
}

pub fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

pub fn sample(labels: Labels, value: f64) -> Sample {
    Sample { labels, value, timestamp_ms: None }
}

pub fn gauge(name: &str, help: &str, samples: Vec<Sample>) -> Metric {
    Metric {
        name: name.to_string(),
        help: help.to_string(),
        metric_type: MetricType::Gauge,
        samples,
    }
}

pub fn counter(name: &str, help: &str, samples: Vec<Sample>) -> Metric {
    Metric {
        name: name.to_string(),
        help: help.to_string(),
        metric_type: MetricType::Counter,
        samples,
    }
}
