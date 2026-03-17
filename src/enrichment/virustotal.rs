use crate::collector::{gauge, labels, sample, Metric};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const VT_API_BASE: &str = "https://www.virustotal.com/api/v3/ip_addresses";
const CACHE_TTL: Duration = Duration::from_secs(24 * 3600); // 24 hours
const RATE_INTERVAL: Duration = Duration::from_secs(15); // 4 per minute

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct VtIpReport {
    pub ip: String,
    pub malicious: u64,
    pub suspicious: u64,
    pub harmless: u64,
    pub undetected: u64,
    pub reputation: i64,
    pub country: String,
    pub as_owner: String,
    pub asn: u64,
    pub fetched_at: Instant,
}

pub struct VtEnricher {
    api_key: String,
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, VtIpReport>>>,
    debug: bool,
}

impl VtEnricher {
    pub fn new(api_key: String, debug: bool) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        Self {
            api_key,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            debug,
        }
    }

    pub fn cache_handle(&self) -> Arc<RwLock<HashMap<String, VtIpReport>>> {
        Arc::clone(&self.cache)
    }

    /// Run the background enrichment loop. Receives IPs to look up via the channel.
    pub async fn run(&self, mut rx: tokio::sync::mpsc::Receiver<Vec<(String, u64)>>) {
        loop {
            // Wait for a batch of (ip, connection_count) pairs
            let batch = match rx.recv().await {
                Some(b) => b,
                None => return, // channel closed
            };

            // Filter out private IPs and already-cached (fresh) IPs
            let mut to_lookup: Vec<(String, u64)> = Vec::new();
            for (ip, count) in batch {
                if is_private_ip(&ip) {
                    continue;
                }
                let cached_fresh = self.cache.read().ok().map_or(false, |c| {
                    c.get(&ip).map_or(false, |r| r.fetched_at.elapsed() < CACHE_TTL)
                });
                if !cached_fresh {
                    to_lookup.push((ip, count));
                }
            }

            // Sort by connection count descending — enrich highest-traffic IPs first
            to_lookup.sort_by(|a, b| b.1.cmp(&a.1));

            for (ip, _count) in to_lookup {
                if self.debug {
                    eprintln!("[vt] looking up {}", ip);
                }

                match self.lookup_ip(&ip).await {
                    Ok(report) => {
                        if self.debug {
                            eprintln!(
                                "[vt] {} => mal={} sus={} rep={} country={} as={}",
                                ip, report.malicious, report.suspicious,
                                report.reputation, report.country, report.as_owner
                            );
                        }
                        if let Ok(mut cache) = self.cache.write() {
                            cache.insert(ip, report);
                        }
                    }
                    Err(e) => {
                        eprintln!("[vt] lookup error for {}: {}", ip, e);
                    }
                }

                // Rate limit: wait 15s between requests (4/min)
                tokio::time::sleep(RATE_INTERVAL).await;
            }
        }
    }

    async fn lookup_ip(&self, ip: &str) -> Result<VtIpReport, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!("{}/{}", VT_API_BASE, ip);
        let resp = self.client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("VT API {} — {}", status, body).into());
        }

        let json: serde_json::Value = resp.json().await?;
        let attrs = &json["data"]["attributes"];

        let stats = &attrs["last_analysis_stats"];
        Ok(VtIpReport {
            ip: ip.to_string(),
            malicious: stats["malicious"].as_u64().unwrap_or(0),
            suspicious: stats["suspicious"].as_u64().unwrap_or(0),
            harmless: stats["harmless"].as_u64().unwrap_or(0),
            undetected: stats["undetected"].as_u64().unwrap_or(0),
            reputation: attrs["reputation"].as_i64().unwrap_or(0),
            country: attrs["country"].as_str().unwrap_or("--").to_string(),
            as_owner: attrs["as_owner"].as_str().unwrap_or("--").to_string(),
            asn: attrs["asn"].as_u64().unwrap_or(0),
            fetched_at: Instant::now(),
        })
    }
}

/// Convert cached VT reports into Prometheus-style metrics
pub fn vt_cache_to_metrics(cache: &Arc<RwLock<HashMap<String, VtIpReport>>>) -> Vec<Metric> {
    let mut metrics = Vec::new();

    let reports: Vec<VtIpReport> = match cache.read() {
        Ok(c) => c.values()
            .filter(|r| r.fetched_at.elapsed() < CACHE_TTL)
            .cloned()
            .collect(),
        Err(_) => return metrics,
    };

    if reports.is_empty() {
        return metrics;
    }

    // Summary counts
    let total = reports.len() as f64;
    let flagged = reports.iter().filter(|r| r.malicious > 0).count() as f64;
    let suspicious = reports.iter().filter(|r| r.suspicious > 0).count() as f64;

    metrics.push(gauge(
        "sentinel_vt_ips_enriched",
        "Total unique IPs enriched via VirusTotal",
        vec![sample(labels(&[]), total)],
    ));
    metrics.push(gauge(
        "sentinel_vt_ips_flagged_malicious",
        "IPs flagged malicious by at least one VT engine",
        vec![sample(labels(&[]), flagged)],
    ));
    metrics.push(gauge(
        "sentinel_vt_ips_flagged_suspicious",
        "IPs flagged suspicious by at least one VT engine",
        vec![sample(labels(&[]), suspicious)],
    ));

    // Per-IP detail metrics
    for r in &reports {
        let ip = r.ip.as_str();
        let country = r.country.as_str();
        let as_owner = r.as_owner.as_str();
        let asn_str = r.asn.to_string();

        metrics.push(gauge(
            "sentinel_vt_ip_malicious",
            "VT engines flagging this IP as malicious",
            vec![sample(
                labels(&[("ip", ip), ("country", country), ("as_owner", as_owner), ("asn", &asn_str)]),
                r.malicious as f64,
            )],
        ));
        metrics.push(gauge(
            "sentinel_vt_ip_suspicious",
            "VT engines flagging this IP as suspicious",
            vec![sample(
                labels(&[("ip", ip), ("country", country), ("as_owner", as_owner)]),
                r.suspicious as f64,
            )],
        ));
        metrics.push(gauge(
            "sentinel_vt_ip_reputation",
            "VT community reputation score for this IP",
            vec![sample(
                labels(&[("ip", ip), ("country", country), ("as_owner", as_owner)]),
                r.reputation as f64,
            )],
        ));
    }

    metrics
}

fn is_private_ip(ip: &str) -> bool {
    if ip.starts_with("10.")
        || ip.starts_with("127.")
        || ip.starts_with("169.254.")
        || ip.starts_with("::1")
        || ip.starts_with("fe80:")
        || ip.starts_with("fd")
    {
        return true;
    }
    // 172.16.0.0/12
    if ip.starts_with("172.") {
        if let Some(second) = ip.split('.').nth(1) {
            if let Ok(n) = second.parse::<u8>() {
                if (16..=31).contains(&n) {
                    return true;
                }
            }
        }
    }
    // 192.168.0.0/16
    if ip.starts_with("192.168.") {
        return true;
    }
    false
}
