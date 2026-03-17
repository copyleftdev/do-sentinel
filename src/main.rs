mod collector;
mod config;
mod enrichment;
mod store;

use clap::Parser;
use collector::Collector;
use config::Config;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;
use tokio::time::{interval, Duration};
use tokio_rustls::TlsAcceptor;

struct AppState {
    latest_output: RwLock<String>,
    store: Option<store::MetricStore>,
    vt_cache: Option<Arc<RwLock<std::collections::HashMap<String, enrichment::virustotal::VtIpReport>>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Install rustls crypto provider before any TLS usage (reqwest + tokio-rustls)
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let cfg = Config::parse();

    if cfg.debug {
        eprintln!("[sentinel] debug mode enabled");
        eprintln!("[sentinel] config: {:?}", cfg);
    }

    let db = if cfg.no_store {
        None
    } else {
        std::fs::create_dir_all(&cfg.data_dir)?;
        Some(store::MetricStore::open(&cfg.data_dir)?)
    };

    // VT enricher setup
    let (vt_tx, vt_cache) = if let Some(ref api_key) = cfg.vt_api_key {
        let enricher = enrichment::virustotal::VtEnricher::new(api_key.clone(), cfg.debug);
        let cache = enricher.cache_handle();
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<(String, u64)>>(16);
        tokio::spawn(async move { enricher.run(rx).await });
        if cfg.debug {
            eprintln!("[sentinel] VirusTotal enrichment enabled");
        }
        (Some(tx), Some(cache))
    } else {
        (None, None)
    };

    let state = Arc::new(AppState {
        latest_output: RwLock::new(String::new()),
        store: db,
        vt_cache: vt_cache,
    });

    // Build collectors
    let mut collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(collector::cpu::CpuCollector),
        Box::new(collector::memory::MemoryCollector),
        Box::new(collector::disk::DiskCollector),
        Box::new(collector::network::NetworkCollector),
        Box::new(collector::loadavg::LoadAvgCollector),
        Box::new(collector::security::SecurityCollector),
        Box::new(collector::connections::ConnectionsCollector),
        Box::new(collector::forensics::ForensicsCollector),
        Box::new(collector::auth::AuthCollector::new()),
    ];

    if !cfg.no_processes {
        collectors.push(Box::new(collector::process::ProcessCollector::new(cfg.top_k)));
    }

    let interval_secs = cfg.interval;
    let debug = cfg.debug;

    // Collector loop
    let collect_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(interval_secs));
        loop {
            tick.tick().await;

            let start = std::time::Instant::now();
            let mut all_metrics = Vec::new();

            for c in &collectors {
                match c.collect() {
                    Ok(mut m) => all_metrics.append(&mut m),
                    Err(e) => eprintln!("[sentinel] collector {} error: {}", c.name(), e),
                }
            }

            // Feed unique remote peer IPs to VT enricher
            if let Some(ref tx) = vt_tx {
                let mut ip_counts: Vec<(String, u64)> = Vec::new();
                for m in &all_metrics {
                    if m.name == "sentinel_remote_peer_connections" {
                        for s in &m.samples {
                            if let Some(ip) = s.labels.get("remote_ip") {
                                ip_counts.push((ip.clone(), s.value as u64));
                            }
                        }
                    }
                }
                if !ip_counts.is_empty() {
                    let _ = tx.try_send(ip_counts);
                }
            }

            // Append VT enrichment metrics
            if let Some(ref vt_cache) = collect_state.vt_cache {
                let mut vt_metrics = enrichment::virustotal::vt_cache_to_metrics(vt_cache);
                all_metrics.append(&mut vt_metrics);
            }

            let elapsed = start.elapsed();
            if debug {
                eprintln!("[sentinel] collected {} metrics in {:?}", all_metrics.len(), elapsed);
            }

            // Store to sled
            if let Some(ref db) = collect_state.store {
                if let Err(e) = db.store_metrics(&all_metrics) {
                    eprintln!("[sentinel] store error: {}", e);
                }
            }

            // Render Prometheus text
            let output = store::format_prometheus(&all_metrics);
            if let Ok(mut w) = collect_state.latest_output.write() {
                *w = output;
            }
        }
    });

    // Build optional TLS acceptor
    let tls_acceptor = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_file = &mut BufReader::new(std::fs::File::open(cert_path)?);
            let key_file = &mut BufReader::new(std::fs::File::open(key_path)?);

            let certs: Vec<_> = rustls_pemfile::certs(cert_file)
                .filter_map(|c| c.ok())
                .collect();
            let key = rustls_pemfile::private_key(key_file)?
                .ok_or("no private key found in PEM file")?;

            let tls_config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| format!("TLS config error: {}", e))?;

            Some(TlsAcceptor::from(Arc::new(tls_config)))
        }
        _ => None,
    };

    let scheme = if tls_acceptor.is_some() { "https" } else { "http" };
    let addr: SocketAddr = format!("{}:{}", cfg.bind, cfg.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    eprintln!("[sentinel] listening on {}://{}/metrics", scheme, addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let svc_state = Arc::clone(&state);
        let tls = tls_acceptor.clone();

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let st = Arc::clone(&svc_state);
                async move { handle_request(req, st) }
            });

            if let Some(acceptor) = tls {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);
                        if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                            eprintln!("[sentinel] tls connection error: {}", e);
                        }
                    }
                    Err(e) => eprintln!("[sentinel] tls handshake error: {}", e),
                }
            } else {
                let io = TokioIo::new(stream);
                if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                    eprintln!("[sentinel] connection error: {}", e);
                }
            }
        });
    }
}

const DASHBOARD_HTML: &str = include_str!("dashboard/index.html");

fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    match path {
        "/metrics" => {
            let body = state.latest_output.read()
                .map(|s| s.clone())
                .unwrap_or_default();
            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .unwrap())
        }
        "/health" => {
            Ok(Response::builder()
                .status(200)
                .body(Full::new(Bytes::from("ok")))
                .unwrap())
        }
        "/boto" | "/boto/" => {
            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Cache-Control", "no-store")
                .body(Full::new(Bytes::from(DASHBOARD_HTML)))
                .unwrap())
        }
        "/boto/api/metrics" => {
            let prom_text = state.latest_output.read()
                .map(|s| s.clone())
                .unwrap_or_default();
            let json = prometheus_to_json(&prom_text);
            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .header("Cache-Control", "no-store")
                .body(Full::new(Bytes::from(json)))
                .unwrap())
        }
        _ => {
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("not found")))
                .unwrap())
        }
    }
}

fn prometheus_to_json(text: &str) -> String {
    use std::collections::HashMap;
    let mut metrics: HashMap<String, Vec<String>> = HashMap::new();

    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() { continue; }

        // Parse: name{label="val",...} value  OR  name value
        let (name, labels_json, value) = if let Some(brace_start) = line.find('{') {
            let brace_end = line.find('}').unwrap_or(line.len());
            let name = &line[..brace_start];
            let labels_raw = &line[brace_start + 1..brace_end];
            let value_str = line[brace_end + 1..].trim();

            let mut label_parts = Vec::new();
            // Parse labels carefully (values may contain commas in quotes)
            let mut in_quotes = false;
            let mut current = String::new();
            for ch in labels_raw.chars() {
                match ch {
                    '"' => { in_quotes = !in_quotes; current.push(ch); }
                    ',' if !in_quotes => {
                        if !current.is_empty() {
                            label_parts.push(current.clone());
                            current.clear();
                        }
                    }
                    _ => current.push(ch),
                }
            }
            if !current.is_empty() { label_parts.push(current); }

            let mut labels_json_parts = Vec::new();
            for part in &label_parts {
                if let Some(eq) = part.find('=') {
                    let k = &part[..eq];
                    let v = part[eq + 1..].trim_matches('"');
                    let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
                    labels_json_parts.push(format!("\"{}\":\"{}\"", k, escaped));
                }
            }

            (name, format!("{{{}}}", labels_json_parts.join(",")), value_str.to_string())
        } else {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 { continue; }
            (parts[0], "{}".to_string(), parts[1].to_string())
        };

        let entry = format!("{{\"labels\":{},\"value\":{}}}", labels_json, value);
        metrics.entry(name.to_string()).or_default().push(entry);
    }

    let mut json = String::from("{");
    let mut first = true;
    for (name, samples) in &metrics {
        if !first { json.push(','); }
        first = false;
        json.push_str(&format!("\"{}\":[{}]", name, samples.join(",")));
    }
    json.push('}');
    json
}
