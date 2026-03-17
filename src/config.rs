use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "do-sentinel", about = "Lightweight Rust metrics agent")]
pub struct Config {
    /// Port for Prometheus /metrics endpoint
    #[arg(long, default_value = "9101")]
    pub port: u16,

    /// Bind address
    #[arg(long, default_value = "0.0.0.0")]
    pub bind: String,

    /// RocksDB data directory
    #[arg(long, default_value = "/var/lib/do-sentinel")]
    pub data_dir: PathBuf,

    /// Collection interval in seconds
    #[arg(long, default_value = "10")]
    pub interval: u64,

    /// Top-K processes by CPU
    #[arg(long, default_value = "30")]
    pub top_k: usize,

    /// Disable process collection
    #[arg(long)]
    pub no_processes: bool,

    /// Disable RocksDB persistence (metrics only served live)
    #[arg(long)]
    pub no_store: bool,

    /// Enable debug logging
    #[arg(long)]
    pub debug: bool,

    /// TLS certificate file (PEM), e.g. fullchain.pem
    #[arg(long)]
    pub tls_cert: Option<String>,

    /// TLS private key file (PEM), e.g. privkey.pem
    #[arg(long)]
    pub tls_key: Option<String>,
}
