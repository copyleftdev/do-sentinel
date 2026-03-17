use super::*;
use std::fs;
use std::os::unix::fs::MetadataExt;

pub struct ForensicsCollector;

impl Collector for ForensicsCollector {
    fn name(&self) -> &'static str { "forensics" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let mut metrics = Vec::new();

        let mut deleted_binary_count = 0.0_f64;
        let mut memfd_count = 0.0_f64;
        let mut suspicious_cmdline_count = 0.0_f64;

        for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
            let name = entry.file_name();
            let pid_str = name.to_string_lossy().to_string();
            if pid_str.parse::<u32>().is_err() { continue; }

            // --- Deleted binary detection ---
            // A process whose executable has been deleted from disk but still runs in memory
            let exe_path = format!("/proc/{}/exe", pid_str);
            if let Ok(link) = fs::read_link(&exe_path) {
                let link_str = link.to_string_lossy().to_string();
                if link_str.contains("(deleted)") {
                    deleted_binary_count += 1.0;
                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                        .unwrap_or_default().trim().to_string();
                    metrics.push(gauge(
                        "sentinel_forensic_deleted_binary",
                        "Process running from a deleted binary (high suspicion)",
                        vec![sample(
                            labels(&[("pid", &pid_str), ("comm", &comm), ("exe", &link_str)]),
                            1.0,
                        )],
                    ));
                }

                // --- memfd_create detection ---
                // Fileless malware executes from anonymous memory-backed fds
                if link_str.starts_with("/memfd:") || link_str.contains("memfd:") {
                    memfd_count += 1.0;
                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                        .unwrap_or_default().trim().to_string();
                    metrics.push(gauge(
                        "sentinel_forensic_memfd_exec",
                        "Process executing from memfd (fileless execution indicator)",
                        vec![sample(
                            labels(&[("pid", &pid_str), ("comm", &comm), ("exe", &link_str)]),
                            1.0,
                        )],
                    ));
                }
            }

            // --- Suspicious command lines ---
            if let Ok(cmdline_raw) = fs::read_to_string(format!("/proc/{}/cmdline", pid_str)) {
                let cmdline = cmdline_raw.replace('\0', " ").trim().to_string();
                let suspicious = is_suspicious_cmdline(&cmdline);
                if suspicious {
                    suspicious_cmdline_count += 1.0;
                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                        .unwrap_or_default().trim().to_string();
                    metrics.push(gauge(
                        "sentinel_forensic_suspicious_cmdline",
                        "Process with suspicious command line pattern",
                        vec![sample(
                            labels(&[("pid", &pid_str), ("comm", &comm), ("cmdline", &truncate_str(&cmdline, 200))]),
                            1.0,
                        )],
                    ));
                }
            }

            // --- Process wchan (what is each process waiting on) ---
            if let Ok(wchan) = fs::read_to_string(format!("/proc/{}/wchan", pid_str)) {
                let wchan = wchan.trim();
                // Flag processes stuck in interesting kernel wait states
                if wchan == "ptrace_stop" || wchan == "do_coredump" {
                    let comm = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                        .unwrap_or_default().trim().to_string();
                    metrics.push(gauge(
                        "sentinel_forensic_interesting_wchan",
                        "Process in notable kernel wait state",
                        vec![sample(
                            labels(&[("pid", &pid_str), ("comm", &comm), ("wchan", wchan)]),
                            1.0,
                        )],
                    ));
                }
            }

            // --- Namespace detection (containerized / sandboxed) ---
            let pid_ns = fs::read_link(format!("/proc/{}/ns/pid", pid_str))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let init_pid_ns = fs::read_link("/proc/1/ns/pid")
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            if !pid_ns.is_empty() && !init_pid_ns.is_empty() && pid_ns != init_pid_ns {
                let comm = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                    .unwrap_or_default().trim().to_string();
                metrics.push(gauge(
                    "sentinel_forensic_different_namespace",
                    "Process in a different PID namespace (container/sandbox)",
                    vec![sample(
                        labels(&[("pid", &pid_str), ("comm", &comm), ("pid_ns", &pid_ns)]),
                        1.0,
                    )],
                ));
            }
        }

        metrics.push(gauge("sentinel_forensic_deleted_binaries_total", "Total processes running deleted binaries", vec![sample(Labels::new(), deleted_binary_count)]));
        metrics.push(gauge("sentinel_forensic_memfd_execs_total", "Total processes executing from memfd", vec![sample(Labels::new(), memfd_count)]));
        metrics.push(gauge("sentinel_forensic_suspicious_cmdlines_total", "Total processes with suspicious cmdlines", vec![sample(Labels::new(), suspicious_cmdline_count)]));

        // --- SUID/SGID binary scan on key directories ---
        let mut suid_count = 0.0_f64;
        let scan_dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/tmp", "/var/tmp", "/dev/shm"];
        for dir in &scan_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        let mode = meta.mode();
                        // SUID (0o4000) or SGID (0o2000)
                        if (mode & 0o4000 != 0) || (mode & 0o2000 != 0) {
                            suid_count += 1.0;
                            let path = entry.path().to_string_lossy().to_string();
                            let suid_type = if mode & 0o4000 != 0 { "suid" } else { "sgid" };
                            // SUID in /tmp, /var/tmp, /dev/shm is extremely suspicious
                            let severity = if dir.starts_with("/tmp") || dir.starts_with("/var/tmp") || dir.starts_with("/dev/shm") {
                                "critical"
                            } else {
                                "info"
                            };
                            metrics.push(gauge(
                                "sentinel_forensic_suid_binary",
                                "SUID/SGID binary found",
                                vec![sample(
                                    labels(&[("path", &path), ("type", suid_type), ("severity", severity), ("dir", dir)]),
                                    1.0,
                                )],
                            ));
                        }
                    }
                }
            }
        }
        metrics.push(gauge("sentinel_forensic_suid_binaries_total", "Total SUID/SGID binaries in scanned dirs", vec![sample(Labels::new(), suid_count)]));

        // --- World-writable files in sensitive locations ---
        let mut world_writable_count = 0.0_f64;
        let sensitive_dirs = ["/etc", "/usr/lib/systemd/system", "/usr/lib/cron"];
        for dir in &sensitive_dirs {
            scan_world_writable(dir, &mut metrics, &mut world_writable_count, 2);
        }
        metrics.push(gauge("sentinel_forensic_world_writable_sensitive", "World-writable files in sensitive dirs", vec![sample(Labels::new(), world_writable_count)]));

        // --- /dev/shm contents (tmpfs often used for staging) ---
        let mut shm_file_count = 0.0_f64;
        if let Ok(entries) = fs::read_dir("/dev/shm") {
            for entry in entries.flatten() {
                shm_file_count += 1.0;
                let path = entry.path().to_string_lossy().to_string();
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let executable = entry.metadata().map(|m| m.mode() & 0o111 != 0).unwrap_or(false);
                metrics.push(gauge(
                    "sentinel_forensic_shm_file",
                    "File in /dev/shm (in-memory tmpfs, often used for staging)",
                    vec![sample(
                        labels(&[
                            ("path", &path),
                            ("size_bytes", &size.to_string()),
                            ("executable", if executable { "true" } else { "false" }),
                        ]),
                        size as f64,
                    )],
                ));
            }
        }
        metrics.push(gauge("sentinel_forensic_shm_files_total", "Total files in /dev/shm", vec![sample(Labels::new(), shm_file_count)]));

        // --- Loaded kernel modules ---
        if let Ok(content) = read_proc_file("/proc/modules") {
            let mut module_count = 0.0_f64;
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 3 { continue; }
                module_count += 1.0;
                let name = parts[0];
                let size = parts[1];
                let state = if parts.len() > 4 { parts[4] } else { "?" };
                metrics.push(gauge(
                    "sentinel_kernel_module",
                    "Loaded kernel module",
                    vec![sample(
                        labels(&[("name", name), ("size", size), ("state", state)]),
                        1.0,
                    )],
                ));
            }
            metrics.push(gauge("sentinel_kernel_modules_total", "Total loaded kernel modules", vec![sample(Labels::new(), module_count)]));
        }

        // --- Uptime ---
        if let Ok(content) = read_proc_file("/proc/uptime") {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if let Some(up) = parts.first() {
                if let Ok(val) = up.parse::<f64>() {
                    metrics.push(gauge("sentinel_uptime_seconds", "System uptime in seconds", vec![sample(Labels::new(), val)]));
                }
            }
        }

        Ok(metrics)
    }
}

fn is_suspicious_cmdline(cmdline: &str) -> bool {
    let lower = cmdline.to_lowercase();
    let trimmed = lower.trim();

    // Whitelist: plain interactive shells are not suspicious
    if trimmed.ends_with("zsh -i") || trimmed.ends_with("bash -i") || trimmed.ends_with("sh -i") {
        let word_count = trimmed.split_whitespace().count();
        if word_count <= 3 { return false; }
    }

    // High-confidence patterns: any single hit is enough
    let instant_flags = [
        "/dev/tcp/", "/dev/udp/",
        "| bash", "| sh",
        "mkfifo", "LD_PRELOAD",
        "history -c", "unset HISTFILE",
        "etc/shadow",
        ".onion",
    ];
    for p in &instant_flags {
        if lower.contains(p) { return true; }
    }

    // Multi-hit patterns: need >=2 to flag
    let patterns = [
        "curl", "wget", "nc ", "ncat", "netcat",
        "base64", "eval ", "exec ",
        "python -c", "python3 -c", "perl -e", "ruby -e",
        "bash -i >& ", "nohup", "setsid",
        "/tmp/", "/var/tmp/", "/dev/shm/",
        "chmod +x", "chmod 777",
        "socat",
        "reverse", "bind.*shell",
        "LD_LIBRARY_PATH",
        "whoami", "id;", "uname -a",
        "etc/passwd",
        "proxychains",
    ];

    let hit_count: usize = patterns.iter()
        .filter(|p| lower.contains(*p))
        .count();

    hit_count >= 2
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}...", &s[..max]) }
}

fn scan_world_writable(dir: &str, metrics: &mut Vec<Metric>, count: &mut f64, max_depth: u32) {
    if max_depth == 0 { return; }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if let Ok(meta) = entry.metadata() {
            let mode = meta.mode();
            if meta.is_file() && (mode & 0o002 != 0) {
                *count += 1.0;
                let path = entry.path().to_string_lossy().to_string();
                metrics.push(gauge(
                    "sentinel_forensic_world_writable_file",
                    "World-writable file in sensitive directory",
                    vec![sample(labels(&[("path", &path)]), 1.0)],
                ));
            }
            if meta.is_dir() {
                let sub = entry.path().to_string_lossy().to_string();
                scan_world_writable(&sub, metrics, count, max_depth - 1);
            }
        }
    }
}
