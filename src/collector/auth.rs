use super::*;
use std::fs;
use std::io::{BufRead, BufReader};

pub struct AuthCollector {
    pub log_path: String,
}

impl AuthCollector {
    pub fn new() -> Self {
        // Detect which auth log exists
        let path = if std::path::Path::new("/var/log/auth.log").exists() {
            "/var/log/auth.log"
        } else if std::path::Path::new("/var/log/secure").exists() {
            "/var/log/secure"
        } else {
            "/var/log/auth.log"
        };
        Self { log_path: path.to_string() }
    }
}

impl Collector for AuthCollector {
    fn name(&self) -> &'static str { "auth" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let mut metrics = Vec::new();

        // --- Parse auth log (tail last ~500 lines for performance) ---
        let mut ssh_failed = 0.0_f64;
        let mut ssh_accepted = 0.0_f64;
        let mut ssh_invalid_user = 0.0_f64;
        let mut sudo_success = 0.0_f64;
        let mut sudo_fail = 0.0_f64;
        let mut session_opened = 0.0_f64;
        let mut session_closed = 0.0_f64;

        let mut failed_ips: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
        let mut failed_users: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
        let mut accepted_users: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

        if let Ok(file) = fs::File::open(&self.log_path) {
            let reader = BufReader::new(file);
            // Read all lines (auth.log is typically small on droplets)
            // In production you'd track file offset; for now parse the whole file
            let lines: Vec<String> = reader.lines()
                .filter_map(|l| l.ok())
                .collect();

            // Only process recent lines (last 2000)
            let start = if lines.len() > 2000 { lines.len() - 2000 } else { 0 };

            for line in &lines[start..] {
                // SSH failed password
                if line.contains("Failed password") {
                    ssh_failed += 1.0;
                    if let Some(ip) = extract_ip_from_line(line) {
                        *failed_ips.entry(ip).or_insert(0.0) += 1.0;
                    }
                    if let Some(user) = extract_user_from_failed(line) {
                        *failed_users.entry(user).or_insert(0.0) += 1.0;
                    }
                }
                // SSH accepted
                else if line.contains("Accepted") && (line.contains("publickey") || line.contains("password")) {
                    ssh_accepted += 1.0;
                    if let Some(user) = extract_user_from_accepted(line) {
                        *accepted_users.entry(user).or_insert(0.0) += 1.0;
                    }
                }
                // Invalid user attempts
                else if line.contains("Invalid user") || line.contains("invalid user") {
                    ssh_invalid_user += 1.0;
                    if let Some(ip) = extract_ip_from_line(line) {
                        *failed_ips.entry(ip).or_insert(0.0) += 1.0;
                    }
                }
                // sudo
                else if line.contains("sudo:") {
                    if line.contains("COMMAND=") {
                        sudo_success += 1.0;
                    }
                    if line.contains("authentication failure") || line.contains("incorrect password") {
                        sudo_fail += 1.0;
                    }
                }
                // PAM session
                else if line.contains("session opened") {
                    session_opened += 1.0;
                } else if line.contains("session closed") {
                    session_closed += 1.0;
                }
            }
        }

        metrics.push(counter("sentinel_auth_ssh_failed_total", "Total SSH failed password attempts (recent log window)", vec![sample(Labels::new(), ssh_failed)]));
        metrics.push(counter("sentinel_auth_ssh_accepted_total", "Total SSH accepted logins (recent log window)", vec![sample(Labels::new(), ssh_accepted)]));
        metrics.push(counter("sentinel_auth_ssh_invalid_user_total", "Total SSH invalid user attempts", vec![sample(Labels::new(), ssh_invalid_user)]));
        metrics.push(counter("sentinel_auth_sudo_success_total", "Total successful sudo commands", vec![sample(Labels::new(), sudo_success)]));
        metrics.push(counter("sentinel_auth_sudo_fail_total", "Total failed sudo attempts", vec![sample(Labels::new(), sudo_fail)]));
        metrics.push(counter("sentinel_auth_session_opened_total", "Total PAM sessions opened", vec![sample(Labels::new(), session_opened)]));
        metrics.push(counter("sentinel_auth_session_closed_total", "Total PAM sessions closed", vec![sample(Labels::new(), session_closed)]));

        // Top brute-force IPs
        let mut ip_vec: Vec<_> = failed_ips.iter().collect();
        ip_vec.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
        for (ip, count) in ip_vec.iter().take(50) {
            metrics.push(gauge(
                "sentinel_auth_failed_by_ip",
                "Failed SSH attempts per source IP",
                vec![sample(labels(&[("ip", ip)]), **count)],
            ));
        }

        // Top targeted usernames
        let mut user_vec: Vec<_> = failed_users.iter().collect();
        user_vec.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
        for (user, count) in user_vec.iter().take(30) {
            metrics.push(gauge(
                "sentinel_auth_failed_by_user",
                "Failed SSH attempts per target username",
                vec![sample(labels(&[("user", user)]), **count)],
            ));
        }

        // Accepted login users
        for (user, count) in &accepted_users {
            metrics.push(gauge(
                "sentinel_auth_accepted_by_user",
                "Accepted SSH logins per user",
                vec![sample(labels(&[("user", user)]), *count)],
            ));
        }

        // Brute force detection: flag IPs with >10 failures
        let brute_force_count = failed_ips.values().filter(|c| **c > 10.0).count();
        metrics.push(gauge(
            "sentinel_auth_brute_force_ips",
            "Number of IPs with >10 failed attempts (likely brute force)",
            vec![sample(Labels::new(), brute_force_count as f64)],
        ));

        // --- Currently logged-in users from utmp ---
        if let Ok(content) = std::process::Command::new("who").output() {
            let who_output = String::from_utf8_lossy(&content.stdout);
            let logged_in: Vec<&str> = who_output.lines().collect();
            metrics.push(gauge(
                "sentinel_auth_users_logged_in",
                "Currently logged-in users",
                vec![sample(Labels::new(), logged_in.len() as f64)],
            ));
            for line in &logged_in {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let user = parts[0];
                    let tty = parts[1];
                    let from = if parts.len() >= 5 {
                        parts[4].trim_start_matches('(').trim_end_matches(')')
                    } else { "local" };
                    metrics.push(gauge(
                        "sentinel_auth_active_session",
                        "Active login session",
                        vec![sample(labels(&[("user", user), ("tty", tty), ("from", from)]), 1.0)],
                    ));
                }
            }
        }

        // --- Authorized keys file count ---
        if let Ok(home_entries) = fs::read_dir("/home") {
            for entry in home_entries.flatten() {
                let ak_path = entry.path().join(".ssh/authorized_keys");
                if ak_path.exists() {
                    if let Ok(content) = fs::read_to_string(&ak_path) {
                        let key_count = content.lines()
                            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                            .count();
                        let user = entry.file_name().to_string_lossy().to_string();
                        metrics.push(gauge(
                            "sentinel_auth_authorized_keys",
                            "Number of SSH authorized keys per user",
                            vec![sample(labels(&[("user", &user)]), key_count as f64)],
                        ));
                    }
                }
            }
            // Also check root
            let root_ak = std::path::Path::new("/root/.ssh/authorized_keys");
            if root_ak.exists() {
                if let Ok(content) = fs::read_to_string(root_ak) {
                    let key_count = content.lines()
                        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                        .count();
                    metrics.push(gauge(
                        "sentinel_auth_authorized_keys",
                        "Number of SSH authorized keys per user",
                        vec![sample(labels(&[("user", "root")]), key_count as f64)],
                    ));
                }
            }
        }

        Ok(metrics)
    }
}

fn extract_ip_from_line(line: &str) -> Option<String> {
    // Look for "from X.X.X.X" pattern
    if let Some(idx) = line.find("from ") {
        let rest = &line[idx + 5..];
        let ip: String = rest.chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if ip.contains('.') && ip.len() >= 7 {
            return Some(ip);
        }
    }
    None
}

fn extract_user_from_failed(line: &str) -> Option<String> {
    // "Failed password for <user> from" or "Failed password for invalid user <user> from"
    if let Some(idx) = line.find("for invalid user ") {
        let rest = &line[idx + 17..];
        let user: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
        return Some(user);
    }
    if let Some(idx) = line.find("for ") {
        let rest = &line[idx + 4..];
        let user: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
        if user != "invalid" {
            return Some(user);
        }
    }
    None
}

fn extract_user_from_accepted(line: &str) -> Option<String> {
    // "Accepted publickey for <user> from"
    if let Some(idx) = line.find("for ") {
        let rest = &line[idx + 4..];
        let user: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
        return Some(user);
    }
    None
}
