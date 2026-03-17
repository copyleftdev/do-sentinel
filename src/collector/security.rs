use super::*;
use std::fs;

pub struct SecurityCollector;

impl Collector for SecurityCollector {
    fn name(&self) -> &'static str { "security" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let mut metrics = Vec::new();

        // --- Kernel hardening state ---
        let hardening_checks: Vec<(&str, &str, &str)> = vec![
            ("/proc/sys/kernel/randomize_va_space", "sentinel_kernel_aslr", "ASLR status (0=off, 1=partial, 2=full)"),
            ("/proc/sys/kernel/kptr_restrict", "sentinel_kernel_kptr_restrict", "Kernel pointer restriction (0=off, 1=hide from non-root, 2=hide from all)"),
            ("/proc/sys/kernel/dmesg_restrict", "sentinel_kernel_dmesg_restrict", "dmesg access restriction (0=off, 1=restricted)"),
            ("/proc/sys/kernel/perf_event_paranoid", "sentinel_kernel_perf_paranoid", "perf_event access level (-1=allow all, 0-3=increasingly restricted)"),
            ("/proc/sys/kernel/modules_disabled", "sentinel_kernel_modules_disabled", "Kernel module loading disabled (0=allowed, 1=disabled)"),
            ("/proc/sys/kernel/sysrq", "sentinel_kernel_sysrq", "SysRq key enabled (0=disabled, >0=enabled bitmask)"),
            ("/proc/sys/kernel/core_uses_pid", "sentinel_kernel_core_uses_pid", "Core dumps include PID (0=no, 1=yes)"),
            ("/proc/sys/kernel/nmi_watchdog", "sentinel_kernel_nmi_watchdog", "NMI watchdog enabled"),
            ("/proc/sys/fs/protected_hardlinks", "sentinel_fs_protected_hardlinks", "Hardlink protection (0=off, 1=on)"),
            ("/proc/sys/fs/protected_symlinks", "sentinel_fs_protected_symlinks", "Symlink protection (0=off, 1=on)"),
            ("/proc/sys/fs/protected_regular", "sentinel_fs_protected_regular", "Regular file protection in sticky dirs"),
            ("/proc/sys/fs/protected_fifos", "sentinel_fs_protected_fifos", "FIFO protection in sticky dirs"),
            ("/proc/sys/fs/suid_dumpable", "sentinel_fs_suid_dumpable", "SUID core dump policy (0=disabled, 1=enabled, 2=suidsafe)"),
        ];

        for (path, metric_name, help) in &hardening_checks {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(val) = content.trim().parse::<f64>() {
                    metrics.push(gauge(metric_name, help, vec![sample(Labels::new(), val)]));
                }
            }
        }

        // --- Yama ptrace_scope ---
        if let Ok(content) = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            if let Ok(val) = content.trim().parse::<f64>() {
                metrics.push(gauge(
                    "sentinel_kernel_ptrace_scope",
                    "Yama ptrace scope (0=classic, 1=restricted, 2=admin-only, 3=no-attach)",
                    vec![sample(Labels::new(), val)],
                ));
            }
        }

        // --- Network hardening ---
        let net_checks: Vec<(&str, &str, &str)> = vec![
            ("/proc/sys/net/ipv4/ip_forward", "sentinel_net_ipv4_forward", "IPv4 forwarding enabled (container escape indicator)"),
            ("/proc/sys/net/ipv4/conf/all/accept_redirects", "sentinel_net_accept_redirects", "ICMP redirects accepted (0=secure)"),
            ("/proc/sys/net/ipv4/conf/all/accept_source_route", "sentinel_net_accept_source_route", "Source routing accepted (0=secure)"),
            ("/proc/sys/net/ipv4/conf/all/rp_filter", "sentinel_net_rp_filter", "Reverse path filtering (1=strict, 2=loose)"),
            ("/proc/sys/net/ipv4/conf/all/log_martians", "sentinel_net_log_martians", "Log martian packets"),
            ("/proc/sys/net/ipv4/tcp_syncookies", "sentinel_net_tcp_syncookies", "TCP SYN cookies enabled (SYN flood protection)"),
            ("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", "sentinel_net_icmp_ignore_bcast", "Ignore ICMP broadcast (smurf protection)"),
            ("/proc/sys/net/ipv6/conf/all/accept_ra", "sentinel_net_ipv6_accept_ra", "IPv6 router advertisements accepted"),
            ("/proc/sys/net/ipv6/conf/all/forwarding", "sentinel_net_ipv6_forward", "IPv6 forwarding enabled"),
        ];

        for (path, metric_name, help) in &net_checks {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(val) = content.trim().parse::<f64>() {
                    metrics.push(gauge(metric_name, help, vec![sample(Labels::new(), val)]));
                }
            }
        }

        // --- Per-process capabilities (dangerous caps on non-root procs) ---
        let _dangerous_caps = [
            "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module",
            "cap_net_admin", "cap_net_raw", "cap_dac_override",
            "cap_sys_rawio", "cap_mknod", "cap_setuid", "cap_setgid",
        ];

        let mut procs_with_caps = 0.0_f64;
        for entry in fs::read_dir("/proc").into_iter().flatten() {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.file_name();
            let pid_str = name.to_string_lossy();
            if pid_str.parse::<u32>().is_err() { continue; }

            let status = match fs::read_to_string(format!("/proc/{}/status", pid_str)) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let mut uid = 0u32;
            let mut cap_eff: u64 = 0;

            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:\t") {
                    uid = rest.split_whitespace().next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                }
                if let Some(rest) = line.strip_prefix("CapEff:\t") {
                    cap_eff = u64::from_str_radix(rest.trim(), 16).unwrap_or(0);
                }
            }

            // Non-root process with any effective capabilities
            if uid != 0 && cap_eff != 0 {
                procs_with_caps += 1.0;
                let comm = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                    .unwrap_or_default().trim().to_string();
                metrics.push(gauge(
                    "sentinel_sec_process_has_caps",
                    "Non-root process with effective capabilities",
                    vec![sample(
                        labels(&[("pid", &pid_str), ("comm", &comm), ("cap_eff", &format!("{:016x}", cap_eff))]),
                        1.0,
                    )],
                ));
            }

            // Check seccomp status
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Seccomp:\t") {
                    if let Ok(val) = rest.trim().parse::<f64>() {
                        if val == 0.0 {
                            // Process running without seccomp — only flag non-kernel threads
                            let comm = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                                .unwrap_or_default().trim().to_string();
                            if !comm.is_empty() && uid != 0 {
                                metrics.push(gauge(
                                    "sentinel_sec_no_seccomp",
                                    "Non-root process without seccomp",
                                    vec![sample(
                                        labels(&[("pid", &pid_str), ("comm", &comm)]),
                                        1.0,
                                    )],
                                ));
                            }
                        }
                    }
                }
            }
        }

        metrics.push(gauge(
            "sentinel_sec_nonroot_with_caps_total",
            "Total non-root processes with effective capabilities",
            vec![sample(Labels::new(), procs_with_caps)],
        ));

        // --- Open file descriptor limits ---
        if let Ok(content) = fs::read_to_string("/proc/sys/fs/file-nr") {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(allocated) = parts[0].parse::<f64>() {
                    metrics.push(gauge("sentinel_fs_file_nr_allocated", "Allocated file descriptors", vec![sample(Labels::new(), allocated)]));
                }
                if let Ok(max) = parts[2].parse::<f64>() {
                    metrics.push(gauge("sentinel_fs_file_nr_max", "Max file descriptors", vec![sample(Labels::new(), max)]));
                }
            }
        }

        // --- Entropy ---
        if let Ok(content) = fs::read_to_string("/proc/sys/kernel/random/entropy_avail") {
            if let Ok(val) = content.trim().parse::<f64>() {
                metrics.push(gauge("sentinel_entropy_available", "Available kernel entropy bits (low = crypto weakness)", vec![sample(Labels::new(), val)]));
            }
        }
        if let Ok(content) = fs::read_to_string("/proc/sys/kernel/random/poolsize") {
            if let Ok(val) = content.trim().parse::<f64>() {
                metrics.push(gauge("sentinel_entropy_poolsize", "Entropy pool size in bits", vec![sample(Labels::new(), val)]));
            }
        }

        Ok(metrics)
    }
}
