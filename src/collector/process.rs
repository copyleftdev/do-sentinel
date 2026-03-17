use super::*;
use std::fs;

pub struct ProcessCollector {
    pub top_k: usize,
}

impl ProcessCollector {
    pub fn new(top_k: usize) -> Self {
        Self { top_k }
    }
}

struct ProcInfo {
    pid: u32,
    comm: String,
    state: char,
    utime: f64,
    stime: f64,
    rss_bytes: f64,
    num_threads: f64,
    num_fds: f64,
    read_bytes: f64,
    write_bytes: f64,
}

fn read_proc_info(pid: u32) -> Option<ProcInfo> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;

    // comm is in parens, may contain spaces
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat[open + 1..close].to_string();
    let rest: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    if rest.len() < 22 { return None; }

    let state = rest[0].chars().next().unwrap_or('?');
    let utime: f64 = rest[11].parse().unwrap_or(0.0) / 100.0; // jiffies → seconds
    let stime: f64 = rest[12].parse().unwrap_or(0.0) / 100.0;
    let num_threads: f64 = rest[17].parse().unwrap_or(0.0);
    let rss_pages: f64 = rest[21].parse().unwrap_or(0.0);
    let rss_bytes = rss_pages * 4096.0;

    // fd count
    let num_fds = fs::read_dir(format!("/proc/{}/fd", pid))
        .map(|d| d.count() as f64)
        .unwrap_or(0.0);

    // I/O stats (may require root)
    let (read_bytes, write_bytes) = fs::read_to_string(format!("/proc/{}/io", pid))
        .map(|io| {
            let mut rb = 0.0_f64;
            let mut wb = 0.0_f64;
            for line in io.lines() {
                if let Some(v) = line.strip_prefix("read_bytes: ") {
                    rb = v.trim().parse().unwrap_or(0.0);
                } else if let Some(v) = line.strip_prefix("write_bytes: ") {
                    wb = v.trim().parse().unwrap_or(0.0);
                }
            }
            (rb, wb)
        })
        .unwrap_or((0.0, 0.0));

    Some(ProcInfo { pid, comm, state, utime, stime, rss_bytes, num_threads, num_fds, read_bytes, write_bytes })
}

impl Collector for ProcessCollector {
    fn name(&self) -> &'static str { "process" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let mut procs: Vec<ProcInfo> = Vec::new();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                if let Some(info) = read_proc_info(pid) {
                    procs.push(info);
                }
            }
        }

        // Sort by total CPU time descending, take top_k
        procs.sort_by(|a, b| {
            let a_cpu = a.utime + a.stime;
            let b_cpu = b.utime + b.stime;
            b_cpu.partial_cmp(&a_cpu).unwrap_or(std::cmp::Ordering::Equal)
        });
        procs.truncate(self.top_k);

        let mut metrics = Vec::new();

        for p in &procs {
            let pid_str = p.pid.to_string();
            let state_str = p.state.to_string();
            let l = labels(&[("pid", &pid_str), ("comm", &p.comm)]);

            metrics.push(counter(
                "sentinel_process_cpu_user_seconds",
                "Process user CPU time",
                vec![sample(l.clone(), p.utime)],
            ));
            metrics.push(counter(
                "sentinel_process_cpu_system_seconds",
                "Process system CPU time",
                vec![sample(l.clone(), p.stime)],
            ));
            metrics.push(gauge(
                "sentinel_process_rss_bytes",
                "Process resident set size",
                vec![sample(l.clone(), p.rss_bytes)],
            ));
            metrics.push(gauge(
                "sentinel_process_threads",
                "Process thread count",
                vec![sample(l.clone(), p.num_threads)],
            ));
            metrics.push(gauge(
                "sentinel_process_open_fds",
                "Process open file descriptors",
                vec![sample(l.clone(), p.num_fds)],
            ));
            metrics.push(gauge(
                "sentinel_process_state",
                "Process state",
                vec![sample(
                    labels(&[("pid", &pid_str), ("comm", &p.comm), ("state", &state_str)]),
                    1.0,
                )],
            ));
            metrics.push(counter(
                "sentinel_process_read_bytes_total",
                "Process disk read bytes",
                vec![sample(l.clone(), p.read_bytes)],
            ));
            metrics.push(counter(
                "sentinel_process_write_bytes_total",
                "Process disk write bytes",
                vec![sample(l, p.write_bytes)],
            ));
        }

        // Total process count by state
        let all_procs: Vec<ProcInfo> = fs::read_dir("/proc")?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
            .filter_map(|pid| {
                let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
                let close = stat.rfind(')')?;
                let rest: Vec<&str> = stat[close + 2..].split_whitespace().collect();
                let state = rest.first()?.chars().next()?;
                Some(ProcInfo {
                    pid, comm: String::new(), state,
                    utime: 0.0, stime: 0.0, rss_bytes: 0.0,
                    num_threads: 0.0, num_fds: 0.0,
                    read_bytes: 0.0, write_bytes: 0.0,
                })
            })
            .collect();

        let mut state_counts: HashMap<String, f64> = HashMap::new();
        for p in &all_procs {
            *state_counts.entry(p.state.to_string()).or_insert(0.0) += 1.0;
        }
        for (state, count) in &state_counts {
            metrics.push(gauge(
                "sentinel_processes_by_state",
                "Process count by state",
                vec![sample(labels(&[("state", state.as_str())]), *count)],
            ));
        }

        Ok(metrics)
    }
}
