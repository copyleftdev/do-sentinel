use super::*;

pub struct DiskCollector;

impl Collector for DiskCollector {
    fn name(&self) -> &'static str { "disk" }

    fn collect(&self) -> Result<Vec<Metric>, Box<dyn std::error::Error + Send + Sync>> {
        let content = read_proc_file("/proc/diskstats")?;
        let mut metrics = Vec::new();

        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 14 { continue; }

            let device = fields[2];
            if device.starts_with("loop") || device.starts_with("ram") || device.starts_with("dm-") {
                continue;
            }

            let l = |extra: &[(&str, &str)]| {
                let mut pairs = vec![("device", device)];
                pairs.extend_from_slice(extra);
                labels(&pairs)
            };

            // fields[3]: reads completed
            if let Ok(v) = fields[3].parse::<f64>() {
                metrics.push(counter("sentinel_disk_reads_total", "Total reads completed", vec![sample(l(&[]), v)]));
            }
            // fields[4]: reads merged
            if let Ok(v) = fields[4].parse::<f64>() {
                metrics.push(counter("sentinel_disk_reads_merged_total", "Total reads merged", vec![sample(l(&[]), v)]));
            }
            // fields[5]: sectors read
            if let Ok(v) = fields[5].parse::<f64>() {
                metrics.push(counter("sentinel_disk_read_bytes_total", "Total bytes read", vec![sample(l(&[]), v * 512.0)]));
            }
            // fields[6]: time reading (ms)
            if let Ok(v) = fields[6].parse::<f64>() {
                metrics.push(counter("sentinel_disk_read_time_seconds_total", "Total read time", vec![sample(l(&[]), v / 1000.0)]));
            }
            // fields[7]: writes completed
            if let Ok(v) = fields[7].parse::<f64>() {
                metrics.push(counter("sentinel_disk_writes_total", "Total writes completed", vec![sample(l(&[]), v)]));
            }
            // fields[8]: writes merged
            if let Ok(v) = fields[8].parse::<f64>() {
                metrics.push(counter("sentinel_disk_writes_merged_total", "Total writes merged", vec![sample(l(&[]), v)]));
            }
            // fields[9]: sectors written
            if let Ok(v) = fields[9].parse::<f64>() {
                metrics.push(counter("sentinel_disk_written_bytes_total", "Total bytes written", vec![sample(l(&[]), v * 512.0)]));
            }
            // fields[10]: time writing (ms)
            if let Ok(v) = fields[10].parse::<f64>() {
                metrics.push(counter("sentinel_disk_write_time_seconds_total", "Total write time", vec![sample(l(&[]), v / 1000.0)]));
            }
            // fields[11]: I/Os in progress
            if let Ok(v) = fields[11].parse::<f64>() {
                metrics.push(gauge("sentinel_disk_io_in_progress", "I/O operations in progress", vec![sample(l(&[]), v)]));
            }
            // fields[12]: time doing I/Os (ms)
            if let Ok(v) = fields[12].parse::<f64>() {
                metrics.push(counter("sentinel_disk_io_time_seconds_total", "Total I/O time", vec![sample(l(&[]), v / 1000.0)]));
            }
            // fields[13]: weighted time doing I/Os (ms)
            if let Ok(v) = fields[13].parse::<f64>() {
                metrics.push(counter("sentinel_disk_io_weighted_time_seconds_total", "Weighted I/O time", vec![sample(l(&[]), v / 1000.0)]));
            }
        }

        // Filesystem stats via statvfs
        if let Ok(mounts) = read_proc_file("/proc/mounts") {
            for line in mounts.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 3 { continue; }
                let mountpoint = parts[1];
                let fstype = parts[2];

                if !["ext4", "xfs", "btrfs", "zfs"].contains(&fstype) { continue; }

                if let Ok(stat) = nix::sys::statvfs::statvfs(mountpoint) {
                    let block_size = stat.block_size() as f64;
                    let fl = labels(&[("mountpoint", mountpoint), ("fstype", fstype)]);

                    metrics.push(gauge(
                        "sentinel_filesystem_size_bytes", "Filesystem size",
                        vec![sample(fl.clone(), stat.blocks() as f64 * block_size)],
                    ));
                    metrics.push(gauge(
                        "sentinel_filesystem_free_bytes", "Filesystem free space",
                        vec![sample(fl.clone(), stat.blocks_free() as f64 * block_size)],
                    ));
                    metrics.push(gauge(
                        "sentinel_filesystem_avail_bytes", "Filesystem available space",
                        vec![sample(fl.clone(), stat.blocks_available() as f64 * block_size)],
                    ));
                    metrics.push(gauge(
                        "sentinel_filesystem_files_total", "Total inodes",
                        vec![sample(fl.clone(), stat.files() as f64)],
                    ));
                    metrics.push(gauge(
                        "sentinel_filesystem_files_free", "Free inodes",
                        vec![sample(fl, stat.files_free() as f64)],
                    ));
                }
            }
        }

        Ok(metrics)
    }
}
