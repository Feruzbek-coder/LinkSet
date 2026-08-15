use crate::models::{DashboardSnapshot, DiskInfo, NetworkSummary, ProcessInfo};
use sysinfo::{Disks, Networks, System};

pub fn dashboard(
    active_connections: usize,
    listening_ports: usize,
    security_score: u8,
) -> DashboardSnapshot {
    let mut sys = System::new_all();
    std::thread::sleep(std::time::Duration::from_millis(220));
    sys.refresh_all();
    let cpu = sys.global_cpu_usage();
    let memory_total = sys.total_memory() as f64 / 1_073_741_824.0;
    let memory_used = sys.used_memory() as f64 / 1_073_741_824.0;
    let memory_usage = if memory_total > 0.0 {
        (memory_used / memory_total * 100.0) as f32
    } else {
        0.0
    };
    let disks: Vec<DiskInfo> = Disks::new_with_refreshed_list()
        .iter()
        .map(|d| {
            let total = d.total_space() as f64 / 1_073_741_824.0;
            let used = (d.total_space() - d.available_space()) as f64 / 1_073_741_824.0;
            DiskInfo {
                name: d.name().to_string_lossy().into(),
                mount: d.mount_point().to_string_lossy().into(),
                used_gb: used,
                total_gb: total,
                usage: if total > 0.0 {
                    (used / total * 100.0) as f32
                } else {
                    0.0
                },
            }
        })
        .collect();
    let networks = Networks::new_with_refreshed_list();
    let received = networks.values().map(|n| n.total_received()).sum::<u64>() as f64 / 1_048_576.0;
    let transmitted = networks
        .values()
        .map(|n| n.total_transmitted())
        .sum::<u64>() as f64
        / 1_048_576.0;
    let max_disk = disks.iter().map(|d| d.usage).fold(0.0, f32::max);
    let penalty = ((cpu - 80.0).max(0.0) * 0.15
        + (memory_usage - 75.0).max(0.0) * 0.35
        + (max_disk - 80.0).max(0.0) * 0.6)
        .clamp(0.0, 45.0);
    let health = (100.0 - penalty) as u8;
    DashboardSnapshot {
        pc_name: std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows PC".into()),
        windows_version: System::long_os_version().unwrap_or_else(|| "Windows".into()),
        uptime_seconds: System::uptime(),
        cpu_usage: cpu,
        memory_usage,
        memory_used_gb: memory_used,
        memory_total_gb: memory_total,
        disks,
        network: NetworkSummary {
            received_mb: received,
            transmitted_mb: transmitted,
            active_connections,
            listening_ports,
        },
        health_score: health,
        security_score,
    }
}

pub fn processes() -> Vec<ProcessInfo> {
    let mut sys = System::new_all();
    std::thread::sleep(std::time::Duration::from_millis(160));
    sys.refresh_all();
    let mut rows: Vec<_> = sys
        .processes()
        .iter()
        .map(|(pid, p)| ProcessInfo {
            pid: pid.as_u32(),
            name: p.name().to_string_lossy().into(),
            cpu: p.cpu_usage(),
            memory_mb: p.memory() as f64 / 1_048_576.0,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.cpu
            .partial_cmp(&a.cpu)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows.truncate(80);
    rows
}
