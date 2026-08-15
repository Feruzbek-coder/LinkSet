use crate::{
    error::{AppError, AppResult},
    models::{DiagnosticResult, Finding},
    system, windows,
};
use chrono::Utc;
use serde_json::json;

const SUPPORTED: &[&str] = &[
    "SYSTEM_CHECK",
    "PC_SLOW",
    "NO_INTERNET",
    "APP_NOT_OPENING",
    "LOW_DISK_SPACE",
    "PRINTER_NOT_WORKING",
    "HIGH_CPU",
    "HIGH_MEMORY",
    "WINDOWS_UPDATE_ERROR",
    "NETWORK_SLOW",
    "STARTUP_SLOW",
];

pub fn run(kind: &str) -> AppResult<DiagnosticResult> {
    let kind = kind.trim().to_ascii_uppercase();
    if !SUPPORTED.contains(&kind.as_str()) {
        return Err(AppError::Message("Unsupported diagnostic type".into()));
    }

    let connections = windows::network_connections().unwrap_or_default();
    let security = windows::security_status();
    let snapshot = system::dashboard(
        connections.len(),
        connections
            .iter()
            .filter(|c| c.state.eq_ignore_ascii_case("listen"))
            .count(),
        security.score,
    );
    let processes = system::processes();
    let mut findings = Vec::new();
    let mut actions = Vec::new();

    if kind == "SYSTEM_CHECK" {
        for issue in &security.issues {
            push(
                &mut findings,
                "SECURITY_STATUS",
                &issue.severity,
                &issue.title,
                issue.detail.clone(),
                json!({"securityScore":security.score}),
            );
            actions.push("review_security_center".into());
        }
    }

    if matches!(kind.as_str(), "SYSTEM_CHECK" | "PC_SLOW" | "HIGH_CPU")
        && snapshot.cpu_usage >= 80.0
    {
        push(
            &mut findings,
            "HIGH_CPU",
            if snapshot.cpu_usage >= 95.0 {
                "high"
            } else {
                "medium"
            },
            "CPU yuklamasi yuqori",
            format!("Joriy CPU yuklamasi {:.0}%.", snapshot.cpu_usage),
            json!({"usagePercent": snapshot.cpu_usage, "topProcesses": processes.iter().take(5).collect::<Vec<_>>() }),
        );
        actions.push("review_high_cpu_processes".into());
    }

    if matches!(kind.as_str(), "SYSTEM_CHECK" | "PC_SLOW" | "HIGH_MEMORY")
        && snapshot.memory_usage >= 78.0
    {
        push(
            &mut findings,
            "HIGH_MEMORY",
            if snapshot.memory_usage >= 90.0 {
                "high"
            } else {
                "medium"
            },
            "Xotira bosimi yuqori",
            format!("RAM ishlatilishi {:.0}%.", snapshot.memory_usage),
            json!({"usagePercent": snapshot.memory_usage, "usedGb": snapshot.memory_used_gb, "totalGb": snapshot.memory_total_gb}),
        );
        actions.push("review_high_memory_processes".into());
    }

    if matches!(kind.as_str(), "SYSTEM_CHECK" | "PC_SLOW" | "LOW_DISK_SPACE") {
        for disk in &snapshot.disks {
            if disk.usage >= 85.0 {
                push(
                    &mut findings,
                    "LOW_DISK_SPACE",
                    if disk.usage >= 95.0 { "high" } else { "medium" },
                    "Diskda bo‘sh joy kam",
                    format!("{} diski {:.0}% to‘lgan.", disk.mount, disk.usage),
                    json!({"mount":disk.mount,"usagePercent":disk.usage,"usedGb":disk.used_gb,"totalGb":disk.total_gb}),
                );
                actions.push("analyze_temp_files".into());
            }
        }
        if let Ok(disks) = windows::physical_disks() {
            for disk in disks
                .iter()
                .filter(|disk| !disk.health_status.eq_ignore_ascii_case("healthy"))
            {
                push(
                    &mut findings,
                    "DISK_HEALTH_WARNING",
                    "high",
                    "Physical disk health warning",
                    format!("{} health status: {}.", disk.name, disk.health_status),
                    json!(disk),
                );
                actions.push("backup_and_review_disk".into());
            }
        }
        if let Ok(temp) = windows::temp_analysis() {
            if temp.eligible_bytes >= 500 * 1024 * 1024 {
                push(
                    &mut findings,
                    "TEMP_FILES_LARGE",
                    "low",
                    "Xavfsiz tozalanadigan temp fayllar bor",
                    format!(
                        "24 soatdan eski temp fayllar taxminan {:.1} GB.",
                        temp.eligible_bytes as f64 / 1_073_741_824.0
                    ),
                    json!(temp),
                );
                actions.push("clear_temp_files".into());
            }
        }
    }

    if matches!(kind.as_str(), "PC_SLOW" | "STARTUP_SLOW") {
        if let Ok(startup) = windows::startup_apps() {
            if startup.len() >= 12 {
                push(
                    &mut findings,
                    "MANY_STARTUP_APPS",
                    "medium",
                    "Startup dasturlari ko‘p",
                    format!("{} ta startup yozuvi topildi.", startup.len()),
                    json!({"count": startup.len()}),
                );
                actions.push("review_startup_apps".into());
            }
        }
    }

    if matches!(
        kind.as_str(),
        "SYSTEM_CHECK" | "NO_INTERNET" | "NETWORK_SLOW"
    ) {
        let config = windows::network_config().unwrap_or_default();
        if config.local_ips.is_empty() || config.gateways.is_empty() {
            push(
                &mut findings,
                "NETWORK_CONFIG_MISSING",
                "high",
                "Tarmoq konfiguratsiyasi to‘liq emas",
                "IPv4 manzil yoki default gateway topilmadi.".into(),
                json!(config),
            );
            actions.push("run_network_troubleshooter".into());
        } else if connections.is_empty() {
            push(
                &mut findings,
                "NO_ACTIVE_CONNECTIONS",
                "medium",
                "Faol tarmoq ulanishlari topilmadi",
                "Adapter sozlangan, ammo faol TCP/UDP endpointlar ko‘rinmadi.".into(),
                json!({"localIps":config.local_ips,"gateways":config.gateways}),
            );
        }
        if matches!(kind.as_str(), "NO_INTERNET" | "NETWORK_SLOW") {
            if let Ok((dns, internet)) = windows::network_reachability() {
                if dns == Some(false) {
                    push(
                        &mut findings,
                        "DNS_RESOLUTION_FAILED",
                        "high",
                        "DNS so‘rovi bajarilmadi",
                        "Microsoft domeni lokal DNS orqali aniqlanmadi.".into(),
                        json!({"dnsResolved":false}),
                    );
                    actions.push("review_dns_settings".into());
                }
                if internet == Some(false) {
                    push(
                        &mut findings,
                        "INTERNET_PROBE_FAILED",
                        "high",
                        "Tashqi ulanish testi muvaffaqiyatsiz",
                        "1.1.1.1:443 manziliga TCP ulanish o‘rnatilmadi; bu firewall yoki tarmoq cheklovi bo‘lishi mumkin.".into(),
                        json!({"endpoint":"1.1.1.1:443","reachable":false}),
                    );
                    actions.push("run_network_troubleshooter".into());
                }
            }
        }
        for alert in windows::network_alerts(&connections) {
            push(
                &mut findings,
                "UNUSUAL_NETWORK_ACTIVITY",
                &alert.severity,
                &alert.title,
                alert.detail,
                alert.evidence,
            );
            actions.push("review_network_process".into());
        }
    }

    if matches!(
        kind.as_str(),
        "SYSTEM_CHECK" | "PC_SLOW" | "WINDOWS_UPDATE_ERROR"
    ) {
        if let Ok(update) = windows::update_status() {
            if !update.service_enabled || update.reboot_pending {
                push(
                    &mut findings,
                    "WINDOWS_UPDATE_ATTENTION",
                    "medium",
                    "Windows Update e’tibor talab qiladi",
                    if update.reboot_pending {
                        "Yangilanishni yakunlash uchun restart kutilmoqda.".into()
                    } else {
                        "Windows Update xizmati o‘chirib qo‘yilgan.".into()
                    },
                    json!(update),
                );
                actions.push("review_windows_update".into());
            }
        }
    }

    if kind == "PRINTER_NOT_WORKING" {
        let printers = windows::printers().unwrap_or_default();
        if printers.is_empty() {
            push(
                &mut findings,
                "NO_PRINTERS",
                "high",
                "Printer topilmadi",
                "Windows’da o‘rnatilgan printer aniqlanmadi.".into(),
                json!({}),
            );
        } else if printers.iter().any(|p| p.status != "Normal") {
            push(
                &mut findings,
                "PRINTER_STATUS_ERROR",
                "medium",
                "Printer holati normal emas",
                "Kamida bitta printer xato yoki offline holatida.".into(),
                json!(printers),
            );
            actions.push("restart_print_spooler".into());
        }
    }

    if matches!(
        kind.as_str(),
        "SYSTEM_CHECK" | "PC_SLOW" | "APP_NOT_OPENING"
    ) {
        if let Ok(events) = windows::event_summary() {
            if !events.recent_crashes.is_empty() {
                push(
                    &mut findings,
                    "RECENT_APP_CRASHES",
                    "medium",
                    "Yaqinda ilova xatolari qayd etilgan",
                    format!(
                        "{} ta yaqindagi crash yozuvi topildi.",
                        events.recent_crashes.len()
                    ),
                    json!(events.recent_crashes),
                );
                actions.push("review_recent_crashes".into());
            }
        }
    }

    dedup(&mut actions);
    let score = score(&findings);
    Ok(DiagnosticResult {
        diagnostic: kind,
        score,
        summary: if findings.is_empty() {
            "Tekshirilgan ko‘rsatkichlarda jiddiy muammo topilmadi.".into()
        } else {
            format!(
                "{} ta e’tibor talab qiladigan holat topildi.",
                findings.len()
            )
        },
        findings,
        recommended_actions: actions,
        collected_at: Utc::now().to_rfc3339(),
    })
}

fn push(
    out: &mut Vec<Finding>,
    code: &str,
    severity: &str,
    title: &str,
    detail: String,
    evidence: serde_json::Value,
) {
    out.push(Finding {
        code: code.into(),
        severity: severity.into(),
        title: title.into(),
        detail,
        evidence,
    });
}

fn score(findings: &[Finding]) -> u8 {
    let penalty: i16 = findings
        .iter()
        .map(|f| match f.severity.as_str() {
            "critical" => 30,
            "high" => 20,
            "medium" => 10,
            _ => 4,
        })
        .sum();
    (100i16 - penalty).clamp(0, 100) as u8
}

fn dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_changes_score() {
        let mut findings = vec![];
        push(&mut findings, "A", "high", "A", "A".into(), json!({}));
        push(&mut findings, "B", "medium", "B", "B".into(), json!({}));
        assert_eq!(score(&findings), 70);
    }

    #[test]
    fn recommendations_are_deduplicated() {
        let mut values = vec!["a".into(), "b".into(), "a".into()];
        dedup(&mut values);
        assert_eq!(values, vec!["a", "b"]);
    }
}
