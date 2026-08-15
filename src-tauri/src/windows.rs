use crate::{
    error::{AppError, AppResult},
    models::{
        EventSummary, InstalledApp, NetworkAlert, NetworkConfig, NetworkConnection,
        PhysicalDiskHealth, PrinterInfo, SecurityIssue, SecurityStatus, ServiceInfo, StartupApp,
        TempAnalysis, UpdateStatus, WingetPackage,
    },
};
use serde::de::DeserializeOwned;
use std::process::{Command, Stdio};

fn powershell(script: &str) -> AppResult<String> {
    let out = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-Command",
            script,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| AppError::Command(e.to_string()))?;
    if !out.status.success() {
        return Err(AppError::Command(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn powershell_json<T: DeserializeOwned>(script: &str) -> AppResult<T> {
    let raw = powershell(script)?;
    serde_json::from_str(&raw).map_err(|e| AppError::Command(format!("Invalid Windows data: {e}")))
}

fn powershell_json_array<T: DeserializeOwned>(script: &str) -> AppResult<Vec<T>> {
    let raw = powershell(script)?;
    if raw.is_empty() || raw == "null" {
        return Ok(vec![]);
    }
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| AppError::Command(e.to_string()))?;
    let normalized = if value.is_array() {
        value
    } else {
        serde_json::Value::Array(vec![value])
    };
    serde_json::from_value(normalized).map_err(|e| AppError::Command(e.to_string()))
}

pub fn network_connections() -> AppResult<Vec<NetworkConnection>> {
    let script="$p=@{}; Get-Process -ErrorAction SilentlyContinue|%{$p[$_.Id]=$_.ProcessName}; $tcp=Get-NetTCPConnection -ErrorAction SilentlyContinue|Select-Object @{n='protocol';e={'TCP'}},@{n='localAddress';e={$_.LocalAddress+':'+$_.LocalPort}},@{n='remoteAddress';e={$_.RemoteAddress+':'+$_.RemotePort}},@{n='state';e={[string]$_.State}},@{n='pid';e={$_.OwningProcess}},@{n='process';e={$p[$_.OwningProcess]}}; $udp=Get-NetUDPEndpoint -ErrorAction SilentlyContinue|Select-Object @{n='protocol';e={'UDP'}},@{n='localAddress';e={$_.LocalAddress+':'+$_.LocalPort}},@{n='remoteAddress';e={'*:*'}},@{n='state';e={'Bound'}},@{n='pid';e={$_.OwningProcess}},@{n='process';e={$p[$_.OwningProcess]}}; @($tcp)+@($udp)|ConvertTo-Json -Compress";
    powershell_json_array(script)
}

pub fn startup_apps() -> AppResult<Vec<StartupApp>> {
    powershell_json_array("@(Get-CimInstance Win32_StartupCommand -ErrorAction Stop|Select-Object @{n='name';e={[string]$_.Name}},@{n='command';e={[string]$_.Command}},@{n='location';e={[string]$_.Location}},@{n='user';e={[string]$_.User}})|ConvertTo-Json -Compress")
}

pub fn services() -> AppResult<Vec<ServiceInfo>> {
    powershell_json_array("@(Get-CimInstance Win32_Service -ErrorAction Stop|Sort-Object DisplayName|Select-Object @{n='name';e={[string]$_.Name}},@{n='displayName';e={[string]$_.DisplayName}},@{n='status';e={[string]$_.State}},@{n='startType';e={[string]$_.StartMode}})|ConvertTo-Json -Compress")
}

pub fn installed_apps() -> AppResult<Vec<InstalledApp>> {
    powershell_json_array("$paths=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); @($paths|%{Get-ItemProperty $_ -ErrorAction SilentlyContinue}|?{$_.DisplayName}|Sort-Object DisplayName -Unique|Select-Object @{n='name';e={[string]$_.DisplayName}},@{n='version';e={[string]$_.DisplayVersion}},@{n='publisher';e={[string]$_.Publisher}},@{n='source';e={'registry'}})|ConvertTo-Json -Compress")
}

pub fn network_config() -> AppResult<NetworkConfig> {
    powershell_json("$cfg=@(Get-NetIPConfiguration -ErrorAction SilentlyContinue); $ad=@(Get-NetAdapter -ErrorAction SilentlyContinue|Select-Object @{n='name';e={[string]$_.Name}},@{n='description';e={[string]$_.InterfaceDescription}},@{n='status';e={[string]$_.Status}},@{n='linkSpeed';e={[string]$_.LinkSpeed}}); [pscustomobject]@{localIps=@($cfg.IPv4Address.IPAddress|?{$_});gateways=@($cfg.IPv4DefaultGateway.NextHop|?{$_});dnsServers=@($cfg.DNSServer.ServerAddresses|?{$_}|Select-Object -Unique);adapters=$ad}|ConvertTo-Json -Depth 4 -Compress")
}

pub fn network_reachability() -> AppResult<(Option<bool>, Option<bool>)> {
    let value: serde_json::Value = powershell_json("$dns=$null;$internet=$null;try{Resolve-DnsName -Name 'www.microsoft.com' -DnsOnly -ErrorAction Stop|Out-Null;$dns=$true}catch{$dns=$false};try{$internet=Test-NetConnection -ComputerName '1.1.1.1' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop}catch{$internet=$false};[pscustomobject]@{dns=$dns;internet=$internet}|ConvertTo-Json -Compress")?;
    Ok((
        value.get("dns").and_then(serde_json::Value::as_bool),
        value.get("internet").and_then(serde_json::Value::as_bool),
    ))
}

pub fn update_status() -> AppResult<UpdateStatus> {
    powershell_json("$h=Get-HotFix -ErrorAction SilentlyContinue|Sort-Object InstalledOn -Descending|Select-Object -First 1;$svc=Get-CimInstance Win32_Service -Filter \"Name='wuauserv'\" -ErrorAction SilentlyContinue; [pscustomobject]@{serviceRunning=($svc.State -eq 'Running');serviceEnabled=($null -ne $svc -and $svc.StartMode -ne 'Disabled');lastHotfixDate=if($h){$h.InstalledOn.ToString('o')}else{$null};lastHotfixId=if($h){[string]$h.HotFixID}else{$null};rebootPending=(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')}|ConvertTo-Json -Compress")
}

pub fn event_summary() -> AppResult<EventSummary> {
    powershell_json("$since=(Get-Date).AddHours(-24);$sys=@(Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$since;Level=1,2} -ErrorAction SilentlyContinue);$cr=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$since;Level=1,2} -MaxEvents 12 -ErrorAction SilentlyContinue|?{$_.ProviderName -match 'Application Error|Windows Error Reporting'}|Select-Object @{n='timestamp';e={$_.TimeCreated.ToString('o')}},@{n='provider';e={[string]$_.ProviderName}},@{n='eventId';e={[uint32]$_.Id}},@{n='message';e={if($_.Message){[string]$_.Message.Substring(0,[Math]::Min(350,$_.Message.Length))}else{''}}}); [pscustomobject]@{criticalCount24h=@($sys|?{$_.Level -eq 1}).Count;errorCount24h=@($sys|?{$_.Level -eq 2}).Count;recentCrashes=$cr}|ConvertTo-Json -Depth 5 -Compress")
}

pub fn temp_analysis() -> AppResult<TempAnalysis> {
    powershell_json("$cut=(Get-Date).AddDays(-1);$files=@(Get-ChildItem -LiteralPath $env:TEMP -File -Force -Recurse -ErrorAction SilentlyContinue);$eligible=@($files|?{$_.LastWriteTime -lt $cut});[pscustomobject]@{path=[string]$env:TEMP;totalBytes=[uint64](($files|Measure-Object Length -Sum).Sum);eligibleBytes=[uint64](($eligible|Measure-Object Length -Sum).Sum);fileCount=[uint64]$files.Count;eligibleFileCount=[uint64]$eligible.Count}|ConvertTo-Json -Compress")
}

pub fn printers() -> AppResult<Vec<PrinterInfo>> {
    powershell_json_array("$default=(Get-CimInstance Win32_Printer -Filter 'Default=True' -ErrorAction SilentlyContinue).Name; @(Get-Printer -ErrorAction SilentlyContinue|Select-Object @{n='name';e={[string]$_.Name}},@{n='status';e={[string]$_.PrinterStatus}},@{n='driverName';e={[string]$_.DriverName}},@{n='isDefault';e={$_.Name -eq $default}})|ConvertTo-Json -Compress")
}

pub fn physical_disks() -> AppResult<Vec<PhysicalDiskHealth>> {
    powershell_json_array("@(Get-PhysicalDisk -ErrorAction Stop|%{$d=$_;$r=Get-StorageReliabilityCounter -PhysicalDisk $d -ErrorAction SilentlyContinue;[pscustomobject]@{name=[string]$d.FriendlyName;healthStatus=[string]$d.HealthStatus;operationalStatus=[string]($d.OperationalStatus -join ', ');mediaType=[string]$d.MediaType;temperatureC=if($r){$r.Temperature}else{$null};wearPercent=if($r){$r.Wear}else{$null}}})|ConvertTo-Json -Compress")
}

pub fn network_alerts(connections: &[NetworkConnection]) -> Vec<NetworkAlert> {
    use std::collections::{HashMap, HashSet};
    let trusted = [
        "system", "svchost", "chrome", "msedge", "firefox", "onedrive", "teams", "zoom",
    ];
    let mut remotes: HashMap<String, HashSet<String>> = HashMap::new();
    for connection in connections
        .iter()
        .filter(|c| c.protocol == "TCP" && c.state.eq_ignore_ascii_case("established"))
    {
        let process = connection
            .process
            .clone()
            .unwrap_or_else(|| "unknown".into())
            .to_lowercase();
        remotes
            .entry(process)
            .or_default()
            .insert(connection.remote_address.clone());
    }
    remotes.into_iter().filter_map(|(process, endpoints)| {
        if endpoints.len() >= 20 && !trusted.contains(&process.as_str()) {
            Some(NetworkAlert { severity: "medium".into(), process: process.clone(), title: "Unusual outbound fan-out".into(), detail: format!("{process} has connections to {} distinct remote endpoints. This is a heuristic, not a malware verdict.", endpoints.len()), evidence: serde_json::json!({"distinctRemoteEndpoints":endpoints.len()}) })
        } else { None }
    }).collect()
}

pub fn is_elevated() -> bool {
    powershell("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn security_status() -> SecurityStatus {
    let defender=powershell("$d=Get-MpComputerStatus -ErrorAction Stop; [pscustomobject]@{antivirus=$d.AntivirusEnabled; realtime=$d.RealTimeProtectionEnabled}|ConvertTo-Json -Compress").ok().and_then(|s|serde_json::from_str::<serde_json::Value>(&s).ok());
    let firewall =
        powershell("@((Get-NetFirewallProfile -ErrorAction Stop).Enabled) -notcontains $false")
            .ok()
            .map(|s| s.eq_ignore_ascii_case("true"));
    let update=powershell("$s=Get-CimInstance Win32_Service -Filter \"Name='wuauserv'\" -ErrorAction SilentlyContinue;[pscustomobject]@{running=($s.State -eq 'Running');enabled=($null -ne $s -and $s.StartMode -ne 'Disabled')}|ConvertTo-Json -Compress").ok().and_then(|s|serde_json::from_str::<serde_json::Value>(&s).ok());
    let update_running = update
        .as_ref()
        .and_then(|v| v["running"].as_bool())
        .unwrap_or(false);
    let update_enabled = update
        .as_ref()
        .and_then(|v| v["enabled"].as_bool())
        .unwrap_or(false);
    let de = defender.as_ref().and_then(|v| v["antivirus"].as_bool());
    let rt = defender.as_ref().and_then(|v| v["realtime"].as_bool());
    let mut score = 100i16;
    let mut issues = vec![];
    if de.is_none() {
        score -= 10;
        issues.push(SecurityIssue {
            severity: "info".into(),
            title: "Defender holatini o‘qib bo‘lmadi".into(),
            detail: "Windows Security ma’lumoti mavjud emas yoki ruxsat cheklangan.".into(),
        })
    }
    if firewall.is_none() {
        score -= 5;
        issues.push(SecurityIssue {
            severity: "info".into(),
            title: "Firewall holatini o‘qib bo‘lmadi".into(),
            detail: "Firewall profillari haqidagi ma’lumot mavjud emas.".into(),
        })
    }
    if de == Some(false) {
        score -= 35;
        issues.push(SecurityIssue {
            severity: "critical".into(),
            title: "Windows Defender o‘chiq".into(),
            detail: "Antivirus himoyasi yoqilmagan.".into(),
        })
    }
    if rt == Some(false) {
        score -= 25;
        issues.push(SecurityIssue {
            severity: "high".into(),
            title: "Real-time protection o‘chiq".into(),
            detail: "Fayllar real vaqtda tekshirilmayapti.".into(),
        })
    }
    if firewall == Some(false) {
        score -= 25;
        issues.push(SecurityIssue {
            severity: "high".into(),
            title: "Firewall profillaridan biri o‘chiq".into(),
            detail: "Tarmoq himoyasi to‘liq emas.".into(),
        })
    }
    if !update_enabled {
        score -= 15;
        issues.push(SecurityIssue {
            severity: "medium".into(),
            title: "Windows Update o‘chirib qo‘yilgan".into(),
            detail: "Yangilanish xizmati Disabled holatida; xavfsizlik yangilanishlari kelmasligi mumkin.".into(),
        })
    }
    SecurityStatus {
        score: score.clamp(0, 100) as u8,
        defender_enabled: de,
        real_time_protection: rt,
        firewall_enabled: firewall,
        update_service_running: update_running,
        update_service_enabled: update_enabled,
        issues,
    }
}

pub fn winget_runtime_status() -> (bool, Option<String>) {
    match Command::new("winget").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            (true, (!version.is_empty()).then_some(version))
        }
        _ => (false, None),
    }
}

pub fn winget_search(query: &str) -> AppResult<Vec<WingetPackage>> {
    if query.len() < 2
        || !query
            .chars()
            .all(|c| c.is_alphanumeric() || " ._-".contains(c))
    {
        return Err(AppError::Message("Invalid package query".into()));
    }
    let search_args = [
        "search",
        "--query",
        query,
        "--source",
        "winget",
        "--accept-source-agreements",
        "--disable-interactivity",
        "--count",
        "25",
    ];
    let mut out = Command::new("winget")
        .args(search_args)
        .output()
        .map_err(|e| AppError::Command(format!("winget is unavailable: {e}")))?;
    if !out.status.success() && combined_output(&out).contains("0x8a15000f") {
        let _ = Command::new("winget")
            .args([
                "source",
                "update",
                "--name",
                "winget",
                "--disable-interactivity",
            ])
            .output();
        out = Command::new("winget")
            .args(search_args)
            .output()
            .map_err(|e| AppError::Command(format!("winget retry failed: {e}")))?;
    }
    if !out.status.success() {
        let detail = combined_output(&out);
        return Err(AppError::Command(if detail.is_empty() {
            "winget search failed".into()
        } else if detail.contains("0x8a15000f") {
            "winget source data is missing. Open Terminal as administrator and run: winget source reset --force".into()
        } else {
            detail
        }));
    }
    Ok(parse_winget_search(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_winget_search(text: &str) -> Vec<WingetPackage> {
    let mut rows = vec![];
    let mut past_separator = false;
    for line in text.lines() {
        if line.trim_start().starts_with("---") {
            past_separator = true;
            continue;
        }
        if !past_separator || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        let Some(id_index) = parts.iter().position(|part| is_package_id(part)) else {
            continue;
        };
        if id_index == 0 || id_index + 1 >= parts.len() {
            continue;
        }
        rows.push(WingetPackage {
            name: parts[..id_index].join(" "),
            id: parts[id_index].into(),
            version: parts[id_index + 1].into(),
            source: "winget".into(),
        });
        if rows.len() == 10 {
            break;
        }
    }
    rows
}

fn is_package_id(value: &str) -> bool {
    value.len() <= 120
        && value.contains('.')
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_+".contains(c))
}

fn combined_output(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stderr.is_empty() {
        stdout
    } else {
        stderr
    }
}

pub fn run_whitelisted(tool: &str, args: &serde_json::Value, dry_run: bool) -> AppResult<String> {
    let preview = match tool {
        "install_app" => format!(
            "winget install --id {} --exact",
            safe_arg(args, "package_id")?
        ),
        "update_app" => format!(
            "winget upgrade --id {} --exact",
            safe_arg(args, "package_id")?
        ),
        "uninstall_app" => format!(
            "winget uninstall --id {} --exact",
            safe_arg(args, "package_id")?
        ),
        "restart_service" => format!("Restart-Service {}", safe_arg(args, "service_name")?),
        "restart_process" => format!("Restart process {}", safe_arg(args, "process_name")?),
        "clear_temp_files" => "Clear user temporary files older than 24 hours".into(),
        _ => return Err(AppError::Message("Tool is not whitelisted".into())),
    };
    if dry_run {
        return Ok(format!("DRY RUN: {preview}"));
    }
    match tool {
        "install_app" => {
            let id = safe_arg(args, "package_id")?;
            winget_action("install", &id)?;
            verify_winget_installed(&id, true)?;
        }
        "update_app" => {
            let id = safe_arg(args, "package_id")?;
            winget_action("upgrade", &id)?;
            verify_winget_installed(&id, true)?;
        }
        "uninstall_app" => {
            let id = safe_arg(args, "package_id")?;
            winget_action("uninstall", &id)?;
            verify_winget_installed(&id, false)?;
        }
        "restart_service" => {
            let name = safe_arg(args, "service_name")?;
            restart_service(&name)?;
            let running = powershell(&format!(
                "(Get-Service -Name '{}' -ErrorAction Stop).Status -eq 'Running'",
                name
            ))?;
            if !running.eq_ignore_ascii_case("true") {
                return Err(AppError::Command(
                    "Service restart could not be verified".into(),
                ));
            }
        }
        "restart_process" => {
            let name = safe_arg(args, "process_name")?;
            powershell(&format!("$p=Get-Process -Name '{}' -ErrorAction Stop|Select-Object -First 1;$path=$p.Path;Stop-Process -Id $p.Id -Force;Start-Process -FilePath $path",name))?;
            let running = powershell(&format!(
                "@(Get-Process -Name '{}' -ErrorAction SilentlyContinue).Count -gt 0",
                name
            ))?;
            if !running.eq_ignore_ascii_case("true") {
                return Err(AppError::Command(
                    "Process restart could not be verified".into(),
                ));
            }
        }
        "clear_temp_files" => {
            let before = temp_analysis().unwrap_or_default();
            powershell("$root=(Resolve-Path -LiteralPath $env:TEMP -ErrorAction Stop).Path;$cut=(Get-Date).AddDays(-1);Get-ChildItem -LiteralPath $root -File -Force -Recurse -Attributes !ReparsePoint -ErrorAction SilentlyContinue|Where-Object {$_.LastWriteTime -lt $cut -and $_.FullName.StartsWith($root,[System.StringComparison]::OrdinalIgnoreCase)}|Remove-Item -Force -ErrorAction SilentlyContinue;Get-ChildItem -LiteralPath $root -Directory -Force -Recurse -Attributes !ReparsePoint -ErrorAction SilentlyContinue|Sort-Object {$_.FullName.Length} -Descending|Where-Object {-not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue|Select-Object -First 1)}|Remove-Item -Force -ErrorAction SilentlyContinue")?;
            let after = temp_analysis().unwrap_or_default();
            let removed = before.eligible_bytes.saturating_sub(after.eligible_bytes);
            return Ok(format!(
                "{} bytes of eligible temporary files removed and verified",
                removed
            ));
        }
        _ => unreachable!(),
    }
    Ok(preview)
}

fn restart_service(name: &str) -> AppResult<()> {
    let command = format!("Restart-Service -Name {name} -ErrorAction Stop");
    if is_elevated() {
        return powershell(&command).map(|_| ());
    }
    let launcher = format!(
        "$p=Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','RemoteSigned','-Command','{command}');if($p.ExitCode -ne 0){{exit $p.ExitCode}}"
    );
    powershell(&launcher).map(|_| ()).map_err(|error| {
        AppError::PermissionDenied(format!(
            "Administrator approval was cancelled or the service restart failed: {error}"
        ))
    })
}

fn winget_action(action: &str, id: &str) -> AppResult<()> {
    let mut args = vec![action, "--id", id, "--exact", "--disable-interactivity"];
    if matches!(action, "install" | "upgrade") {
        args.extend([
            "--source",
            "winget",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ]);
    }
    let status = Command::new("winget")
        .args(args)
        .status()
        .map_err(|e| AppError::Command(e.to_string()))?;
    if !status.success() {
        return Err(AppError::Command(format!("winget {action} failed")));
    }
    Ok(())
}

fn verify_winget_installed(id: &str, expected: bool) -> AppResult<()> {
    let status = Command::new("winget")
        .args(["list", "--id", id, "--exact", "--disable-interactivity"])
        .status()
        .map_err(|e| AppError::Command(e.to_string()))?;
    if status.success() != expected {
        return Err(AppError::Command(
            "Package state verification failed".into(),
        ));
    }
    Ok(())
}
fn safe_arg(v: &serde_json::Value, key: &str) -> AppResult<String> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| AppError::Message(format!("Missing {key}")))?;
    let valid = if key == "package_id" {
        is_package_id(s)
    } else {
        s.len() <= 120 && s.chars().all(|c| c.is_alphanumeric() || " ._-".contains(c))
    };
    if !valid {
        return Err(AppError::Message(format!("Invalid {key}")));
    }
    Ok(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_shell_metacharacters() {
        for value in ["Zoom.Zoom; whoami", "$(whoami)", "name|cmd", "a'b"] {
            assert!(safe_arg(&json!({"id":value}), "id").is_err());
        }
    }

    #[test]
    fn accepts_exact_winget_id() {
        assert_eq!(
            safe_arg(&json!({"id":"Zoom.Zoom"}), "id").unwrap(),
            "Zoom.Zoom"
        );
    }

    #[test]
    fn rejects_non_exact_winget_ids() {
        for value in ["Zoom", "Zoom Zoom", ".Zoom", "Zoom."] {
            assert!(safe_arg(&json!({"package_id":value}), "package_id").is_err());
        }
    }

    #[test]
    fn parses_winget_rows_with_optional_match_column() {
        let text = "Name Id Version Match Source\n-------------------------------------------\nZoom Workplace Zoom.Zoom 6.7.5 winget\nZoom Player Inmatrix.ZoomPlayer 22.0 Tag: zoom winget\n";
        let rows = parse_winget_search(text);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "Zoom.Zoom");
        assert_eq!(rows[1].id, "Inmatrix.ZoomPlayer");
        assert_eq!(rows[1].version, "22.0");
        assert_eq!(rows[1].source, "winget");
    }

    #[test]
    fn all_mutating_tools_have_safe_dry_run_dispatch() {
        for (tool, arguments) in [
            ("install_app", json!({"package_id":"Zoom.Zoom"})),
            ("update_app", json!({"package_id":"Zoom.Zoom"})),
            ("uninstall_app", json!({"package_id":"Zoom.Zoom"})),
            ("restart_service", json!({"service_name":"Spooler"})),
            ("restart_process", json!({"process_name":"explorer"})),
            ("clear_temp_files", json!({})),
        ] {
            let result = run_whitelisted(tool, &arguments, true).unwrap();
            assert!(result.starts_with("DRY RUN:"));
        }
    }
}
