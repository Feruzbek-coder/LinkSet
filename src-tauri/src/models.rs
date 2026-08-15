use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardSnapshot {
    pub pc_name: String,
    pub windows_version: String,
    pub uptime_seconds: u64,
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub memory_used_gb: f64,
    pub memory_total_gb: f64,
    pub disks: Vec<DiskInfo>,
    pub network: NetworkSummary,
    pub health_score: u8,
    pub security_score: u8,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskInfo {
    pub name: String,
    pub mount: String,
    pub used_gb: f64,
    pub total_gb: f64,
    pub usage: f32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu: f32,
    pub memory_mb: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSummary {
    pub received_mb: f64,
    pub transmitted_mb: f64,
    pub active_connections: usize,
    pub listening_ports: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub state: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityStatus {
    pub score: u8,
    pub defender_enabled: Option<bool>,
    pub real_time_protection: Option<bool>,
    pub firewall_enabled: Option<bool>,
    pub update_service_running: bool,
    pub update_service_enabled: bool,
    pub issues: Vec<SecurityIssue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityIssue {
    pub severity: String,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub id: i64,
    pub timestamp: String,
    pub action: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRequest {
    pub tool: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionProposal {
    pub confirmation_id: String,
    pub tool: String,
    pub title: String,
    pub description: String,
    pub risk_level: u8,
    pub requires_confirmation: bool,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    pub success: bool,
    pub message: String,
    pub data: serde_json::Value,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WingetPackage {
    pub name: String,
    pub id: String,
    pub version: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupApp {
    pub name: String,
    pub command: String,
    pub location: String,
    pub user: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
    pub status: String,
    pub start_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledApp {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConfig {
    pub local_ips: Vec<String>,
    pub gateways: Vec<String>,
    pub dns_servers: Vec<String>,
    pub adapters: Vec<NetworkAdapter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkAdapter {
    pub name: String,
    pub description: String,
    pub status: String,
    pub link_speed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatus {
    pub service_running: bool,
    pub service_enabled: bool,
    pub last_hotfix_date: Option<String>,
    pub last_hotfix_id: Option<String>,
    pub reboot_pending: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    pub dry_run: bool,
    pub elevated: bool,
    pub ai_configured: bool,
    pub ai_model: String,
    pub winget_available: bool,
    pub winget_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EventSummary {
    pub critical_count_24h: u32,
    pub error_count_24h: u32,
    pub recent_crashes: Vec<EventItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventItem {
    pub timestamp: String,
    pub provider: String,
    pub event_id: u32,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TempAnalysis {
    pub path: String,
    pub total_bytes: u64,
    pub eligible_bytes: u64,
    pub file_count: u64,
    pub eligible_file_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrinterInfo {
    pub name: String,
    pub status: String,
    pub driver_name: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub code: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticResult {
    pub diagnostic: String,
    pub score: u8,
    pub summary: String,
    pub findings: Vec<Finding>,
    pub recommended_actions: Vec<String>,
    pub collected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalDiskHealth {
    pub name: String,
    pub health_status: String,
    pub operational_status: String,
    pub media_type: String,
    pub temperature_c: Option<i32>,
    pub wear_percent: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkAlert {
    pub severity: String,
    pub process: String,
    pub title: String,
    pub detail: String,
    pub evidence: serde_json::Value,
}
