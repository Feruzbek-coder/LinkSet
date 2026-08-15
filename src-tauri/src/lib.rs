mod ai;
mod db;
mod diagnostics;
mod error;
mod models;
mod safety;
mod system;
mod windows;
use crate::{
    db::Database,
    error::{AppError, AppResult},
    models::*,
    safety::SafetyState,
};
use tauri::{Manager, State};

#[tauri::command]
fn get_dashboard(db: State<Database>) -> AppResult<DashboardSnapshot> {
    let connections = windows::network_connections().unwrap_or_default();
    let listening = connections
        .iter()
        .filter(|c| c.state.eq_ignore_ascii_case("listen"))
        .count();
    let sec = windows::security_status();
    let snap = system::dashboard(connections.len(), listening, sec.score);
    let _ = db.log(
        "System snapshot",
        "success",
        &format!(
            "Health {} · Security {}",
            snap.health_score, snap.security_score
        ),
    );
    Ok(snap)
}
#[tauri::command]
fn get_processes() -> Vec<ProcessInfo> {
    system::processes()
}
#[tauri::command]
fn get_network_connections() -> AppResult<Vec<NetworkConnection>> {
    windows::network_connections()
}
#[tauri::command]
fn get_security_status() -> SecurityStatus {
    windows::security_status()
}
#[tauri::command]
fn get_startup_apps() -> AppResult<Vec<StartupApp>> {
    windows::startup_apps()
}
#[tauri::command]
fn get_services() -> AppResult<Vec<ServiceInfo>> {
    windows::services()
}
#[tauri::command]
fn get_installed_apps() -> AppResult<Vec<InstalledApp>> {
    windows::installed_apps()
}
#[tauri::command]
fn get_network_config() -> AppResult<NetworkConfig> {
    windows::network_config()
}
#[tauri::command]
fn get_update_status() -> AppResult<UpdateStatus> {
    windows::update_status()
}
#[tauri::command]
fn get_event_summary() -> AppResult<EventSummary> {
    windows::event_summary()
}
#[tauri::command]
fn analyze_temp_files() -> AppResult<TempAnalysis> {
    windows::temp_analysis()
}
#[tauri::command]
fn get_printers() -> AppResult<Vec<PrinterInfo>> {
    windows::printers()
}
#[tauri::command]
fn get_physical_disks() -> AppResult<Vec<PhysicalDiskHealth>> {
    windows::physical_disks()
}
#[tauri::command]
fn get_network_alerts() -> AppResult<Vec<NetworkAlert>> {
    let rows = windows::network_connections()?;
    Ok(windows::network_alerts(&rows))
}
#[tauri::command]
fn run_diagnostic(kind: String, db: State<Database>) -> AppResult<DiagnosticResult> {
    let result = diagnostics::run(&kind)?;
    let value = serde_json::to_value(&result).map_err(|e| AppError::Message(e.to_string()))?;
    db.save_diagnostic(&result.diagnostic, &value)?;
    db.log(
        "Diagnostic",
        "success",
        &format!("{} · score {}", result.diagnostic, result.score),
    )?;
    Ok(result)
}
#[tauri::command]
fn search_apps(query: String, db: State<Database>) -> AppResult<Vec<WingetPackage>> {
    let rows = windows::winget_search(&query)?;
    let _ = db.log(
        "Software search",
        "success",
        &format!("{}: {} results", query, rows.len()),
    );
    Ok(rows)
}
#[tauri::command]
fn list_activity(limit: Option<u32>, db: State<Database>) -> AppResult<Vec<Activity>> {
    db.activities(limit.unwrap_or(50))
}
#[tauri::command]
fn propose_action(
    request: ActionRequest,
    state: State<SafetyState>,
    db: State<Database>,
) -> AppResult<ActionProposal> {
    let p = safety::propose(&state, request)?;
    let _ = db.log(&p.title, "awaiting_confirmation", &p.description);
    Ok(p)
}
#[tauri::command]
fn execute_action(
    confirmation_id: String,
    state: State<SafetyState>,
    db: State<Database>,
) -> AppResult<ToolResult> {
    let req = safety::consume(&state, &confirmation_id)?;
    let dry = std::env::var("DRY_RUN")
        .map(|v| !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    db.log(
        &req.tool,
        "started",
        if dry {
            "Dry-run execution started"
        } else {
            "Execution started"
        },
    )?;
    match windows::run_whitelisted(&req.tool, &req.arguments, dry) {
        Ok(msg) => {
            db.log(&req.tool, if dry { "dry_run" } else { "success" }, &msg)?;
            Ok(ToolResult {
                success: true,
                message: msg,
                data: serde_json::json!({}),
                dry_run: dry,
            })
        }
        Err(e) => {
            let _ = db.log(&req.tool, "failed", &e.to_string());
            Err(e)
        }
    }
}
#[tauri::command]
fn cancel_action(confirmation_id: String, state: State<SafetyState>, db: State<Database>) -> bool {
    let removed = safety::cancel(&state, &confirmation_id);
    if removed {
        let _ = db.log(
            "Action cancelled",
            "cancelled",
            "User cancelled pending confirmation",
        );
    }
    removed
}
#[tauri::command]
fn assistant_message(message: String, db: State<Database>) -> AppResult<ai::AssistantReply> {
    if message.trim().is_empty() || message.len() > 2000 {
        return Err(AppError::Message(
            "Message must be 1–2000 characters".into(),
        ));
    }
    let (reply, usage) = ai::orchestrate(&message);
    if let Some(usage) = usage {
        db.record_ai_usage(
            &usage.request_id,
            &usage.model,
            usage.input_tokens,
            usage.output_tokens,
        )?;
    }
    Ok(reply)
}
#[tauri::command]
fn get_ai_usage(db: State<Database>) -> AppResult<serde_json::Value> {
    let (input_tokens, output_tokens) = db.ai_usage_summary()?;
    Ok(serde_json::json!({"inputTokens":input_tokens,"outputTokens":output_tokens}))
}

#[tauri::command]
fn get_runtime_status() -> RuntimeStatus {
    let (winget_available, winget_version) = windows::winget_runtime_status();
    RuntimeStatus {
        dry_run: std::env::var("DRY_RUN")
            .map(|value| !value.eq_ignore_ascii_case("false"))
            .unwrap_or(true),
        elevated: windows::is_elevated(),
        ai_configured: ai::is_configured(),
        ai_model: ai::configured_model(),
        winget_available,
        winget_version,
    }
}

pub fn run() {
    let _ = dotenvy::dotenv();
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let data = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data)?;
            let db = Database::open(&data.join("linkset.db"))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            app.manage(db);
            app.manage(SafetyState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_dashboard,
            get_processes,
            get_network_connections,
            get_security_status,
            get_startup_apps,
            get_services,
            get_installed_apps,
            get_network_config,
            get_update_status,
            get_event_summary,
            analyze_temp_files,
            get_printers,
            get_physical_disks,
            get_network_alerts,
            run_diagnostic,
            search_apps,
            list_activity,
            propose_action,
            execute_action,
            cancel_action,
            assistant_message,
            get_ai_usage,
            get_runtime_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running LinkSet");
}
