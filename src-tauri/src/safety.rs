use crate::{
    error::{AppError, AppResult},
    models::{ActionProposal, ActionRequest},
};
use chrono::{DateTime, Duration, Utc};
use std::{collections::HashMap, sync::Mutex};
use uuid::Uuid;

#[derive(Clone)]
pub struct PendingAction {
    pub request: ActionRequest,
    pub expires: DateTime<Utc>,
}
pub struct SafetyState(pub Mutex<HashMap<String, PendingAction>>);
impl Default for SafetyState {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

struct Policy {
    risk: u8,
    title: &'static str,
    description: &'static str,
}
fn policy(tool: &str) -> Option<Policy> {
    match tool {
        "install_app" => Some(Policy { risk: 2, title: "Ilovani o‘rnatish", description: "Tasdiqlangan winget paketini o‘rnatadi. Administrator ruxsati talab qilinishi mumkin." }),
        "update_app" => Some(Policy { risk: 2, title: "Ilovani yangilash", description: "Tanlangan winget paketini yangi versiyaga yangilaydi." }),
        "uninstall_app" => Some(Policy { risk: 2, title: "Ilovani o‘chirish", description: "Tanlangan ilovani Windows’dan o‘chiradi. Ilovaning lokal ma’lumotlari saqlanib qolishi mumkin." }),
        "restart_service" => Some(Policy { risk: 1, title: "Windows xizmatini qayta ishga tushirish", description: "Faqat ruxsat etilgan xizmat qayta ishga tushiriladi." }),
        "restart_process" => Some(Policy { risk: 1, title: "Jarayonni qayta ishga tushirish", description: "Ishlayotgan ilova yopilib qayta ochiladi; saqlanmagan ma’lumot yo‘qolishi mumkin." }),
        "clear_temp_files" => Some(Policy { risk: 1, title: "Vaqtinchalik fayllarni tozalash", description: "Faqat joriy foydalanuvchining 24 soatdan eski temp fayllari o‘chiriladi." }),
        _ => None,
    }
}

pub fn propose(state: &SafetyState, request: ActionRequest) -> AppResult<ActionProposal> {
    let p =
        policy(&request.tool).ok_or_else(|| AppError::Message("Tool is not registered".into()))?;
    validate(&request)?;
    let id = Uuid::new_v4().to_string();
    let expires = Utc::now() + Duration::minutes(5);
    let mut pending = state.0.lock().unwrap();
    pending.retain(|_, action| action.expires >= Utc::now());
    pending.insert(
        id.clone(),
        PendingAction {
            request: request.clone(),
            expires,
        },
    );
    Ok(ActionProposal {
        confirmation_id: id,
        tool: request.tool,
        title: p.title.into(),
        description: p.description.into(),
        risk_level: p.risk,
        requires_confirmation: p.risk >= 1,
        expires_at: expires.to_rfc3339(),
    })
}
pub fn cancel(state: &SafetyState, id: &str) -> bool {
    state.0.lock().unwrap().remove(id).is_some()
}
pub fn consume(state: &SafetyState, id: &str) -> AppResult<ActionRequest> {
    let item = state
        .0
        .lock()
        .unwrap()
        .remove(id)
        .ok_or_else(|| AppError::Message("Confirmation is invalid or already used".into()))?;
    if item.expires < Utc::now() {
        return Err(AppError::Message("Confirmation expired".into()));
    }
    Ok(item.request)
}
fn validate(r: &ActionRequest) -> AppResult<()> {
    if r.tool == "restart_service" {
        let n = r
            .arguments
            .get("service_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let allowed = ["Spooler", "wuauserv", "Dnscache"];
        if !allowed.contains(&n) {
            return Err(AppError::Message(
                "Service is not in the safe allowlist".into(),
            ));
        }
    }
    if r.tool == "restart_process" {
        let name = r
            .arguments
            .get("process_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let allowed = ["explorer", "OneDrive", "Zoom", "Teams", "ms-teams"];
        if !allowed.iter().any(|item| item.eq_ignore_ascii_case(name)) {
            return Err(AppError::Message(
                "Process is not in the safe allowlist".into(),
            ));
        }
    }
    if matches!(
        r.tool.as_str(),
        "install_app" | "update_app" | "uninstall_app"
    ) {
        let id = r
            .arguments
            .get("package_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if id.len() > 120
            || !id.contains('.')
            || id.starts_with('.')
            || id.ends_with('.')
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-_+".contains(c))
        {
            return Err(AppError::Message(
                "A valid exact winget package_id is required".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejects_unknown_tool() {
        let s = SafetyState::default();
        assert!(propose(
            &s,
            ActionRequest {
                tool: "shell".into(),
                arguments: json!({})
            }
        )
        .is_err())
    }
    #[test]
    fn rejects_unlisted_service() {
        let s = SafetyState::default();
        assert!(propose(
            &s,
            ActionRequest {
                tool: "restart_service".into(),
                arguments: json!({"service_name":"WinDefend"})
            }
        )
        .is_err())
    }
    #[test]
    fn token_is_single_use() {
        let s = SafetyState::default();
        let p = propose(
            &s,
            ActionRequest {
                tool: "clear_temp_files".into(),
                arguments: json!({}),
            },
        )
        .unwrap();
        assert!(consume(&s, &p.confirmation_id).is_ok());
        assert!(consume(&s, &p.confirmation_id).is_err())
    }
    #[test]
    fn rejects_critical_process_restart() {
        let s = SafetyState::default();
        assert!(propose(
            &s,
            ActionRequest {
                tool: "restart_process".into(),
                arguments: json!({"process_name":"lsass"})
            }
        )
        .is_err());
    }
    #[test]
    fn package_mutations_require_exact_id() {
        let s = SafetyState::default();
        for tool in ["install_app", "update_app", "uninstall_app"] {
            assert!(propose(
                &s,
                ActionRequest {
                    tool: tool.into(),
                    arguments: json!({})
                }
            )
            .is_err());
        }
        assert!(propose(
            &s,
            ActionRequest {
                tool: "install_app".into(),
                arguments: json!({"package_id":"Zoom Zoom"})
            }
        )
        .is_err());
    }
}
