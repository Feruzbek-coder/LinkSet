use crate::{
    error::{AppError, AppResult},
    models::ActionRequest,
};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

const SYSTEM_PROMPT: &str = "You are LinkSet, a concise Windows PC assistant. Reply in the user's language. Never claim a heuristic proves malware. Never request, expose, or repeat passwords, tokens, cookies, private keys, or file contents. You may only suggest the provided read-only tools. System-changing actions are handled later by a local confirmation layer.";

pub trait AiProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_configured(&self) -> bool;
    fn respond(&self, text: &str) -> AppResult<ProviderResponse>;
}

pub struct OpenAiProvider;

#[derive(Debug)]
pub struct ProviderResponse {
    pub message: String,
    pub suggested_action: Option<ActionRequest>,
    pub request_id: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl AiProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "OpenAI"
    }
    fn is_configured(&self) -> bool {
        std::env::var("OPENAI_API_KEY")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    }
    fn respond(&self, text: &str) -> AppResult<ProviderResponse> {
        let key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| AppError::Message("OpenAI API key is not configured".into()))?;
        let model = configured_model();
        let body = json!({
            "model": model, "store": false, "instructions": SYSTEM_PROMPT,
            "input": redact_sensitive(text),
            "tools": [
                {"type":"function","name":"run_diagnostic","description":"Run one safe, local, read-only Windows diagnostic workflow.","strict":true,"parameters":{"type":"object","properties":{"type":{"type":"string","enum":["SYSTEM_CHECK","PC_SLOW","NO_INTERNET","APP_NOT_OPENING","LOW_DISK_SPACE","PRINTER_NOT_WORKING","HIGH_CPU","HIGH_MEMORY","WINDOWS_UPDATE_ERROR","NETWORK_SLOW","STARTUP_SLOW"]}},"required":["type"],"additionalProperties":false}},
                {"type":"function","name":"search_app","description":"Search the trusted winget repository. This does not install anything.","strict":true,"parameters":{"type":"object","properties":{"query":{"type":"string","minLength":2,"maxLength":80}},"required":["query"],"additionalProperties":false}}
            ]
        });
        let response = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(35))
            .build()
            .map_err(|e| AppError::Command(format!("AI client error: {e}")))?
            .post("https://api.openai.com/v1/responses")
            .bearer_auth(key)
            .json(&body)
            .send()
            .map_err(|e| AppError::Command(format!("AI request failed: {e}")))?;
        let status = response.status();
        let value: Value = response
            .json()
            .map_err(|e| AppError::Command(format!("Invalid AI response: {e}")))?;
        if !status.is_success() {
            let message = value
                .pointer("/error/message")
                .and_then(Value::as_str)
                .unwrap_or("OpenAI request was rejected");
            return Err(AppError::Command(format!(
                "OpenAI: {}",
                truncate(message, 240)
            )));
        }
        parse_response(value, model)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantReply {
    pub message: String,
    pub suggested_action: Option<ActionRequest>,
    pub provider: String,
}

pub fn orchestrate(text: &str) -> (AssistantReply, Option<ProviderResponse>) {
    let provider = OpenAiProvider;
    if provider.is_configured() {
        if let Ok(remote) = provider.respond(text) {
            let reply = AssistantReply {
                message: if remote.message.is_empty() {
                    local_orchestrate(text).message
                } else {
                    remote.message.clone()
                },
                suggested_action: remote.suggested_action.clone(),
                provider: format!("{} · {}", provider.name(), remote.model),
            };
            return (reply, Some(remote));
        }
    }
    (local_orchestrate(text), None)
}

pub fn local_orchestrate(text: &str) -> AssistantReply {
    let q = text.to_lowercase();
    let is_slow = q.contains("sekin") || q.contains("slow") || q.contains("медлен");
    let diagnostic = if is_slow
        && (q.contains("internet") || q.contains("network") || q.contains("сеть"))
    {
        Some("NETWORK_SLOW")
    } else if q.contains("cpu") || q.contains("processor") || q.contains("процессор") {
        Some("HIGH_CPU")
    } else if q.contains("ram")
        || q.contains("memory")
        || q.contains("xotira")
        || q.contains("памят")
    {
        Some("HIGH_MEMORY")
    } else if q.contains("startup") || q.contains("avtoyuk") || q.contains("автозагруз") {
        Some("STARTUP_SLOW")
    } else if q.contains("ochilmay") || q.contains("not opening") || q.contains("не откры") {
        Some("APP_NOT_OPENING")
    } else if is_slow {
        Some("PC_SLOW")
    } else if q.contains("internet") || q.contains("интернет") {
        Some("NO_INTERNET")
    } else if q.contains("printer") || q.contains("принтер") {
        Some("PRINTER_NOT_WORKING")
    } else if q.contains("disk") || q.contains("joy") || q.contains("мест") {
        Some("LOW_DISK_SPACE")
    } else if q.contains("update") || q.contains("обновлен") {
        Some("WINDOWS_UPDATE_ERROR")
    } else {
        None
    };
    if (q.contains("o‘rnat")
        || q.contains("ornat")
        || q.contains("install")
        || q.contains("установ"))
        && extract_app_query(text).is_some()
    {
        let query = extract_app_query(text).unwrap_or_else(|| "application".into());
        return AssistantReply { message: format!("{query} paketini ishonchli winget manbasidan qidiraman. O‘rnatish alohida tasdiq talab qiladi."), suggested_action: Some(ActionRequest { tool: "search_app".into(), arguments: json!({"query":query}) }), provider: "Local diagnostic".into() };
    }
    let kind = diagnostic.unwrap_or("SYSTEM_CHECK");
    AssistantReply { message: format!("{kind} lokal diagnostikasini boshlayman. Faqat zarur tizim ko‘rsatkichlari tahlil qilinadi."), suggested_action: Some(ActionRequest { tool: "run_diagnostic".into(), arguments: json!({"type":kind}) }), provider: "Local diagnostic".into() }
}

pub fn redact_sensitive(input: &str) -> String {
    let patterns = [
        (
            r"(?i)\b(sk|pk|api)[-_][a-z0-9_-]{12,}\b",
            "[REDACTED_TOKEN]",
        ),
        (
            r"(?i)\b(?:password|passwd|token|secret)\s*[:=]\s*\S+",
            "[REDACTED_SECRET]",
        ),
        (r"(?i)\b[A-Z]:\\(?:[^\s\\]+\\)*[^\s]*", "[REDACTED_PATH]"),
        (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "[REDACTED_EMAIL]",
        ),
    ];
    patterns
        .iter()
        .fold(input.to_string(), |text, (pattern, replacement)| {
            Regex::new(pattern)
                .map(|re| re.replace_all(&text, *replacement).into_owned())
                .unwrap_or(text)
        })
}

fn parse_response(value: Value, model: String) -> AppResult<ProviderResponse> {
    let mut message = String::new();
    let mut action = None;
    if let Some(output) = value.get("output").and_then(Value::as_array) {
        for item in output {
            match item.get("type").and_then(Value::as_str) {
                Some("message") => {
                    if let Some(content) = item.get("content").and_then(Value::as_array) {
                        for part in content {
                            if part.get("type").and_then(Value::as_str) == Some("output_text") {
                                if let Some(text) = part.get("text").and_then(Value::as_str) {
                                    message.push_str(text);
                                }
                            }
                        }
                    }
                }
                Some("function_call") if action.is_none() => {
                    let name = item.get("name").and_then(Value::as_str).unwrap_or("");
                    if matches!(name, "run_diagnostic" | "search_app") {
                        let args = item
                            .get("arguments")
                            .and_then(Value::as_str)
                            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                            .unwrap_or_else(|| json!({}));
                        if args.is_object() {
                            action = Some(ActionRequest {
                                tool: name.into(),
                                arguments: args,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok(ProviderResponse {
        message,
        suggested_action: action,
        request_id: value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .into(),
        model,
        input_tokens: value
            .pointer("/usage/input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens: value
            .pointer("/usage/output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

pub fn configured_model() -> String {
    let model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-5.4-mini".into());
    if model.len() <= 80
        && model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        model
    } else {
        "gpt-5.4-mini".into()
    }
}

pub fn is_configured() -> bool {
    OpenAiProvider.is_configured()
}

fn extract_app_query(input: &str) -> Option<String> {
    input
        .split_whitespace()
        .find(|word| {
            let lower = word.to_lowercase();
            !matches!(
                lower.as_str(),
                "install" | "o‘rnat" | "ornat" | "qil" | "qiling" | "установить" | "установи"
            )
        })
        .map(|s| s.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
        .filter(|s| s.len() >= 2 && s.len() <= 80)
}
fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacts_tokens_paths_and_email() {
        let result = redact_sensitive(
            "token=abc123456789 C:\\Users\\Ali\\secret.txt ali@example.com sk-test_123456789012",
        );
        assert!(!result.contains("secret.txt"));
        assert!(!result.contains("example.com"));
        assert!(!result.contains("sk-test"));
    }
    #[test]
    fn ignores_unregistered_remote_tool() {
        let response=parse_response(json!({"id":"r1","output":[{"type":"function_call","name":"shell","arguments":"{\"command\":\"whoami\"}"}],"usage":{}}),"test".into()).unwrap();
        assert!(response.suggested_action.is_none());
    }

    #[test]
    fn routes_specific_local_diagnostics_before_generic_slow() {
        for (message, expected) in [
            ("Internet sekin", "NETWORK_SLOW"),
            ("RAM juda ko‘p ishlayapti", "HIGH_MEMORY"),
            ("CPU yuqori", "HIGH_CPU"),
            ("Dastur ochilmayapti", "APP_NOT_OPENING"),
            ("Startup sekin", "STARTUP_SLOW"),
        ] {
            let reply = local_orchestrate(message);
            assert_eq!(reply.suggested_action.unwrap().arguments["type"], expected);
        }
    }
}
