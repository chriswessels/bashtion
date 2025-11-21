use llm_json::{repair_json, RepairOptions};
use reqwest::{Client, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json_lenient as serde_json;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

use crate::config::ResolvedConfig;
use crate::error::BashtionError;
use crate::logging::log_stderr;

const SYSTEM_PROMPT: &str = r#"You are a cybersecurity expert analyzing a shell script that the user wants to pipe directly into a shell. Provide actionable evidence when you find malicious or risky behavior.

Output JSON **only**. The JSON must match exactly:
{
  "safe": boolean,
  "summary": "Short sentence explaining the overall decision",
  "findings": [
    {
      "title": "One-line title for the issue",
      "severity": "low|medium|high",
      "explanation": "Detailed reasoning that references the script's behavior",
      "code": "Exact snippet(s) copied verbatim from the script"
    }
  ]
}

Rules:
- If safe=false, include at least one finding with concrete shell commands or code responsible for the risk.
- The code field must quote the relevant lines exactly as they appear; do not paraphrase or use ellipses.
- Mention outbound network hosts, file paths, privilege escalation, and any obfuscation that influences the decision.
- If safe=true, you may return an empty findings array or list benign behaviors.
- Downloading artifacts with curl/wget into local files **without executing them** (no piping to shells, no chmod+run, no sourcing) is SAFE. You may record a LOW severity finding, but `safe` must remain true.
- Mark unsafe only when the script executes or installs remote code, modifies sensitive files, escalates privileges, or exfiltrates data.
- Never include markdown code fences or commentary outside the JSON document."#;

const MAX_LLM_ATTEMPTS: usize = 3;

#[cfg(test)]
const RETRY_BASE_DELAY_MS: u64 = 25;
#[cfg(not(test))]
const RETRY_BASE_DELAY_MS: u64 = 200;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct LlmVerdict {
    pub safe: bool,
    #[serde(default = "default_summary", alias = "reason")]
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<LlmFinding>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct LlmFinding {
    pub title: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub explanation: String,
    #[serde(default)]
    pub code: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Unknown,
}

impl FindingSeverity {
    pub fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => FindingSeverity::Low,
            "medium" | "med" => FindingSeverity::Medium,
            "high" | "critical" => FindingSeverity::High,
            _ => FindingSeverity::Unknown,
        }
    }
}

pub fn max_finding_severity(verdict: &LlmVerdict) -> Option<FindingSeverity> {
    verdict
        .findings
        .iter()
        .map(|f| FindingSeverity::from_str(&f.severity))
        .max()
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ResponseFormat<'a> {
    #[serde(rename = "type")]
    r#type: &'a str,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    temperature: f32,
    response_format: ResponseFormat<'a>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

pub async fn analyze(script: &str, config: &ResolvedConfig) -> Result<LlmVerdict, BashtionError> {
    run_with_retries(|| analyze_once(script, config)).await
}

async fn analyze_once(script: &str, config: &ResolvedConfig) -> Result<LlmVerdict, AttemptError> {
    let base = config
        .base_url
        .as_ref()
        .ok_or_else(|| AttemptError::fatal("BASHTION_OPENAI_BASE_URL is required"))?;

    let api_key = config.api_key.as_ref().filter(|k| !k.trim().is_empty());

    let client = Client::builder()
        .timeout(config.timeout)
        .build()
        .map_err(|e| AttemptError::fatal(format!("Failed to build HTTP client: {e}")))?;

    let request = ChatRequest {
        model: &config.model,
        temperature: 0.0,
        response_format: ResponseFormat {
            r#type: "json_object",
        },
        messages: vec![
            ChatMessage {
                role: "system",
                content: SYSTEM_PROMPT,
            },
            ChatMessage {
                role: "user",
                content: script,
            },
        ],
    };

    let url = join_chat_url(base).map_err(|e| AttemptError::fatal(e.to_string()))?;

    let response = client
        .post(url.clone())
        .bearer_auth(api_key.as_deref().map_or("", |v| v))
        .json(&request)
        .send()
        .await
        .map_err(|e| AttemptError::retryable(format!("API call failed: {e}")))?;

    let status = response.status();
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| AttemptError::retryable(format!("Failed to read LLM response body: {e}")))?;

    if !status.is_success() {
        let snippet = summarize_body(&body_bytes);
        let message = format!("LLM API POST {url} returned HTTP {status}: {snippet}");
        let retryable = status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS;
        return if retryable {
            Err(AttemptError::retryable(message))
        } else {
            Err(AttemptError::fatal(message))
        };
    }

    let data: ChatResponse = parse_json_bytes(&body_bytes, "LLM response body")
        .map_err(|e| e.with_context("while parsing chat response"))?;

    let choice = data
        .choices
        .first()
        .ok_or_else(|| AttemptError::retryable("LLM response missing choices".to_string()))?;

    let _ = &choice.message.role; // consider field used
    let content = choice.message.content.trim();
    let json_slice = extract_json_block(content).ok_or_else(|| {
        AttemptError::retryable(format!(
            "LLM response was not JSON. Model output snippet: {}",
            summarize_text(content)
        ))
    })?;

    let verdict: LlmVerdict = parse_json_bytes(json_slice.as_bytes(), "LLM verdict JSON")
        .map_err(|e| e.with_context("while parsing verdict"))?;

    Ok(verdict)
}

fn default_summary() -> String {
    "Model did not return a summary".to_string()
}

fn join_chat_url(base: &Url) -> Result<Url, BashtionError> {
    // ensure we don't lose base path components
    let mut url = base.clone();
    let mut segments = url
        .path_segments_mut()
        .map_err(|_| BashtionError::SemanticError("Invalid OPENAI_BASE_URL".into()))?;
    segments.push("chat");
    segments.push("completions");
    drop(segments);
    Ok(url)
}

fn extract_json_block(text: &str) -> Option<&str> {
    let trimmed = text.trim();

    if trimmed.starts_with("```") {
        let inner = trimmed.trim_start_matches("```");
        if let Some(pos) = inner.find('\n') {
            let without_lang = &inner[pos + 1..];
            if let Some(end) = without_lang.find("```") {
                let candidate = &without_lang[..end];
                let candidate = candidate.trim();
                if candidate.trim_start().starts_with('{') {
                    return Some(candidate);
                }
            }
        }
    }

    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            return Some(trimmed[start..=end].trim());
        }
    }

    None
}

fn summarize_text(text: &str) -> String {
    summarize_body(text.as_bytes())
}

fn summarize_body(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty response body>".to_string();
    }

    let text = String::from_utf8_lossy(bytes);
    if text.chars().all(|ch| ch.is_whitespace()) {
        return "<whitespace response body>".to_string();
    }

    text.chars()
        .map(|ch| {
            if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' {
                ' '
            } else {
                ch
            }
        })
        .collect()
}

fn parse_json_bytes<T>(bytes: &[u8], context: &str) -> Result<T, AttemptError>
where
    T: DeserializeOwned,
{
    match serde_json::from_slice(bytes) {
        Ok(value) => Ok(value),
        Err(primary_err) => {
            let snippet = summarize_body(bytes);
            let repaired = attempt_json_repair(bytes).map_err(|repair_msg| {
                AttemptError::retryable(format!(
                    "Failed to parse {context}: {primary_err}; {repair_msg}; snippet: {snippet}"
                ))
            })?;

            serde_json::from_str(&repaired).map_err(|err| {
                AttemptError::retryable(format!(
                    "Failed to parse {context}: {primary_err}; after repair: {err}; repaired snippet: {}",
                    summarize_text(&repaired)
                ))
            })
        }
    }
}

fn attempt_json_repair(bytes: &[u8]) -> Result<String, String> {
    let text = String::from_utf8_lossy(bytes);
    let mut options = RepairOptions::default();
    options.ensure_ascii = false;
    options.stream_stable = true;

    repair_json(&text, &options).map_err(|err| err.to_string())
}

async fn run_with_retries<F, Fut>(mut attempt_fn: F) -> Result<LlmVerdict, BashtionError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<LlmVerdict, AttemptError>>,
{
    let mut attempt = 0usize;
    let mut last_error: Option<AttemptError> = None;

    while attempt < MAX_LLM_ATTEMPTS {
        attempt += 1;
        match attempt_fn().await {
            Ok(verdict) => return Ok(verdict),
            Err(err) => {
                let should_retry = err.retryable && attempt < MAX_LLM_ATTEMPTS;
                if should_retry {
                    let delay_ms = retry_delay_ms(attempt);
                    if let Err(log_err) = log_stderr(format!(
                        "[Bashtion] AI analysis attempt {attempt}/{max} failed: {reason}. Retrying in {delay} ms...",
                        max = MAX_LLM_ATTEMPTS,
                        reason = err.message,
                        delay = delay_ms
                    )) {
                        return Err(log_err);
                    }
                    last_error = Some(err);
                    sleep(Duration::from_millis(delay_ms)).await;
                    continue;
                } else {
                    return Err(err.into_bashtion_error(attempt));
                }
            }
        }
    }

    Err(last_error
        .unwrap_or_else(|| AttemptError::fatal("LLM analysis failed without diagnostic output"))
        .into_bashtion_error(MAX_LLM_ATTEMPTS))
}

fn retry_delay_ms(attempt_index: usize) -> u64 {
    // attempt_index starts at 1
    let exponent = attempt_index.saturating_sub(1) as u32;
    let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX).min(8);
    RETRY_BASE_DELAY_MS * multiplier
}

#[derive(Debug, Clone)]
struct AttemptError {
    message: String,
    retryable: bool,
}

impl AttemptError {
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }

    fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }

    fn with_context(mut self, context: &str) -> Self {
        self.message = format!("{context}: {}", self.message);
        self
    }

    fn into_bashtion_error(self, attempts: usize) -> BashtionError {
        let suffix = format!(
            " (after {attempts} attempt{plural})",
            plural = if attempts == 1 { "" } else { "s" }
        );
        BashtionError::SemanticError(format!("{}{suffix}", self.message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_json_inside_plain_text() {
        let input = "some text {\"safe\":true}\n";
        let slice = extract_json_block(input).unwrap();
        assert_eq!(slice, "{\"safe\":true}");
    }

    #[test]
    fn finds_json_inside_codeblock() {
        let input = "```json\n{\"safe\":false}\n```";
        let slice = extract_json_block(input).unwrap();
        assert_eq!(slice, "{\"safe\":false}");
    }

    #[test]
    fn join_url_keeps_base() {
        let base: Url = "https://api.openai.com/v1".parse().unwrap();
        let joined = join_chat_url(&base).unwrap();
        assert_eq!(
            joined.as_str(),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn verdict_falls_back_to_reason_field() {
        let json = r#"{"safe":false,"reason":"bad","findings":[]}"#;
        let verdict: LlmVerdict = serde_json::from_str(json).unwrap();
        assert_eq!(verdict.summary, "bad");
    }

    #[test]
    fn summarize_body_preserves_full_text() {
        let long_body = "oops\u{0001}error\n".repeat(10);
        let summary = summarize_body(long_body.as_bytes());
        assert!(summary.contains("oops"));
        assert!(summary.contains("error"));
        assert!(!summary.contains("truncated"));
        assert!(!summary.contains("\u{0001}"));
    }

    #[tokio::test]
    async fn retries_transient_errors_then_succeeds() {
        let mut attempts = 0;
        let verdict = run_with_retries(|| {
            attempts += 1;
            let current = attempts;
            async move {
                if current < 3 {
                    Err(AttemptError::retryable(format!("transient {current}")))
                } else {
                    Ok(LlmVerdict {
                        safe: true,
                        summary: "ok".into(),
                        findings: vec![],
                    })
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(attempts, 3);
        assert!(verdict.safe);
    }

    #[tokio::test]
    async fn stops_on_fatal_error_without_retry() {
        let mut attempts = 0;
        let err = run_with_retries(|| {
            attempts += 1;
            async move { Err(AttemptError::fatal("fatal issue")) }
        })
        .await
        .unwrap_err();

        assert_eq!(attempts, 1);
        match err {
            BashtionError::SemanticError(msg) => {
                assert!(msg.contains("fatal issue"));
                assert!(msg.contains("after 1 attempt"));
            }
            other => panic!("Unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn repairs_truncated_llm_json() {
        let broken =
            br#"{"safe":false,"summary":"bad","findings":[{"title":"Issue","severity":"high"}"#;
        let verdict: LlmVerdict = parse_json_bytes(broken, "test verdict").unwrap();
        assert!(!verdict.safe);
        assert_eq!(verdict.findings.len(), 1);
        assert_eq!(verdict.findings[0].title, "Issue");
    }

    #[test]
    fn maps_max_finding_severity() {
        let verdict = LlmVerdict {
            safe: false,
            summary: "bad".into(),
            findings: vec![
                LlmFinding {
                    title: "curl".into(),
                    severity: "low".into(),
                    explanation: String::new(),
                    code: String::new(),
                },
                LlmFinding {
                    title: "chmod".into(),
                    severity: "HIGH".into(),
                    explanation: String::new(),
                    code: String::new(),
                },
            ],
        };

        assert_eq!(max_finding_severity(&verdict), Some(FindingSeverity::High));
    }
}
