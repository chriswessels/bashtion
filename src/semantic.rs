use anyhow::Context;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::BashtionError;

const SYSTEM_PROMPT: &str = "You are a cybersecurity expert analyzing a shell script. Your goal is to detect malicious intent.\nContext: The user is piping this script to bash.\nCriteria:\n- SAFE: Standard installers (Rust, Node, Docker, Foundry).\n- UNSAFE: Obfuscation, Exfiltration of env vars/SSH keys, Reverse Shells, unauthorized system modifications.\nResponse Format: JSON ONLY: {\"safe\": boolean, \"reason\": \"string\"}";

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct LlmVerdict {
    pub safe: bool,
    pub reason: String,
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

pub async fn analyze(script: &str, config: &Config) -> Result<LlmVerdict, BashtionError> {
    let api_key = config
        .api_key
        .as_ref()
        .filter(|k| !k.trim().is_empty())
        .ok_or_else(|| BashtionError::SemanticError("OPENAI_API_KEY is required".into()))?;

    let client = Client::builder()
        .timeout(config.timeout)
        .build()
        .context("Failed to build HTTP client")
        .map_err(|e| BashtionError::SemanticError(e.to_string()))?;

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

    let url = join_chat_url(&config.base_url)?;

    let response = client
        .post(url)
        .bearer_auth(api_key)
        .json(&request)
        .send()
        .await
        .context("API call failed")
        .map_err(|e| BashtionError::SemanticError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(BashtionError::SemanticError(format!(
            "LLM API returned HTTP {}",
            response.status()
        )));
    }

    let data: ChatResponse = response
        .json()
        .await
        .context("Failed to parse LLM response body")
        .map_err(|e| BashtionError::SemanticError(e.to_string()))?;

    let choice = data
        .choices
        .first()
        .ok_or_else(|| BashtionError::SemanticError("LLM response missing choices".into()))?;

    let _ = &choice.message.role; // consider field used
    let content = choice.message.content.trim();
    let json_slice = extract_json_block(content)
        .ok_or_else(|| BashtionError::SemanticError("LLM response was not JSON".into()))?;
    let verdict: LlmVerdict = serde_json::from_str(json_slice)
        .context("Failed to deserialize LLM verdict JSON")
        .map_err(|e| BashtionError::SemanticError(e.to_string()))?;

    Ok(verdict)
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
}
