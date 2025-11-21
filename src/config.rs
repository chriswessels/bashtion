use std::env;
use std::fmt;
use std::time::Duration;

use reqwest::Url;

#[derive(Debug, Clone, Default)]
pub struct EnvConfig {
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub timeout_secs: Option<u64>,
    pub buffer_limit: Option<usize>,
    pub auto_exec: Option<bool>,
    pub exec_shell: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CliConfig {
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub timeout_secs: Option<u64>,
    pub buffer_limit: Option<usize>,
    pub auto_exec: Option<bool>,
    pub exec_shell: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub base_url: Option<Url>,
    pub api_key: Option<String>,
    pub model: String,
    pub timeout: Duration,
    pub buffer_limit: usize,
    pub auto_exec: bool,
    pub exec_shell: Option<String>,
}

#[derive(Debug)]
pub enum ConfigError {
    InvalidUtf8 {
        key: &'static str,
    },
    InvalidNumber {
        key: &'static str,
        value: String,
        source: String,
    },
    InvalidBool {
        key: &'static str,
        value: String,
    },
    InvalidUrl {
        value: String,
        source: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidUtf8 { key } => write!(f, "{key} contains invalid UTF-8"),
            ConfigError::InvalidNumber { key, value, source } => {
                write!(f, "{key} value '{value}' is not a valid number: {source}")
            }
            ConfigError::InvalidBool { key, value } => {
                write!(f, "{key} value '{value}' is not a valid boolean")
            }
            ConfigError::InvalidUrl { value, source } => {
                write!(f, "Invalid OpenAI base URL '{value}': {source}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl EnvConfig {
    pub fn read() -> Result<Self, ConfigError> {
        Ok(Self {
            base_url: read_env_string("BASHTION_OPENAI_BASE_URL")?,
            api_key: read_env_string("BASHTION_OPENAI_API_KEY")?,
            model: read_env_string("BASHTION_OPENAI_MODEL")?,
            timeout_secs: read_env_number("BASHTION_TIMEOUT_SECS")?,
            buffer_limit: read_env_number("BASHTION_BUFFER_LIMIT")?,
            auto_exec: read_env_bool("BASHTION_AUTO_EXEC")?,
            exec_shell: read_env_string("BASHTION_EXEC_SHELL")?,
        })
    }
}

impl ResolvedConfig {
    pub fn resolve(cli: CliConfig, env: EnvConfig) -> Result<Self, ConfigError> {
        let base_url = merge_strings(cli.base_url, env.base_url);
        let api_key = merge_strings(cli.api_key, env.api_key);
        let model = merge_strings(cli.model, env.model).unwrap_or_else(|| "gpt-4o".to_string());
        let timeout_secs = cli.timeout_secs.or(env.timeout_secs).unwrap_or(30);
        let buffer_limit = cli.buffer_limit.or(env.buffer_limit).unwrap_or(500 * 1024);
        let auto_exec = cli.auto_exec.or(env.auto_exec).unwrap_or(true);
        let exec_shell = merge_strings(cli.exec_shell, env.exec_shell);

        Ok(Self {
            base_url: base_url
                .map(|value| {
                    Url::parse(&value).map_err(|err| ConfigError::InvalidUrl {
                        value,
                        source: err.to_string(),
                    })
                })
                .transpose()?,
            api_key,
            model,
            timeout: Duration::from_secs(timeout_secs),
            buffer_limit,
            auto_exec,
            exec_shell,
        })
    }
}

fn merge_strings(cli: Option<String>, env: Option<String>) -> Option<String> {
    cli.or(env).and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn read_env_string(key: &'static str) -> Result<Option<String>, ConfigError> {
    match env::var(key) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidUtf8 { key }),
    }
}

fn read_env_number<T>(key: &'static str) -> Result<Option<T>, ConfigError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    match env::var(key) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                trimmed
                    .parse::<T>()
                    .map(Some)
                    .map_err(|err| ConfigError::InvalidNumber {
                        key,
                        value: trimmed.to_string(),
                        source: err.to_string(),
                    })
            }
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidUtf8 { key }),
    }
}

fn read_env_bool(key: &'static str) -> Result<Option<bool>, ConfigError> {
    match env::var(key) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            parse_bool(trimmed)
                .ok_or_else(|| ConfigError::InvalidBool {
                    key,
                    value: trimmed.to_string(),
                })
                .map(Some)
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ConfigError::InvalidUtf8 { key }),
    }
}

pub fn parse_bool(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_prefers_cli() {
        let cli = CliConfig {
            model: Some("cli".into()),
            ..Default::default()
        };
        let env = EnvConfig {
            model: Some("env".into()),
            ..Default::default()
        };
        let resolved = ResolvedConfig::resolve(cli, env).unwrap();
        assert_eq!(resolved.model, "cli");
    }

    #[test]
    fn defaults_apply_when_missing() {
        let resolved = ResolvedConfig::resolve(CliConfig::default(), EnvConfig::default()).unwrap();
        assert_eq!(resolved.model, "gpt-4o");
        assert_eq!(resolved.timeout.as_secs(), 30);
        assert_eq!(resolved.buffer_limit, 500 * 1024);
        assert!(resolved.auto_exec);
    }

    #[test]
    fn parse_bool_recognizes_values() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("nope"), None);
    }
}
