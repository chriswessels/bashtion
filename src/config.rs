use std::time::Duration;

use reqwest::Url;

#[derive(Debug, Clone)]
pub struct Config {
    pub api_key: Option<String>,
    pub model: String,
    pub base_url: Url,
    pub timeout: Duration,
    pub buffer_limit: usize,
    pub allow_caution: bool,
    pub auto_exec: bool,
}

impl Config {
    pub fn new(
        api_key: Option<String>,
        model: String,
        base_url: Url,
        timeout: Duration,
        buffer_limit: usize,
        allow_caution: bool,
        auto_exec: bool,
    ) -> Self {
        Self {
            api_key,
            model,
            base_url,
            timeout,
            buffer_limit,
            allow_caution,
            auto_exec,
        }
    }
}
