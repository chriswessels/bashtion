use std::time::Duration;

use reqwest::Url;

#[derive(Debug, Clone)]
pub struct Config {
    pub api_key: String,
    pub model: String,
    pub base_url: Url,
    pub timeout: Duration,
    pub buffer_limit: usize,
}

impl Config {
    pub fn new(
        api_key: String,
        model: String,
        base_url: Url,
        timeout: Duration,
        buffer_limit: usize,
    ) -> Self {
        Self {
            api_key,
            model,
            base_url,
            timeout,
            buffer_limit,
        }
    }
}
