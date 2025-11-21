use std::time::Duration;

use clap::Parser;
use colored::{control::set_override, Colorize};

use bashtion::{config::Config, error::BashtionError, run};

#[derive(Parser, Debug)]
#[command(
    name = "bashtion",
    about = "Intercepts and inspects piped shell scripts",
    version
)]
struct Cli {
    /// OpenAI-compatible API key (env: OPENAI_API_KEY)
    #[arg(long, env = "OPENAI_API_KEY")]
    api_key: Option<String>,

    /// Model name (env: OPENAI_MODEL)
    #[arg(long, env = "OPENAI_MODEL", default_value = "gpt-4o")]
    model: String,

    /// Base URL for OpenAI-compatible endpoint (env: OPENAI_BASE_URL)
    #[arg(
        long,
        env = "OPENAI_BASE_URL",
        default_value = "https://api.openai.com/v1"
    )]
    base_url: String,

    /// HTTP timeout seconds (env: BASHTION_TIMEOUT_SECS)
    #[arg(long, env = "BASHTION_TIMEOUT_SECS", default_value_t = 30)]
    timeout_secs: u64,

    /// Buffer limit in bytes (env: BASHTION_BUFFER_LIMIT)
    #[arg(long, env = "BASHTION_BUFFER_LIMIT", default_value_t = 500 * 1024)]
    buffer_limit: usize,

    /// Disable colored stderr output (env: BASHTION_NO_COLOR)
    #[arg(long, env = "BASHTION_NO_COLOR", default_value_t = false)]
    no_color: bool,

    /// Allow scripts that trigger caution (soft) rules (env: BASHTION_ALLOW_CAUTION)
    #[arg(long, env = "BASHTION_ALLOW_CAUTION", default_value_t = false)]
    allow_caution: bool,

    /// Automatically exec the validated script in the user's shell (env: BASHTION_AUTO_EXEC)
    #[arg(long = "no-exec", env = "BASHTION_AUTO_EXEC", default_value_t = true, action = clap::ArgAction::SetFalse)]
    auto_exec: bool,
}

#[tokio::main]
async fn main() {
    if let Err(err) = entrypoint().await {
        match &err {
            BashtionError::StaticBlocked(r) => {
                eprintln!("{}", format!("[Bashtion] BLOCKED (static): {r}").red())
            }
            BashtionError::SemanticBlocked(r) => {
                eprintln!("{}", format!("[Bashtion] BLOCKED (ai): {r}").red())
            }
            _ => eprintln!("{}", format!("[Bashtion] ERROR: {err}").yellow()),
        }
        std::process::exit(1);
    }
}

async fn entrypoint() -> Result<(), BashtionError> {
    let cli = Cli::parse();
    set_override(!cli.no_color);

    let base_url = cli
        .base_url
        .parse()
        .map_err(|e| BashtionError::Other(format!("Invalid OPENAI_BASE_URL: {e}")))?;

    let config = Config::new(
        cli.api_key,
        cli.model,
        base_url,
        Duration::from_secs(cli.timeout_secs),
        cli.buffer_limit,
        cli.allow_caution,
        cli.auto_exec,
    );

    run(config).await
}
