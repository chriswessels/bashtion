use clap::Parser;
use colored::{control::set_override, Colorize};

use bashtion::{
    config::{parse_bool, CliConfig, EnvConfig, ResolvedConfig},
    error::BashtionError,
    run,
};

#[derive(Parser, Debug)]
#[command(
    name = "bashtion",
    about = "Intercepts and inspects piped shell scripts",
    version
)]
struct Cli {
    /// OpenAI-compatible API key (env: BASHTION_OPENAI_API_KEY)
    #[arg(long)]
    api_key: Option<String>,

    /// Model name (env: BASHTION_OPENAI_MODEL)
    #[arg(long)]
    model: Option<String>,

    /// Base URL for OpenAI-compatible endpoint (env: BASHTION_OPENAI_BASE_URL)
    #[arg(long)]
    base_url: Option<String>,

    /// HTTP timeout seconds (env: BASHTION_TIMEOUT_SECS)
    #[arg(long)]
    timeout_secs: Option<u64>,

    /// Buffer limit in bytes (env: BASHTION_BUFFER_LIMIT)
    #[arg(long)]
    buffer_limit: Option<usize>,

    /// Shell executable to run scripts with (env: BASHTION_EXEC_SHELL)
    #[arg(long)]
    exec_shell: Option<String>,

    /// Disable colored stderr output (env: BASHTION_NO_COLOR)
    #[arg(long)]
    no_color: bool,

    /// Skip auto-exec; when set, bashtion prints to stdout instead of running the script (env: BASHTION_AUTO_EXEC=false)
    #[arg(long = "no-exec", default_value_t = true, action = clap::ArgAction::SetFalse)]
    auto_exec: bool,
}

#[tokio::main]
async fn main() {
    if let Err(err) = entrypoint().await {
        eprintln!("{}", format!("[Bashtion] ERROR: {err}").red());
        std::process::exit(1);
    }
}

async fn entrypoint() -> Result<(), BashtionError> {
    let cli = Cli::parse();
    let no_color = resolve_no_color_flag(cli.no_color)?;
    set_override(!no_color);

    let env_cfg = EnvConfig::read().map_err(|err| BashtionError::Other(err.to_string()))?;
    let cli_cfg = CliConfig {
        base_url: cli.base_url,
        api_key: cli.api_key,
        model: cli.model,
        timeout_secs: cli.timeout_secs,
        buffer_limit: cli.buffer_limit,
        auto_exec: (!cli.auto_exec).then_some(false),
        exec_shell: cli.exec_shell,
    };

    let config: ResolvedConfig = ResolvedConfig::resolve(cli_cfg, env_cfg)
        .map_err(|err| BashtionError::Other(err.to_string()))?;

    run(config).await
}

fn resolve_no_color_flag(cli_flag: bool) -> Result<bool, BashtionError> {
    if cli_flag {
        return Ok(true);
    }

    match std::env::var("BASHTION_NO_COLOR") {
        Ok(value) => parse_bool(value.trim()).ok_or_else(|| {
            BashtionError::Other(format!("Invalid boolean for BASHTION_NO_COLOR: {}", value))
        }),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => Err(BashtionError::Other(
            "BASHTION_NO_COLOR contains invalid UTF-8".into(),
        )),
    }
}
