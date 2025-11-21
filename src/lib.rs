pub mod config;
pub mod error;
pub mod io;
pub mod logging;
pub mod semantic;
pub mod static_analysis;

use colored::*;
use std::io::Write;

use config::Config;
use error::BashtionError;
use logging::log_stderr;
use semantic::analyze as semantic_analyze;
use static_analysis::{analyze as static_analyze, BlockReason, Verdict as StaticVerdict};

pub async fn run(config: Config) -> Result<(), BashtionError> {
    let script = io::read_stdin_limited(config.buffer_limit)?;
    log_stderr(format!(
        "[Bashtion] Buffer read ({:.1} KB).",
        script.len() as f64 / 1024.0
    ))?;

    match static_analyze(&script)? {
        StaticVerdict::Pass => log_stderr(
            "[Bashtion] Static analysis passed."
                .to_string()
                .green()
                .to_string(),
        )?,
        StaticVerdict::Blocked(BlockReason { rule, detail }) => {
            log_stderr(
                "[Bashtion] ALERT: Static analysis failed."
                    .to_string()
                    .red()
                    .to_string(),
            )?;
            log_stderr(
                format!("[Bashtion] Rule: {rule}; Reason: {detail}")
                    .to_string()
                    .red()
                    .to_string(),
            )?;
            return Err(BashtionError::StaticBlocked(detail));
        }
    }

    let verdict = semantic_analyze(&script, &config).await?;
    if !verdict.safe {
        log_stderr(
            "[Bashtion] ALERT: AI analysis blocked the script."
                .to_string()
                .red()
                .to_string(),
        )?;
        log_stderr(
            format!("[Bashtion] Reason: {}", verdict.reason)
                .to_string()
                .red()
                .to_string(),
        )?;
        return Err(BashtionError::SemanticBlocked(verdict.reason));
    }
    log_stderr(
        format!(
            "[Bashtion] AI analysis passed (Verdict: {}).",
            verdict.reason
        )
        .green()
        .to_string(),
    )?;

    print!("{}", script);
    std::io::stdout().flush().ok();
    Ok(())
}
