pub mod config;
pub mod error;
pub mod io;
pub mod logging;
pub mod semantic;
pub mod static_analysis;

use colored::*;
use std::io::Write;
use std::process::{Command, Stdio};

use config::Config;
use error::BashtionError;
use logging::log_stderr;
use semantic::analyze as semantic_analyze;
use static_analysis::{analyze as static_analyze, BlockReason, Severity, Verdict as StaticVerdict};

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
        StaticVerdict::Flagged(BlockReason {
            rule,
            detail,
            severity,
        }) => match severity {
            Severity::Block => {
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
            Severity::Caution => {
                log_stderr(
                    "[Bashtion] CAUTION: Potentially risky pattern detected."
                        .to_string()
                        .yellow()
                        .to_string(),
                )?;
                log_stderr(
                    format!("[Bashtion] Rule: {rule}; Detail: {detail}")
                        .to_string()
                        .yellow()
                        .to_string(),
                )?;

                if !config.allow_caution {
                    log_stderr(
                            "[Bashtion] To proceed despite caution, rerun with --allow-caution or BASHTION_ALLOW_CAUTION=1"
                                .to_string()
                                .yellow()
                                .to_string(),
                        )?;
                    return Err(BashtionError::StaticCaution(detail));
                }
            }
        },
    }

    if config
        .api_key
        .as_ref()
        .map(|k| k.trim().is_empty())
        .unwrap_or(true)
    {
        log_stderr(
            "[Bashtion] AI analysis skipped (no OPENAI_API_KEY provided)."
                .to_string()
                .yellow()
                .to_string(),
        )?;
    } else {
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
    }

    if config.auto_exec {
        log_stderr(
            "[Bashtion] Executing script via /bin/bash (override with BASHTION_EXEC_SHELL)."
                .to_string()
                .green()
                .to_string(),
        )?;
        exec_script(&script)?;
    } else {
        print!("{}", script);
        std::io::stdout().flush().ok();
    }
    Ok(())
}

fn exec_script(script: &str) -> Result<(), BashtionError> {
    let shell = std::env::var("BASHTION_EXEC_SHELL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "/bin/bash".to_string());
    let mut child = Command::new(shell)
        .arg("-s")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| BashtionError::Other(format!("Failed to spawn shell: {e}")))?;

    if let Some(mut stdin) = child.stdin.take() {
        std::io::Write::write_all(&mut stdin, script.as_bytes())
            .map_err(|e| BashtionError::Other(format!("Failed to pipe script to shell: {e}")))?;
    }

    let status = child
        .wait()
        .map_err(|e| BashtionError::Other(format!("Failed to wait on shell: {e}")))?;

    if !status.success() {
        return Err(BashtionError::Other(format!(
            "Shell exited with status {}",
            status
        )));
    }

    Ok(())
}
