pub mod config;
pub mod error;
pub mod io;
pub mod logging;
pub mod semantic;
pub mod static_analysis;

use colored::*;
use std::io::Write;
use std::process::{Command, Stdio};

use config::ResolvedConfig;
use error::BashtionError;
use logging::log_stderr;
use semantic::{
    analyze as semantic_analyze, max_finding_severity, FindingSeverity, LlmFinding, LlmVerdict,
};
use static_analysis::{analyze as static_analyze, BlockReason, Severity, Verdict as StaticVerdict};

pub async fn run(config: ResolvedConfig) -> Result<(), BashtionError> {
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

    let base_missing = config.base_url.is_none();

    if base_missing {
        log_stderr(
            "[Bashtion] AI analysis skipped (no BASHTION_OPENAI_BASE_URL set)."
                .to_string()
                .yellow()
                .to_string(),
        )?;
    } else {
        let verdict = semantic_analyze(&script, &config).await?;
        match classify_semantic(&verdict) {
            SemanticDisposition::Pass => log_semantic_pass(&verdict)?,
            SemanticDisposition::Caution => log_semantic_caution(&verdict)?,
            SemanticDisposition::Block => {
                log_semantic_block(&verdict)?;
                return Err(BashtionError::SemanticBlocked(block_error_message(
                    &verdict,
                )));
            }
        }
    }

    if config.auto_exec {
        let shell = config.exec_shell.as_deref().unwrap_or("/bin/bash");
        log_stderr(
            format!(
                "[Bashtion] Executing script via {shell} (override with --exec-shell or BASHTION_EXEC_SHELL)."
            )
            .green()
            .to_string(),
        )?;
        exec_script(&script, shell)?;
    } else {
        print!("{}", script);
        std::io::stdout().flush().ok();
    }
    Ok(())
}

fn exec_script(script: &str, shell: &str) -> Result<(), BashtionError> {
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

fn log_semantic_pass(verdict: &LlmVerdict) -> Result<(), BashtionError> {
    log_stderr(
        format!("[Bashtion] AI analysis passed: {}", verdict.summary)
            .green()
            .to_string(),
    )?;

    if !verdict.findings.is_empty() {
        log_findings(&verdict.findings)?;
    }

    Ok(())
}

fn log_semantic_block(verdict: &LlmVerdict) -> Result<(), BashtionError> {
    log_stderr(
        "[Bashtion] ALERT: AI analysis blocked the script."
            .to_string()
            .red()
            .to_string(),
    )?;
    log_stderr(
        format!("[Bashtion] Summary: {}", verdict.summary)
            .to_string()
            .red()
            .to_string(),
    )?;
    if verdict.findings.is_empty() {
        log_stderr(
            "[Bashtion] (Model returned no granular findings.)"
                .to_string()
                .yellow()
                .to_string(),
        )?;
    } else {
        log_findings(&verdict.findings)?;
    }
    Ok(())
}

fn log_semantic_caution(verdict: &LlmVerdict) -> Result<(), BashtionError> {
    log_stderr(
        "[Bashtion] CAUTION: AI analysis flagged potential risks."
            .to_string()
            .yellow()
            .to_string(),
    )?;
    log_stderr(
        format!("[Bashtion] Summary: {}", verdict.summary)
            .to_string()
            .yellow()
            .to_string(),
    )?;
    if verdict.findings.is_empty() {
        log_stderr(
            "[Bashtion] (Model returned no granular findings.)"
                .to_string()
                .yellow()
                .to_string(),
        )?;
    } else {
        log_findings(&verdict.findings)?;
    }
    log_stderr(
        "[Bashtion] Proceeding because semantic caution is advisory."
            .to_string()
            .yellow()
            .to_string(),
    )?;
    Ok(())
}

fn log_findings(findings: &[LlmFinding]) -> Result<(), BashtionError> {
    for (idx, finding) in findings.iter().enumerate() {
        let severity_label = finding.severity.trim();
        let severity_text = if severity_label.is_empty() {
            "info"
        } else {
            severity_label
        };
        let heading = format!(
            "[Bashtion] Finding #{idx}: {title} [{severity}]",
            idx = idx + 1,
            title = finding.title.trim(),
            severity = severity_text.to_ascii_uppercase()
        );
        log_stderr(colorize_by_severity(heading, severity_text))?;

        let explanation = finding.explanation.trim();
        if !explanation.is_empty() {
            log_stderr(format!("          Detail: {explanation}"))?;
        }

        let code = finding.code.trim();
        if !code.is_empty() {
            log_stderr("          Code:")?;
            for line in code.lines() {
                log_stderr(format!("            {line}"))?;
            }
        }
    }
    Ok(())
}

fn colorize_by_severity(message: String, severity: &str) -> String {
    match severity.to_ascii_lowercase().as_str() {
        "high" => message.red().to_string(),
        "medium" => message.yellow().to_string(),
        "low" => message.green().to_string(),
        _ => message.cyan().to_string(),
    }
}

fn block_error_message(verdict: &LlmVerdict) -> String {
    if verdict.findings.is_empty() {
        return verdict.summary.clone();
    }

    let highlights: Vec<String> = verdict
        .findings
        .iter()
        .map(|f| format!("{} [{}]", f.title.trim(), f.severity.trim()))
        .collect();
    format!("{} | Findings: {}", verdict.summary, highlights.join(", "))
}

enum SemanticDisposition {
    Pass,
    Caution,
    Block,
}

fn classify_semantic(verdict: &LlmVerdict) -> SemanticDisposition {
    if verdict.safe {
        return SemanticDisposition::Pass;
    }

    match max_finding_severity(verdict) {
        Some(FindingSeverity::Low) => SemanticDisposition::Caution,
        Some(FindingSeverity::Medium) | Some(FindingSeverity::High) => SemanticDisposition::Block,
        Some(FindingSeverity::Unknown) | None => SemanticDisposition::Block,
    }
}
