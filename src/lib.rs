pub mod config;
pub mod error;
pub mod io;
pub mod logging;
pub mod semantic;
pub mod static_analysis;

use colored::*;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use config::ResolvedConfig;
use error::BashtionError;
use logging::log_stderr;
use semantic::{analyze as semantic_analyze, LlmFinding, LlmVerdict};
use static_analysis::{analyze as static_analyze, Severity as StaticSeverity, StaticFinding};

pub async fn run(config: ResolvedConfig) -> Result<(), BashtionError> {
    let script = io::read_stdin_limited(config.buffer_limit)?;
    log_stderr(format!(
        "[Bashtion] Buffer read ({:.1} KB).",
        script.len() as f64 / 1024.0
    ))?;

    let static_findings = static_analyze(&script)?;
    log_static_findings(&static_findings)?;

    let semantic_verdict = if config.base_url.is_some() {
        let verdict = semantic_analyze(&script, &config).await?;
        log_semantic_report(&verdict)?;
        Some(verdict)
    } else {
        log_stderr(
            "[Bashtion] AI analysis skipped (no BASHTION_OPENAI_BASE_URL set)."
                .to_string()
                .yellow()
                .to_string(),
        )?;
        None
    };

    let intent_summary = semantic_verdict
        .as_ref()
        .map(|v| v.intent.clone())
        .unwrap_or_else(|| "AI analysis unavailable; review findings carefully.".to_string());

    if config.auto_exec {
        if confirm_execution(&intent_summary)? {
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
            log_stderr(
                "[Bashtion] Execution cancelled by user."
                    .to_string()
                    .yellow()
                    .to_string(),
            )?;
        }
    } else {
        log_stderr(
            "[Bashtion] Auto-execution disabled (--no-exec). Writing script to stdout."
                .to_string()
                .yellow()
                .to_string(),
        )?;
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

fn log_static_findings(findings: &[StaticFinding]) -> Result<(), BashtionError> {
    if findings.is_empty() {
        return log_stderr(
            "[Bashtion] Static analysis found no issues."
                .to_string()
                .green()
                .to_string(),
        );
    }

    log_stderr(
        format!(
            "[Bashtion] Static analysis reported {} finding(s).",
            findings.len()
        )
        .yellow()
        .to_string(),
    )?;

    for (idx, finding) in findings.iter().enumerate() {
        let heading = format!(
            "[Bashtion] Static Finding #{idx}: {rule} [{severity}]",
            idx = idx + 1,
            rule = finding.rule,
            severity = match finding.severity {
                StaticSeverity::Block => "HIGH",
                StaticSeverity::Caution => "CAUTION",
            }
        );
        let colored = match finding.severity {
            StaticSeverity::Block => heading.red().to_string(),
            StaticSeverity::Caution => heading.yellow().to_string(),
        };
        log_stderr(colored)?;
        log_stderr(format!("          Detail: {}", finding.detail))?;
    }

    Ok(())
}

fn log_semantic_report(verdict: &LlmVerdict) -> Result<(), BashtionError> {
    log_stderr(
        format!("[Bashtion] AI intent: {}", verdict.intent)
            .cyan()
            .to_string(),
    )?;
    log_stderr(
        format!("[Bashtion] Overall AI risk: {}", verdict.risk)
            .to_string()
            .yellow()
            .to_string(),
    )?;

    if verdict.findings.is_empty() {
        log_stderr(
            "[Bashtion] AI analysis reported no additional findings."
                .to_string()
                .green()
                .to_string(),
        )?;
    } else {
        log_stderr(
            format!(
                "[Bashtion] AI analysis reported {} finding(s).",
                verdict.findings.len()
            )
            .yellow()
            .to_string(),
        )?;
        log_llm_findings(&verdict.findings)?;
    }

    Ok(())
}

fn log_llm_findings(findings: &[LlmFinding]) -> Result<(), BashtionError> {
    for (idx, finding) in findings.iter().enumerate() {
        let severity = finding.severity.trim();
        let level = if severity.is_empty() {
            "INFO".to_string()
        } else {
            severity.to_ascii_uppercase()
        };
        let heading = format!(
            "[Bashtion] AI Finding #{idx}: {title} [{level}]",
            idx = idx + 1,
            title = finding.title.trim()
        );
        let colored = match level.as_str() {
            "HIGH" => heading.red().to_string(),
            "MEDIUM" => heading.yellow().to_string(),
            "LOW" => heading.green().to_string(),
            _ => heading.cyan().to_string(),
        };
        log_stderr(colored)?;
        if !finding.explanation.trim().is_empty() {
            log_stderr(format!("          Detail: {}", finding.explanation.trim()))?;
        }
        if !finding.code.trim().is_empty() {
            log_stderr("          Code:".to_string())?;
            for line in finding.code.lines() {
                log_stderr(format!("            {line}"))?;
            }
        }
    }
    Ok(())
}

fn confirm_execution(intent: &str) -> Result<bool, BashtionError> {
    log_stderr(
        format!("[Bashtion] Script intent: {intent}")
            .to_string()
            .white()
            .to_string(),
    )?;

    let mut stderr = std::io::stderr();
    stderr
        .write_all(b"[Bashtion] Proceed with executing the script? [y/N]: ")
        .map_err(BashtionError::Io)?;
    stderr.flush().map_err(BashtionError::Io)?;

    let mut reader = confirmation_reader()?;
    let mut input = String::new();
    let bytes = reader.read_line(&mut input).map_err(BashtionError::Io)?;
    if bytes == 0 {
        log_stderr(
            "[Bashtion] No response detected; cancelling execution."
                .to_string()
                .yellow()
                .to_string(),
        )?;
        return Ok(false);
    }

    let normalized = input.trim().to_ascii_lowercase();
    Ok(matches!(normalized.as_str(), "y" | "yes"))
}

fn confirmation_reader() -> Result<Box<dyn BufRead>, BashtionError> {
    match File::open("/dev/tty") {
        Ok(file) => Ok(Box::new(BufReader::new(file))),
        Err(_) => Ok(Box::new(BufReader::new(std::io::stdin()))),
    }
}
