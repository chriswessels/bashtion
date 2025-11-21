pub const DANGEROUS_COMMAND: &str = r#"
(command
  name: (command_name (word) @cmd_name)
  (#match? @cmd_name "^(eval|base64|openssl|nc|netcat|telnet|rm)$")
) @dangerous_command
"#;
