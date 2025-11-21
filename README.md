# Bashtion 🛡️

Bashtion intercepts shell scripts before they hit your interpreter. It captures the script, runs static and AI-powered safety analysis, shows you the findings, and only executes after you explicitly confirm. Think of it as "curl | bash" with a security checkpoint.

[![Rust](https://img.shields.io/badge/rust-1.83+-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/chriswessels/bashtion/workflows/CI/badge.svg)](https://github.com/chriswessels/bashtion/actions)
[![Release](https://img.shields.io/github/v/release/chriswessels/bashtion)](https://github.com/chriswessels/bashtion/releases)

## ✨ Features

- **🛡️ Double Analysis**: Tree-sitter-based static checks plus LLM intent/risk summaries on every script
- **🔍 Full Transparency**: Shows exact code snippets for each finding, logs overall risk, and requires your confirmation
- **💻 Shell-Agnostic**: Supports any `stdin` source (`curl ... | bashtion`) and runs in whatever shell you configure
- **⚙️ Structured Reports**: Colorized terminal output, structured JSON verdicts, and manual review prompt by default
- **🧪 Manual Test Scripts**: Sample scripts (`scripts/manual/*.sh`) exercise different detections for easy regression testing
- **🔌 Configurable Backend**: Works with OpenAI-compatible endpoints (override base URL, key, model, timeouts) and falls back gracefully when AI is unavailable
- **📦 Installer**: Single `install.sh` fetches the correct binary for macOS/Linux and keeps the repo overrideable via env vars

## 🚀 Quick Start

### Installation

#### 📦 Pre-built Binaries

```bash
curl -fsSL https://raw.githubusercontent.com/chriswessels/bashtion/main/install.sh | bash
```

Manual downloads: grab the latest tarball for your platform from the [releases page](https://github.com/chriswessels/bashtion/releases/latest).

#### 🔧 From Source (Rust 1.83+)

```bash
git clone https://github.com/chriswessels/bashtion
cd bashtion
cargo install --path .
```

#### 📋 Verify Installation

```bash
bashtion --version
```

### Basic Usage

```bash
# Inspect a remote installer before execution
curl https://example.com/install.sh | bashtion

# Capture stdin but skip execution (print script to stdout)
curl https://example.com/install.sh | bashtion --no-exec

# Use a custom OpenAI-compatible endpoint
BASHTION_OPENAI_BASE_URL=https://llm.example.com/v1 \
BASHTION_OPENAI_API_KEY=sk-... \
curl https://example.com/install.sh | bashtion

# Force a different shell to execute the approved script
BASHTION_EXEC_SHELL=/bin/zsh curl https://example.com/install.sh | bashtion

# Analyze a local script non-interactively
bashtion < scripts/manual/static_eval.sh
```

During each run Bashtion:
1. Reads stdin into a bounded buffer (default 500 KB)
2. Runs static analysis and AI analysis (if configured)
3. Presents findings + summary
4. Prompts “[y/N]” before actually executing the script via your shell (unless `--no-exec`)

## ⚙️ Configuration

All settings can be controlled via CLI flags or `BASHTION_*` env vars:

| Flag / Env | Description | Default |
|------------|-------------|---------|
| `--no-exec` / `BASHTION_AUTO_EXEC=false` | Skip shell execution; print script instead | auto-exec on |
| `--exec-shell` / `BASHTION_EXEC_SHELL` | Shell command used to run approved scripts | `/bin/bash` |
| `--timeout-secs` / `BASHTION_TIMEOUT_SECS` | HTTP timeout for AI calls | 30s |
| `--buffer-limit` / `BASHTION_BUFFER_LIMIT` | Max bytes read from stdin | 512 KB |
| `BASHTION_OPENAI_BASE_URL` | OpenAI-compatible endpoint base URL | unset (AI disabled) |
| `BASHTION_OPENAI_API_KEY` | API key for the endpoint | unset |
| `BASHTION_OPENAI_MODEL` | Model name sent to the endpoint | `gpt-4o` |

Example:
```bash
BASHTION_OPENAI_BASE_URL=http://localhost:8080/v1 \
BASHTION_OPENAI_API_KEY=dev-secret \
BASHTION_OPENAI_MODEL=local-mixtral \
  curl https://example.com/install.sh | bashtion
```

## 🧪 Manual Test Scripts

Use the bundled scripts to validate detections:

```bash
# Triggers the eval static rule
cat scripts/manual/static_eval.sh | bashtion --no-exec

# Shows curl|bash caution
cat scripts/manual/static_curl_pipe.sh | bashtion --no-exec

# Benign download (AI low risk)
cat scripts/manual/semantic_download.sh | bashtion --no-exec

# Reverse shell (AI + static high risk)
cat scripts/manual/semantic_reverse_shell.sh | bashtion --no-exec
```

## 🤖 AI Backend

- Bashtion sends the captured script to `POST {base_url}/chat/completions` with a structured-output prompt.
- The model must respond with JSON: `{ "intent": ..., "risk": "low|medium|high", "findings": [...] }`.
- Responses are retried up to 3 times with exponential backoff, and malformed JSON is auto-repaired with [`llm_json`](https://crates.io/crates/llm_json).
- If no base URL is configured, AI analysis is skipped (only static findings are shown).

## 📦 Release Artifacts

`install.sh` and the GitHub release workflow publish four archives:

- `bashtion-linux-x86_64.tar.gz`
- `bashtion-linux-aarch64.tar.gz`
- `bashtion-macos-x86_64.tar.gz`
- `bashtion-macos-aarch64.tar.gz`

Each contains a single `bashtion` binary. SHA256 files are provided for integrity checks.

## 📄 License

Bashtion is MIT-licensed. See [LICENSE](LICENSE) for details.