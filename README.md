# Remy Agent

**AI-Powered Codebase Bug & Vulnerability Scanning CLI**

[![PyPI version](https://badge.fury.io/py/remy-agent.svg)](https://pypi.org/project/remy-agent/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/Medusa-Security/remy/actions/workflows/ci.yml/badge.svg)](https://github.com/Medusa-Security/remy/actions/workflows/ci.yml)

---

## What is Remy?

Remy is a terminal-native AI security and bug-scanning agent. It performs static application security testing (SAST) plus an optional AI-assisted logic/bug detection pass across your codebase, then generates a single, structured **Fix Prompt** — ready to paste into any AI coding agent of your choice.

Remy is the **finder and prompt-compiler**, not the editor. That makes it lightweight, model-agnostic, and safe to run on any codebase without needing write access.

> [!TIP]
> 📖 Create a .remyignore file to restrict which files and directories the Remy Agent can access during scans.

---

## Features

- **Multi-engine SAST** — Python AST rules for injection, insecure deserialization, weak crypto, and more
- **Secrets scanner** — regex + Shannon entropy detection for API keys, tokens, and credentials across all file types
- **API surface auditor** — finds unauthenticated routes, missing rate limiting, and overly permissive CORS
- **Auth/bypass scanner** — detects JWT bypass, IDOR patterns, non-constant-time comparisons, client-controlled admin flags
- **Dependency scanner** — cross-references your packages against the OSV vulnerability database
- **LLM logic-bug pass** (`--deep`) — sends code to your AI provider to catch race conditions, edge cases, and business logic flaws
- **Multi-provider AI** — bring your own key for OpenRouter, Groq, OpenAI, Anthropic, xAI, NVIDIA NIM, or run fully local with Ollama
- **Drop-in Fix Prompt** — output is a portable Markdown artifact you paste into Claude Code, Cursor, Windsurf, Copilot, or any other agent

---

## Install

```bash
pip install remy-agent
```

---

## Quick Start

```bash
# First run — launches config wizard
remy

# After setup — scan current directory
remy scan

# Deep scan (SAST + LLM logic pass)
remy scan --deep

# Scan a specific path
remy scan /path/to/your/project

# Secrets only (fast, no LLM needed)
remy scan --secrets-only

# Get the Fix Prompt and copy to clipboard
remy prompt --copy
```

---

## Supported Providers

| Provider | API Key Required | Notes |
|---|:---:|---|
| OpenRouter | ✅ Yes | Routes to 200+ models. Great flexibility. |
| Groq | ✅ Yes | Ultra-low latency. Best for fast bulk scanning. |
| OpenAI | ✅ Yes | GPT-4o and newer models. |
| Anthropic | ✅ Yes | Claude family. Excellent at code reasoning. |
| xAI | ✅ Yes | Grok model family. OpenAI-compatible. |
| NVIDIA NIM | ✅ Yes | Cloud or self-hosted NIM endpoint. |
| Ollama | ❌ No | Fully local. Run `ollama serve` first. |

---

## Example Terminal Output

```
  ██████╗ ███████╗███╗   ███╗██╗   ██╗
  ██╔══██╗██╔════╝████╗ ████║╚██╗ ██╔╝
  ██████╔╝█████╗  ██╔████╔██║ ╚████╔╝
  ██╔══██╗██╔══╝  ██║╚██╔╝██║  ╚██╔╝
  ██║  ██║███████╗██║ ╚═╝ ██║   ██║
  ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝   ╚═╝

  ┌─────────────────────────────────────────────┐
  │   Remy Scan Report — 14 Finding(s)          │
  │  🔴 CRITICAL  3  ████████░░░░░░░░           │
  │  🟠 HIGH      5  ██████████████░░           │
  │  🟡 MEDIUM    4  ██████████░░░░░░           │
  │  🔵 LOW       2  ████░░░░░░░░░░░░           │
  └─────────────────────────────────────────────┘
```

---

## Example Fix Prompt Output

```markdown
# Remy Security & Bug Fix Prompt

You are an AI coding agent. Fix the following issues in this codebase.
Apply minimal, targeted changes. Preserve existing behavior and style.

## Findings

### [CRITICAL] Hardcoded production Stripe API key
**File:** `src/services/payments.py`, lines 12–14
**CWE:** CWE-798

**Issue:** A Stripe Live API key was found hardcoded in source code: `sk_l***0xyz`.
Committing secrets to version control is a critical security risk.

**Fix instructions:** Remove from source code immediately. Store in environment
variable: `STRIPE_SECRET_KEY = os.environ['STRIPE_SECRET_KEY']`. Rotate the key
in your Stripe Dashboard.
```

---

## Configuration

Config is stored at `~/.remy/config.toml`. API keys are stored in the OS keyring.

| Setting | Default | Description |
|---|---|---|
| `provider` | — | LLM provider (openrouter, groq, openai, anthropic, xai, nvidia_nim, ollama) |
| `model` | — | Model ID (e.g. `gpt-4o`, `claude-sonnet-4-5`) |
| `base_url` | provider default | Override base URL (for Ollama or self-hosted NIM) |
| `scan_defaults.deep` | `false` | Enable LLM logic-bug pass by default |
| `scan_defaults.max_file_size_kb` | `1000` | Skip files larger than this |
| `scan_defaults.respect_gitignore` | `true` | Honor `.gitignore` and `.remyignore` |

Run `remy config show` to see your current settings (key redacted).

---

## Commands

```
remy                        # First run → wizard; subsequent → scan cwd
remy scan [PATH]            # Full scan
remy scan --deep            # SAST + LLM logic pass
remy scan --secrets-only    # Secrets/credentials only
remy scan --api-surface     # API route audit only
remy scan --bypass-check    # Auth bypass detection only
remy scan --deps            # Dependency CVE scan only
remy scan --format json     # Machine-readable output
remy scan --output FILE     # Write output to file
remy prompt                 # View last scan's Fix Prompt
remy prompt --copy          # Copy Fix Prompt to clipboard
remy config                 # Run config wizard
remy config show            # Print current config
remy config set-provider    # Change provider/model
remy providers list         # List all supported providers
remy version                # Show version
```

---

## Using as a CI Gate

Remy exits with code `2` when Critical or High findings are present, making it easy to use as a CI gate:

```yaml
# .github/workflows/security.yml
- name: Remy security scan
  run: remy scan . --secrets-only --format json --output scan.json
  # Exits 2 if critical/high findings found
```

---

## Roadmap

- [ ] `tree-sitter` multi-language SAST (JS/TS, Go, Java, Rust, PHP, Ruby)
- [ ] VS Code extension for inline findings
- [ ] SARIF output format for GitHub Security tab integration
- [ ] Custom rule packs via `~/.remy/rules/`
- [ ] PR diff scanning (scan only changed files)
- [ ] HTML report output
- [ ] Jira/Linear issue creation from findings

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, how to add SAST rules, and how to add new providers.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

## Credits

Built by [Medusa Security](https://github.com/Medusa-Security).  
Maintained by [Abhay Gupta](https://github.com/abhay-1310) (CTO, Medusa Security) // [Ak](https://github.com/ak495867) (CEO, Medusa Security).
