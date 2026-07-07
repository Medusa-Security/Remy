# Changelog

All notable changes to Remy Agent are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.1.0] - 2026-07-07

### Added
- **Multi-engine scanning:** Python AST-based SAST, secrets/credentials scanner with regex + Shannon entropy, API surface auditor, auth/bypass pattern scanner, dependency vulnerability scanner (OSV)
- **LLM logic-bug pass (`--deep`):** Send code to configured provider for logic error, race condition, and edge-case detection
- **7 LLM providers:** OpenRouter, Groq, OpenAI, Anthropic, xAI (Grok), NVIDIA NIM, Ollama (local)
- **Fix Prompt output:** Generates `.remy/fix_prompt.md` — a structured, paste-ready Markdown artifact for any AI coding agent
- **Rich terminal UI:** Color-coded severity summary, findings tree with syntax-highlighted code snippets, live progress bars
- **First-run config wizard:** Provider selection, API key validation via live ping, model listing, scan defaults
- **Config stored securely:** `~/.remy/config.toml` (TOML, comments preserved) + OS keyring for API keys
- **CLI commands:** `remy scan`, `remy prompt`, `remy config`, `remy providers list`, `remy version`
- **CI gate exit codes:** Exit 2 on Critical/High findings for use in CI pipelines
- **YAML rule packs:** Extensible rules for Python, JavaScript, secrets, API routes, auth bypass
- **File walker:** Respects `.gitignore` and `.remyignore`, skips binary files and oversized files

### Security
- API keys never stored in plaintext — OS keyring via `keyring` library
- Fix Prompt redacts secret values (shows only first/last 4 chars)
- `remy scan . --secrets-only` run as self-scan in CI

---

*Built by [Medusa Security](https://github.com/Medusa-Security) · Maintained by [Abhay Gupta](https://github.com/abhay-1310)*
