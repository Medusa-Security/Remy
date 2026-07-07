# Remy Usage Reference

## Command Reference

### `remy`
Invoked with no arguments. On first run (no `~/.remy/config.toml`), launches the config wizard. On subsequent runs, performs a default scan of the current working directory.

### `remy scan [PATH]`
Full scan of a directory or file. PATH defaults to `.` (current directory).

**Options:**
| Flag | Description |
|---|---|
| `--deep` | Enable LLM logic-bug pass (requires configured provider) |
| `--secrets-only` | Run only the secrets/credentials scanner |
| `--api-surface` | Run only the API route + rate-limit auditor |
| `--bypass-check` | Run only the auth/logic bypass scanner |
| `--deps` | Run only the dependency vulnerability scanner |
| `--format json` | Output machine-readable JSON instead of rich terminal display |
| `--output FILE` | Write output to a file instead of stdout |

### `remy prompt`
Regenerates the Fix Prompt from the last scan's cached findings (stored in `~/.remy/last_scan.json`).

**Options:**
| Flag | Description |
|---|---|
| `--copy` | Copy the Fix Prompt to clipboard (requires `pyperclip`) |

### `remy config`
Launches the interactive configuration wizard.

### `remy config show`
Prints the current configuration with the API key redacted.

### `remy config set-provider`
Change provider and model without running the full wizard.

### `remy providers list`
Display a table of all supported providers with their required keys and endpoints.

### `remy version`
Print Remy version and attribution.

---

## Config File

Config is stored at `~/.remy/config.toml`. You can edit it manually:

```toml
provider = "openai"
model = "gpt-4o"
# base_url = ""  # Optional override

[scan_defaults]
deep = false
max_file_size_kb = 1000
respect_gitignore = true
```

API keys are stored separately in the OS keyring (not in the config file). On systems without a keyring backend, they fall back to an encrypted local store.

---

## Running Remy in CI (Headless Mode)

Remy is designed to work as a CI security gate. It exits with a non-zero code if critical or high findings are present:

| Exit Code | Meaning |
|---|---|
| `0` | No critical/high findings |
| `1` | Error (scan failed, config missing, etc.) |
| `2` | Critical or High severity findings found |

### Example GitHub Actions Step

```yaml
- name: Security scan
  run: remy scan . --secrets-only --format json --output scan-results.json

- name: Check for critical findings
  run: |
    python -c "
    import json, sys
    data = json.load(open('scan-results.json'))
    if data['summary']['critical'] > 0:
        print(f'FAIL: {data[\"summary\"][\"critical\"]} critical secrets found')
        sys.exit(1)
    print('OK: No critical findings')
    "
```

---

## Using `.remyignore`

Create a `.remyignore` file in your project root to tell Remy to skip specific paths. It uses the same syntax as `.gitignore`:

```gitignore
# Skip test fixtures with intentional vulnerabilities
tests/fixtures/

# Skip generated files
dist/
build/

# Skip large data files
data/*.csv
```

See `.remyignore.example` in the repo for a full example.

---

## Fix Prompt Files

After a scan, Remy writes Fix Prompt files to `.remy/` in the current directory:

- `.remy/fix_prompt.md` — all findings in one file (most scans)
- `.remy/fix_prompt_1.md`, `.remy/fix_prompt_2.md`, ... — chunked files for large scans

The Fix Prompt is designed to be pasted directly into:
- Claude Code / Claude.ai
- Cursor
- Windsurf (Codeium)
- GitHub Copilot Workspace
- Any other AI coding agent

---

## Troubleshooting

### Provider auth fails during wizard
- Double-check the API key was copied correctly (no trailing spaces)
- Some providers (OpenRouter, Groq) may have brief outages — the wizard will ask if you want to save anyway
- For Anthropic: ensure you're using an `sk-ant-` prefixed key

### Ollama not detected
- Run `ollama serve` in a separate terminal first
- Default URL is `http://localhost:11434` — use `remy config set-provider` to change it
- Verify Ollama is accessible: `curl http://localhost:11434/api/tags`

### Scan is slow on large repos
- Increase specificity: use `--secrets-only` or `--api-surface` for targeted scans
- Add a `.remyignore` to skip large generated directories (`node_modules/`, `dist/`, etc.)
- Reduce `max_file_size_kb` in config for repos with large files

### Fix Prompt is very long
- Remy auto-chunks into multiple `fix_prompt_N.md` files when findings are extensive
- Paste each chunk separately, starting with `fix_prompt_1.md`

---

*Built by [Medusa Security](https://github.com/Medusa-Security) · Maintained by [Abhay Gupta](https://github.com/abhay-1310)*
