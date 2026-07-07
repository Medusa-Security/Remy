# Remy Architecture

## Overview

Remy is structured as a pipeline: **file discovery → multi-engine scanning → report aggregation → output rendering**.

```
User runs `remy scan`
         │
         ▼
   ┌─────────────┐
   │  cli.py     │  Click command router
   │  (entry)    │
   └──────┬──────┘
          │
          ▼
   ┌──────────────┐
   │ ScanOptions  │  Build scan config from CLI flags + ~/.remy/config.toml
   └──────┬───────┘
          │
          ▼
   ┌──────────────────┐
   │  FileWalker      │  Walk directory, respect .gitignore/.remyignore,
   │  (utils/)        │  skip binary/oversized files
   └──────┬───────────┘
          │  list of (Path, content, language)
          ▼
   ┌──────────────────────────────────────────────┐
   │  ScanOrchestrator                            │
   │  ┌──────────┐ ┌────────────┐ ┌───────────┐  │
   │  │ Secrets  │ │ SAST Py    │ │ API Surface│  │  asyncio.gather()
   │  │ Scanner  │ │ Scanner    │ │ Scanner   │  │  — all scanners run
   │  └──────────┘ └────────────┘ └───────────┘  │    concurrently
   │  ┌──────────┐ ┌────────────┐ ┌───────────┐  │
   │  │ Auth     │ │ Dependency │ │ LLM Logic │  │
   │  │ Bypass   │ │ Scanner    │ │ Scanner   │  │
   │  └──────────┘ └────────────┘ └───────────┘  │
   └──────┬───────────────────────────────────────┘
          │  raw findings (may overlap)
          ▼
   ┌──────────────────┐
   │  Deduplication   │  fingerprint_finding() SHA-256 hash on
   │  & Sorting       │  (file, line, title, scanner)
   └──────┬───────────┘
          │  ScanReport
          ▼
   ┌───────────────────────────────────────────┐
   │  Output                                   │
   │  ┌─────────────────┐ ┌─────────────────┐  │
   │  │ TerminalReporter│ │  JSON Export    │  │
   │  │ (rich tables,   │ │  (--format json)│  │
   │  │  tree, syntax)  │ └─────────────────┘  │
   │  └─────────────────┘ ┌─────────────────┐  │
   │                       │ PromptBuilder   │  │
   │                       │ (.remy/fix_     │  │
   │                       │  prompt.md)     │  │
   │                       └─────────────────┘  │
   └───────────────────────────────────────────┘
```

## Key Design Decisions

### No Write Access
Remy never modifies your codebase. It is strictly a reader and reporter. The Fix Prompt it generates is consumed by a separate agent of the user's choosing.

### asyncio Concurrency
All scanner `scan_file()` methods are `async`. The orchestrator uses `asyncio.gather()` to run all scanners concurrently across all files, maximizing throughput on I/O-bound scans (especially the dependency scanner, which makes network requests to OSV).

### Finding Deduplication
Every finding is fingerprinted with a 12-character SHA-256 hash of `(file, line_start, title, scanner)`. The orchestrator deduplicates across all scanners, so a hardcoded secret caught by both the regex rule and the entropy scorer only appears once.

### Provider Abstraction
All LLM providers implement the same three-method `Provider` interface (`list_models`, `complete`, `validate_credentials`). The registry pattern in `registry.py` dispatches by config `provider` field. Adding a new provider requires only implementing the interface and registering it — no changes to scanning logic.

### Config & Secret Storage
- Config (provider, model, scan defaults) is written to `~/.remy/config.toml` using `tomlkit` (preserves comments and formatting).
- API keys are stored separately in the OS keyring via the `keyring` library. Remy never writes API keys to disk in plaintext.

### YAML Rule Packs
Deterministic SAST patterns for each language are defined in `remy/rules/sast_rules/<language>_rules.yaml`. This allows community contributions to detection rules without touching Python code. The AST-based rules in `sast_python.py` handle complex multi-node patterns that regex cannot express.
