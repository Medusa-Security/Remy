# Contributing to Remy

Thanks for helping make Remy better. This guide covers dev setup, adding SAST rules, adding providers, and the PR checklist.

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). Be kind and constructive.

---

## Dev Setup

```bash
git clone https://github.com/Medusa-Security/remy.git
cd remy
pip install -e ".[dev]"
pre-commit install
```

Run tests:
```bash
pytest tests/ -v
```

Lint and format:
```bash
ruff check remy/
black remy/ tests/
```

---

## Adding a SAST Rule (YAML Rule Pack)

The easiest way to add a detection pattern is to add an entry to the relevant YAML file under `remy/rules/sast_rules/`.

Each rule follows this schema:

```yaml
- id: PY999
  name: "Descriptive rule name"
  pattern: 'regex_pattern_here'
  severity: HIGH          # CRITICAL | HIGH | MEDIUM | LOW | INFO
  cwe: "CWE-89"
  remediation: "Specific fix guidance for the downstream agent."
```

After adding the rule:
1. Add a test case in `tests/test_scanners/` that verifies the rule fires and doesn't false-positive.
2. Update `remy/rules/sast_rules/<language>_rules.yaml`.
3. Open a PR with a description of what vulnerability class the rule detects.

Note: YAML rules supplement the AST-based rules in `sast_python.py`. For complex multi-node logic, add a method to `_RemyAstVisitor` in `sast_python.py` directly and call it from `visit_Call` or the appropriate visitor method.

---

## Adding a New LLM Provider

1. Create `remy/providers/<provider_name>.py`
2. Implement the `Provider` abstract base class from `remy/providers/base.py`:

```python
class MyProvider(Provider):
    async def list_models(self) -> list[ModelInfo]: ...
    async def complete(self, messages: list[Message], **kwargs) -> str: ...
    async def validate_credentials(self) -> bool: ...
```

3. Register it in `remy/providers/registry.py` — add an `elif provider_name == "my_provider":` branch.
4. Add it to the `PROVIDER_NOTES` dict in `remy/config/wizard.py`.
5. Add it to the `Literal` union in `remy/config/schema.py`.
6. Add it to the providers table in `remy/ui/tables.py`.
7. Write tests in `tests/test_providers/`.
8. Document it in `docs/PROVIDERS.md`.

---

## PR Checklist

Before opening a PR, verify:

- [ ] All existing tests pass (`pytest tests/ -v`)
- [ ] New functionality has tests
- [ ] `ruff check remy/` passes with no errors
- [ ] `black --check remy/ tests/` passes
- [ ] `remy scan . --secrets-only` on your branch shows no critical secrets
- [ ] If adding a provider: `validate_credentials()` is tested against a mocked response
- [ ] If adding a rule: both a true-positive and false-positive test case are included
- [ ] Docs updated if behavior changed

---

## Project Structure Reference

```
remy/
├── cli.py              # Click command router — all user-facing commands
├── config/             # Config schema, file store, keyring, wizard
├── providers/          # LLM provider implementations + registry
├── scanners/           # All scanning engines + orchestrator
├── rules/              # YAML rule packs (extend without touching Python)
├── report/             # ScanReport models, terminal renderer, JSON export, prompt builder
├── ui/                 # Rich theme, banner, progress, tables
└── utils/              # File walker, entropy scoring, fingerprint hashing
```

---

Built by [Medusa Security](https://github.com/Medusa-Security) · Maintained by [Abhay Gupta](https://github.com/abhay-1310)
