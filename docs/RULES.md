# Remy Rules Reference

## Python SAST Rules (`sast_python.py` + `rules/sast_rules/python_rules.yaml`)

| ID | Name | Severity | CWE |
|---|---|:---:|---|
| PY001 | `eval()` with dynamic argument | HIGH | CWE-78 |
| PY002 | `exec()` with dynamic argument | HIGH | CWE-78 |
| PY003 | `pickle.loads()` — insecure deserialization | HIGH | CWE-502 |
| PY004 | `subprocess` with `shell=True` and dynamic command | CRITICAL | CWE-78 |
| PY005 | SQL injection via f-string or concatenation in `.execute()` | HIGH | CWE-89 |
| PY006 | `random` module used for security token | MEDIUM | CWE-338 |
| PY007 | `hashlib.md5()` usage | MEDIUM | CWE-327 |
| PY008 | `hashlib.sha1()` usage | MEDIUM | CWE-327 |
| PY009 | `yaml.load()` without `SafeLoader` | HIGH | CWE-502 |
| PY010 | Broad `except: pass` — silent error swallowing | LOW | CWE-390 |
| PY011 | `assert` used for security/auth check | MEDIUM | CWE-617 |
| PY012 | Hardcoded credential in security-sensitive variable | HIGH | CWE-798 |
| PY013 | Flask `debug=True` in `app.run()` | HIGH | CWE-94 |
| PY014 | `verify=False` in SSL/TLS context | HIGH | CWE-295 |
| PY015 | `tempfile.mktemp()` — TOCTOU race | MEDIUM | CWE-377 |

## JavaScript/TypeScript SAST Rules (`rules/sast_rules/javascript_rules.yaml`)

| ID | Name | Severity | CWE |
|---|---|:---:|---|
| JS001 | `eval()` with dynamic argument | HIGH | CWE-78 |
| JS002 | `child_process.exec()` with string concatenation | CRITICAL | CWE-78 |
| JS003 | `innerHTML` assignment (XSS) | HIGH | CWE-79 |
| JS004 | `document.write()` | MEDIUM | CWE-79 |
| JS005 | Prototype pollution pattern | HIGH | CWE-1321 |
| JS006 | Hardcoded API key or secret | HIGH | CWE-798 |
| JS007 | `Math.random()` for security token | MEDIUM | CWE-338 |
| JS008 | SQL injection via template literal | HIGH | CWE-89 |
| JS009 | Cookie without Secure/HttpOnly flags | MEDIUM | CWE-614 |
| JS010 | `JSON.parse()` without error handling | LOW | CWE-20 |
| JS011 | Missing CSRF protection on state-changing route | MEDIUM | CWE-352 |
| JS012 | `rejectUnauthorized: false` in HTTPS | HIGH | CWE-295 |

## Secrets Detection (`secrets_scanner.py` + `rules/secrets_patterns.yaml`)

The secrets scanner combines regex rules for known key formats with Shannon entropy scoring for novel/unlisted secrets.

| Pattern | Severity |
|---|:---:|
| AWS Access Key ID (`AKIA...`) | CRITICAL |
| AWS Secret Access Key | CRITICAL |
| Stripe Live Key (`sk_live_...`) | CRITICAL |
| Stripe Test Key (`sk_test_...`) | MEDIUM |
| GitHub PAT (`ghp_...`, `gho_...`, `github_pat_...`) | CRITICAL |
| Slack Bot/App Token (`xoxb-...`, `xoxa-...`) | HIGH |
| Database connection string with credentials | CRITICAL |
| PEM Private Key | CRITICAL |
| Generic API key assignment | HIGH |
| Hardcoded Bearer/Authorization token | HIGH |
| Hardcoded JWT token | MEDIUM |
| High-entropy string literal (≥4.5 bits Shannon entropy) | HIGH |
| SendGrid, Twilio, Mailgun, Google, Firebase, Heroku, npm, Docker Hub, Azure, Shopify, DigitalOcean, PyPI keys | HIGH–CRITICAL |

## API Surface Rules (`api_surface_scanner.py`)

- **Missing authentication** on non-public routes — HIGH (CWE-306)
- **Missing rate limiting** on sensitive routes (auth, login, upload, webhook) — MEDIUM (CWE-770)
- **Overly permissive CORS** (`*` with credentials) — MEDIUM (CWE-942)

## Auth/Bypass Rules (`auth_bypass_scanner.py`)

- **JWT `algorithm=none`** — CRITICAL (CWE-347)
- **Non-constant-time secret comparison** — HIGH (CWE-208)
- **Client-controlled admin/role flag** — CRITICAL (CWE-639)
- **IDOR without ownership check** — HIGH (CWE-639)
- **Role from request body/cookie** — HIGH (CWE-602)
- **Hardcoded backdoor credentials** — CRITICAL (CWE-798)

## Dependency Vulnerability Scanner

Parses `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod`, `Pipfile` and queries [OSV.dev](https://osv.dev) for known CVEs. Severity is mapped from CVSS scores.

---

*Built by [Medusa Security](https://github.com/Medusa-Security)*
