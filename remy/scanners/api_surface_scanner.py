"""
API Surface & Rate-Limit Auditor

Parses route definitions across Flask, FastAPI, Express, Next.js,
Django REST Framework, and NestJS to build an inventory of exposed
endpoints. Flags missing authentication and missing rate limiting.
"""

import re
from pathlib import Path
from remy.report.models import Finding, Severity
from remy.utils.hashing import fingerprint_finding
from .base import Scanner


# ── Route detection patterns ──────────────────────────────────────────────────

ROUTE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Flask / Blueprint
    (
        "flask",
        re.compile(
            r"""@(?:app|blueprint|bp|\w+)\.route\s*\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        ),
    ),
    # FastAPI
    (
        "fastapi",
        re.compile(
            r"""@(?:router|app)\.(?:get|post|put|delete|patch|options|head)\s*\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE,
        ),
    ),
    # Express.js
    (
        "express",
        re.compile(
            r"""(?:app|router)\.(?:get|post|put|delete|patch|use)\s*\(\s*['"`]([^'"`]+)['"`]""",
            re.IGNORECASE,
        ),
    ),
    # Next.js (file-based, just mark the handler)
    (
        "nextjs",
        re.compile(
            r"""export\s+(?:default\s+function|async\s+function|const)\s+(?:handler|GET|POST|PUT|DELETE|PATCH)"""
        ),
    ),
    # Django urlpatterns — only match inside urlpatterns context or at module level
    (
        "django",
        re.compile(r"""^\s*(?:re_)?path\s*\(\s*r?['"]([^'"]+)['"]""", re.IGNORECASE),
    ),
    # NestJS decorators
    (
        "nestjs",
        re.compile(
            r"""@(?:Get|Post|Put|Delete|Patch|Options)\s*\(\s*['"]?([^'"\)]+)?['"]?\s*\)"""
        ),
    ),
]

# ── Auth indicator patterns ───────────────────────────────────────────────────

AUTH_PATTERNS = re.compile(
    r"@(?:login_required|auth_required|jwt_required|require_http_methods|permission_required"
    r"|token_required|requires_auth|authenticated)"
    r"|Depends\s*\(\s*(?:get_current_user|get_user|verify_token|oauth2_scheme|authenticate)"
    r"|requireAuth|isAuthenticated|verifyToken|checkAuth|authenticate\s*\("
    r"|@UseGuards\s*\(\s*\w*Auth"
    r"|middleware\s*\(\s*auth"
    r"|passport\.authenticate"
    r"|authMiddleware",
    re.IGNORECASE,
)

# ── Rate-limit indicator patterns ─────────────────────────────────────────────

RATE_LIMIT_PATTERNS = re.compile(
    r"@limiter\.|flask_limiter|slowapi|@Throttle|@UseGuards\s*\(\s*ThrottlerGuard"
    r"|express-rate-limit|rateLimit\s*\(|rate_limit\s*\(|RateLimit"
    r"|@ratelimit|throttle\s*\(",
    re.IGNORECASE,
)

# Routes where rate limiting is especially critical
SENSITIVE_ROUTE_KEYWORDS = re.compile(
    r"(?:auth|login|register|signup|password|reset|forgot|verify|upload|webhook|otp|token|mfa)",
    re.IGNORECASE,
)

# Public routes that don't need auth
PUBLIC_ROUTE_PATTERNS = re.compile(
    r"^/?(?:$|health/?|status/?|docs/?|redoc/?|openapi/?|metrics/?|favicon|robots\.txt|static/)",
    re.IGNORECASE,
)


class ApiSurfaceScanner(Scanner):
    """Audits exposed API routes for missing authentication and rate limiting."""

    name = "api_surface"
    CONTEXT_WINDOW = 50  # lines to check before/after route definition

    async def scan_file(
        self,
        path: Path,
        content: str,
        language: str | None,
    ) -> list[Finding]:
        """Scan a file for route definitions and audit their security controls.

        Args:
            path: File path.
            content: File content.
            language: Detected language.

        Returns:
            List of findings for unsecured routes.
        """
        # Only scan relevant file types — skip test files
        relevant_langs = {"python", "javascript", "typescript"}
        relevant_names = {"urls.py", "routes.js", "routes.ts", "router.js", "router.ts"}

        # Skip test/spec files — they use path() and similar for test setup, not routes
        TEST_FILE_PATTERNS = re.compile(
            r"(?:^|[\\/])(?:test[s]?|spec|__tests__)[\\/]|"
            r"(?:_test|\.test|\.spec|_spec)\.[a-z]+$",
            re.IGNORECASE,
        )
        path_str = str(path).replace("\\", "/")
        if TEST_FILE_PATTERNS.search(path_str):
            return []

        if language not in relevant_langs and path.name not in relevant_names:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        seen_ids: set[str] = set()

        for line_idx, line in enumerate(lines):
            line_no = line_idx + 1

            # Check each route pattern
            for framework, pattern in ROUTE_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue

                route_path = match.group(1) if match.lastindex else "/"

                # Skip if this doesn't look like a real URL path — catches false
                # positives where the pattern matches code like Path("test.py")
                if (
                    route_path
                    and not route_path.startswith("/")
                    and "/" not in route_path
                ):
                    continue

                # Extract the surrounding context (±CONTEXT_WINDOW lines)
                ctx_start = max(0, line_idx - self.CONTEXT_WINDOW)
                ctx_end = min(len(lines), line_idx + self.CONTEXT_WINDOW)
                context = "\n".join(lines[ctx_start:ctx_end])

                # ── Check for authentication ──────────────────────────────
                has_auth = bool(AUTH_PATTERNS.search(context))
                is_public = bool(PUBLIC_ROUTE_PATTERNS.match(route_path or ""))

                if not has_auth and not is_public:
                    fid = fingerprint_finding(
                        str(path), line_no, f"missing_auth_{route_path}", self.name
                    )
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        findings.append(
                            Finding(
                                id=fid,
                                scanner=self.name,
                                severity=Severity.HIGH,
                                cwe="CWE-306",
                                file=str(path),
                                line_start=line_no,
                                line_end=line_no,
                                title=f"Missing Authentication on Route `{route_path}`",
                                description=(
                                    f"The route `{route_path}` ({framework}) has no detected "
                                    "authentication decorator or middleware in the surrounding "
                                    f"{self.CONTEXT_WINDOW} lines. It may be publicly accessible."
                                ),
                                remediation_hint=(
                                    "Add authentication: `@login_required` (Flask), `Depends(get_current_user)` "
                                    "(FastAPI), or appropriate middleware (Express/NestJS). "
                                    "Ensure all non-public endpoints require valid credentials."
                                ),
                                confidence=0.70,
                                code_snippet=line.rstrip(),
                            )
                        )

                # ── Check for rate limiting on sensitive routes ────────────
                is_sensitive = bool(SENSITIVE_ROUTE_KEYWORDS.search(route_path or line))
                has_rate_limit = bool(RATE_LIMIT_PATTERNS.search(context))

                if is_sensitive and not has_rate_limit:
                    fid = fingerprint_finding(
                        str(path), line_no, f"missing_ratelimit_{route_path}", self.name
                    )
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        findings.append(
                            Finding(
                                id=fid,
                                scanner=self.name,
                                severity=Severity.MEDIUM,
                                cwe="CWE-770",
                                file=str(path),
                                line_start=line_no,
                                line_end=line_no,
                                title=f"Missing Rate Limiting on Sensitive Route `{route_path}`",
                                description=(
                                    f"The sensitive route `{route_path}` ({framework}) has no detected "
                                    "rate limiting. This makes it vulnerable to brute-force attacks, "
                                    "credential stuffing, and abuse."
                                ),
                                remediation_hint=(
                                    "Add rate limiting: `slowapi` / `flask-limiter` for Flask/FastAPI, "
                                    "`express-rate-limit` for Express, `@Throttle()` for NestJS. "
                                    "Apply strict limits (e.g., 5/min) on auth and password endpoints."
                                ),
                                confidence=0.80,
                                code_snippet=line.rstrip(),
                            )
                        )

        # ── CORS wildcard check ────────────────────────────────────────────
        CORS_WILDCARD = re.compile(
            r"(?:CORS|cors)\s*\([^)]*origins?\s*=\s*['\"]?\*['\"]?|"
            r"Access-Control-Allow-Origin['\"]?\s*[=:]\s*['\"]?\*",
            re.IGNORECASE,
        )
        for line_idx, line in enumerate(lines):
            line_no = line_idx + 1
            if CORS_WILDCARD.search(line):
                # Check if credentials=True is also nearby
                ctx = "\n".join(
                    lines[max(0, line_idx - 5) : min(len(lines), line_idx + 5)]
                )
                if re.search(
                    r"credentials\s*=\s*True|allow_credentials\s*=\s*true",
                    ctx,
                    re.IGNORECASE,
                ):
                    fid = fingerprint_finding(
                        str(path), line_no, "cors_wildcard_with_creds", self.name
                    )
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        findings.append(
                            Finding(
                                id=fid,
                                scanner=self.name,
                                severity=Severity.MEDIUM,
                                cwe="CWE-942",
                                file=str(path),
                                line_start=line_no,
                                line_end=line_no,
                                title="Overly Permissive CORS — Wildcard with Credentials",
                                description=(
                                    "CORS is configured with `*` (all origins) AND credentials enabled. "
                                    "This combination is insecure and most browsers will reject it, "
                                    "but it indicates a misconfiguration that could be exploited."
                                ),
                                remediation_hint=(
                                    "Replace the wildcard origin with an explicit allowlist of trusted domains. "
                                    "Never use `*` with `allow_credentials=True`."
                                ),
                                confidence=0.90,
                                code_snippet=line.rstrip(),
                            )
                        )

        return findings
