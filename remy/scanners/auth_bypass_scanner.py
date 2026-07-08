"""
Auth/Logic Bypass Pattern Scanner

Detects access-control vulnerabilities, JWT bypass patterns, IDOR-shaped code,
non-constant-time comparisons, and hardcoded admin backdoors.

Lines containing `# nosec` or `# remy: nosec` are skipped to prevent
false positives when defining rule patterns or in test fixtures.
"""

import re
from pathlib import Path
from remy.report.models import Finding, Severity
from remy.utils.hashing import fingerprint_finding
from .base import Scanner

# Lines with these markers are excluded from scanning (prevents self-scan FPs)
NOSEC_MARKERS = ("# nosec", "# remy: nosec", "# noqa")


class AuthBypassScanner(Scanner):
    """Detects authentication and authorization bypass patterns."""

    name = "auth_bypass"

    # ── Detection rules as (title, pattern, severity, cwe, remediation) ───────
    # NOTE: Rule title strings deliberately avoid containing the trigger patterns
    # themselves to prevent self-scan false positives.

    RULES: list[tuple[str, re.Pattern, Severity, str, str]] = [
        # 1. JWT algorithm bypass
        (
            "JWT Signature Verification Bypass",
            re.compile(
                r"algorithm\s*=\s*['\"]none['\"]"
                r"|algorithms\s*=\s*\[['\"]none['\"]\]"
                r"|options\s*=\s*\{[^}]*['\"]verify['\"]?\s*:\s*False"
                r"|jwt\.decode\s*\([^)]*verify\s*=\s*False",
                re.IGNORECASE,
            ),
            Severity.CRITICAL,
            "CWE-347",
            (
                "Never allow JWT algorithm=none. Enforce a specific strong algorithm "
                "(RS256, ES256, or HS256). Always set options={'verify_signature': True, "
                "'verify_exp': True}. Use a well-maintained JWT library."
            ),
        ),
        # 2. Non-constant-time secret comparison (narrowed to string literal comparisons only)
        (
            "Non-Constant-Time Comparison of Secret Value",
            re.compile(
                r"(?:token|secret|password|hash|sig|hmac|api_key)\s*==\s*['\"][^'\"]{4,}['\"]",
                re.IGNORECASE,
            ),
            Severity.HIGH,
            "CWE-208",
            (
                "Use `hmac.compare_digest(a, b)` instead of `==` for comparing secrets. "
                "Python's `==` on strings exits early on first mismatch, leaking timing info."
            ),
        ),
        # 3. Client-controlled admin flag from request parameters
        (
            "Client-Controlled Privilege via Request Parameter",
            re.compile(
                r"request\.(?:args|params|GET|POST|query)\.get\s*\(\s*['\"](?:admin|role|is_admin|superuser|root)['\"]"
                r"|req\.(?:query|params|body)\.(?:admin|role|is_admin|superuser)\b"
                r"|request\.headers\.get\s*\(\s*['\"](?:X-Admin|X-Role|X-User-Role)['\"]",
                re.IGNORECASE,
            ),
            Severity.CRITICAL,
            "CWE-639",
            (
                "Never trust client-supplied role or admin flags. "
                "Authorization must be based on server-side session/token data only. "
                "Remove all code that reads privilege level from request parameters."
            ),
        ),
        # 4. IDOR — direct object lookup without ownership filter
        (
            "Direct Object Lookup Without Ownership Check (IDOR)",
            re.compile(
                r"\.objects\.get\s*\(\s*(?:id|pk)\s*=(?!\s*\w+\.(?:user|owner|created_by))"
                r"|\.findById\s*\(\s*req\."
                r"|\.find_by_id\s*\(\s*params",
                re.IGNORECASE,
            ),
            Severity.HIGH,
            "CWE-639",
            (
                "Add an ownership filter: `Model.objects.get(id=obj_id, owner=request.user)`. "
                "Never trust a client-supplied object ID alone — always verify the requester "
                "is the owner or has explicit permission."
            ),
        ),
        # 5. Role/permission read from request body or cookie
        (
            "Authorization Role Sourced from Untrusted Request Data",
            re.compile(
                r"request\.(?:json|form|POST|data)\s*(?:\[|\.get\s*\(\s*)['\"](?:role|is_admin|admin|permission)['\"]"
                r"|req\.body\.(?:role|is_admin|admin|permission)\b"
                r"|request\.cookies\.get\s*\(\s*['\"](?:role|is_admin|admin)['\"]",
                re.IGNORECASE,
            ),
            Severity.HIGH,
            "CWE-602",
            (
                "Never read authorization roles from request body, form data, or cookies. "
                "Roles must be loaded server-side from the authenticated session or a signed token."
            ),
        ),
        # 6. Hardcoded backdoor credential comparison
        (
            "Hardcoded Backdoor Credential in Comparison",
            re.compile(
                r"(?:password|passwd)\s*==\s*['\"](?:admin|password|123456|test|root|letmein|qwerty)['\"]"
                r"|(?:username|user)\s*==\s*['\"](?:admin|root|superuser)['\"]",
                re.IGNORECASE,
            ),
            Severity.CRITICAL,
            "CWE-798",
            (
                "Remove all hardcoded credential comparisons. Use a proper auth system with "
                "hashed passwords (bcrypt/argon2) stored in a database. Rotate any exposed credentials."
            ),
        ),
        # 7. debug=True / debug mode in production
        (
            "Debug Mode Enabled in Application",
            re.compile(
                r"app\.run\s*\([^)]*debug\s*=\s*True"
                r"|DEBUG\s*=\s*True\s*(?:#[^\n]*)?\n",
                re.IGNORECASE,
            ),
            Severity.HIGH,
            "CWE-94",
            (
                "Never enable debug mode in production. Set DEBUG=False and use "
                "FLASK_ENV=production or DJANGO_SETTINGS_MODULE pointing to production settings."
            ),
        ),
    ]

    async def scan_file(
        self,
        path: Path,
        content: str,
        language: str | None,
    ) -> list[Finding]:
        """Scan for auth bypass patterns in source files.

        Skips lines annotated with # nosec or # remy: nosec to prevent
        false positives on scanner rule definition strings.

        Args:
            path: File path.
            content: File content.
            language: Language (scanner applies to most code languages).

        Returns:
            List of auth bypass findings.
        """
        # Skip test/spec files to prevent false positives on assertion strings
        _TEST_RE = re.compile(
            r"(?:^|[\\/])(?:test[s]?|spec|__tests__)[\\/]|"
            r"(?:_test|\.test|\.spec|_spec)\.[a-z]+$",
            re.IGNORECASE,
        )
        if _TEST_RE.search(str(path).replace("\\", "/")):
            return []

        # Skip non-code files
        code_exts = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".rb",
            ".php",
            ".go",
            ".java",
            ".cs",
        }
        skip_langs = {"yaml", "json", "toml", "markdown"}
        if language in skip_langs and path.suffix not in code_exts:
            return []

        findings: list[Finding] = []
        lines = content.splitlines()
        seen_ids: set[str] = set()

        for line_idx, line in enumerate(lines):
            line_no = line_idx + 1
            stripped = line.strip()

            # Skip blank lines, comments, and nosec-annotated lines
            if not stripped:
                continue
            if stripped.startswith(("#", "//", "*", "<!--", "--")):
                continue
            if any(marker in line for marker in NOSEC_MARKERS):
                continue

            for title, pattern, severity, cwe, remediation in self.RULES:
                if not pattern.search(line):
                    continue

                fid = fingerprint_finding(str(path), line_no, title, self.name)
                if fid in seen_ids:
                    continue
                seen_ids.add(fid)

                findings.append(
                    Finding(
                        id=fid,
                        scanner=self.name,
                        severity=severity,
                        cwe=cwe,
                        file=str(path),
                        line_start=line_no,
                        line_end=line_no,
                        title=title,
                        description=(
                            f"Potential auth/access-control weakness at line {line_no}: {title}."
                        ),
                        remediation_hint=remediation,
                        confidence=0.75,
                        code_snippet=line.rstrip(),
                    )
                )

        return findings
