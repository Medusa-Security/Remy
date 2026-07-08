"""
Python SAST Scanner

Uses Python's built-in `ast` module to detect security vulnerabilities
and bug patterns in Python source files. Implements 10 detection rules
covering injection, insecure deserialization, weak cryptography, and more.
"""

import ast
from pathlib import Path
from remy.report.models import Finding, Severity
from remy.utils.hashing import fingerprint_finding
from .base import Scanner


# Names that suggest a variable holds a secret
SECRET_VARNAMES = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth_key",
        "access_key",
        "private_key",
        "credential",
        "credentials",
        "passphrase",
        "pass",
        "auth_token",
        "jwt_secret",
        "session_key",
        "encryption_key",
        "secret_key",
    }
)

# Names that suggest randomness used for security tokens
SECURITY_RANDOM_VARNAMES = frozenset(
    {
        "token",
        "secret",
        "nonce",
        "salt",
        "key",
        "session_id",
        "csrf_token",
        "otp",
        "pin",
        "password",
        "reset_token",
    }
)


class _RemyAstVisitor(ast.NodeVisitor):
    """AST visitor that applies Remy's SAST detection rules to a Python file."""

    def __init__(self, source_lines: list[str], file_path: str) -> None:
        self.source_lines = source_lines
        self.file_path = file_path
        self.findings: list[Finding] = []
        self._seen_ids: set[str] = set()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_line(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].rstrip()
        return ""

    def _add(
        self,
        lineno: int,
        end_lineno: int,
        title: str,
        description: str,
        remediation: str,
        severity: Severity,
        cwe: str,
        confidence: float = 0.85,
    ) -> None:
        fid = fingerprint_finding(self.file_path, lineno, title, "sast_python")
        if fid in self._seen_ids:
            return
        self._seen_ids.add(fid)
        self.findings.append(
            Finding(
                id=fid,
                scanner="sast_python",
                severity=severity,
                cwe=cwe,
                file=self.file_path,
                line_start=lineno,
                line_end=end_lineno,
                title=title,
                description=description,
                remediation_hint=remediation,
                confidence=confidence,
                code_snippet=self._get_line(lineno),
            )
        )

    def _is_var_call(self, node: ast.expr, *names: str) -> bool:
        """Check if a node is a call like `names[0].names[1]()`."""
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and len(names) == 2:
                return (
                    isinstance(func.value, ast.Name)
                    and func.value.id == names[0]
                    and func.attr == names[1]
                )
            if isinstance(func, ast.Name) and len(names) == 1:
                return func.id == names[0]
        return False

    def _call_name(self, node: ast.Call) -> str:
        """Return a dotted string representation of the call's function."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts = []
            cur = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""

    # ── Rule 1: eval() / exec() ───────────────────────────────────────────────

    def _check_eval_exec(self, node: ast.Call) -> None:
        name = self._call_name(node)
        if name not in ("eval", "exec"):
            return
        # Flag if argument is not a constant/literal
        if node.args and not isinstance(node.args[0], ast.Constant):
            self._add(
                node.lineno,
                node.end_lineno or node.lineno,
                f"Dangerous use of `{name}()` with dynamic argument",
                f"`{name}()` is called with a non-literal argument. "
                "If user input can influence this, it enables arbitrary code execution.",
                f"Replace `{name}()` with a safe alternative. If dynamic execution is truly "
                "required, use `ast.literal_eval()` for expressions or a whitelist approach.",
                Severity.HIGH,
                "CWE-78",
            )

    # ── Rule 2: pickle.loads / pickle.load ────────────────────────────────────

    def _check_pickle(self, node: ast.Call) -> None:
        name = self._call_name(node)
        if name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"):
            self._add(
                node.lineno,
                node.end_lineno or node.lineno,
                "Insecure deserialization via `pickle`",
                f"`{name}()` deserializes arbitrary Python objects. "
                "Deserializing untrusted data can lead to remote code execution.",
                "Replace pickle with a safe serialization format such as JSON. "
                "If pickle is required, only deserialize data from fully trusted, signed sources.",
                Severity.HIGH,
                "CWE-502",
            )

    # ── Rule 3: subprocess with shell=True ───────────────────────────────────

    def _check_subprocess(self, node: ast.Call) -> None:
        name = self._call_name(node)
        SUBPROCESS_FUNCS = {
            "subprocess.call",
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
        }
        if name not in SUBPROCESS_FUNCS:
            return
        shell_true = False
        for kw in node.keywords:
            if (
                kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                shell_true = True
                break
        if not shell_true:
            return
        # Check if the first arg is not a plain constant
        if node.args:
            first_arg = node.args[0]
            if not isinstance(first_arg, ast.Constant):
                self._add(
                    node.lineno,
                    node.end_lineno or node.lineno,
                    "Shell Injection — `subprocess` with `shell=True` and dynamic command",
                    f"`{name}()` is called with `shell=True` and a non-literal command. "
                    "If user input is included, this allows OS command injection.",
                    "Pass a list of arguments instead of a string command. "
                    "Avoid `shell=True`. Use `shlex.quote()` if a shell string is unavoidable.",
                    Severity.CRITICAL,
                    "CWE-78",
                )

    # ── Rule 4: SQL string concatenation ──────────────────────────────────────

    def _check_sql_injection(self, node: ast.Call) -> None:
        name = self._call_name(node)
        if not name.endswith(".execute"):
            return
        if not node.args:
            return
        sql_arg = node.args[0]
        # Flag f-strings and string concatenation (+) as potential SQL injection
        if isinstance(sql_arg, ast.JoinedStr):  # f-string
            self._add(
                node.lineno,
                node.end_lineno or node.lineno,
                "SQL Injection — f-string in `.execute()` call",
                "An f-string is passed directly to `.execute()`. "
                "If any variable in the f-string comes from user input, SQL injection is possible.",
                "Use parameterized queries: `cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))`. "
                "Never use string formatting to build SQL queries.",
                Severity.HIGH,
                "CWE-89",
            )
        elif isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Add):
            self._add(
                node.lineno,
                node.end_lineno or node.lineno,
                "SQL Injection — String concatenation in `.execute()` call",
                "String concatenation (`+`) is used to build a SQL query passed to `.execute()`. "
                "This pattern enables SQL injection if any concatenated part is user-controlled.",
                "Use parameterized queries with placeholders (%s or ?) instead of concatenation.",
                Severity.HIGH,
                "CWE-89",
            )

    # ── Rule 5: Weak random for security tokens ───────────────────────────────

    def _check_weak_random(self, node: ast.Call) -> None:
        name = self._call_name(node)
        RANDOM_FUNCS = {
            "random.random",
            "random.randint",
            "random.choice",
            "random.choices",
            "random.uniform",
            "random.shuffle",
        }
        if name not in RANDOM_FUNCS:
            return
        # Heuristic: check if the result is assigned to a security-sensitive name
        parent_assign = getattr(node, "_parent_assign_target", None)
        if parent_assign and any(
            sec_name in parent_assign.lower() for sec_name in SECURITY_RANDOM_VARNAMES
        ):
            self._add(
                node.lineno,
                node.end_lineno or node.lineno,
                "Weak Randomness Used for Security-Sensitive Token",
                f"`{name}()` is not cryptographically secure and should not be used for "
                "tokens, session IDs, nonces, or passwords. The `random` module is predictable.",
                "Use `secrets.token_hex()`, `secrets.token_urlsafe()`, or `os.urandom()` "
                "for any security-sensitive random value generation.",
                Severity.MEDIUM,
                "CWE-338",
            )

    # ── Rule 6: MD5/SHA1 for passwords ───────────────────────────────────────

    def _check_weak_hash(self, node: ast.Call) -> None:
        name = self._call_name(node)
        WEAK_HASHES = {"hashlib.md5", "hashlib.sha1"}
        if name not in WEAK_HASHES:
            return
        # Heuristic: check if a 'password' variable appears in the same expression
        # Just flag any usage of MD5/SHA1 in a security context
        self._add(
            node.lineno,
            node.end_lineno or node.lineno,
            f"Weak Hashing Algorithm — `{name}`",
            f"`{name}()` produces hashes that are computationally trivial to crack for password storage. "
            "MD5 and SHA1 are broken for cryptographic purposes.",
            "For password hashing use `bcrypt`, `argon2`, or `hashlib.scrypt`. "
            "For data integrity use SHA-256 or SHA-3.",
            Severity.MEDIUM,
            "CWE-327",
            confidence=0.70,
        )

    # ── Rule 9: yaml.load without SafeLoader ─────────────────────────────────

    def _check_yaml_load(self, node: ast.Call) -> None:
        name = self._call_name(node)
        if name != "yaml.load":
            return
        has_safe_loader = any(
            (isinstance(kw.value, ast.Attribute) and "safe" in kw.value.attr.lower())
            or (isinstance(kw.value, ast.Name) and "safe" in kw.value.id.lower())
            for kw in node.keywords
            if kw.arg == "Loader"
        )
        if not has_safe_loader and not any(
            (isinstance(a, ast.Attribute) and "safe" in a.attr.lower())
            or (isinstance(a, ast.Name) and "safe" in a.id.lower())
            for a in node.args[1:]
        ):
            self._add(
                node.lineno,
                node.end_lineno or node.lineno,
                "Insecure `yaml.load()` — Missing SafeLoader",
                "`yaml.load()` without `Loader=yaml.SafeLoader` can deserialize arbitrary Python "
                "objects from YAML data, enabling remote code execution.",
                "Use `yaml.safe_load()` or pass `Loader=yaml.SafeLoader` explicitly.",
                Severity.HIGH,
                "CWE-502",
            )

    # ── Node visitors ─────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        self._check_eval_exec(node)
        self._check_pickle(node)
        self._check_subprocess(node)
        self._check_sql_injection(node)
        self._check_weak_random(node)
        self._check_weak_hash(node)
        self._check_yaml_load(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Rule 7: Broad except that silently passes."""
        # Check if the handler body is effectively empty (pass / ellipsis only)
        body_is_empty = all(
            isinstance(stmt, (ast.Pass, ast.Expr))
            and (not isinstance(stmt, ast.Expr) or isinstance(stmt.value, ast.Constant))
            for stmt in node.body
        )
        if body_is_empty:
            # Broad except: catches Exception or all exceptions
            is_broad = node.type is None or (
                isinstance(node.type, ast.Name) and node.type.id == "Exception"
            )
            if is_broad:
                self._add(
                    node.lineno,
                    node.end_lineno or node.lineno,
                    "Broad Exception Silently Swallowed",
                    "A broad `except:` or `except Exception: pass` silently discards errors. "
                    "This can hide bugs, mask security events, and make debugging very difficult.",
                    "Handle specific exceptions. At minimum, log the exception. "
                    "Use `except Exception as e: logger.error('...', exc_info=True)` instead of passing.",
                    Severity.LOW,
                    "CWE-390",
                )
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Rule 8: Assert used for authentication/authorization checks."""
        # Look at the assert test expression — if it references auth/permission keywords
        test_src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
        AUTH_KEYWORDS = (
            "auth",
            "admin",
            "permission",
            "role",
            "user",
            "access",
            "login",
        )
        if any(kw in test_src.lower() for kw in AUTH_KEYWORDS):
            self._add(
                node.lineno,
                node.end_lineno or node.lineno,
                "`assert` Used for Security/Auth Check",
                "`assert` statements are removed when Python runs with the `-O` (optimize) flag, "
                "which completely bypasses the check. Using `assert` for auth is a security antipattern.",
                "Replace `assert` with an explicit `if not condition: raise PermissionError(...)` "
                "or framework-provided auth decorators.",
                Severity.MEDIUM,
                "CWE-617",
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Rule 10: Hardcoded credentials assigned to sensitive variable names."""
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id.lower()
            elif isinstance(target, ast.Attribute):
                target_name = target.attr.lower()

            if not any(sec in target_name for sec in SECRET_VARNAMES):
                continue

            # Check if the value is a non-trivial string literal
            if isinstance(node.value, ast.Constant) and isinstance(
                node.value.value, str
            ):
                val = node.value.value
                if len(val) > 8 and not _is_placeholder(val):
                    # Attach the target name to Call nodes for Rule 5 heuristic
                    for child in ast.walk(
                        node.value if hasattr(node, "value") else node
                    ):
                        if isinstance(child, ast.Call):
                            child._parent_assign_target = target_name  # type: ignore[attr-defined]

                    self._add(
                        node.lineno,
                        node.end_lineno or node.lineno,
                        f"Hardcoded Credential in Variable `{target_name}`",
                        f"The variable `{target_name}` is assigned a hardcoded string literal. "
                        "Committing secrets in source code risks credential exposure via version control.",
                        "Move the value to an environment variable: "
                        f"`{target_name.upper()} = os.environ['...']`. "
                        "Use a .env file (in .gitignore) or a secrets manager.",
                        Severity.HIGH,
                        "CWE-798",
                    )

        # Propagate target name to Call children for weak-random rule
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id.lower()
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    child._parent_assign_target = target_name  # type: ignore[attr-defined]

        self.generic_visit(node)


def _is_placeholder(val: str) -> bool:
    PLACEHOLDERS = {
        "placeholder",
        "example",
        "your_key",
        "yourkey",
        "replace_me",
        "your_secret",
        "fake",
        "dummy",
        "test",
        "changeme",
        "none",
        "",
    }
    return val.lower() in PLACEHOLDERS or val.lower().startswith(
        ("<", "$", "your_", "insert")
    )


class PythonSastScanner(Scanner):
    """AST-based static analysis scanner for Python source files."""

    name = "sast_python"

    async def scan_file(
        self,
        path: Path,
        content: str,
        language: str | None,
    ) -> list[Finding]:
        """Run all Python SAST rules against the file.

        Args:
            path: File path.
            content: Source code string.
            language: Must be 'python' for this scanner to activate.

        Returns:
            List of findings, empty list for non-Python files.
        """
        if language != "python":
            return []

        try:
            tree = ast.parse(content, filename=str(path))
        except SyntaxError:
            return []

        visitor = _RemyAstVisitor(
            source_lines=content.splitlines(),
            file_path=str(path),
        )
        visitor.visit(tree)
        return visitor.findings
