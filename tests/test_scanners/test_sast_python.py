"""Tests for the Python SAST scanner."""

import asyncio
from pathlib import Path
import pytest

from remy.scanners.sast_python import PythonSastScanner
from remy.report.models import Severity


@pytest.fixture
def scanner():
    return PythonSastScanner()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestPythonSastScanner:
    def test_detects_eval_with_dynamic_arg(self, scanner):
        code = "result = eval(user_input)"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("eval" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_ignores_eval_with_literal(self, scanner):
        code = "result = eval('1 + 1')"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert not any("eval" in f.title.lower() for f in findings)

    def test_detects_pickle_loads(self, scanner):
        code = "import pickle\nobj = pickle.loads(data)"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("pickle" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_detects_subprocess_shell_true_with_dynamic_cmd(self, scanner):
        code = "import subprocess\nsubprocess.run(cmd, shell=True)"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("Shell Injection" in f.title or "shell" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_ignores_subprocess_shell_true_with_literal(self, scanner):
        code = "import subprocess\nsubprocess.run('ls -la', shell=True)"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        # Literal string — no dynamic input, should not flag
        assert not any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_sql_fstring(self, scanner):
        code = 'conn.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("SQL" in f.title or "sql" in f.title.lower() for f in findings)

    def test_detects_sql_concatenation(self, scanner):
        code = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("SQL" in f.title or "sql" in f.title.lower() for f in findings)

    def test_detects_weak_hash_md5(self, scanner):
        code = "import hashlib\nhashlib.md5(data)"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("MD5" in f.title or "md5" in f.title.lower() for f in findings)

    def test_detects_yaml_load_unsafe(self, scanner):
        code = "import yaml\nyaml.load(data)"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("yaml" in f.title.lower() for f in findings)

    def test_ignores_yaml_safe_load(self, scanner):
        code = "import yaml\nyaml.safe_load(data)"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert not any("yaml" in f.title.lower() for f in findings)

    def test_detects_broad_except_pass(self, scanner):
        code = "try:\n    risky()\nexcept Exception:\n    pass"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("Broad Exception" in f.title or "exception" in f.title.lower() for f in findings)

    def test_detects_assert_auth_check(self, scanner):
        code = "assert user.is_admin, 'Access denied'"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("assert" in f.title.lower() or "Assert" in f.title for f in findings)

    def test_detects_hardcoded_credential(self, scanner):
        code = 'api_key = "sk-real-production-key-123456"'
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert any("Credential" in f.title or "credential" in f.title.lower() for f in findings)

    def test_ignores_non_python_files(self, scanner):
        code = "const x = eval(input);"
        findings = run(scanner.scan_file(Path("test.js"), code, "javascript"))
        assert findings == []

    def test_handles_syntax_error_gracefully(self, scanner):
        code = "def broken(:"
        findings = run(scanner.scan_file(Path("test.py"), code, "python"))
        assert findings == []  # Should not raise, just return empty

