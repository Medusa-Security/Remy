"""Tests for JavaScript/TypeScript SAST scanner."""

import asyncio
from pathlib import Path
import pytest

from remy.scanners.sast_js_ts import JsTsSastScanner
from remy.report.models import Severity


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def scanner():
    return JsTsSastScanner()


class TestJsTsSastScanner:
    def test_detects_eval_and_new_function(self, scanner):
        code = """
        const userInput = req.query.cmd;
        eval(userInput);
        const fn = new Function(userInput);
        """
        findings = run(scanner.scan_file(Path("app.js"), code, "javascript"))
        assert any("eval() / new Function()" in f.title for f in findings)

    def test_detects_command_injection(self, scanner):
        code = """
        const { execSync } = require('child_process');
        execSync('ls ' + req.query.dir);
        """
        findings = run(scanner.scan_file(Path("app.js"), code, "javascript"))
        assert any(
            "child_process.exec/execSync" in f.title and f.severity == Severity.CRITICAL
            for f in findings
        )

    def test_detects_dom_xss_sinks(self, scanner):
        code = """
        document.getElementById('app').innerHTML = userInput;
        element.outerHTML = `<div class="badge">${userInput}</div>`;
        document.write(userInput);
        """
        findings = run(scanner.scan_file(Path("app.ts"), code, "typescript"))
        assert any("innerHTML / outerHTML" in f.title for f in findings)
        assert any("document.write()" in f.title for f in findings)

    def test_detects_prototype_pollution(self, scanner):
        code = """
        Object.assign(target, req.body);
        _.merge(userConfig, req.query);
        """
        findings = run(scanner.scan_file(Path("app.js"), code, "javascript"))
        assert any("Prototype Pollution Pattern" in f.title for f in findings)

    def test_detects_weak_crypto(self, scanner):
        code = """
        const crypto = require('crypto');
        const hash = crypto.createHash('md5').update(data).digest('hex');
        """
        findings = run(scanner.scan_file(Path("app.js"), code, "javascript"))
        assert any(
            "Weak Cryptography" in f.title and f.cwe == "CWE-327" for f in findings
        )

    def test_ignores_non_js_ts_files(self, scanner):
        code = "eval(userInput)"
        findings = run(scanner.scan_file(Path("app.py"), code, "python"))
        assert findings == []
