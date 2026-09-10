"""Tests for Remy CLI commands (init-ci, scan --fail-on, etc.)."""

from click.testing import CliRunner

from remy.cli import main


class TestCliCommands:
    def test_init_ci_creates_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(main, ["init-ci"])
        assert result.exit_code == 0
        assert (tmp_path / ".github" / "workflows" / "remy-security.yml").exists()
        assert (tmp_path / ".pre-commit-config.yaml").exists()
        assert (
            "remy scan --format sarif"
            in (tmp_path / ".github" / "workflows" / "remy-security.yml").read_text()
        )

    def test_init_ci_skips_existing_unless_force(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        runner.invoke(main, ["init-ci"])

        # Modify pre-commit file
        precommit_path = tmp_path / ".pre-commit-config.yaml"
        precommit_path.write_text("custom: true\n", encoding="utf-8")

        # Run without force
        result = runner.invoke(main, ["init-ci"])
        assert "custom: true" in precommit_path.read_text()
        assert "Skipped" in result.output

        # Run with force
        result = runner.invoke(main, ["init-ci", "--force"])
        assert "custom: true" not in precommit_path.read_text()
        assert "repos:" in precommit_path.read_text()

    def test_scan_fail_on_gate(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Create a file with a MEDIUM severity finding (Math.random without token/secret variable name)
        test_js = tmp_path / "app.js"
        test_js.write_text("const x = Math.random();\n", encoding="utf-8")

        runner = CliRunner()
        # With default or --fail-on HIGH, Math.random (MEDIUM) should not trigger exit code 2
        # Note: We mock _load_config_or_exit to return a basic dummy config or let it run
        from remy.config.schema import Config, ScanDefaults

        dummy_cfg = Config(
            provider="openai", model="gpt-4o", scan_defaults=ScanDefaults()
        )
        monkeypatch.setattr("remy.cli._load_config_or_exit", lambda: dummy_cfg)

        result_high = runner.invoke(main, ["scan", "--fail-on", "HIGH"])
        assert result_high.exit_code == 0

        # With --fail-on MEDIUM, it should exit 2
        result_medium = runner.invoke(main, ["scan", "--fail-on", "MEDIUM"])
        assert result_medium.exit_code == 2

    def test_risk_command_runs(self, tmp_path, monkeypatch):
        (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
        from remy.config.schema import Config, ScanDefaults

        monkeypatch.setattr(
            "remy.cli._load_config_or_exit",
            lambda: Config(
                provider="openai", model="gpt-4o", scan_defaults=ScanDefaults()
            ),
        )
        result = CliRunner().invoke(main, ["risk", str(tmp_path)])
        assert result.exit_code == 0
        assert "Risk" in result.output

    def test_diff_command_runs(self, tmp_path, monkeypatch):
        # tmp_path is not a git repo, so changed-files resolves to empty
        result = CliRunner().invoke(main, ["diff", str(tmp_path)])
        assert result.exit_code == 0
        assert "No changed files" in result.output

    def test_scan_diff_mode_runs(self, tmp_path, monkeypatch):
        (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")
        from remy.config.schema import Config, ScanDefaults

        monkeypatch.setattr(
            "remy.cli._load_config_or_exit",
            lambda: Config(
                provider="openai", model="gpt-4o", scan_defaults=ScanDefaults()
            ),
        )
        result = CliRunner().invoke(main, ["scan", "--diff", str(tmp_path)])
        assert result.exit_code == 0
