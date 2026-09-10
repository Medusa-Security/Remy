"""
Remy CLI — Click command router

Entry point for all `remy` commands. Handles first-run detection,
dispatches to the config wizard, and wires up all subcommands.
"""

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from remy import __version__
from remy.ui.theme import THEME
from remy.ui.banner import print_banner

console = Console(theme=THEME)

CONFIG_DIR = Path.home() / ".remy"
CONFIG_FILE = CONFIG_DIR / "config.toml"
CACHE_FILE = CONFIG_DIR / "last_scan.json"

_SEVERITY_CHOICES = click.Choice(
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False
)


def _is_first_run() -> bool:
    return not CONFIG_FILE.exists()


def _load_config_or_exit():
    """Load config or print a helpful redirect and exit."""
    from remy.config.store import load_config

    cfg = load_config()
    if cfg is None:
        console.print(
            Panel(
                "[bold yellow]⚠  Remy is not configured yet.[/]\n\n"
                "Run [bold color(220)]remy config[/] to set up your provider and API key.",
                border_style="yellow",
                title="[bold]Setup Required[/]",
            )
        )
        sys.exit(1)
    return cfg


# ── Root command ──────────────────────────────────────────────────────────────


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """Remy Agent — AI-Powered Codebase Bug & Vulnerability Scanning CLI.

    Built by Medusa Security · github.com/Medusa-Security
    """
    if ctx.invoked_subcommand is not None:
        return

    if _is_first_run():
        print_banner(console)
        console.print(
            Panel(
                "[bold]Welcome to Remy![/]\n\n"
                "It looks like this is your first time running Remy.\n"
                "Let's connect you to an LLM provider before scanning.",
                border_style="color(220)",
                title="[bold color(220)]First Run Setup[/]",
                padding=(1, 4),
            )
        )
        from remy.config.wizard import run_wizard

        cfg = run_wizard()
        # After wizard, offer to run a scan immediately
        if cfg is not None:
            import questionary

            if questionary.confirm(
                "\nConfiguration saved! Run a quick scan of the current directory now?",
                default=True,
            ).ask():
                _run_scan(
                    path=".",
                    deep=cfg.scan_defaults.deep,
                    secrets_only=False,
                    api_surface=False,
                    bypass_check=False,
                    deps=False,
                    fmt="text",
                    output=None,
                    no_prompt=False,
                    min_severity="INFO",
                    fail_on=None,
                    config=cfg,
                )
    else:
        # Default: quick scan of cwd
        cfg = _load_config_or_exit()
        _run_scan(
            path=".",
            deep=cfg.scan_defaults.deep,
            secrets_only=False,
            api_surface=False,
            bypass_check=False,
            deps=False,
            fmt="text",
            output=None,
            no_prompt=False,
            min_severity="INFO",
            fail_on=None,
            config=cfg,
        )


# ── scan ──────────────────────────────────────────────────────────────────────


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--deep", is_flag=True, help="Enable LLM logic-bug pass in addition to SAST"
)
@click.option(
    "--secrets-only", is_flag=True, help="Hardcoded key / credential scan only"
)
@click.option(
    "--api-surface", is_flag=True, help="Exposed route + rate-limit audit only"
)
@click.option("--bypass-check", is_flag=True, help="Auth/logic bypass detection only")
@click.option("--deps", is_flag=True, help="Dependency vulnerability scan only")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif", "gitlab"]),
    default="text",
    help="Output format (default: text)",
)
@click.option("--output", type=click.Path(), default=None, help="Write output to file")
@click.option(
    "--min-severity",
    type=_SEVERITY_CHOICES,
    default="INFO",
    help="Only show findings at this severity or above (default: INFO = show all)",
)
@click.option(
    "--no-prompt",
    is_flag=True,
    default=False,
    help="Skip Fix Prompt generation (useful in CI)",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"], case_sensitive=False
    ),
    default=None,
    help="Fail CI gate (exit 2) on findings at or above this severity (default: HIGH)",
)
@click.option(
    "--diff/--no-diff",
    default=False,
    help="PR-diff mode: scan only changed files + their transitive dependents",
)
@click.option(
    "--base",
    default="main",
    help="Base ref used to compute the changed-file set for --diff",
)
def scan(
    path,
    deep,
    secrets_only,
    api_surface,
    bypass_check,
    deps,
    fmt,
    output,
    min_severity,
    no_prompt,
    fail_on,
    diff,
    base,
):
    """Scan a path for bugs and vulnerabilities.

    PATH defaults to the current working directory.
    Exits with code 2 if findings meet or exceed the fail-on threshold (CI gate).
    """
    cfg = _load_config_or_exit()
    use_deep = deep or cfg.scan_defaults.deep
    _run_scan(
        path=path,
        deep=use_deep,
        secrets_only=secrets_only,
        api_surface=api_surface,
        bypass_check=bypass_check,
        deps=deps,
        fmt=fmt,
        output=output,
        no_prompt=no_prompt,
        min_severity=min_severity,
        fail_on=fail_on,
        diff=diff,
        base=base,
        config=cfg,
    )


def _build_report(path: str, config, deep: bool = False):
    """Run the orchestrator and return a ScanReport without rendering/caching."""
    from remy.scanners.orchestrator import ScanOrchestrator, ScanOptions

    target_path = Path(path).resolve()
    options = ScanOptions(
        deep=deep,
        secrets_only=False,
        api_surface_only=False,
        bypass_check_only=False,
        deps_only=False,
        max_file_size_kb=config.scan_defaults.max_file_size_kb,
        respect_gitignore=config.scan_defaults.respect_gitignore,
        min_severity="INFO",
    )
    orchestrator = ScanOrchestrator(config=config, options=options, console=console)
    try:
        return asyncio.run(orchestrator.run(str(target_path)))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        console.print(f"[bold red]Scan failed:[/] {e}")
        console.print(
            "[dim]For a full traceback, run: python -m remy scan with REMY_DEBUG=1[/dim]"
        )
        import os

        if os.environ.get("REMY_DEBUG"):
            import traceback

            traceback.print_exc()
        sys.exit(1)


def _run_scan(
    path,
    deep,
    secrets_only,
    api_surface,
    bypass_check,
    deps,
    fmt,
    output,
    no_prompt,
    min_severity,
    fail_on,
    diff,
    base,
    config,
):
    """Internal scan runner — shared by `remy` (default) and `remy scan`."""
    from remy.scanners.orchestrator import ScanOrchestrator, ScanOptions
    from remy.report.terminal_report import TerminalReporter
    from remy.report.json_export import export_json
    from remy.report.prompt_builder import save_prompt

    print_banner(console)

    target_path = Path(path).resolve()

    options = ScanOptions(
        deep=deep,
        secrets_only=secrets_only,
        api_surface_only=api_surface,
        bypass_check_only=bypass_check,
        deps_only=deps,
        max_file_size_kb=config.scan_defaults.max_file_size_kb,
        respect_gitignore=config.scan_defaults.respect_gitignore,
        min_severity=min_severity,
    )

    if diff:
        from remy.diff import changed_files, pr_scope
        from remy.knowledge.dependencies import build_dependency_graph

        changed = changed_files(target_path, base)
        dep_graph = build_dependency_graph(target_path)
        scope = pr_scope(changed, dep_graph)
        if not scope:
            console.print(
                f"[yellow]No changed files vs '{base}' — diff scope is empty.[/yellow]"
            )
        else:
            console.print(
                f"[dim]PR-diff scope:[/dim] {len(changed)} changed -> "
                f"{len(scope)} files (incl. dependents)"
            )
        options.only_paths = scope

    orchestrator = ScanOrchestrator(config=config, options=options, console=console)

    try:
        report = asyncio.run(orchestrator.run(str(target_path)))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[bold red]Scan failed:[/] {e}")
        console.print(
            "[dim]For a full traceback, run: python -m remy scan with REMY_DEBUG=1[/dim]"
        )
        import os

        if os.environ.get("REMY_DEBUG"):
            import traceback

            traceback.print_exc()
        sys.exit(1)

    # ── Render / export ───────────────────────────────────────────────────────
    if fmt == "json":
        json_str = export_json(report)
        if output:
            Path(output).write_text(json_str, encoding="utf-8")
            console.print(f"[green]JSON report written to[/] [bold]{output}[/]")
        else:
            click.echo(json_str)
    elif fmt == "sarif":
        from remy.report.json_export import export_sarif

        sarif_str = export_sarif(report)
        if output:
            Path(output).write_text(sarif_str, encoding="utf-8")
            console.print(f"[green]SARIF report written to[/] [bold]{output}[/]")
        else:
            click.echo(sarif_str)
    elif fmt == "gitlab":
        from remy.report.json_export import export_gitlab_sast

        gitlab_str = export_gitlab_sast(report)
        if output:
            Path(output).write_text(gitlab_str, encoding="utf-8")
            console.print(f"[green]GitLab SAST report written to[/] [bold]{output}[/]")
        else:
            click.echo(gitlab_str)
    else:
        reporter = TerminalReporter(console=console, target_path=str(target_path))
        reporter.render(report)

        if not no_prompt and report.total_count > 0:
            # Save Fix Prompt relative to the scan target directory
            prompt_dir = target_path / ".remy"
            prompt_paths = save_prompt(report, output_dir=prompt_dir)
            if prompt_paths:
                console.print(
                    Panel(
                        "[bold]Fix Prompt generated![/] Paste it into Claude Code, Cursor, "
                        "Windsurf, or any AI coding agent to remediate the findings.\n\n"
                        + "\n".join(f"  📄 {p}" for p in prompt_paths)
                        + "\n\n[dim]Run [/dim][bold color(220)]remy prompt --copy[/bold color(220)]"
                        " [dim]to copy to clipboard.[/dim]",
                        border_style="color(220)",
                        title="[bold color(220)]Fix Prompt Ready[/]",
                        padding=(1, 2),
                    )
                )

    # Cache findings for `remy prompt` regeneration
    _cache_report(report)

    # CI gate: exit 2 if any finding meets or exceeds the fail_on threshold
    gate_str = (fail_on or config.scan_defaults.fail_on or "HIGH").upper()
    _sev_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "NONE": 99,
        "OFF": 99,
    }
    gate_order = _sev_order.get(gate_str, 1)

    if any(f.severity.sort_order <= gate_order for f in report.findings):
        sys.exit(2)


def _cache_report(report) -> None:
    """Persist scan report to ~/.remy/last_scan.json for prompt regeneration."""
    from remy.report.json_export import export_json

    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(export_json(report), encoding="utf-8")
    except OSError as e:
        console.print(f"[dim yellow]⚠ Could not cache scan results: {e}[/dim yellow]")


# ── prompt ────────────────────────────────────────────────────────────────────


@main.command()
@click.option("--copy", is_flag=True, help="Copy Fix Prompt to clipboard")
@click.argument("path", default=".", type=click.Path(exists=True))
def prompt(copy: bool, path: str) -> None:
    """View or copy the Fix Prompt from the last scan.

    Looks for the prompt in <PATH>/.remy/ first, then falls back to
    the global cache at ~/.remy/last_scan.json.
    """
    from remy.report.prompt_builder import save_prompt_from_cache

    # Check local .remy/ directory first (always numbered now)
    Path(path) / ".remy" / "fix_prompt_1.md"
    local_prompt_dir = Path(path) / ".remy"

    if local_prompt_dir.exists() and any(local_prompt_dir.glob("fix_prompt_*.md")):
        prompt_paths = sorted(str(p) for p in local_prompt_dir.glob("fix_prompt_*.md"))
    elif CACHE_FILE.exists():
        # Regenerate from cache
        prompt_paths = save_prompt_from_cache(CACHE_FILE)
    else:
        console.print(
            Panel(
                "[yellow]No Fix Prompt found.[/]\n\n"
                "Run [bold color(220)]remy scan[/] first.",
                border_style="yellow",
            )
        )
        sys.exit(1)

    if not prompt_paths:
        console.print("[yellow]No findings to build a prompt from.[/]")
        return

    console.print(
        Panel(
            "[bold green]Fix Prompt ready![/]\n\n"
            + "\n".join(f"  📄 {p}" for p in prompt_paths),
            border_style="green",
            title="[bold]Fix Prompt[/]",
        )
    )

    if copy:
        try:
            import pyperclip

            text = Path(prompt_paths[0]).read_text(encoding="utf-8")
            pyperclip.copy(text)
            console.print("[green]✅ Copied to clipboard![/]")
        except ImportError:
            console.print(
                "[yellow]pyperclip not installed. Run: pip install pyperclip[/]"
            )
        except Exception as e:
            console.print(
                f"[yellow]Could not copy to clipboard: {e}[/]\n"
                "[dim]On Linux, install xclip or xsel. On Windows, check clipboard permissions.[/dim]"
            )


# ── graph ──────────────────────────────────────────────────────────────────────


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--deep", is_flag=True, help="Include the LLM logic-bug pass when building the graph")
@click.option(
    "--ask",
    default=None,
    type=click.Choice(
        ["summary", "hotspots", "by-scanner", "unauthenticated", "secrets"], case_sensitive=False
    ),
    help="Run a built-in graph query instead of printing the full tree",
)
@click.option(
    "--impact",
    default=None,
    help="Print everything reachable from a file path or finding id (the 'what breaks if I remove X' query)",
)
def graph(path: str, deep: bool, ask: str | None, impact: str | None) -> None:
    """Build Remy's Knowledge Graph from a scan and query it.

    Turns findings into a graph (file → finding → scanner → CWE → secret) and
    lets you ask questions about risk, exposure, and blast radius.
    """
    from remy.knowledge.graph import KnowledgeGraph
    from remy.knowledge import render as graph_render

    cfg = _load_config_or_exit()
    report = _build_report(path, cfg, deep=deep)
    g = KnowledgeGraph.from_findings(report.findings, report.target_path)

    if not g.nodes:
        console.print("[yellow]No findings to graph. Run a scan first.[/yellow]")
        return

    if impact is not None:
        graph_render.render_impact(console, g, impact)
        return

    if ask:
        ask = ask.lower()
        if ask == "summary":
            graph_render.render_summary(console, g)
        elif ask == "hotspots":
            graph_render.render_hotspots(console, g)
        elif ask == "by-scanner":
            graph_render.render_by_scanner(console, g)
        elif ask == "unauthenticated":
            graph_render.render_unauthenticated(console, g)
        elif ask == "secrets":
            graph_render.render_secrets(console, g)
        return

    graph_render.render_tree(console, g)
    console.print(
        "\n[dim]Queries:[/dim] [bold color(220)]remy graph --ask hotspots[/bold color(220)]"
        " [dim]·[/dim] [bold color(220)]--ask secrets[/bold color(220)]"
        " [dim]·[/dim] [bold color(220)]--impact <file>[/bold color(220)]"
    )


# ── diff ──────────────────────────────────────────────────────────────────────


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--base", default="main", help="Base ref to diff changed files against")
def diff(path: str, base: str) -> None:
    """Show the PR test surface: changed files + their transitive dependents."""
    from remy.diff import changed_files, pr_scope
    from remy.knowledge.dependencies import build_dependency_graph

    target = Path(path).resolve()
    changed = changed_files(target, base)
    dep_graph = build_dependency_graph(target)
    scope = pr_scope(changed, dep_graph)

    if not changed:
        console.print(
            f"[yellow]No changed files vs '{base}'.[/yellow] "
            "Commit changes or pass a different --base."
        )
        return

    console.print(
        f"[bold color(220)]PR-diff scope[/] vs [bold]{base}[/] -> "
        f"{len(changed)} changed, {len(scope)} to scan\n"
    )
    for f in sorted(changed):
        deps = dep_graph.dependents(f)
        extra = f"  [dim](+{len(deps)} dependent(s))[/dim]" if deps else ""
        label = Path(f).relative_to(target) if str(f).startswith(str(target)) else f
        console.print(f"  [bold yellow]M[/] {label}{extra}")


# ── risk ──────────────────────────────────────────────────────────────────────


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--deep", is_flag=True, help="Include the LLM logic-bug pass when scoring")
@click.option("--url", default=None, help="Optional live app URL; folds runtime reachability into scores")
def risk(path: str, deep: bool, url: str | None) -> None:
    """Rank findings by risk: severity x reachability x blast-radius.

    Builds the dependency graph, scores every finding (a CRITICAL on a public
    endpoint that 40 modules import outranks an isolated INFO), and prints the
    ranked list so you know what to fix first.
    """
    from remy.knowledge.dependencies import build_dependency_graph
    from remy.knowledge.risk import score_findings
    from remy.knowledge.render import render_risk

    cfg = _load_config_or_exit()
    report = _build_report(path, cfg, deep=deep)
    target = Path(path).resolve()

    dep_graph = build_dependency_graph(target)
    findings = list(report.findings)
    public_endpoints: set[str] = set()

    if url:
        from remy.medusa import MedusaOrchestrator, MedusaTarget

        target_obj = MedusaTarget.from_spec_file(url, auth_token=None)
        mreport = MedusaOrchestrator(baseline_dir=".remy/medusa/baselines").run(
            target_obj, agents=["api", "trace"], regression=False
        )
        findings.extend(mreport.findings)
        if mreport.graph:
            public_endpoints = {
                n.label for n in mreport.graph.nodes.values() if n.kind == "ENDPOINT"
            }

    risk_report = score_findings(findings, dep_graph, public_endpoints)
    render_risk(console, risk_report)


# ── medusa ──────────────────────────────────────────────────────────────────────


@main.command()
@click.option("--url", required=True, help="Base URL of the running app to test")
@click.option("--spec", default=None, help="OpenAPI spec (YAML/JSON) describing the API surface")
@click.option(
    "--agents",
    default="all",
    help="Comma-separated agents: browser,workflow,api,e2e,trace (or 'all')",
)
@click.option("--workflow", default=None, help="Workflow YAML/JSON for the workflow agent")
@click.option("--token", default=None, help="Auth token injected as a Bearer header")
@click.option("--baseline/--no-baseline", default=True, help="Compare against / save regression baseline")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Output format",
)
@click.option("--output", default=None, help="Write JSON report to file")
@click.option(
    "--explain",
    default=None,
    help="Show the causal chain for a failure event id (from the run output)",
)
def medusa(url, spec, agents, workflow, token, baseline, fmt, output, explain):
    """Run the Medusa dynamic agents against a live app.

    Autonomous browser exploration, workflow execution, API fuzzing,
    stateful E2E, and runtime tracing are orchestrated into one run, merged
    into a runtime graph, root-caused, and regression-checked.
    """
    from remy.medusa import MedusaOrchestrator, MedusaTarget
    from remy.medusa.json_export import report_to_dict as _report_to_dict
    from remy.medusa.render import render_report

    target = MedusaTarget.from_spec_file(url, spec, auth_token=token)
    orchestrator = MedusaOrchestrator(workflow_path=workflow)

    try:
        agent_list = [a.strip() for a in agents.split(",") if a.strip()]
        report = orchestrator.run(target, agents=agent_list, regression=baseline)
    except ValueError as e:
        console.print(f"[bold red]{e}[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Medusa run failed:[/] {e}")
        sys.exit(1)

    if explain:
        for rc in report.root_causes:
            if rc.failure_id == explain:
                console.print(rc.explanation)
                for step in rc.chain:
                    console.print(f"  - {step.kind.value} {step.target}")
                return
        console.print(f"[yellow]No root cause recorded for '{explain}'.[/yellow]")
        return

    if fmt == "json":
        data = _report_to_dict(report)
        if output:
            Path(output).write_text(_json_dump(data), encoding="utf-8")
            console.print(f"[green]Medusa JSON report written to[/] [bold]{output}[/]")
        else:
            click.echo(_json_dump(data))
        return

    render_report(console, report)


def _json_dump(data: dict) -> str:
    import json

    return json.dumps(data, indent=2, default=str)


# ── init-ci ───────────────────────────────────────────────────────────────────


@main.command(name="init-ci")
@click.option(
    "--force", is_flag=True, help="Overwrite existing CI/pre-commit files if present"
)
def init_ci(force: bool) -> None:
    """Generate GitHub Actions workflow and pre-commit hooks for CI/CD."""
    github_dir = Path(".github") / "workflows"
    github_dir.mkdir(parents=True, exist_ok=True)

    workflow_path = github_dir / "remy-security.yml"
    precommit_path = Path(".pre-commit-config.yaml")

    workflow_content = """name: Remy AI Security Scanner

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Check out code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Remy
        run: |
          python -m pip install --upgrade pip
          pip install remy-security

      - name: Run Remy Security Scan (SARIF Export)
        run: |
          remy scan --format sarif --output remy-results.sarif --no-prompt
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: remy-results.sarif
"""

    precommit_content = """repos:
  - repo: local
    hooks:
      - id: remy-security
        name: Remy Security Scanner
        entry: remy scan --secrets-only
        language: system
        pass_filenames: false
        always_run: true
"""

    created = []
    if not workflow_path.exists() or force:
        workflow_path.write_text(workflow_content, encoding="utf-8")
        created.append(str(workflow_path))
    else:
        console.print(
            f"[yellow]Skipped {workflow_path} (already exists, use --force to overwrite)[/]"
        )

    if not precommit_path.exists() or force:
        precommit_path.write_text(precommit_content, encoding="utf-8")
        created.append(str(precommit_path))
    else:
        console.print(
            f"[yellow]Skipped {precommit_path} (already exists, use --force to overwrite)[/]"
        )

    if created:
        console.print(
            Panel(
                "[bold green]⚡ CI/CD Automation Setup Complete![/]\n\nGenerated files:\n"
                + "\n".join(f"  • {f}" for f in created)
                + "\n\n[dim]Commit these files to activate GitHub Code Scanning and local pre-commit hooks.[/dim]",
                border_style="green",
                title="[bold]Remy CI/CD[/]",
            )
        )


# ── config ────────────────────────────────────────────────────────────────────


@main.group(invoke_without_command=True)
@click.pass_context
def config(ctx: click.Context) -> None:
    """Manage Remy configuration."""
    if ctx.invoked_subcommand is None:
        print_banner(console)
        from remy.config.wizard import run_wizard

        run_wizard()


@config.command(name="show")
def config_show() -> None:
    """Print current active config (API key redacted)."""
    from remy.config.store import load_config, get_api_key
    from remy.ui.tables import render_config_table

    cfg = load_config()
    if cfg is None:
        console.print("[yellow]No configuration found. Run `remy config` to set up.[/]")
        sys.exit(1)

    api_key = get_api_key(cfg.provider)
    render_config_table(console, cfg, api_key)
    console.print(f"\n[dim]Config file: {CONFIG_FILE}[/dim]")


@config.command(name="set-provider")
def config_set_provider() -> None:
    """Change provider and model without running the full wizard."""
    from remy.config.wizard import run_provider_step

    run_provider_step()


@config.command(name="reset")
@click.confirmation_option(
    prompt="This will delete your Remy config and cached scan data. Continue?"
)
def config_reset() -> None:
    """Delete all Remy config and start fresh (runs wizard on next invocation)."""

    deleted = []
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        deleted.append(str(CONFIG_FILE))
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()
        deleted.append(str(CACHE_FILE))

    # Offer to remove keyring entries
    try:
        import questionary

        if questionary.confirm(
            "Also remove stored API keys from the OS keyring?", default=False
        ).ask():
            import keyring

            for provider in [
                "openrouter",
                "groq",
                "openai",
                "anthropic",
                "xai",
                "nvidia_nim",
                "ollama",
            ]:
                try:
                    keyring.delete_password("remy-agent", f"{provider}_api_key")
                except Exception:
                    pass
            deleted.append("keyring entries")
    except Exception:
        pass

    if deleted:
        console.print(
            Panel(
                "[bold green]✅ Reset complete.[/]\n\nRemoved:\n"
                + "\n".join(f"  • {d}" for d in deleted)
                + "\n\nRun [bold color(220)]remy[/] to set up again.",
                border_style="green",
                title="[bold]Config Reset[/]",
            )
        )
    else:
        console.print("[dim]Nothing to delete — Remy was not configured.[/dim]")


# ── providers ─────────────────────────────────────────────────────────────────


@main.group()
def providers() -> None:
    """List and inspect supported LLM providers."""
    pass


@providers.command(name="list")
def providers_list() -> None:
    """List all supported providers with required keys and notes."""
    from remy.ui.tables import render_providers_table

    render_providers_table(console)


# ── version ───────────────────────────────────────────────────────────────────


@main.command()
def version() -> None:
    """Show version and attribution."""
    console.print(
        Panel(
            Text.assemble(
                ("Remy Agent  ", "bold color(220)"),
                (f"v{__version__}\n", "bold white"),
                ("Built by Medusa Security  ·  ", "dim"),
                ("github.com/Medusa-Security", "underline color(220)"),
                ("\nMaintained by Abhay Gupta  ·  ", "dim"),
                ("github.com/abhay-1310", "underline color(220)"),
            ),
            border_style="color(220)",
            padding=(1, 4),
        )
    )


if __name__ == "__main__":
    main()
