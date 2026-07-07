"""
Remy CLI — Click command router

Entry point for all `remy` commands. Handles first-run detection,
dispatches to the config wizard, and wires up all subcommands.
"""

import asyncio
import json
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
                    path=".", deep=cfg.scan_defaults.deep,
                    secrets_only=False, api_surface=False,
                    bypass_check=False, deps=False, fmt="text",
                    output=None, no_prompt=False,
                    min_severity="INFO", config=cfg,
                )
    else:
        # Default: quick scan of cwd
        cfg = _load_config_or_exit()
        _run_scan(
            path=".",
            deep=cfg.scan_defaults.deep,
            secrets_only=False, api_surface=False,
            bypass_check=False, deps=False, fmt="text",
            output=None, no_prompt=False,
            min_severity="INFO", config=cfg,
        )


# ── scan ──────────────────────────────────────────────────────────────────────

@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--deep", is_flag=True, help="Enable LLM logic-bug pass in addition to SAST")
@click.option("--secrets-only", is_flag=True, help="Hardcoded key / credential scan only")
@click.option("--api-surface", is_flag=True, help="Exposed route + rate-limit audit only")
@click.option("--bypass-check", is_flag=True, help="Auth/logic bypass detection only")
@click.option("--deps", is_flag=True, help="Dependency vulnerability scan only")
@click.option(
    "--format", "fmt",
    type=click.Choice(["text", "json"]),
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
    "--no-prompt", is_flag=True, default=False,
    help="Skip Fix Prompt generation (useful in CI)",
)
def scan(path, deep, secrets_only, api_surface, bypass_check, deps, fmt, output, min_severity, no_prompt):
    """Scan a path for bugs and vulnerabilities.

    PATH defaults to the current working directory.
    Exits with code 2 if Critical or High findings are present (CI gate).
    """
    cfg = _load_config_or_exit()
    use_deep = deep or cfg.scan_defaults.deep
    _run_scan(
        path=path, deep=use_deep, secrets_only=secrets_only,
        api_surface=api_surface, bypass_check=bypass_check,
        deps=deps, fmt=fmt, output=output, no_prompt=no_prompt,
        min_severity=min_severity, config=cfg,
    )


def _run_scan(path, deep, secrets_only, api_surface, bypass_check,
              deps, fmt, output, no_prompt, min_severity, config):
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

    # CI gate: exit 2 if critical or high findings present
    if report.critical_count > 0 or report.high_count > 0:
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
    local_prompt_1 = Path(path) / ".remy" / "fix_prompt_1.md"
    local_prompt_dir = Path(path) / ".remy"

    if local_prompt_dir.exists() and any(local_prompt_dir.glob("fix_prompt_*.md")):
        prompt_paths = sorted(
            str(p) for p in local_prompt_dir.glob("fix_prompt_*.md")
        )
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
            console.print("[yellow]pyperclip not installed. Run: pip install pyperclip[/]")
        except Exception as e:
            console.print(
                f"[yellow]Could not copy to clipboard: {e}[/]\n"
                "[dim]On Linux, install xclip or xsel. On Windows, check clipboard permissions.[/dim]"
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
    import shutil

    deleted = []
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        deleted.append(str(CONFIG_FILE))
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()
        deleted.append(str(CACHE_FILE))

    # Offer to remove keyring entries
    try:
        from remy.config.store import load_config
        import questionary
        if questionary.confirm(
            "Also remove stored API keys from the OS keyring?", default=False
        ).ask():
            import keyring
            for provider in ["openrouter", "groq", "openai", "anthropic", "xai", "nvidia_nim", "ollama"]:
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
