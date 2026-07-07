from rich.console import Console
from rich.table import Table
from rich.text import Text


def render_providers_table(console: Console) -> None:
    """Render a formatted table of all supported LLM providers."""
    table = Table(
        title="[bold color(220)]Supported LLM Providers[/]",
        border_style="color(220)",
        header_style="bold color(220)",
        show_lines=True,
    )
    table.add_column("Provider", style="bold white", no_wrap=True)
    table.add_column("Requires API Key", justify="center")
    table.add_column("Default Base URL", style="dim")
    table.add_column("Notes")

    providers = [
        ("OpenRouter",   "✅ Yes", "https://openrouter.ai/api/v1",          "Routes to many upstream models. Great for flexibility."),
        ("Groq",         "✅ Yes", "https://api.groq.com/openai/v1",         "Ultra-low latency. Best for fast bulk scanning."),
        ("OpenAI",       "✅ Yes", "https://api.openai.com/v1",              "Standard GPT-4o / GPT-4-turbo support."),
        ("Anthropic",    "✅ Yes", "https://api.anthropic.com",              "Claude family. Native Messages API."),
        ("xAI",          "✅ Yes", "https://api.x.ai/v1",                   "Grok model family. OpenAI-compatible."),
        ("NVIDIA NIM",   "✅ Yes", "https://integrate.api.nvidia.com/v1",   "Llama, Mistral, Phi on NVIDIA infra. Self-hosted override available."),
        ("Ollama",       "❌ No",  "http://localhost:11434",                 "Fully local. No API key needed. Run `ollama serve` first."),
    ]
    for name, key_req, base_url, notes in providers:
        table.add_row(name, key_req, base_url, notes)

    console.print(table)


def render_findings_summary_table(console: Console, report) -> None:
    """Render a color-coded severity count summary table.

    Args:
        console: Rich Console.
        report: ScanReport instance.
    """
    table = Table(
        title=f"[bold color(220)]Scan Summary — {report.total_count} total findings[/]",
        border_style="color(220)",
        header_style="bold color(220)",
        show_lines=False,
        expand=False,
    )
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Count", justify="right", style="bold")
    table.add_column("Bar", justify="left", no_wrap=True)

    severity_data = [
        ("🔴 CRITICAL", report.critical_count, "bold red"),
        ("🟠 HIGH",     report.high_count,     "red"),
        ("🟡 MEDIUM",   report.medium_count,   "yellow"),
        ("🔵 LOW",      report.low_count,       "cyan"),
        ("⚪ INFO",     report.info_count,      "dim white"),
    ]

    max_count = max((c for _, c, _ in severity_data), default=1) or 1
    bar_width = 20

    for label, count, style in severity_data:
        filled = int((count / max_count) * bar_width)
        bar = Text("█" * filled + "░" * (bar_width - filled), style=style)
        table.add_row(Text(label, style=style), Text(str(count), style=style), bar)

    console.print(table)


def render_config_table(console: Console, config, api_key: str | None) -> None:
    """Render the current configuration with the API key redacted.

    Args:
        console: Rich Console.
        config: Config pydantic model.
        api_key: Raw API key string (will be redacted for display).
    """
    table = Table(
        title="[bold color(220)]Current Configuration[/]",
        border_style="color(220)",
        header_style="bold color(220)",
        show_lines=True,
    )
    table.add_column("Setting", style="bold color(102)", no_wrap=True)
    table.add_column("Value", style="white")

    # Redact API key: show first 4 and last 4 chars
    if api_key and len(api_key) > 8:
        redacted = api_key[:4] + "•" * (len(api_key) - 8) + api_key[-4:]
    elif api_key:
        redacted = "•" * len(api_key)
    else:
        redacted = "[dim]Not set[/dim]"

    table.add_row("Provider", config.provider)
    table.add_row("Model", config.model)
    table.add_row("Base URL", config.base_url or "[dim](default)[/dim]")
    table.add_row("API Key", redacted)
    table.add_row("Deep Scan Default", str(config.scan_defaults.deep))
    table.add_row("Max File Size (KB)", str(config.scan_defaults.max_file_size_kb))
    table.add_row("Respect .gitignore", str(config.scan_defaults.respect_gitignore))

    console.print(table)
