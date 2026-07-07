"""
Config Wizard

Interactive, Rich-rendered step-by-step configuration setup.
Validates API keys with a live provider ping before saving.
Auto-detects Ollama if running locally.
"""

import asyncio
from typing import Optional

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .schema import Config, ScanDefaults
from .store import save_config, set_api_key, get_api_key, load_config


console = Console()

PROVIDER_NOTES = {
    "openrouter":  "Routes requests to 200+ models. Great for flexibility.",
    "groq":        "Ultra-low latency inference. Best for fast scanning.",
    "openai":      "GPT-4o and newer models from OpenAI.",
    "anthropic":   "Claude family — excellent at code reasoning.",
    "xai":         "xAI Grok model family. OpenAI-compatible endpoint.",
    "nvidia_nim":  "NVIDIA NIM cloud or self-hosted inference.",
    "ollama":      "Fully local, no API key required. Run `ollama serve` first.",
}


def _check_ollama_running() -> bool:
    """Return True if a local Ollama instance is detected."""
    try:
        from remy.providers.ollama import OllamaProvider
        return asyncio.run(OllamaProvider.detect_running())
    except Exception:
        return False


def _validate_api_key(provider: str, api_key: str, model: str, base_url: Optional[str] = None) -> bool:
    """Perform a live ping to validate the API key. Returns True if valid."""
    try:
        from remy.config.schema import Config, ScanDefaults
        from remy.providers.registry import get_provider
        import keyring

        # Temporarily set key in keyring for validation
        try:
            keyring.set_password("remy-agent-validate", f"{provider}_api_key", api_key)
        except Exception:
            pass

        # Build a minimal config to get a provider instance
        cfg = Config(provider=provider, model=model, base_url=base_url)

        # Monkey-patch get_api_key for this validation call
        from remy.config import store as _store
        _orig = _store.get_api_key

        def _temp_get(p: str) -> Optional[str]:
            if p == provider:
                return api_key
            return _orig(p)

        _store.get_api_key = _temp_get
        try:
            prov = get_provider(cfg)
            result = asyncio.run(prov.validate_credentials())
        finally:
            _store.get_api_key = _orig

        return result
    except Exception:
        return False


def _fetch_models(provider: str, api_key: str, model: str, base_url: Optional[str] = None) -> list:
    """Fetch available models from provider. Returns empty list on failure."""
    try:
        from remy.config.schema import Config
        from remy.providers.registry import get_provider
        from remy.config import store as _store

        cfg = Config(provider=provider, model=model, base_url=base_url)
        _orig = _store.get_api_key

        def _temp_get(p: str) -> Optional[str]:
            if p == provider:
                return api_key
            return _orig(p)

        _store.get_api_key = _temp_get
        try:
            prov = get_provider(cfg)
            models = asyncio.run(prov.list_models())
        finally:
            _store.get_api_key = _orig

        return models
    except Exception:
        return []


def _render_models_table(models: list) -> None:
    """Display a Rich table of available models."""
    table = Table(
        title="[bold color(220)]Available Models[/]",
        border_style="color(220)",
        header_style="bold color(220)",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Model ID", style="bold white")
    table.add_column("Context", justify="right", style="dim")
    table.add_column("Notes", style="dim")

    for i, m in enumerate(models[:30], 1):  # Cap display at 30
        ctx = f"{m.context_length:,}" if m.context_length else "—"
        notes = (m.notes or "")[:60]
        table.add_row(str(i), m.id, ctx, notes)

    if len(models) > 30:
        table.caption = f"[dim]...and {len(models) - 30} more. Type a model ID manually.[/dim]"

    console.print(table)


def run_wizard() -> Optional[Config]:
    """Run the full interactive configuration wizard.

    Returns:
        The saved Config, or None if the user cancelled.
    """
    console.print(
        Panel(
            Text.assemble(
                ("Remy Configuration Wizard\n\n", "bold color(220)"),
                ("Let's connect Remy to an LLM provider.\n", "white"),
                ("Your API key is stored securely via the OS keyring.\n", "dim"),
                ("It is never written to disk in plaintext.", "dim"),
            ),
            border_style="color(220)",
            title="[bold color(220)]🔧 Setup[/]",
            padding=(1, 4),
        )
    )

    # ── Step 1: Provider selection ────────────────────────────────────────────
    ollama_running = _check_ollama_running()

    provider_choices = []
    for p, note in PROVIDER_NOTES.items():
        suffix = " [green](detected locally)[/]" if (p == "ollama" and ollama_running) else ""
        provider_choices.append(
            questionary.Choice(title=f"{p:<14} — {note}" + (
                " ✅ (running locally)" if (p == "ollama" and ollama_running) else ""
            ), value=p)
        )

    if ollama_running:
        console.print(
            Panel(
                "[bold green]🟢 Ollama detected running locally![/] "
                "You can use it without an API key.",
                border_style="green",
                padding=(0, 2),
            )
        )

    provider = questionary.select(
        "Step 1/5 — Select your LLM provider:",
        choices=provider_choices,
    ).ask()

    if provider is None:
        console.print("[yellow]Setup cancelled.[/]")
        return None

    # ── Step 2: API key ───────────────────────────────────────────────────────
    api_key: Optional[str] = None
    base_url: Optional[str] = None

    if provider == "ollama":
        console.print("\n[dim]Ollama does not require an API key.[/dim]")
        ollama_url = questionary.text(
            "Step 2/5 — Ollama base URL:",
            default="http://localhost:11434",
        ).ask()
        if ollama_url is None:
            console.print("[yellow]Setup cancelled.[/]")
            return None
        base_url = ollama_url.strip() or "http://localhost:11434"
    else:
        console.print()
        api_key = questionary.password(
            f"Step 2/5 — Enter your {provider} API key:",
        ).ask()

        if not api_key:
            console.print("[yellow]Setup cancelled.[/]")
            return None
        api_key = api_key.strip()

        # Optional base URL override (for NVIDIA NIM self-hosted, etc.)
        if provider in ("nvidia_nim", "openai", "openrouter"):
            custom_url = questionary.text(
                "  Custom base URL? (Leave blank to use the default):",
                default="",
            ).ask()
            if custom_url and custom_url.strip():
                base_url = custom_url.strip()

    # ── Step 3: Model selection ───────────────────────────────────────────────
    console.print()
    default_models = {
        "openrouter":  "openai/gpt-4o",
        "groq":        "llama-3.3-70b-versatile",
        "openai":      "gpt-4o",
        "anthropic":   "claude-sonnet-4-5",
        "xai":         "grok-3-mini",
        "nvidia_nim":  "nvidia/llama-3.1-nemotron-70b-instruct",
        "ollama":      "llama3.2",
    }
    default_model = default_models.get(provider, "")

    console.print(f"[dim]Fetching available models from {provider}...[/dim]")
    models = _fetch_models(provider, api_key or "", default_model, base_url)

    if models:
        _render_models_table(models)
        model_ids = [m.id for m in models]
        model = questionary.autocomplete(
            "Step 3/5 — Select or type a model ID:",
            choices=model_ids,
            default=default_model if default_model in model_ids else (model_ids[0] if model_ids else default_model),
            validate=lambda x: bool(x.strip()) or "Model ID cannot be empty",
        ).ask()
    else:
        console.print("[yellow]  Could not fetch model list. Enter a model ID manually.[/yellow]")
        model = questionary.text(
            "Step 3/5 — Model ID:",
            default=default_model,
            validate=lambda x: bool(x.strip()) or "Model ID cannot be empty",
        ).ask()

    if not model:
        console.print("[yellow]Setup cancelled.[/]")
        return None
    model = model.strip()

    # ── Step 4: Validate credentials (live ping) ──────────────────────────────
    if provider != "ollama" and api_key:
        console.print(f"\n[dim]Validating API key with {provider}...[/dim]")
        valid = _validate_api_key(provider, api_key, model, base_url)
        if valid:
            console.print("[bold green]  ✅ API key validated successfully![/]")
        else:
            console.print("[bold yellow]  ⚠  Could not validate the API key.[/]")
            proceed = questionary.confirm(
                "  The key may still be correct (network issues can cause false failures). Save anyway?",
                default=True,
            ).ask()
            if not proceed:
                console.print("[yellow]Setup cancelled.[/]")
                return None

    # ── Step 5: Scan defaults ─────────────────────────────────────────────────
    console.print()
    deep = questionary.confirm(
        "Step 4/5 — Enable deep scanning (LLM logic-bug pass) by default?",
        default=False,
    ).ask()

    max_size_str = questionary.text(
        "Step 5/5 — Max file size to scan (KB):",
        default="1000",
        validate=lambda x: x.isdigit() and int(x) > 0 or "Must be a positive integer",
    ).ask()
    max_file_size_kb = int(max_size_str) if max_size_str and max_size_str.isdigit() else 1000

    respect_gitignore = questionary.confirm(
        "  Auto-respect .gitignore and .remyignore?",
        default=True,
    ).ask()

    # ── Step 6: Confirmation summary ──────────────────────────────────────────
    console.print()
    redacted_key = "N/A (local)"
    if api_key and len(api_key) > 8:
        redacted_key = api_key[:4] + "•" * (len(api_key) - 8) + api_key[-4:]
    elif api_key:
        redacted_key = "•" * len(api_key)

    summary_table = Table(
        title="[bold color(220)]Configuration Summary[/]",
        border_style="color(220)",
        header_style="bold color(220)",
        show_lines=True,
        expand=False,
    )
    summary_table.add_column("Setting", style="bold color(102)")
    summary_table.add_column("Value", style="white")
    summary_table.add_row("Provider",         provider)
    summary_table.add_row("Model",            model)
    summary_table.add_row("API Key",          redacted_key)
    summary_table.add_row("Base URL",         base_url or "(default)")
    summary_table.add_row("Deep Scan",        str(deep))
    summary_table.add_row("Max File Size",    f"{max_file_size_kb} KB")
    summary_table.add_row("Respect .gitignore", str(respect_gitignore))
    console.print(summary_table)

    confirm = questionary.confirm(
        "Save this configuration?",
        default=True,
    ).ask()

    if not confirm:
        console.print("[yellow]Setup cancelled.[/]")
        return None

    # ── Save ──────────────────────────────────────────────────────────────────
    config = Config(
        provider=provider,
        model=model,
        base_url=base_url,
        scan_defaults=ScanDefaults(
            deep=deep or False,
            max_file_size_kb=max_file_size_kb,
            respect_gitignore=respect_gitignore if respect_gitignore is not None else True,
        ),
    )

    if api_key:
        set_api_key(provider, api_key)
    save_config(config)

    console.print(
        Panel(
            Text.assemble(
                ("✅ Remy is configured!\n\n", "bold green"),
                ("Run ", "white"),
                ("remy scan", "bold color(220)"),
                (" to start scanning.\n\n", "white"),
                ("💡 Tips:\n", "bold"),
                ("  • ", "dim"), ("remy providers list", "color(220)"), (" — view all providers\n", "dim"),
                ("  • ", "dim"), ("remy config show", "color(220)"),    (" — view current config\n", "dim"),
                ("  • ", "dim"), ("remy scan --deep", "color(220)"),    (" — enable LLM logic analysis\n", "dim"),
                ("  • ", "dim"), ("remy --help", "color(220)"),         (" — full command reference", "dim"),
            ),
            border_style="green",
            title="[bold green]Setup Complete[/]",
            padding=(1, 4),
        )
    )

    return config


def run_provider_step() -> None:
    """Run only the provider + model + key steps (used by `remy config set-provider`)."""
    current = load_config()

    console.print(
        Panel(
            "[bold color(220)]Change Provider / Model[/]\n\n"
            "Updates your provider and model. Other settings are preserved.",
            border_style="color(220)",
            padding=(1, 2),
        )
    )

    provider_choices = list(PROVIDER_NOTES.keys())
    provider = questionary.select(
        "Select provider:",
        choices=provider_choices,
        default=current.provider if current else "openrouter",
    ).ask()

    if not provider:
        return

    api_key: Optional[str] = None
    base_url: Optional[str] = None

    if provider != "ollama":
        existing_key = get_api_key(provider)
        mask = ""
        if existing_key and len(existing_key) > 8:
            mask = f" (current: {existing_key[:4]}...{existing_key[-4:]})"
        api_key = questionary.password(
            f"API key for {provider}{mask} (leave blank to keep current):",
        ).ask()
        if api_key == "":
            api_key = existing_key  # keep existing
    else:
        url = questionary.text("Ollama base URL:", default="http://localhost:11434").ask()
        base_url = url.strip() if url else None

    default_models = {
        "openrouter":  "openai/gpt-4o",
        "groq":        "llama-3.3-70b-versatile",
        "openai":      "gpt-4o",
        "anthropic":   "claude-sonnet-4-5",
        "xai":         "grok-3-mini",
        "nvidia_nim":  "nvidia/llama-3.1-nemotron-70b-instruct",
        "ollama":      "llama3.2",
    }
    current_model = current.model if current and current.provider == provider else default_models.get(provider, "")

    model = questionary.text(
        "Model ID:",
        default=current_model,
        validate=lambda x: bool(x.strip()) or "Model ID cannot be empty",
    ).ask()

    if not model:
        return

    # Preserve existing scan_defaults
    scan_defaults = current.scan_defaults if current else ScanDefaults()

    config = Config(
        provider=provider,
        model=model.strip(),
        base_url=base_url,
        scan_defaults=scan_defaults,
    )

    if api_key:
        set_api_key(provider, api_key)
    save_config(config)

    console.print("[bold green]✅ Provider updated![/]")
