from rich.theme import Theme

# Medusa Security brand palette
NAVY = "#001F3F"
GOLD = "#FFD700"
STEEL = "#708090"
CRIMSON = "#DC143C"
EMERALD = "#2ECC71"

THEME = Theme(
    {
        "remy.banner": "bold color(220) on color(17)",
        "remy.title": "bold color(220)",
        "remy.subtitle": "color(102)",
        "remy.critical": "bold red",
        "remy.high": "red",
        "remy.medium": "yellow",
        "remy.low": "cyan",
        "remy.info": "dim white",
        "remy.success": "bold green",
        "remy.error": "bold red",
        "remy.footer": "dim color(102)",
        "remy.highlight": "bold color(220)",
        "remy.panel_border": "color(220)",
        "remy.link": "underline color(220)",
    }
)
