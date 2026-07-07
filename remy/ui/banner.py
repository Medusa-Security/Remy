from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from remy import __version__


ASCII_ART = """\
██████╗ ███████╗███╗   ███╗██╗   ██╗
██╔══██╗██╔════╝████╗ ████║╚██╗ ██╔╝
██████╔╝█████╗  ██╔████╔██║ ╚████╔╝ 
██╔══██╗██╔══╝  ██║╚██╔╝██║  ╚██╔╝  
██║  ██║███████╗██║ ╚═╝ ██║   ██║   
╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝   ╚═╝   """


def print_banner(console: Console) -> None:
    """Print the Remy Agent banner with Medusa Security branding.

    Args:
        console: Rich Console instance to print to.
    """
    art = Text(ASCII_ART, style="bold color(220)")  # gold

    subtitle = Text(
        "\nAI-Powered Security & Bug Scanning Agent",
        style="bold color(102)",
        justify="center",
    )
    version_line = Text(
        f"  v{__version__}  ",
        style="dim color(220)",
        justify="center",
    )
    credit = Text(
        "\nBuilt by Medusa Security  ·  github.com/Medusa-Security",
        style="dim color(102)",
        justify="center",
    )

    content = Text.assemble(art, "\n", subtitle, "\n", version_line, credit)

    panel = Panel(
        Align.center(content),
        border_style="color(220)",   # gold border
        padding=(1, 4),
        expand=False,
    )
    console.print()
    console.print(Align.center(panel))
    console.print()
