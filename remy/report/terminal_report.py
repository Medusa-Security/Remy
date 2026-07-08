"""
Terminal Reporter

Renders the full scan report in the terminal using Rich:
- Color-coded severity summary table
- File-grouped findings tree with code snippets
- Attribution footer
"""

from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich.syntax import Syntax
from rich.rule import Rule
from rich.padding import Padding
from .models import ScanReport, Severity


LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".sh": "bash",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
}


def _detect_lang(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return LANG_MAP.get(ext, "text")


class TerminalReporter:
    """Renders ScanReport output to the terminal using Rich components."""

    def __init__(
        self, console: Console | None = None, target_path: str | None = None
    ) -> None:
        self.console = console or Console()
        self._target = Path(target_path).resolve() if target_path else None

    def _rel(self, file_path: str) -> str:
        """Return a path relative to the scan target for compact display."""
        try:
            if self._target:
                rel = Path(file_path).resolve().relative_to(self._target)
                return str(rel).replace("\\", "/")
        except ValueError:
            pass
        return file_path.replace("\\", "/")

    def render(self, report: ScanReport) -> None:
        """Render the complete scan report to the terminal.

        Args:
            report: The ScanReport produced by the orchestrator.
        """
        self.console.print()
        self._render_summary(report)
        self.console.print()
        self._render_findings_tree(report)
        self._render_footer()

    def _render_summary(self, report: ScanReport) -> None:
        """Render the top-level severity count table inside a panel."""
        table = Table(
            show_header=True,
            header_style="bold color(220)",
            border_style="color(220)",
            expand=False,
            show_lines=False,
        )
        table.add_column("Severity", style="bold", no_wrap=True, width=14)
        table.add_column("Count", justify="right", width=8)
        table.add_column("Indicator", justify="left", width=22)

        severity_data = [
            (Severity.CRITICAL, report.critical_count),
            (Severity.HIGH, report.high_count),
            (Severity.MEDIUM, report.medium_count),
            (Severity.LOW, report.low_count),
            (Severity.INFO, report.info_count),
        ]
        max_count = max((c for _, c in severity_data), default=1) or 1
        bar_width = 16

        for sev, count in severity_data:
            filled = int((count / max_count) * bar_width)
            bar_str = "█" * filled + "░" * (bar_width - filled)
            label = Text(f"{sev.icon}  {sev.value}", style=sev.color)
            count_text = Text(str(count), style=sev.color)
            bar_text = Text(bar_str, style=sev.color)
            table.add_row(label, count_text, bar_text)

        meta = (
            f"  📁 [bold]{report.files_scanned}[/bold] files scanned  ·  "
            f"⏱ [bold]{report.duration_seconds:.2f}s[/bold]  ·  "
            f"🔍 Scanners: [dim]{', '.join(report.scanners_used)}[/dim]"
        )
        panel = Panel(
            table,
            title=f"[bold color(220)]Remy Scan Report — {report.total_count} Finding(s)[/]",
            subtitle=meta,
            border_style="color(220)",
            padding=(1, 2),
        )
        self.console.print(panel)

    def _render_findings_tree(self, report: ScanReport) -> None:
        """Render findings grouped by file as a Rich Tree."""
        if not report.findings:
            self.console.print(
                Panel(
                    "[bold green]✅ No findings detected! Your codebase looks clean.[/]",
                    border_style="green",
                    padding=(1, 4),
                )
            )
            return

        grouped = report.findings_by_file()

        for file_path, findings in sorted(grouped.items()):
            rel = self._rel(file_path)
            tree = Tree(
                f"[bold color(220)]📄 {rel}[/]",
                guide_style="color(102)",
            )
            for finding in findings:
                sev_text = Text(
                    f"{finding.severity.icon} [{finding.severity.value}]",
                    style=finding.severity.color,
                )
                title_text = Text(f" {finding.title}", style="bold white")
                line_text = Text(
                    f"  (line {finding.line_start}–{finding.line_end})",
                    style="dim",
                )
                label = Text.assemble(sev_text, title_text, line_text)
                node = tree.add(label)

                # Description sub-node
                node.add(Text(f"ℹ  {finding.description}", style="dim white"))

                # Code snippet
                if finding.code_snippet:
                    lang = _detect_lang(finding.file)
                    syntax = Syntax(
                        finding.code_snippet.strip(),
                        lang,
                        theme="monokai",
                        line_numbers=False,
                        background_color="default",
                    )
                    node.add(syntax)

                # Remediation
                hint = finding.remediation_hint
                if hint:
                    node.add(Text(f"🔧 {hint}", style="color(220) dim"))

            self.console.print(tree)
            self.console.print()

    def _render_footer(self) -> None:
        """Render the Medusa Security attribution footer."""
        self.console.print(
            Rule(style="color(102)"),
        )
        self.console.print(
            Padding(
                Text(
                    "Powered by Remy  ·  Built by Medusa Security  ·  github.com/Medusa-Security",
                    style="dim color(102)",
                    justify="center",
                ),
                (0, 2),
            )
        )
        self.console.print()
