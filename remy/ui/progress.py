from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)
from rich.console import Console
from types import TracebackType
from typing import Optional


class ScanProgress:
    """Wrapper around rich.progress.Progress for Remy scan display.

    Supports both synchronous and asynchronous context manager usage.
    Displays scanner name, progress bar, count, and elapsed time for each task.

    Usage:
        with ScanProgress() as progress:
            task = progress.add_task("Secrets Scanner", total=100)
            progress.update(task, advance=1)
            progress.complete(task)
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()
        self._progress = Progress(
            SpinnerColumn(style="color(220)"),           # gold spinner
            TextColumn("[bold color(220)]{task.description}[/]"),
            BarColumn(bar_width=30, style="color(17)", complete_style="color(220)"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )

    def start(self) -> None:
        """Start the progress display."""
        self._progress.start()

    def stop(self) -> None:
        """Stop and finalize the progress display."""
        self._progress.stop()

    def add_task(self, name: str, total: int = 100) -> int:
        """Add a new task to the progress display.

        Args:
            name: Human-readable name for this scanner/task.
            total: Total number of units of work.

        Returns:
            Task ID integer to be used with update() and complete().
        """
        return self._progress.add_task(name, total=total)

    def update(
        self,
        task_id: int,
        advance: int = 1,
        description: Optional[str] = None,
    ) -> None:
        """Update a task's progress.

        Args:
            task_id: Task ID returned by add_task().
            advance: Number of units to advance by.
            description: Optional new description string.
        """
        kwargs: dict = {"advance": advance}
        if description is not None:
            kwargs["description"] = description
        self._progress.update(task_id, **kwargs)

    def complete(self, task_id: int) -> None:
        """Mark a task as fully complete."""
        task = self._progress.tasks[task_id]
        self._progress.update(task_id, completed=task.total or 100)

    # --- Sync context manager ---

    def __enter__(self) -> "ScanProgress":
        self.start()
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.stop()

    # --- Async context manager ---

    async def __aenter__(self) -> "ScanProgress":
        self.start()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.stop()
