from pathlib import Path
from typing import Iterator
import fnmatch

SKIP_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "ENV",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "htmlcov",
    ".tox",
    "eggs",
    ".eggs",
    ".remy",  # never scan remy's own output directory
}

EXT_TO_LANG: dict[str, str] = {
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
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".kt": "kotlin",
    ".swift": "swift",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".tf": "hcl",
}

BINARY_SIGNATURES = [
    b"\x89PNG",  # PNG image
    b"GIF8",  # GIF image
    b"\xff\xd8\xff",  # JPEG image
    b"PK\x03\x04",  # ZIP / JAR / DOCX etc
    b"\x7fELF",  # ELF binary
    b"MZ",  # Windows PE executable
    b"\xca\xfe\xba\xbe",  # Mach-O fat binary
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
]


class FileWalker:
    """Walks a directory tree, yielding scannable source files.

    Respects .gitignore and .remyignore patterns. Skips binary files,
    hidden directories, common build/dependency directories, and files
    that exceed the configured size limit.
    """

    def __init__(
        self,
        root: str,
        respect_gitignore: bool = True,
        max_file_size_kb: int = 1000,
    ):
        self.root = Path(root).resolve()
        self.respect_gitignore = respect_gitignore
        self.max_file_size_bytes = max_file_size_kb * 1024
        self._ignore_patterns: list[str] = []
        if respect_gitignore:
            self._ignore_patterns = self._load_ignore_patterns()

    def _load_ignore_patterns(self) -> list[str]:
        """Load patterns from .gitignore and .remyignore files in the root."""
        patterns: list[str] = []
        for ignore_file in [".gitignore", ".remyignore"]:
            ignore_path = self.root / ignore_file
            if ignore_path.exists():
                try:
                    with open(ignore_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                patterns.append(line)
                except OSError:
                    pass
        return patterns

    def _is_ignored(self, path: Path) -> bool:
        """Check if a path matches any loaded ignore pattern."""
        try:
            rel = path.relative_to(self.root)
        except ValueError:
            return False
        rel_str = str(rel).replace("\\", "/")
        for pattern in self._ignore_patterns:
            # Match against just filename, full relative path, and each parent dir
            if fnmatch.fnmatch(rel_str, pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True
            # directory-only pattern (ends with /)
            if pattern.endswith("/") and fnmatch.fnmatch(
                rel_str, pattern.rstrip("/") + "/*"
            ):
                return True
        return False

    def _is_binary(self, path: Path) -> bool:
        """Detect binary files by checking magic bytes and null bytes."""
        try:
            with open(path, "rb") as f:
                header = f.read(512)
            # Check known binary magic bytes
            for sig in BINARY_SIGNATURES:
                if header.startswith(sig):
                    return True
            # Heuristic: if >30% of first 512 bytes are null or non-printable, it's binary
            non_text = sum(
                1 for b in header if b == 0 or (b < 8 and b not in (9, 10, 13))
            )
            if len(header) > 0 and non_text / len(header) > 0.10:
                return True
            return False
        except OSError:
            return True

    def walk(self) -> Iterator[Path]:
        """Yield all scannable file paths under the root directory.

        Files are filtered by:
        - Not in a skipped directory
        - Not matching gitignore/remyignore patterns
        - Not binary
        - Not exceeding the max file size limit
        """
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue

            # Skip files inside blacklisted directories
            skip = False
            for part in path.parts:
                if part in SKIP_DIRS or part.endswith(".egg-info"):
                    skip = True
                    break
            if skip:
                continue

            # Skip hidden files/dirs (starting with .)
            if any(
                part.startswith(".") and part not in (".", "..")
                for part in path.relative_to(self.root).parts
            ):
                if path.suffix not in EXT_TO_LANG:
                    continue

            # Apply gitignore/remyignore patterns
            if self.respect_gitignore and self._is_ignored(path):
                continue

            # Skip oversized files
            try:
                if path.stat().st_size > self.max_file_size_bytes:
                    continue
            except OSError:
                continue

            # Skip binary files
            if self._is_binary(path):
                continue

            yield path

    @staticmethod
    def get_language(path: Path) -> str | None:
        """Map a file's extension to a language name.

        Args:
            path: File path to inspect.

        Returns:
            Language string (e.g. 'python') or None if unknown.
        """
        return EXT_TO_LANG.get(path.suffix.lower())
