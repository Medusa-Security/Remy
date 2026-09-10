"""PR-diff scope: which files actually need to be scanned for a change.

Given a base ref, we collect changed files via git, then expand that set to
include every file that *transitively depends on* a changed file (using the
module dependency graph). The result is the true test/scan surface of a PR —
not just the files someone touched.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from remy.knowledge.dependencies import DependencyGraph


def changed_files(repo_root: str | Path, base: str = "main") -> set[str]:
    """Return changed file paths (relative to repo root) vs ``base``.

    Tries diff against ``base...HEAD``, then ``base``, then falls back to the
    last commit. Returns an empty set if git is unavailable.
    """
    root = str(repo_root)
    candidates = [f"{base}...HEAD", base, "HEAD~1", "--staged"]
    seen: set[str] = set()
    for spec in candidates:
        files = _git_diff_names(root, spec)
        if files:
            for f in files:
                p = Path(root) / f
                if p.exists():
                    seen.add(str(p.resolve()))
            break
    return seen


def _git_diff_names(root: str, spec: str) -> list[str]:
    if spec == "--staged":
        cmd = ["git", "diff", "--staged", "--name-only"]
    else:
        cmd = ["git", "diff", "--name-only", spec]
    try:
        out = subprocess.run(
            cmd, cwd=root, capture_output=True, text=True, timeout=30
        )
    except (subprocess.SubprocessError, OSError):
        return []
    if out.returncode != 0:
        return []
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def pr_scope(changed: set[str], dep_graph: DependencyGraph) -> set[str]:
    """changed files expanded with their transitive dependents."""
    scope = set(changed)
    for f in changed:
        scope.update(dep_graph.dependents(f))
    return scope
