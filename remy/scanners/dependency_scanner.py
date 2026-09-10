"""
Dependency Vulnerability Scanner

Parses dependency manifest files (requirements.txt, pyproject.toml,
package.json, go.mod, Pipfile) and queries the OSV database API for
known CVEs in the discovered packages.
"""

import asyncio
import re
import json
from pathlib import Path
from typing import Optional
import httpx
from remy.report.models import Finding, Severity
from remy.utils.hashing import fingerprint_finding
from .base import Scanner

OSV_API_URL = "https://api.osv.dev/v1/query"
MAX_CONCURRENT_REQUESTS = 10


def _classify_severity(cvss_score: Optional[float]) -> Severity:
    """Map a CVSS numeric score to a Remy Severity level."""
    if cvss_score is None:
        return Severity.HIGH
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    if cvss_score >= 7.0:
        return Severity.HIGH
    if cvss_score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _parse_requirements_txt(content: str) -> list[tuple[str, str, int]]:
    """Parse requirements.txt into (package, version, line_no) tuples."""
    deps: list[tuple[str, str, int]] = []
    for line_no, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", "-r", "--")):
            continue
        # Handle name==version, name>=version, name~=version etc.
        m = re.match(
            r"^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([^\s;#,]+)", line
        )
        if m:
            deps.append((m.group(1), m.group(2).strip(), line_no))
    return deps


def _parse_package_json(content: str) -> list[tuple[str, str, int]]:
    """Parse package.json dependencies into (package, version, line_no) tuples."""
    deps: list[tuple[str, str, int]] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    lines = content.splitlines()
    for section in ("dependencies", "devDependencies"):
        for pkg, ver in data.get(section, {}).items():
            ver_clean = re.sub(r"[\^~>=<]", "", str(ver)).strip()
            # Find approximate line number
            line_no = next(
                (i + 1 for i, line in enumerate(lines) if f'"{pkg}"' in line),
                1,
            )
            deps.append((pkg, ver_clean, line_no))
    return deps


def _parse_go_mod(content: str) -> list[tuple[str, str, int]]:
    """Parse go.mod require blocks into (package, version, line_no) tuples."""
    deps: list[tuple[str, str, int]] = []
    for line_no, line in enumerate(content.splitlines(), 1):
        m = re.match(r"\s+([A-Za-z0-9_\-\./]+)\s+v([^\s/]+)", line)
        if m:
            deps.append((m.group(1), m.group(2), line_no))
    return deps


def _parse_pipfile(content: str) -> list[tuple[str, str, int]]:
    """Parse Pipfile [packages] into (package, version, line_no) tuples."""
    deps: list[tuple[str, str, int]] = []
    in_packages = False
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped in ("[packages]", "[dev-packages]"):
            in_packages = True
            continue
        if stripped.startswith("[") and in_packages:
            in_packages = False
        if not in_packages:
            continue
        m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\']?([^"\']+)["\']?', stripped)
        if m:
            ver = re.sub(r"[^0-9\.]", "", m.group(2)) or "*"
            deps.append((m.group(1), ver, line_no))
    return deps


def _parse_pyproject_toml(content: str) -> list[tuple[str, str, int]]:
    """Parse pyproject.toml [project].dependencies into tuples."""
    deps: list[tuple[str, str, int]] = []
    in_deps = False
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped == "dependencies = [":
            in_deps = True
            continue
        if in_deps and stripped.startswith("]"):
            in_deps = False
        if not in_deps:
            continue
        # Match "package>=version" style inside the list
        m = re.match(
            r"""['"]\s*([A-Za-z0-9_\-\.]+)\s*(?:[>=<~!]+)\s*([^'"]+)""", stripped
        )
        if m:
            deps.append((m.group(1), m.group(2).strip(), line_no))
    return deps


def _parse_package_lock_json(content: str) -> list[tuple[str, str, int]]:
    """Parse package-lock.json packages/dependencies into (package, version, line_no) tuples."""
    deps: list[tuple[str, str, int]] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    lines = content.splitlines()
    packages = data.get("packages", {})
    if not packages:
        packages = data.get("dependencies", {})
    for path_key, info in packages.items():
        if not isinstance(info, dict) or "version" not in info:
            continue
        pkg_name = path_key.split("node_modules/")[-1].strip()
        if not pkg_name:
            continue
        ver = str(info["version"]).strip()
        line_no = next(
            (
                i + 1
                for i, line in enumerate(lines)
                if f'"{pkg_name}"' in line or f'"node_modules/{pkg_name}"' in line
            ),
            1,
        )
        deps.append((pkg_name, ver, line_no))
    return deps


def _parse_poetry_lock(content: str) -> list[tuple[str, str, int]]:
    """Parse poetry.lock [[package]] blocks into (package, version, line_no) tuples."""
    deps: list[tuple[str, str, int]] = []
    current_pkg = None
    current_ver = None
    pkg_line = 1
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped == "[[package]]":
            if current_pkg and current_ver:
                deps.append((current_pkg, current_ver, pkg_line))
            current_pkg = None
            current_ver = None
            pkg_line = line_no
            continue
        m_name = re.match(r'^name\s*=\s*["\']([^"\']+)["\']', stripped)
        if m_name:
            current_pkg = m_name.group(1)
        m_ver = re.match(r'^version\s*=\s*["\']([^"\']+)["\']', stripped)
        if m_ver:
            current_ver = m_ver.group(1)
    if current_pkg and current_ver:
        deps.append((current_pkg, current_ver, pkg_line))
    return deps


def _parse_uv_lock(content: str) -> list[tuple[str, str, int]]:
    """Parse uv.lock [[package]] blocks into (package, version, line_no) tuples."""
    return _parse_poetry_lock(content)


def _parse_pipfile_lock(content: str) -> list[tuple[str, str, int]]:
    """Parse Pipfile.lock default/develop sections into (package, version, line_no) tuples."""
    deps: list[tuple[str, str, int]] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    lines = content.splitlines()
    for section in ("default", "develop"):
        for pkg, info in data.get(section, {}).items():
            if isinstance(info, dict) and "version" in info:
                ver = re.sub(r"[^0-9\.]", "", str(info["version"])) or "*"
                line_no = next(
                    (i + 1 for i, line in enumerate(lines) if f'"{pkg}"' in line), 1
                )
                deps.append((pkg, ver, line_no))
    return deps


def _parse_yarn_lock(content: str) -> list[tuple[str, str, int]]:
    """Parse yarn.lock into (package, version, line_no) tuples."""
    deps: list[tuple[str, str, int]] = []
    current_pkg = None
    pkg_line = 1
    for line_no, line in enumerate(content.splitlines(), 1):
        if line and not line.startswith((" ", "\t", "#")) and ":" in line:
            header = line.split(":", 1)[0].strip("\"'")
            parts = header.split(",")[0].strip().rsplit("@", 1)
            if len(parts) == 2 and parts[0]:
                current_pkg = parts[0]
                pkg_line = line_no
            else:
                current_pkg = None
        elif current_pkg and line.strip().startswith("version "):
            m = re.search(r'version\s+["\']?([^"\'\s]+)["\']?', line)
            if m:
                deps.append((current_pkg, m.group(1), pkg_line))
                current_pkg = None
    return deps


def _parse_go_sum(content: str) -> list[tuple[str, str, int]]:
    """Parse go.sum lines into (package, version, line_no) tuples."""
    deps: list[tuple[str, str, int]] = []
    seen = set()
    for line_no, line in enumerate(content.splitlines(), 1):
        m = re.match(r"^\s*([A-Za-z0-9_\-\./]+)\s+v([^\s/]+)", line)
        if m:
            pkg, ver = m.group(1), m.group(2)
            key = f"{pkg}@{ver}"
            if key not in seen:
                seen.add(key)
                deps.append((pkg, ver, line_no))
    return deps


OSV_BATCH_API_URL = "https://api.osv.dev/v1/querybatch"


async def _query_osv(
    session: httpx.AsyncClient,
    pkg_name: str,
    version: str,
    ecosystem: str,
    semaphore: asyncio.Semaphore,
) -> list[dict]:
    """Query the OSV database for a specific package version."""
    if not version or version in ("*", "latest"):
        return []
    async with semaphore:
        try:
            payload = {
                "package": {"name": pkg_name, "ecosystem": ecosystem},
                "version": version,
            }
            resp = await session.post(OSV_API_URL, json=payload, timeout=15.0)
            if resp.status_code == 200:
                return resp.json().get("vulns", [])
        except (httpx.RequestError, json.JSONDecodeError):
            pass
    return []


async def _query_osv_batch_chunk(
    session: httpx.AsyncClient,
    chunk: list[tuple[str, str, str]],
    semaphore: asyncio.Semaphore,
) -> list[list[dict]]:
    """Query the OSV querybatch endpoint for up to 1000 packages at once."""
    if not chunk:
        return []
    payload_queries = []
    for pkg, ver, eco in chunk:
        if not ver or ver in ("*", "latest"):
            payload_queries.append({"package": {"name": pkg, "ecosystem": eco}})
        else:
            payload_queries.append(
                {"package": {"name": pkg, "ecosystem": eco}, "version": ver}
            )

    async with semaphore:
        try:
            resp = await session.post(
                OSV_BATCH_API_URL, json={"queries": payload_queries}, timeout=30.0
            )
            if resp.status_code == 200:
                data = resp.json().get("results", [])
                results = []
                for idx, item in enumerate(data):
                    if idx < len(chunk):
                        pkg, ver, _ = chunk[idx]
                        if not ver or ver in ("*", "latest"):
                            results.append([])
                        else:
                            results.append(item.get("vulns", []))
                    else:
                        results.append([])
                while len(results) < len(chunk):
                    results.append([])
                return results
        except (httpx.RequestError, json.JSONDecodeError):
            pass

    return [[] for _ in chunk]


class DependencyScanner(Scanner):
    """Scans dependency manifests for known vulnerabilities via OSV."""

    name = "dependency"

    MANIFEST_PARSERS: dict[str, tuple] = {
        "requirements.txt": (_parse_requirements_txt, "PyPI"),
        "Pipfile": (_parse_pipfile, "PyPI"),
        "pyproject.toml": (_parse_pyproject_toml, "PyPI"),
        "package.json": (_parse_package_json, "npm"),
        "go.mod": (_parse_go_mod, "Go"),
        "package-lock.json": (_parse_package_lock_json, "npm"),
        "poetry.lock": (_parse_poetry_lock, "PyPI"),
        "uv.lock": (_parse_uv_lock, "PyPI"),
        "Pipfile.lock": (_parse_pipfile_lock, "PyPI"),
        "yarn.lock": (_parse_yarn_lock, "npm"),
        "go.sum": (_parse_go_sum, "Go"),
    }

    async def scan_file(
        self,
        path: Path,
        content: str,
        language: str | None,
    ) -> list[Finding]:
        """Scan a dependency manifest file for known vulnerabilities.

        Args:
            path: Path to the manifest file.
            content: File content.
            language: Ignored; detection is by filename.

        Returns:
            List of vulnerability findings.
        """
        filename = path.name
        if filename not in self.MANIFEST_PARSERS:
            return []

        parser_fn, ecosystem = self.MANIFEST_PARSERS[filename]
        deps = parser_fn(content)
        if not deps:
            return []

        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        _seen_vuln_keys: set[str] = set()

        async with httpx.AsyncClient() as client:
            chunk_size = 1000
            dep_tuples = [(pkg, ver, ecosystem) for pkg, ver, _ in deps]
            chunks = [
                dep_tuples[i : i + chunk_size]
                for i in range(0, len(dep_tuples), chunk_size)
            ]
            tasks = [
                _query_osv_batch_chunk(client, chunk, semaphore) for chunk in chunks
            ]
            chunk_results = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[list[dict]] = []
        for res in chunk_results:
            if isinstance(res, list):
                results.extend(res)
            else:
                results.extend([[]] * chunk_size)
        results = results[: len(deps)]
        while len(results) < len(deps):
            results.append([])

        {pkg: (ver, line_no) for pkg, ver, line_no in deps}

        for (pkg, ver, line_no), result in zip(deps, results):
            if not isinstance(result, list) or not result:
                continue

            for vuln in result:
                vuln_id = vuln.get("id", "UNKNOWN")
                aliases = vuln.get("aliases", [])
                summary = vuln.get("summary", "No description available.")
                vuln.get("details", "")

                # Extract CVSS score from severity
                cvss_score: Optional[float] = None
                for sev in vuln.get("severity", []):
                    score_str = sev.get("score", "")
                    m = re.search(r"(\d+\.\d+)", str(score_str))
                    if m:
                        cvss_score = float(m.group(1))
                        break

                # Extract fix version from affected ranges
                fix_version = "latest"
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for event in rng.get("events", []):
                            if "fixed" in event:
                                fix_version = event["fixed"]
                                break

                cve_ids = [a for a in aliases if a.startswith("CVE-")]
                # Also grab the primary ID if it's a CVE
                if vuln_id.startswith("CVE-") and vuln_id not in cve_ids:
                    cve_ids.insert(0, vuln_id)
                cve_str = ", ".join(cve_ids[:2]) if cve_ids else vuln_id
                severity = _classify_severity(cvss_score)

                # ── Deduplicate: same package+CVE, different OSV record IDs ──────
                # OSV may return PYSEC + GHSA + CVE records all describing the same
                # underlying issue. Deduplicate by registering ALL CVE IDs seen for
                # this package version, not just the first one.
                if not cve_ids:
                    canonical_keys = {f"{pkg}@{ver}::{vuln_id}"}
                else:
                    canonical_keys = {f"{pkg}@{ver}::{c}" for c in cve_ids}

                if canonical_keys & _seen_vuln_keys:
                    continue  # already reported this CVE for this package
                _seen_vuln_keys.update(canonical_keys)

                fid = fingerprint_finding(
                    str(path),
                    line_no,
                    f"{pkg}_{cve_ids[0] if cve_ids else vuln_id}",
                    self.name,
                )

                findings.append(
                    Finding(
                        id=fid,
                        scanner=self.name,
                        severity=severity,
                        cwe="CWE-1035",  # Using vulnerable components
                        file=str(path),
                        line_start=line_no,
                        line_end=line_no,
                        title=f"Vulnerable Dependency — {pkg} {ver} ({cve_str})",
                        description=(
                            f"`{pkg}` version `{ver}` has a known vulnerability: {summary}. "
                            f"IDs: {', '.join([vuln_id] + aliases[:3])}. "
                            f"CVSS Score: {cvss_score or 'N/A'}."
                        ),
                        remediation_hint=(
                            f"Upgrade `{pkg}` to version `{fix_version}` or later to patch this vulnerability. "
                            f"Run `pip install --upgrade {pkg}` (Python) or `npm update {pkg}` (Node.js)."
                        ),
                        confidence=0.95,
                        code_snippet=f"{pkg}=={ver}",
                    )
                )

        return findings
