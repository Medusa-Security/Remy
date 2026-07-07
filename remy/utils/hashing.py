import hashlib


def fingerprint_finding(file: str, line_start: int, title: str, scanner: str) -> str:
    """Return a stable 12-character hex fingerprint for finding deduplication.

    The fingerprint is based on the combination of file path, line number, title,
    and scanner name — enough to uniquely identify a finding location without
    being sensitive to minor description wording changes.

    Args:
        file: File path of the finding.
        line_start: Starting line number of the finding.
        title: Short title/rule name of the finding.
        scanner: Name of the scanner that produced the finding.

    Returns:
        A 12-character lowercase hex string.
    """
    raw = f"{file}:{line_start}:{title}:{scanner}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def hash_content(content: str) -> str:
    """Return the full SHA256 hex digest of any string content.

    Args:
        content: String content to hash.

    Returns:
        Full 64-character SHA256 hex digest.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
