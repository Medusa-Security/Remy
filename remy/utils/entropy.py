import math
import base64
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy (base 2) of a string.

    H(X) = -sum(p(x) * log2(p(x))) for each unique character x.
    A perfectly random string has high entropy; predictable strings have low entropy.
    Used to detect potential secrets and API keys in source code.

    Args:
        data: The string to evaluate.

    Returns:
        Float entropy value in bits (0.0 for empty string).
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def is_high_entropy(s: str, threshold: float = 4.5) -> bool:
    """Return True if the string's Shannon entropy exceeds the threshold.

    Args:
        s: String to evaluate.
        threshold: Entropy threshold above which the string is considered high-entropy.
                   Default 4.5 bits is tuned to catch most API keys while minimizing
                   false positives on English prose.

    Returns:
        True if entropy > threshold, False otherwise.
    """
    return shannon_entropy(s) > threshold


def is_high_entropy_b64(s: str, threshold: float = 4.0) -> bool:
    """Detect high-entropy base64-looking strings (common format for API keys/secrets).

    Checks if the string resembles base64 encoding AND has high entropy,
    which is a strong signal for encoded credentials or secrets.

    Args:
        s: String to evaluate.
        threshold: Entropy threshold for the base64 character set.

    Returns:
        True if the string looks like high-entropy base64, False otherwise.
    """
    B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    B64_URL_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")

    if len(s) < 16:
        return False

    # Check if it's composed of base64 characters
    if not all(c in B64_CHARS or c in B64_URL_CHARS for c in s):
        return False

    return is_high_entropy(s, threshold)
