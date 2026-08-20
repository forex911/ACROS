"""
Parser Utilities — Common Parsing Functions for the Backend

Provides utility functions for parsing file metadata, command lines,
structured data, and path normalization used across backend services.
"""

import os
import re
import json
import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("parser_utils")


def safe_json_loads(raw: str, default: Any = None) -> Any:
    """
    Safely parse a JSON string, returning a default value on failure.

    Args:
        raw: JSON string to parse.
        default: Value to return on parse failure (default: None).

    Returns:
        Parsed JSON object, or default if parsing fails.
    """
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return default


def parse_command_line(cmdline: str) -> Dict[str, Any]:
    """
    Parse a command line string into structured components.

    Returns:
        Dict with keys: executable, args, flags, full_command
    """
    if not cmdline or not isinstance(cmdline, str):
        return {"executable": "", "args": [], "flags": [], "full_command": ""}

    parts = cmdline.strip().split()
    if not parts:
        return {"executable": "", "args": [], "flags": [], "full_command": cmdline}

    executable = parts[0]
    args = []
    flags = []

    for part in parts[1:]:
        if part.startswith("-"):
            flags.append(part)
        else:
            args.append(part)

    return {
        "executable": executable,
        "args": args,
        "flags": flags,
        "full_command": cmdline.strip(),
    }


def extract_file_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract basic metadata from a file (size, extension, permissions).
    Does NOT read the file content — for fast metadata-only extraction.

    Returns:
        Dict with keys: path, filename, extension, size, exists, is_executable
    """
    result = {
        "path": normalize_path(file_path),
        "filename": os.path.basename(file_path),
        "extension": os.path.splitext(file_path)[1].lower(),
        "size": 0,
        "exists": False,
        "is_executable": False,
    }

    try:
        if os.path.exists(file_path):
            stat = os.stat(file_path)
            result["exists"] = True
            result["size"] = stat.st_size
            result["is_executable"] = os.access(file_path, os.X_OK)
    except (OSError, PermissionError) as e:
        logger.debug("Could not stat file %s: %s", file_path, e)

    return result


def normalize_path(path: str) -> str:
    """
    Normalize a file path: resolve symlinks, normalize separators,
    and convert to a consistent forward-slash format for cross-platform use.

    Args:
        path: File path to normalize.

    Returns:
        Normalized path string with forward slashes.
    """
    if not path:
        return ""
    try:
        normalized = os.path.normpath(path)
        # Convert backslashes to forward slashes for consistency
        return normalized.replace("\\", "/")
    except (ValueError, TypeError):
        return path


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Compute a hash digest of a file.

    Args:
        file_path: Path to the file.
        algorithm: Hash algorithm (md5, sha1, sha256).

    Returns:
        Hex digest string, or empty string on failure.
    """
    try:
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, OSError, ValueError) as e:
        logger.warning("Failed to compute %s hash for %s: %s", algorithm, file_path, e)
        return ""


def truncate_string(s: str, max_length: int = 200, suffix: str = "...") -> str:
    """Truncate a string to max_length, appending suffix if truncated."""
    if not s or len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix


def extract_ips_from_text(text: str) -> List[str]:
    """Extract valid IPv4 addresses from a text blob."""
    pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    matches = re.findall(pattern, text)
    # Filter out common non-routable addresses
    return [
        ip for ip in set(matches)
        if not ip.startswith("127.")
        and not ip.startswith("0.")
        and not ip.startswith("169.254.")
    ]


def extract_urls_from_text(text: str) -> List[str]:
    """Extract HTTP/HTTPS URLs from a text blob."""
    pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    return list(set(re.findall(pattern, text)))


def safe_decode(data: bytes, encodings: Optional[List[str]] = None) -> str:
    """
    Try multiple encodings to decode bytes into a string.
    Falls back to 'replace' error handling on the last encoding.
    """
    encodings = encodings or ["utf-8", "ascii", "latin-1"]

    for i, encoding in enumerate(encodings):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, AttributeError):
            if i == len(encodings) - 1:
                return data.decode("utf-8", errors="replace")
    return ""


def flatten_dict(d: Dict, parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    """
    Flatten a nested dictionary into a single-level dict with dotted keys.

    Example:
        {"a": {"b": 1, "c": {"d": 2}}} → {"a.b": 1, "a.c.d": 2}
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)
