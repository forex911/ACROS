"""
Universal Deobfuscation & Normalization Layer
=============================================
First-class analysis stage that recursively decodes obfuscated content
BEFORE IOC extraction, MITRE mapping, and capability detection.

Supports: Base64, Hex, URL-encoding, Unicode escapes, PowerShell -enc,
          Gzip, Zlib, XOR (single-byte brute), string concatenation,
          and arbitrary nesting of the above.
"""

import base64
import binascii
import gzip
import hashlib
import html
import io
import logging
import math
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("deobfuscation")

# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────
MAX_RECURSION_DEPTH = 5
MAX_DECODED_SIZE = 10 * 1024 * 1024  # 10 MB
MIN_INTERESTING_LENGTH = 8           # ignore tiny fragments

# ────────────────────────────────────────────────────────────────────────────
# Data classes
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class EncodingDetection:
    encoding_type: str
    confidence: float      # 0.0 – 1.0
    entropy: float         # Shannon entropy
    layer_depth: int
    matched_pattern: str   # what triggered the detection


@dataclass
class DecodeLayer:
    encoding_type: str
    input_preview: str     # first 120 chars of input
    output_preview: str    # first 120 chars of output
    confidence: float


@dataclass
class DeobfuscationResult:
    original: str
    decoded: str
    normalized: str
    layers: List[DecodeLayer] = field(default_factory=list)
    confidence: float = 0.0
    was_obfuscated: bool = False
    recovered_iocs: List[Dict] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════════
# Phase 1 — Encoding Detection
# ════════════════════════════════════════════════════════════════════════════

class EncodingDetector:
    """Detect which encoding(s) are present in a string."""

    # PowerShell -EncodedCommand: the flag + base64 blob
    _PS_ENC = re.compile(
        r'(?:powershell|pwsh)(?:\.exe)?\s+.*?'
        r'-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|'
        r'encodedcomm|encodedcomma|encodedcomman|encodedcommand)\s+'
        r'([A-Za-z0-9+/=]{8,})',
        re.IGNORECASE
    )

    # Standalone base64 blob  (min 20 chars, valid chars only)
    _B64_BLOB = re.compile(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])')

    # Hex-encoded string  (must be even length, ≥16 hex chars)
    _HEX_BLOB = re.compile(r'(?<![0-9a-fA-F])([0-9a-fA-F]{16,})(?![0-9a-fA-F])')

    # URL-encoded sequences  (%XX appearing 3+ times)
    _URL_ENC = re.compile(r'(?:%[0-9a-fA-F]{2}){3,}')

    # Unicode escape sequences  (\uXXXX or \xXX)
    _UNICODE_ESC = re.compile(r'(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){3,}')

    # Python / JS eval+decode wrappers
    _EVAL_B64 = re.compile(
        r'(?:eval|exec)\s*\(\s*(?:base64\.b64decode|atob|Buffer\.from)\s*\(',
        re.IGNORECASE
    )

    # String concatenation obfuscation  ("c"+"m"+"d")
    _CONCAT = re.compile(r'(?:"[^"]{1,4}"\s*\+\s*){3,}')

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not data:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    @classmethod
    def detect(cls, content: str, depth: int = 0) -> List[EncodingDetection]:
        """Return all encoding detections found in *content*."""
        if not content or len(content) < MIN_INTERESTING_LENGTH:
            return []

        detections: List[EncodingDetection] = []
        entropy = cls.shannon_entropy(content)

        # PowerShell encoded command  (highest-priority pattern)
        m = cls._PS_ENC.search(content)
        if m:
            detections.append(EncodingDetection(
                encoding_type="powershell_enc",
                confidence=0.98,
                entropy=entropy,
                layer_depth=depth,
                matched_pattern=m.group(0)[:120]
            ))

        # eval(base64.b64decode(...))
        if cls._EVAL_B64.search(content):
            detections.append(EncodingDetection(
                encoding_type="eval_base64",
                confidence=0.95,
                entropy=entropy,
                layer_depth=depth,
                matched_pattern="eval+base64decode wrapper"
            ))

        # URL-encoded
        m = cls._URL_ENC.search(content)
        if m:
            detections.append(EncodingDetection(
                encoding_type="url_encoding",
                confidence=0.90,
                entropy=entropy,
                layer_depth=depth,
                matched_pattern=m.group(0)[:120]
            ))

        # Unicode escape sequences
        m = cls._UNICODE_ESC.search(content)
        if m:
            detections.append(EncodingDetection(
                encoding_type="unicode_escape",
                confidence=0.85,
                entropy=entropy,
                layer_depth=depth,
                matched_pattern=m.group(0)[:120]
            ))

        # String concatenation
        m = cls._CONCAT.search(content)
        if m:
            detections.append(EncodingDetection(
                encoding_type="string_concat",
                confidence=0.80,
                entropy=entropy,
                layer_depth=depth,
                matched_pattern=m.group(0)[:120]
            ))

        # Standalone base64  (entropy heuristic: real b64 usually > 4.5)
        for m in cls._B64_BLOB.finditer(content):
            blob = m.group(1)
            blob_entropy = cls.shannon_entropy(blob)
            if blob_entropy > 4.0 and len(blob) >= 20:
                detections.append(EncodingDetection(
                    encoding_type="base64",
                    confidence=min(0.90, 0.50 + blob_entropy / 10),
                    entropy=blob_entropy,
                    layer_depth=depth,
                    matched_pattern=blob[:120]
                ))

        # Hex-encoded
        for m in cls._HEX_BLOB.finditer(content):
            blob = m.group(1)
            if len(blob) % 2 == 0 and len(blob) >= 16:
                detections.append(EncodingDetection(
                    encoding_type="hex",
                    confidence=0.70,
                    entropy=entropy,
                    layer_depth=depth,
                    matched_pattern=blob[:120]
                ))

        return detections


# ════════════════════════════════════════════════════════════════════════════
# Phase 2 — Recursive Decode Engine
# ════════════════════════════════════════════════════════════════════════════

class RecursiveDecoder:
    """
    Recursively decode nested encodings with safety protections:
      • Maximum recursion depth  (default 5)
      • Seen-hash loop detection (prevents infinite cycles)
      • Maximum decoded size     (10 MB)
    """

    def __init__(self, max_depth: int = MAX_RECURSION_DEPTH,
                 max_size: int = MAX_DECODED_SIZE):
        self.max_depth = max_depth
        self.max_size = max_size

    # ── individual decoders ─────────────────────────────────────────────

    @staticmethod
    def _try_base64(blob: str) -> Optional[str]:
        """Attempt standard Base64 decode."""
        try:
            # Pad if needed
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(padded, validate=True)
            # Heuristic: reject if >30 % non-printable (likely binary/gzip)
            text = raw.decode("utf-8", errors="replace")
            non_printable = sum(1 for c in text if ord(c) < 32 and c not in '\r\n\t')
            if non_printable / max(len(text), 1) > 0.30:
                # Might be gzip/zlib — try that first
                return RecursiveDecoder._try_decompress(raw)
            return text
        except Exception:
            return None

    @staticmethod
    def _try_utf16_base64(blob: str) -> Optional[str]:
        """PowerShell -enc uses UTF-16LE base64."""
        try:
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(padded, validate=True)
            return raw.decode("utf-16-le")
        except Exception:
            return None

    @staticmethod
    def _try_hex(blob: str) -> Optional[str]:
        """Decode hex string."""
        try:
            raw = binascii.unhexlify(blob)
            text = raw.decode("utf-8", errors="replace")
            non_printable = sum(1 for c in text if ord(c) < 32 and c not in '\r\n\t')
            if non_printable / max(len(text), 1) > 0.30:
                return RecursiveDecoder._try_decompress(raw)
            return text
        except Exception:
            return None

    @staticmethod
    def _try_url_decode(content: str) -> Optional[str]:
        """Decode URL-encoded content."""
        try:
            decoded = urllib.parse.unquote(content)
            if decoded != content:
                return decoded
        except Exception:
            pass
        return None

    @staticmethod
    def _try_unicode_unescape(content: str) -> Optional[str]:
        """Decode \\uXXXX and \\xXX escape sequences."""
        try:
            decoded = content.encode("utf-8").decode("unicode_escape")
            if decoded != content:
                return decoded
        except Exception:
            pass
        return None

    @staticmethod
    def _try_decompress(raw_bytes: bytes) -> Optional[str]:
        """Try gzip then zlib decompression."""
        # Gzip
        try:
            decompressed = gzip.decompress(raw_bytes)
            return decompressed.decode("utf-8", errors="replace")
        except Exception:
            pass
        # Zlib
        try:
            decompressed = zlib.decompress(raw_bytes)
            return decompressed.decode("utf-8", errors="replace")
        except Exception:
            pass
        # Zlib raw deflate
        try:
            decompressed = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
            return decompressed.decode("utf-8", errors="replace")
        except Exception:
            pass
        return None

    @staticmethod
    def _try_concat_resolve(content: str) -> Optional[str]:
        """Resolve string concatenation like "c"+"m"+"d"."""
        try:
            # Match "x"+"y"+"z" patterns
            pattern = re.compile(r'"([^"]{1,4})"\s*\+\s*')
            parts = pattern.findall(content)
            if len(parts) >= 3:
                # Also grab the last quoted string after the final +
                last = re.search(r'\+\s*"([^"]{1,4})"(?:\s*$|\s*\))', content)
                resolved = "".join(parts)
                if last:
                    resolved += last.group(1)
                if resolved and resolved != content:
                    return resolved
        except Exception:
            pass
        return None

    @staticmethod
    def _try_xor_bruteforce(raw_bytes: bytes, min_printable: float = 0.85) -> Optional[Tuple[str, int]]:
        """Try XOR with single-byte keys 0x01–0xFF. Return (decoded, key) or None."""
        for key in range(1, 256):
            decoded = bytes(b ^ key for b in raw_bytes)
            try:
                text = decoded.decode("ascii")
                printable_ratio = sum(1 for c in text if 32 <= ord(c) < 127 or c in '\r\n\t') / max(len(text), 1)
                if printable_ratio >= min_printable and len(text) >= MIN_INTERESTING_LENGTH:
                    return text, key
            except Exception:
                continue
        return None

    # ── main recursive decode ───────────────────────────────────────────

    def decode(self, content: str, depth: int = 0,
               seen: Optional[set] = None) -> DeobfuscationResult:
        """
        Recursively decode *content*. Returns a DeobfuscationResult with
        all decoding layers recorded.
        """
        if seen is None:
            seen = set()

        result = DeobfuscationResult(
            original=content,
            decoded=content,
            normalized=content,
        )

        if depth >= self.max_depth:
            logger.debug("Max recursion depth reached (%d)", depth)
            return result

        content_hash = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        if content_hash in seen:
            logger.debug("Loop detected at depth %d", depth)
            return result
        seen.add(content_hash)

        if len(content) > self.max_size:
            logger.warning("Content exceeds max size (%d bytes), truncating", len(content))
            content = content[:self.max_size]

        detections = EncodingDetector.detect(content, depth)
        if not detections:
            return result

        # Sort by confidence descending; try highest-confidence first
        detections.sort(key=lambda d: d.confidence, reverse=True)

        decoded_text: Optional[str] = None
        chosen_detection: Optional[EncodingDetection] = None

        for det in detections:
            candidate = self._apply_decode(content, det)
            if candidate and candidate != content and len(candidate) >= MIN_INTERESTING_LENGTH:
                decoded_text = candidate
                chosen_detection = det
                break

        if decoded_text is None or chosen_detection is None:
            return result

        # Record this layer
        layer = DecodeLayer(
            encoding_type=chosen_detection.encoding_type,
            input_preview=content[:120],
            output_preview=decoded_text[:120],
            confidence=chosen_detection.confidence,
        )

        # Recurse into decoded text
        child = self.decode(decoded_text, depth + 1, seen)

        result.decoded = child.decoded
        result.normalized = child.normalized
        result.layers = [layer] + child.layers
        result.was_obfuscated = True
        result.confidence = chosen_detection.confidence
        return result

    def _apply_decode(self, content: str,
                      det: EncodingDetection) -> Optional[str]:
        """Apply the correct decoder for a given detection."""
        enc = det.encoding_type

        if enc == "powershell_enc":
            m = EncodingDetector._PS_ENC.search(content)
            if m:
                blob = m.group(1)
                decoded = self._try_utf16_base64(blob)
                if decoded:
                    # Replace the encoded command in the full string
                    return content[:m.start(1)] + decoded + content[m.end(1):]
            return None

        if enc == "eval_base64":
            # Extract the base64 blob from inside the wrapper
            inner = re.search(
                r'(?:b64decode|atob|Buffer\.from)\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']',
                content, re.IGNORECASE
            )
            if inner:
                return self._try_base64(inner.group(1))
            return None

        if enc == "url_encoding":
            return self._try_url_decode(content)

        if enc == "unicode_escape":
            return self._try_unicode_unescape(content)

        if enc == "string_concat":
            return self._try_concat_resolve(content)

        if enc == "base64":
            blob = det.matched_pattern
            decoded = self._try_base64(blob)
            if decoded and decoded != blob:
                return content.replace(blob, decoded, 1)
            return None

        if enc == "hex":
            blob = det.matched_pattern
            decoded = self._try_hex(blob)
            if decoded and decoded != blob:
                return content.replace(blob, decoded, 1)
            return None

        return None


# ════════════════════════════════════════════════════════════════════════════
# Phase 3 — Content Normalization
# ════════════════════════════════════════════════════════════════════════════

class ContentNormalizer:
    """
    Normalize decoded content so downstream detection rules
    match regardless of casing, aliasing, or env-var usage.
    """

    # PowerShell alias → canonical form
    PS_ALIASES: Dict[str, str] = {
        "iex":                  "Invoke-Expression",
        "iwr":                  "Invoke-WebRequest",
        "iweb":                 "Invoke-WebRequest",
        "sal":                  "Set-Alias",
        "gal":                  "Get-Alias",
        "gcm":                  "Get-Command",
        "gci":                  "Get-ChildItem",
        "gi":                   "Get-Item",
        "gp":                   "Get-ItemProperty",
        "ni":                   "New-Item",
        "ri":                   "Remove-Item",
        "si":                   "Set-Item",
        "sp":                   "Set-ItemProperty",
        "where":                "Where-Object",
        "foreach":              "ForEach-Object",
        "select":               "Select-Object",
        "sort":                 "Sort-Object",
        "measure":              "Measure-Object",
        "wget":                 "Invoke-WebRequest",
        "curl":                 "Invoke-WebRequest",
        "saps":                 "Start-Process",
        "start":                "Start-Process",
        "sleep":                "Start-Sleep",
        "cls":                  "Clear-Host",
        "echo":                 "Write-Output",
        "write":                "Write-Output",
        "sc":                   "Set-Content",
        "gc":                   "Get-Content",
        "ac":                   "Add-Content",
        "cp":                   "Copy-Item",
        "mv":                   "Move-Item",
        "rm":                   "Remove-Item",
        "md":                   "New-Item -Type Directory",
        "rd":                   "Remove-Item -Recurse",
        "dir":                  "Get-ChildItem",
        "ls":                   "Get-ChildItem",
        "cat":                  "Get-Content",
        "type":                 "Get-Content",
        "net-webclient":        "System.Net.WebClient",
        "downloadstring":       "DownloadString",
        "downloadfile":         "DownloadFile",
        "new-object":           "New-Object",
        "invoke-expression":    "Invoke-Expression",
        "invoke-webrequest":    "Invoke-WebRequest",
        "invoke-restmethod":    "Invoke-RestMethod",
    }

    # Windows environment variables → canonical tokens
    ENV_VARS: Dict[str, str] = {
        "%temp%":               "TEMP_PATH",
        "%tmp%":                "TEMP_PATH",
        "%appdata%":            "APPDATA_PATH",
        "%localappdata%":       "LOCALAPPDATA_PATH",
        "%userprofile%":        "USER_HOME",
        "%systemroot%":         "SYSTEM_ROOT",
        "%windir%":             "WINDOWS_DIR",
        "%programfiles%":       "PROGRAM_FILES",
        "%programfiles(x86)%":  "PROGRAM_FILES_X86",
        "%comspec%":            "CMD_SHELL",
        "%systemdrive%":        "SYSTEM_DRIVE",
        "%public%":             "PUBLIC_PATH",
        "%programdata%":        "PROGRAMDATA_PATH",
        "$env:temp":            "TEMP_PATH",
        "$env:tmp":             "TEMP_PATH",
        "$env:appdata":         "APPDATA_PATH",
        "$env:localappdata":    "LOCALAPPDATA_PATH",
        "$env:userprofile":     "USER_HOME",
        "$env:systemroot":      "SYSTEM_ROOT",
        "$env:windir":          "WINDOWS_DIR",
        "$env:programfiles":    "PROGRAM_FILES",
        "$env:computername":    "HOSTNAME",
        "$env:username":        "USERNAME",
    }

    # CMD / Shell meta-commands → canonical tokens
    CMD_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r'\bcmd\s*/c\b', re.I),             "CMD_EXECUTION"),
        (re.compile(r'\bcmd\s*/k\b', re.I),             "CMD_PERSISTENT"),
        (re.compile(r'\bstart\s+/b\b', re.I),           "BACKGROUND_EXEC"),
        (re.compile(r'\brundll32(?:\.exe)?\b', re.I),    "RUNDLL32_EXEC"),
        (re.compile(r'\bregsvr32(?:\.exe)?\b', re.I),   "REGSVR32_EXEC"),
        (re.compile(r'\bmshta(?:\.exe)?\b', re.I),      "MSHTA_EXEC"),
        (re.compile(r'\bcertutil(?:\.exe)?\b', re.I),   "CERTUTIL_EXEC"),
        (re.compile(r'\bbitsadmin(?:\.exe)?\b', re.I),  "BITSADMIN_EXEC"),
    ]

    @classmethod
    def normalize(cls, content: str) -> str:
        """Normalize decoded content for downstream detection."""
        if not content:
            return content

        normalized = content

        # 1. HTML entity decode
        normalized = html.unescape(normalized)

        # 2. Resolve environment variables (case-insensitive)
        for env_var, token in cls.ENV_VARS.items():
            pattern = re.compile(re.escape(env_var), re.IGNORECASE)
            normalized = pattern.sub(token, normalized)

        # 3. Resolve PowerShell aliases (word-boundary match)
        for alias, canonical in cls.PS_ALIASES.items():
            # Match as whole word, case-insensitive
            pattern = re.compile(r'\b' + re.escape(alias) + r'\b', re.IGNORECASE)
            normalized = pattern.sub(canonical, normalized)

        # 4. Normalize CMD patterns
        for pattern, token in cls.CMD_PATTERNS:
            normalized = pattern.sub(token, normalized)

        # 5. Collapse whitespace
        normalized = re.sub(r'[ \t]+', ' ', normalized).strip()

        return normalized


# ════════════════════════════════════════════════════════════════════════════
# Phase 4-6 — IOC Recovery + MITRE + Capability Enhancement
# (These are exposed as helpers; the actual integration is done by
#  modifying ioc_pipeline, mitre_mapper, and capability_engine to
#  consume the decoded/normalized fields.)
# ════════════════════════════════════════════════════════════════════════════

# IOC patterns for recovery from decoded content
_IOC_PATTERNS = {
    "ip":       re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "domain":   re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|tk|ru|cn|info|biz|top|club|online|site|icu|buzz)\b', re.I),
    "url":      re.compile(r'https?://[^\s<>"\']+', re.I),
    "email":    re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
    "sha256":   re.compile(r'\b[a-fA-F0-9]{64}\b'),
    "md5":      re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "ipv6":     re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
    "filepath": re.compile(r'[A-Za-z]:\\(?:[^\\\s<>"\'|?*]+\\)*[^\\\s<>"\'|?*]+', re.I),
    "registry": re.compile(r'\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s<>"\']+', re.I),
    "mutex":    re.compile(r'\b(?:Global|Local)\\[^\s<>"\']+', re.I),
    "pipe":     re.compile(r'\\\\.\\pipe\\[^\s<>"\']+', re.I),
}


def recover_iocs_from_text(text: str, source_layer: str = "Decoded") -> List[Dict]:
    """Extract IOCs from arbitrary text (decoded/normalized content)."""
    iocs: List[Dict] = []
    seen: set = set()

    for ioc_type, pattern in _IOC_PATTERNS.items():
        for m in pattern.finditer(text):
            value = m.group(0)
            key = f"{ioc_type}:{value}"
            if key not in seen:
                seen.add(key)
                iocs.append({
                    "type": ioc_type,
                    "value": value,
                    "source_layer": source_layer,
                    "confidence": "High" if source_layer == "Decoded Payload" else "Medium"
                })
    return iocs


# ════════════════════════════════════════════════════════════════════════════
# Phase 7 — Orchestrator
# ════════════════════════════════════════════════════════════════════════════

class UniversalDeobfuscator:
    """
    Top-level orchestrator.
    Call `process_telemetry` to deobfuscate an entire list of telemetry
    events in-place, or `deobfuscate_string` for a single string.
    """

    def __init__(self):
        self.decoder = RecursiveDecoder()
        self.normalizer = ContentNormalizer

    def deobfuscate_string(self, content: str) -> DeobfuscationResult:
        """Deobfuscate and normalize a single string."""
        if not content or len(content) < MIN_INTERESTING_LENGTH:
            return DeobfuscationResult(
                original=content or "",
                decoded=content or "",
                normalized=content or "",
            )

        result = self.decoder.decode(content)
        result.normalized = self.normalizer.normalize(result.decoded)

        # Recover IOCs from decoded content
        if result.was_obfuscated:
            result.recovered_iocs = recover_iocs_from_text(
                result.decoded, "Decoded Payload"
            )

        return result

    def process_telemetry(self, telemetry_events: list) -> Dict:
        """
        Process all telemetry events:
          1. Decode cmdline, stdout, stderr, output fields
          2. Attach decoded_cmdline, normalized_cmdline to each event
          3. Return a summary report
        """
        total_decoded = 0
        total_layers = 0
        all_recovered_iocs: List[Dict] = []
        layer_summary: List[Dict] = []

        for event in telemetry_events:
            data = event.get("data", {})
            if not data:
                continue

            # Process each text field
            for field_name in ("cmdline", "stdout", "stderr", "output"):
                raw_value = data.get(field_name)
                if not raw_value or not isinstance(raw_value, str):
                    continue

                result = self.deobfuscate_string(raw_value)

                if result.was_obfuscated:
                    total_decoded += 1
                    total_layers += len(result.layers)
                    all_recovered_iocs.extend(result.recovered_iocs)

                    # Attach decoded content to event data
                    data[f"decoded_{field_name}"] = result.decoded
                    data[f"normalized_{field_name}"] = result.normalized
                    data[f"deobfuscation_layers_{field_name}"] = [
                        {
                            "encoding": l.encoding_type,
                            "confidence": l.confidence,
                            "input_preview": l.input_preview,
                            "output_preview": l.output_preview,
                        }
                        for l in result.layers
                    ]

                    layer_summary.append({
                        "field": field_name,
                        "event_type": event.get("type", "UNKNOWN"),
                        "encoding_chain": " → ".join(l.encoding_type for l in result.layers),
                        "confidence": result.confidence,
                    })

        report = {
            "total_fields_decoded": total_decoded,
            "total_encoding_layers_stripped": total_layers,
            "recovered_iocs": all_recovered_iocs,
            "layer_summary": layer_summary,
        }

        logger.info(
            "[Deobfuscation] Processed %d events: %d fields decoded, %d layers stripped, %d IOCs recovered",
            len(telemetry_events), total_decoded, total_layers, len(all_recovered_iocs)
        )

        return report

    def process_static_strings(self, static_results: dict) -> Dict:
        """
        Deobfuscate interesting strings from static analysis.
        Returns a report and mutates static_results to include decoded strings.
        """
        strings_data = static_results.get("strings", {})
        interesting = strings_data.get("interesting", [])
        if not interesting:
            return {"decoded_strings": [], "total_decoded": 0}

        decoded_strings: List[Dict] = []
        all_recovered_iocs: List[Dict] = []

        for raw_str in interesting:
            if not isinstance(raw_str, str):
                continue
            result = self.deobfuscate_string(raw_str)
            if result.was_obfuscated:
                decoded_strings.append({
                    "original": raw_str[:200],
                    "decoded": result.decoded[:500],
                    "normalized": result.normalized[:500],
                    "layers": [l.encoding_type for l in result.layers],
                })
                all_recovered_iocs.extend(result.recovered_iocs)

        # Attach decoded strings back to static results for downstream consumption
        if "strings" not in static_results:
            static_results["strings"] = {}
        static_results["strings"]["decoded"] = decoded_strings

        return {
            "decoded_strings": decoded_strings,
            "total_decoded": len(decoded_strings),
            "recovered_iocs": all_recovered_iocs,
        }
