"""
Dropped File Extraction & Recursive Analysis Engine
====================================================
Collects, classifies, and recursively analyzes artifacts created during
sandbox execution — dropped executables, downloaded payloads, extracted
archives, generated scripts, and shellcode blobs.

Phases:
  1. ArtifactCollector  — scans telemetry for FILE_WRITE / HTTP_DOWNLOAD events
  2. ArtifactClassifier — magic-byte + extension + entropy classification
  3. RecursiveAnalyzer  — runs static + YARA + IOC + MITRE + capabilities per artifact
  4. ArchiveExpander    — extracts ZIP contents and recurses into them
  5. DownloadDetector   — identifies HTTP/FTP/PS download patterns in telemetry
"""

import hashlib
import logging
import math
import mimetypes
import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set

logger = logging.getLogger("artifact_engine")

# ────────────────────────────────────────────────────────────────────────────
# Constants & Safety Limits
# ────────────────────────────────────────────────────────────────────────────
MAX_RECURSION_DEPTH = 3
MAX_ARTIFACT_SIZE = 50 * 1024 * 1024   # 50 MB per artifact
MAX_ARTIFACTS_PER_JOB = 50             # cap total artifacts to prevent abuse
MAX_ARCHIVE_FILES = 100                # max files to extract from a single archive
SUSPICIOUS_ENTROPY_THRESHOLD = 7.0     # packed / encrypted binaries

# File extensions by category
EXECUTABLE_EXTENSIONS = {".exe", ".com", ".scr", ".pif", ".msi"}
DLL_EXTENSIONS = {".dll", ".sys", ".drv", ".ocx", ".cpl"}
SCRIPT_EXTENSIONS = {".py", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".sh", ".bash", ".rb", ".pl", ".php", ".wsf", ".hta"}
DOCUMENT_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tar.gz", ".tgz"}
CONFIG_EXTENSIONS = {".ini", ".cfg", ".conf", ".json", ".xml", ".yaml", ".yml", ".toml", ".reg"}

# Magic bytes for classification
MAGIC_BYTES = {
    b"MZ":          "PE_Executable",
    b"\x7fELF":     "ELF_Executable",
    b"PK\x03\x04":  "ZIP_Archive",
    b"PK\x05\x06":  "ZIP_Archive",
    b"\x1f\x8b":    "GZIP_Archive",
    b"Rar!\x1a\x07": "RAR_Archive",
    b"7z\xbc\xaf":  "SevenZip_Archive",
    b"\xca\xfe\xba\xbe": "Mach-O_Executable",
    b"\xfe\xed\xfa": "Mach-O_Executable",
    b"%PDF":        "PDF_Document",
    b"\xd0\xcf\x11\xe0": "OLE_Document",
}


# ────────────────────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class ArtifactResult:
    """Complete analysis result for a single collected artifact."""
    sha256: str = ""
    md5: str = ""
    filename: str = ""
    file_type: str = "Unknown"          # Executable, DLL, Script, Archive, etc.
    mime_type: str = "application/octet-stream"
    size: int = 0
    entropy: float = 0.0
    creator_process: str = ""
    source_url: str = ""                # if downloaded
    parent_sha256: str = ""             # provenance chain
    depth: int = 0
    risk_score: int = 0
    is_suspicious: bool = False
    is_executable: bool = False
    capabilities: List[str] = field(default_factory=list)
    yara_matches: List[str] = field(default_factory=list)
    mitre_mappings: List[str] = field(default_factory=list)
    iocs: List[Dict] = field(default_factory=list)
    relationship: str = "dropped"       # "dropped", "downloaded", "extracted", "created"
    children: List["ArtifactResult"] = field(default_factory=list)
    static_analysis: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dict, recursing into children."""
        d = {
            "sha256": self.sha256,
            "md5": self.md5,
            "filename": self.filename,
            "file_type": self.file_type,
            "mime_type": self.mime_type,
            "size": self.size,
            "entropy": self.entropy,
            "creator_process": self.creator_process,
            "source_url": self.source_url,
            "parent_sha256": self.parent_sha256,
            "depth": self.depth,
            "risk_score": self.risk_score,
            "is_suspicious": self.is_suspicious,
            "is_executable": self.is_executable,
            "capabilities": self.capabilities,
            "yara_matches": self.yara_matches,
            "mitre_mappings": self.mitre_mappings,
            "iocs": self.iocs,
            "relationship": self.relationship,
            "children": [c.to_dict() for c in self.children],
        }
        return d


@dataclass
class CollectedArtifact:
    """Raw artifact collected from telemetry before classification."""
    path: str
    process: str = ""
    timestamp: str = ""
    size: int = 0
    sha256: str = ""
    md5: str = ""
    source_url: str = ""
    relationship: str = "dropped"       # dropped / downloaded / created
    creator_pid: int = 0
    parent_pid: int = 0


@dataclass
class DownloadRecord:
    """A detected download event."""
    source_url: str
    destination_file: str
    sha256: str = ""
    process: str = ""
    timestamp: str = ""


# ════════════════════════════════════════════════════════════════════════════
# Phase 1 — Artifact Collector
# ════════════════════════════════════════════════════════════════════════════

class ArtifactCollector:
    """
    Scans telemetry events for FILE_WRITE, FILE_CREATE, HTTP_DOWNLOAD
    events and collects metadata for each created artifact.
    """

    # Paths to ignore (sandbox internals, Python cache, etc.)
    IGNORE_PATTERNS = [
        "__pycache__",
        ".pyc",
        "aegis_uploads",
        "sentinel_uploads",
        "\\Temp\\pip",
        "/tmp/pip",
        "\\AppData\\Local\\Temp\\pip",
    ]

    @classmethod
    def collect(cls, telemetry_events: list, upload_dir: str = "") -> List[CollectedArtifact]:
        """
        Scan telemetry events and collect all file-creation artifacts.
        Returns deduplicated list of CollectedArtifact objects.
        """
        artifacts: List[CollectedArtifact] = []
        seen_paths: Set[str] = set()

        for event in telemetry_events:
            evt_type = event.get("type", "")
            data = event.get("data", {})
            timestamp = event.get("timestamp", "")

            if evt_type in ("FILE_WRITE", "FILE_CREATE"):
                path = data.get("path", data.get("filename", ""))
                if not path or cls._should_ignore(path):
                    continue

                # Normalize path for dedup
                norm_path = os.path.normpath(path).lower()
                if norm_path in seen_paths:
                    continue
                seen_paths.add(norm_path)

                artifact = CollectedArtifact(
                    path=path,
                    process=data.get("cmdline", data.get("process", "")),
                    timestamp=timestamp,
                    size=data.get("size", 0),
                    sha256=data.get("sha256", ""),
                    md5=data.get("md5", ""),
                    relationship="dropped",
                    creator_pid=data.get("pid", 0),
                    parent_pid=data.get("ppid", 0),
                )
                artifacts.append(artifact)

            elif evt_type == "HTTP_DOWNLOAD":
                path = data.get("destination", data.get("path", ""))
                url = data.get("url", data.get("source_url", ""))
                if not path:
                    continue

                norm_path = os.path.normpath(path).lower()
                if norm_path in seen_paths:
                    continue
                seen_paths.add(norm_path)

                artifact = CollectedArtifact(
                    path=path,
                    process=data.get("cmdline", data.get("process", "")),
                    timestamp=timestamp,
                    size=data.get("size", 0),
                    sha256=data.get("sha256", ""),
                    source_url=url,
                    relationship="downloaded",
                    creator_pid=data.get("pid", 0),
                )
                artifacts.append(artifact)

            elif evt_type == "HTTP_REQUEST":
                # Check if this HTTP request triggered a download
                url = data.get("url", "")
                method = data.get("method", "GET")
                if method == "GET" and url and cls._looks_like_download(url):
                    artifact = CollectedArtifact(
                        path="",  # May not have a destination path
                        process=data.get("cmdline", ""),
                        timestamp=timestamp,
                        source_url=url,
                        relationship="downloaded",
                    )
                    artifacts.append(artifact)

        logger.info(f"[ArtifactCollector] Collected {len(artifacts)} artifacts from telemetry")
        return artifacts[:MAX_ARTIFACTS_PER_JOB]

    @classmethod
    def _should_ignore(cls, path: str) -> bool:
        """Return True if path matches any ignore pattern."""
        path_lower = path.lower()
        return any(p.lower() in path_lower for p in cls.IGNORE_PATTERNS)

    @staticmethod
    def _looks_like_download(url: str) -> bool:
        """Heuristic: URL looks like it delivers a binary payload."""
        payload_extensions = (".exe", ".dll", ".bin", ".ps1", ".bat",
                              ".zip", ".rar", ".7z", ".msi", ".scr",
                              ".vbs", ".hta", ".js")
        url_lower = url.lower().split("?")[0]  # strip query params
        return any(url_lower.endswith(ext) for ext in payload_extensions)


# ════════════════════════════════════════════════════════════════════════════
# Phase 2 — Artifact Classifier
# ════════════════════════════════════════════════════════════════════════════

class ArtifactClassifier:
    """
    Determines file type via magic bytes + extension + entropy.
    Returns classification dict: {type, mime, entropy, executable, suspicious}.
    """

    @classmethod
    def classify(cls, file_path: str) -> Dict:
        """Classify a file on disk. Returns classification metadata."""
        result = {
            "type": "Unknown",
            "mime": "application/octet-stream",
            "entropy": 0.0,
            "executable": False,
            "suspicious": False,
        }

        if not os.path.exists(file_path):
            return result

        try:
            size = os.path.getsize(file_path)
            if size == 0:
                result["type"] = "Empty"
                return result
            if size > MAX_ARTIFACT_SIZE:
                result["type"] = "Oversized"
                return result

            # Read header for magic bytes
            with open(file_path, "rb") as f:
                header = f.read(16)
                f.seek(0)
                data = f.read(min(size, 1024 * 1024))  # Read up to 1MB for entropy

            # 1. Magic byte detection
            magic_type = cls._detect_magic(header)
            if magic_type:
                result["type"] = cls._normalize_type(magic_type)

            # 2. Extension-based fallback
            ext = os.path.splitext(file_path)[1].lower()
            if result["type"] == "Unknown" and ext:
                result["type"] = cls._classify_by_extension(ext)

            # 3. MIME type
            mime = mimetypes.guess_type(file_path)[0]
            if mime:
                result["mime"] = mime

            # 4. Entropy
            result["entropy"] = cls._compute_entropy(data)

            # 5. Executable flag
            result["executable"] = (
                result["type"] in ("Executable", "DLL", "ELF_Executable", "Mach-O_Executable")
                or ext in EXECUTABLE_EXTENSIONS
                or ext in DLL_EXTENSIONS
            )

            # 6. Suspicious flag
            result["suspicious"] = (
                result["executable"]
                or result["entropy"] > SUSPICIOUS_ENTROPY_THRESHOLD
                or ext in SCRIPT_EXTENSIONS
                or result["type"] == "Shellcode"
            )

        except Exception as e:
            logger.error(f"[ArtifactClassifier] Failed to classify {file_path}: {e}")

        return result

    @staticmethod
    def _detect_magic(header: bytes) -> Optional[str]:
        """Match file header against known magic bytes."""
        for magic, file_type in MAGIC_BYTES.items():
            if header.startswith(magic):
                return file_type
        # Shellcode heuristic: starts with common x86 prologs
        if header[:2] in (b"\x55\x89", b"\x55\x48", b"\xe8\x00", b"\xfc\xe8"):
            return "Shellcode"
        return None

    @staticmethod
    def _normalize_type(magic_type: str) -> str:
        """Normalize magic detection to canonical types."""
        mapping = {
            "PE_Executable": "Executable",
            "ELF_Executable": "Executable",
            "Mach-O_Executable": "Executable",
            "ZIP_Archive": "Archive",
            "GZIP_Archive": "Archive",
            "RAR_Archive": "Archive",
            "SevenZip_Archive": "Archive",
            "PDF_Document": "Document",
            "OLE_Document": "Document",
            "Shellcode": "Shellcode",
        }
        return mapping.get(magic_type, magic_type)

    @staticmethod
    def _classify_by_extension(ext: str) -> str:
        """Classify file by extension when magic bytes don't match."""
        if ext in EXECUTABLE_EXTENSIONS:
            return "Executable"
        if ext in DLL_EXTENSIONS:
            return "DLL"
        if ext in SCRIPT_EXTENSIONS:
            return "Script"
        if ext in DOCUMENT_EXTENSIONS:
            return "Document"
        if ext in ARCHIVE_EXTENSIONS:
            return "Archive"
        if ext in CONFIG_EXTENSIONS:
            return "Configuration"
        return "Unknown"

    @staticmethod
    def _compute_entropy(data: bytes) -> float:
        """Shannon entropy of binary data."""
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq if count > 0
        )


# ════════════════════════════════════════════════════════════════════════════
# Phase 3 — Recursive Analyzer
# ════════════════════════════════════════════════════════════════════════════

class RecursiveAnalyzer:
    """
    Runs the full ACROS static analysis pipeline on each collected
    artifact: hashing, strings, PE/Python analysis, YARA, IOC extraction,
    MITRE mapping, and capability detection.

    Safety: max depth, hash dedup, per-artifact size limit.
    """

    def __init__(self):
        self._seen_hashes: Set[str] = set()
        self._artifact_count: int = 0

    def analyze(self, file_path: str, parent_sha256: str = "",
                depth: int = 0, relationship: str = "dropped",
                source_url: str = "", creator_process: str = "") -> Optional[ArtifactResult]:
        """
        Analyze a single artifact file and return an ArtifactResult.
        Recursively analyzes archives and their contents.
        """
        if depth > MAX_RECURSION_DEPTH:
            logger.debug(f"[RecursiveAnalyzer] Max depth reached for {file_path}")
            return None

        if self._artifact_count >= MAX_ARTIFACTS_PER_JOB:
            logger.warning(f"[RecursiveAnalyzer] Artifact cap reached ({MAX_ARTIFACTS_PER_JOB})")
            return None

        if not os.path.exists(file_path):
            return None

        file_size = os.path.getsize(file_path)
        if file_size == 0 or file_size > MAX_ARTIFACT_SIZE:
            return None

        # Hash for dedup
        sha256, md5 = self._compute_hashes(file_path)
        if sha256 in self._seen_hashes:
            logger.debug(f"[RecursiveAnalyzer] Duplicate artifact skipped: {sha256[:16]}...")
            return None
        self._seen_hashes.add(sha256)
        self._artifact_count += 1

        # Classify
        classification = ArtifactClassifier.classify(file_path)

        # Build result
        result = ArtifactResult(
            sha256=sha256,
            md5=md5,
            filename=os.path.basename(file_path),
            file_type=classification["type"],
            mime_type=classification["mime"],
            size=file_size,
            entropy=classification["entropy"],
            creator_process=creator_process,
            source_url=source_url,
            parent_sha256=parent_sha256,
            depth=depth,
            is_suspicious=classification["suspicious"],
            is_executable=classification["executable"],
            relationship=relationship,
        )

        # Run static analysis
        try:
            static_results = self._run_static_analysis(file_path, result.filename)
            result.static_analysis = static_results
        except Exception as e:
            logger.error(f"[RecursiveAnalyzer] Static analysis failed for {result.filename}: {e}")

        # Run YARA
        try:
            result.yara_matches = self._run_yara(file_path)
        except Exception as e:
            logger.error(f"[RecursiveAnalyzer] YARA scan failed for {result.filename}: {e}")

        # Run IOC extraction on static results
        try:
            result.iocs = self._extract_iocs(result.static_analysis)
        except Exception as e:
            logger.error(f"[RecursiveAnalyzer] IOC extraction failed for {result.filename}: {e}")

        # Run MITRE mapping
        try:
            result.mitre_mappings = self._map_mitre(result.static_analysis)
        except Exception as e:
            logger.error(f"[RecursiveAnalyzer] MITRE mapping failed for {result.filename}: {e}")

        # Run capability detection
        try:
            caps = self._detect_capabilities(result.static_analysis)
            result.capabilities = [c.get("capability", "") for c in caps] if caps else []
        except Exception as e:
            logger.error(f"[RecursiveAnalyzer] Capability detection failed for {result.filename}: {e}")

        # Calculate risk score for this artifact
        result.risk_score = self._calculate_artifact_risk(result)

        # If it's an archive, expand and recurse
        if classification["type"] == "Archive":
            children = ArchiveExpander.expand_and_analyze(
                file_path, self, parent_sha256=sha256, depth=depth + 1
            )
            result.children = children

        logger.info(
            f"[RecursiveAnalyzer] Analyzed artifact: {result.filename} "
            f"(type={result.file_type}, risk={result.risk_score}, "
            f"depth={depth}, children={len(result.children)})"
        )

        return result

    @staticmethod
    def _compute_hashes(file_path: str):
        """Compute SHA256 and MD5 of a file."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5(usedforsecurity=False)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
                md5.update(chunk)
        return sha256.hexdigest(), md5.hexdigest()

    @staticmethod
    def _run_static_analysis(file_path: str, filename: str) -> dict:
        """Run the same static analysis pipeline used by the main report."""
        from app.services.static_analysis.hash_analyzer import analyze_hashes
        from app.services.static_analysis.string_extractor import extract_strings

        results = {}
        results["hash"] = analyze_hashes(file_path)
        results["strings"] = extract_strings(file_path)

        if filename.endswith(".py"):
            from app.services.static_analysis.python_analyzer import analyze_python_file
            results["python"] = analyze_python_file(file_path)
        else:
            from app.services.static_analysis.pe_analyzer import analyze_pe_file
            results["pe"] = analyze_pe_file(file_path)

        return results

    @staticmethod
    def _run_yara(file_path: str) -> List[str]:
        """Scan file with YARA rules."""
        try:
            from app.services.yara_service import YaraService
            yara_svc = YaraService()
            matches = yara_svc.scan_file(file_path)
            return [m["rule"] for m in matches] if matches else []
        except Exception:
            return []

    @staticmethod
    def _extract_iocs(static_results: dict) -> List[Dict]:
        """Extract IOCs from static analysis results."""
        try:
            from app.services.ioc_pipeline import extract_and_store_iocs
            return extract_and_store_iocs(static_results, [])
        except Exception:
            return []

    @staticmethod
    def _map_mitre(static_results: dict) -> List[str]:
        """Map static results to MITRE ATT&CK techniques."""
        try:
            from app.services.mitre_mapper import map_to_mitre
            mappings = map_to_mitre(static_results, [])
            return [m.get("id", "") for m in mappings] if mappings else []
        except Exception:
            return []

    @staticmethod
    def _detect_capabilities(static_results: dict) -> list:
        """Detect capabilities from static results."""
        try:
            from app.analysis.capability_engine import CapabilityEngine
            caps = CapabilityEngine.extract_capabilities(static_results, [])
            return [{"capability": c.capability, "severity": c.severity} for c in caps]
        except Exception:
            return []

    @staticmethod
    def _calculate_artifact_risk(artifact: ArtifactResult) -> int:
        """Calculate a risk score for a single artifact based on its properties."""
        score = 0

        # Base score by type
        type_scores = {
            "Executable": 40, "DLL": 35, "Shellcode": 60,
            "Script": 25, "Archive": 10, "Document": 15,
            "Configuration": 5, "Unknown": 10,
        }
        score += type_scores.get(artifact.file_type, 10)

        # Entropy bonus
        if artifact.entropy > SUSPICIOUS_ENTROPY_THRESHOLD:
            score += 15

        # YARA matches
        score += min(30, len(artifact.yara_matches) * 15)

        # Capabilities
        score += min(20, len(artifact.capabilities) * 5)

        # MITRE mappings
        score += min(15, len(artifact.mitre_mappings) * 3)

        # Downloaded from external URL
        if artifact.source_url:
            score += 10

        return min(100, score)


# ════════════════════════════════════════════════════════════════════════════
# Phase 4 — Archive Expander
# ════════════════════════════════════════════════════════════════════════════

class ArchiveExpander:
    """
    Extracts archive contents (ZIP) to a temporary directory and
    recursively analyzes each extracted file.
    """

    @classmethod
    def expand_and_analyze(cls, archive_path: str, analyzer: RecursiveAnalyzer,
                           parent_sha256: str = "", depth: int = 1) -> List[ArtifactResult]:
        """
        Extract archive contents and analyze each file.
        Returns list of ArtifactResult for extracted files.
        """
        results: List[ArtifactResult] = []

        if depth > MAX_RECURSION_DEPTH:
            return results

        extract_dir = None
        try:
            extract_dir = tempfile.mkdtemp(prefix="aegis_archive_")

            # Try ZIP extraction
            if zipfile.is_zipfile(archive_path):
                results = cls._extract_zip(archive_path, extract_dir, analyzer,
                                           parent_sha256, depth)
            else:
                logger.info(f"[ArchiveExpander] Unsupported archive format: {archive_path}")

        except Exception as e:
            logger.error(f"[ArchiveExpander] Extraction failed for {archive_path}: {e}")
        finally:
            # Clean up temp directory
            if extract_dir and os.path.exists(extract_dir):
                try:
                    shutil.rmtree(extract_dir, ignore_errors=True)
                except Exception:
                    pass

        return results

    @classmethod
    def _extract_zip(cls, zip_path: str, extract_dir: str,
                     analyzer: RecursiveAnalyzer, parent_sha256: str,
                     depth: int) -> List[ArtifactResult]:
        """Extract ZIP and analyze contents."""
        results: List[ArtifactResult] = []

        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Safety: check member count
                members = zf.namelist()
                if len(members) > MAX_ARCHIVE_FILES:
                    logger.warning(
                        f"[ArchiveExpander] ZIP has {len(members)} files, "
                        f"limiting to {MAX_ARCHIVE_FILES}"
                    )
                    members = members[:MAX_ARCHIVE_FILES]

                # Safety: check for zip bombs (total uncompressed size)
                total_size = sum(info.file_size for info in zf.infolist()
                                 if info.filename in members)
                if total_size > MAX_ARTIFACT_SIZE * 2:
                    logger.warning(
                        f"[ArchiveExpander] ZIP bomb detected "
                        f"(uncompressed size: {total_size} bytes), skipping"
                    )
                    return results

                # Safety: check for path traversal
                for member in members:
                    if ".." in member or member.startswith("/") or member.startswith("\\"):
                        logger.warning(f"[ArchiveExpander] Path traversal detected: {member}")
                        continue

                    # Skip directories
                    if member.endswith("/"):
                        continue

                    try:
                        zf.extract(member, extract_dir)
                        extracted_path = os.path.join(extract_dir, member)

                        if os.path.exists(extracted_path) and os.path.isfile(extracted_path):
                            artifact = analyzer.analyze(
                                extracted_path,
                                parent_sha256=parent_sha256,
                                depth=depth,
                                relationship="extracted",
                            )
                            if artifact:
                                results.append(artifact)
                    except Exception as e:
                        logger.error(f"[ArchiveExpander] Failed to extract {member}: {e}")

        except zipfile.BadZipFile:
            logger.error(f"[ArchiveExpander] Corrupt ZIP file: {zip_path}")
        except Exception as e:
            logger.error(f"[ArchiveExpander] ZIP extraction error: {e}")

        return results


# ════════════════════════════════════════════════════════════════════════════
# Phase 5 — Download Detector
# ════════════════════════════════════════════════════════════════════════════

class DownloadDetector:
    """
    Scans telemetry for HTTP/HTTPS/FTP downloads, curl/wget/PowerShell
    download patterns. Returns DownloadRecord objects.
    """

    # Patterns for download commands in cmdline
    DOWNLOAD_PATTERNS = [
        # PowerShell downloads
        re.compile(r'(?:invoke-webrequest|iwr|wget|curl)\s+["\']?(https?://\S+)', re.I),
        re.compile(r'downloadstring\s*\(\s*["\']?(https?://\S+)', re.I),
        re.compile(r'downloadfile\s*\(\s*["\']?(https?://\S+)', re.I),
        re.compile(r'start-bitstransfer\s+["\']?(https?://\S+)', re.I),
        # curl / wget
        re.compile(r'\bcurl\b.*?(https?://\S+)', re.I),
        re.compile(r'\bwget\b.*?(https?://\S+)', re.I),
        # certutil -urlcache (LOLBin)
        re.compile(r'certutil.*?-urlcache.*?(https?://\S+)', re.I),
        # bitsadmin /transfer
        re.compile(r'bitsadmin.*?/transfer.*?(https?://\S+)', re.I),
    ]

    # PowerShell outfile patterns
    OUTFILE_PATTERN = re.compile(r'-outfile\s+["\']?([^\s"\']+)', re.I)

    @classmethod
    def detect(cls, telemetry_events: list) -> List[DownloadRecord]:
        """Scan all telemetry events for download patterns."""
        downloads: List[DownloadRecord] = []
        seen_urls: Set[str] = set()

        for event in telemetry_events:
            evt_type = event.get("type", "")
            data = event.get("data", {})
            timestamp = event.get("timestamp", "")

            # Direct HTTP download events
            if evt_type == "HTTP_DOWNLOAD":
                url = data.get("url", data.get("source_url", ""))
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    downloads.append(DownloadRecord(
                        source_url=url,
                        destination_file=data.get("destination", ""),
                        sha256=data.get("sha256", ""),
                        process=data.get("process", ""),
                        timestamp=timestamp,
                    ))

            # HTTP requests that look like downloads
            elif evt_type == "HTTP_REQUEST":
                url = data.get("url", "")
                if url and url not in seen_urls:
                    if ArtifactCollector._looks_like_download(url):
                        seen_urls.add(url)
                        downloads.append(DownloadRecord(
                            source_url=url,
                            destination_file="",
                            process=data.get("process", ""),
                            timestamp=timestamp,
                        ))

            # Command-line download patterns
            elif evt_type == "PROCESS_CREATE":
                cmdline = data.get("cmdline", "")
                decoded = data.get("decoded_cmdline", data.get("normalized_cmdline", ""))
                for cmd_text in (cmdline, decoded):
                    if not cmd_text:
                        continue
                    for pattern in cls.DOWNLOAD_PATTERNS:
                        match = pattern.search(cmd_text)
                        if match:
                            url = match.group(1).rstrip("\"')")
                            if url not in seen_urls:
                                seen_urls.add(url)
                                # Try to find outfile
                                outfile = ""
                                outfile_match = cls.OUTFILE_PATTERN.search(cmd_text)
                                if outfile_match:
                                    outfile = outfile_match.group(1)
                                downloads.append(DownloadRecord(
                                    source_url=url,
                                    destination_file=outfile,
                                    process=cmdline[:200],
                                    timestamp=timestamp,
                                ))

        logger.info(f"[DownloadDetector] Detected {len(downloads)} download(s)")
        return downloads


# ════════════════════════════════════════════════════════════════════════════
# Phase 6-9 — Orchestrator
# ════════════════════════════════════════════════════════════════════════════

class ArtifactEngine:
    """
    Top-level orchestrator that runs the full artifact collection,
    classification, recursive analysis, and download detection pipeline.
    """

    def __init__(self):
        self.analyzer = RecursiveAnalyzer()
        self.artifacts: List[ArtifactResult] = []
        self.downloads: List[DownloadRecord] = []

    def process(self, telemetry_events: list, upload_dir: str = "") -> Dict:
        """
        Run the full artifact engine pipeline.
        Returns a report dict with artifact tree and download records.
        """
        # Phase 1: Collect artifacts from telemetry
        collected = ArtifactCollector.collect(telemetry_events, upload_dir)

        # Phase 5: Detect downloads
        self.downloads = DownloadDetector.detect(telemetry_events)

        # Phase 2-4: Classify and recursively analyze each artifact
        for artifact in collected:
            if not os.path.exists(artifact.path):
                # File may have been created in sandbox but not accessible on host
                # Create a stub result with metadata from telemetry
                stub = ArtifactResult(
                    sha256=artifact.sha256,
                    md5=artifact.md5,
                    filename=os.path.basename(artifact.path),
                    creator_process=artifact.process,
                    source_url=artifact.source_url,
                    relationship=artifact.relationship,
                    file_type="Inaccessible",
                    size=artifact.size,
                )
                self.artifacts.append(stub)
                continue

            result = self.analyzer.analyze(
                file_path=artifact.path,
                relationship=artifact.relationship,
                source_url=artifact.source_url,
                creator_process=artifact.process,
            )
            if result:
                self.artifacts.append(result)

        # Build report
        report = self._build_report()

        logger.info(
            f"[ArtifactEngine] Pipeline complete: "
            f"{len(self.artifacts)} artifact(s), "
            f"{len(self.downloads)} download(s), "
            f"max child risk: {report.get('max_child_risk', 0)}"
        )

        return report

    def _build_report(self) -> Dict:
        """Build the artifact engine report."""
        artifact_tree = [a.to_dict() for a in self.artifacts]

        # Find max child risk for propagation
        max_child_risk = 0
        total_children = 0
        for artifact in self.artifacts:
            max_child_risk = max(max_child_risk, artifact.risk_score)
            total_children += len(artifact.children)
            for child in artifact.children:
                max_child_risk = max(max_child_risk, child.risk_score)

        return {
            "artifact_tree": artifact_tree,
            "artifact_count": len(self.artifacts),
            "total_children": total_children,
            "max_child_risk": max_child_risk,
            "downloads": [
                {
                    "source_url": d.source_url,
                    "destination_file": d.destination_file,
                    "sha256": d.sha256,
                    "process": d.process,
                    "timestamp": d.timestamp,
                }
                for d in self.downloads
            ],
            "download_count": len(self.downloads),
            "suspicious_artifacts": [
                a.to_dict() for a in self.artifacts if a.is_suspicious
            ],
        }

    def get_max_child_risk(self) -> int:
        """Return the highest risk score across all artifacts and their children."""
        max_risk = 0
        for artifact in self.artifacts:
            max_risk = max(max_risk, artifact.risk_score)
            for child in artifact.children:
                max_risk = max(max_risk, child.risk_score)
        return max_risk

    def get_artifact_graph_edges(self) -> List[Dict]:
        """
        Return parent→child edges for graph ingestion.
        Each edge: {parent_sha256, child_sha256, relationship, child_type, child_risk}
        """
        edges: List[Dict] = []

        def _walk(parent_sha256: str, artifacts: List[ArtifactResult]):
            for art in artifacts:
                if parent_sha256:
                    edges.append({
                        "parent_sha256": parent_sha256,
                        "child_sha256": art.sha256,
                        "relationship": art.relationship,
                        "child_type": art.file_type,
                        "child_risk": art.risk_score,
                        "child_filename": art.filename,
                    })
                if art.children:
                    _walk(art.sha256, art.children)

        _walk("", self.artifacts)
        return edges
