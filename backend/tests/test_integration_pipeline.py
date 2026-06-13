import pytest
import asyncio
from unittest.mock import patch, MagicMock

from app.services.report_generator import generate_report_pipeline
from app.services.sandbox.orchestrator import publish_state

@pytest.fixture
def mock_telemetry():
    return [
        {
            "type": "PROCESS_CREATE",
            "timestamp": "2023-10-27T10:00:00Z",
            "data": {"pid": 123, "ppid": 100, "name": "malware.exe", "cmdline": "malware.exe --drop"}
        },
        {
            "type": "DNS_QUERY",
            "timestamp": "2023-10-27T10:00:01Z",
            "data": {"pid": 123, "query": "evil-c2.com", "resolved_ip": "192.168.1.100"}
        },
        {
            "type": "SOCKET_CONNECT",
            "timestamp": "2023-10-27T10:00:02Z",
            "data": {"pid": 123, "dest_ip": "8.8.8.8", "dest_port": 443}
        }
    ]

@pytest.fixture
def mock_static():
    return {
        "hash": {"sha256": "abcdef123456", "md5": "123456abcdef"},
        "strings": {"ips": [], "domains": [], "urls": [], "interesting": []},
        "pe": {"is_pe": True, "is_packed": False, "suspicious_apis": []}
    }


@pytest.mark.asyncio
@patch("app.services.report_generator.analyze_hashes")
@patch("app.services.report_generator.extract_strings")
@patch("app.services.report_generator.analyze_pe_file")
@patch("app.services.report_generator.orchestrate_sandbox")
@patch("app.services.yara_service.YaraService")
@patch("app.services.report_generator.GraphIngester")
@patch("app.services.report_generator.update_job_status")
@patch("app.services.report_generator.set_report")
@patch("app.services.report_generator.publish_state")
@patch("app.services.report_generator.append_log")
@patch("app.services.threat_correlation.get_neo4j_async_session")
async def test_integration_pipeline(
    mock_neo4j, mock_append_log, mock_publish_state, mock_set_report, mock_update_status,
    MockGraphIngester, MockYaraService, mock_orchestrate, mock_analyze_pe,
    mock_extract_strings, mock_analyze_hashes, mock_telemetry, mock_static
):
    """
    Tests the end-to-end report generation pipeline to ensure all components
    (Static, Sandbox, IOC, MITRE, Timeline, Scoring, Graph) are called and wired correctly.
    """
    job_id = "test-job-123"
    local_path = "/tmp/malware.exe"
    
    # Setup Mocks
    mock_analyze_hashes.return_value = mock_static["hash"]
    mock_extract_strings.return_value = mock_static["strings"]
    mock_analyze_pe.return_value = mock_static["pe"]
    mock_orchestrate.return_value = mock_telemetry
    
    from unittest.mock import AsyncMock
    MockGraphIngester.ingest_job_execution = AsyncMock()
    MockGraphIngester.ingest_process_event = AsyncMock()
    MockGraphIngester.ingest_network_event = AsyncMock()
    MockGraphIngester.ingest_dns_event = AsyncMock()
    MockGraphIngester.ingest_iocs_batch = AsyncMock()
    MockGraphIngester.ingest_attack_technique = AsyncMock()
    MockGraphIngester.ingest_yara_match = AsyncMock()
    
    
    mock_yara_instance = MagicMock()
    mock_yara_instance.scan_file.return_value = [{"rule": "test_rule"}]
    MockYaraService.return_value = mock_yara_instance
    
    # Execute Pipeline
    report = await generate_report_pipeline(job_id, local_path, "malware.exe")
    
    # 1. Assert Pipeline Output Structure
    assert "metadata" in report
    assert "mitre_tactics" in report
    assert "risk_score" in report
    assert "iocs" in report
    assert "attack_timeline" in report
    assert "telemetry_events" in report
    
    # 2. Assert IOC Extraction
    iocs = {ioc["value"]: ioc for ioc in report["iocs"]}
    assert "evil-c2.com" in iocs
    assert "8.8.8.8" in iocs
    
    # 3. Assert MITRE Mapping
    tactics = [t["name"] for t in report["mitre_tactics"]]
    assert any("Command and Control" in t or "Network Service Discovery" in t for t in tactics)
    
    # 4. Assert Threat Timeline Correlation
    timeline = report["attack_timeline"]
    assert len(timeline) == 3
    assert timeline[0]["type"] == "PROCESS_CREATE"
    assert timeline[1]["type"] == "DNS_QUERY"
    assert timeline[2]["type"] == "SOCKET_CONNECT"
    
    # 5. Assert Graph Ingestion Calls
    MockGraphIngester.ingest_job_execution.assert_called_once_with(job_id, "abcdef123456", "malware.exe")
    assert MockGraphIngester.ingest_process_event.called
    assert MockGraphIngester.ingest_network_event.called
    assert MockGraphIngester.ingest_dns_event.called
    assert MockGraphIngester.ingest_iocs_batch.called
    assert MockGraphIngester.ingest_attack_technique.called
    
    # 6. Assert MongoDB Status Updates
    mock_update_status.assert_called_with(job_id, "analyzing")
    mock_set_report.assert_called_once()
    
    # 7. Assert WebSocket Pub/Sub
    mock_publish_state.assert_any_call(job_id, "CREATED", {"status": "created"})
    mock_publish_state.assert_any_call(job_id, "COMPLETED")
