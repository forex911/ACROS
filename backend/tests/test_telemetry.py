"""
Telemetry Validator + Normalizer — Test Suite
==============================================
Tests event validation, size limits, event caps, deduplication, and normalization.
"""

import pytest
from app.services.telemetry.validator import (
    validate_event, validate_event_stream,
    MAX_EVENTS_PER_JOB, MAX_DATA_SIZE,
)
from app.services.telemetry.normalizer import normalize_telemetry
from app.services.telemetry.stats import compute_telemetry_stats


# ═══════════════════════════════════════════════════════════════════════
# Validator Tests
# ═══════════════════════════════════════════════════════════════════════

class TestValidateEvent:

    def test_valid_event_passes(self):
        event = {"type": "PROCESS_CREATE", "data": {"pid": 123}, "timestamp": "2025-01-01T00:00:00Z"}
        result = validate_event(event)
        assert result is not None
        assert result["type"] == "PROCESS_CREATE"

    def test_missing_type_rejected(self):
        event = {"data": {"pid": 123}}
        result = validate_event(event)
        assert result is None

    def test_missing_data_rejected(self):
        event = {"type": "PROCESS_CREATE"}
        result = validate_event(event)
        assert result is None

    def test_non_dict_rejected(self):
        assert validate_event("not a dict") is None
        assert validate_event(42) is None
        assert validate_event(None) is None

    def test_non_dict_data_rejected(self):
        event = {"type": "DNS_QUERY", "data": "not a dict"}
        assert validate_event(event) is None

    def test_empty_type_rejected(self):
        event = {"type": "", "data": {}}
        assert validate_event(event) is None

    def test_timestamp_auto_filled(self):
        event = {"type": "PROCESS_CREATE", "data": {"pid": 1}}
        result = validate_event(event)
        assert result is not None
        assert "timestamp" in result
        assert result["timestamp"].endswith("Z")

    def test_severity_auto_filled(self):
        event = {"type": "DNS_QUERY", "data": {"query": "evil.com"}, "timestamp": "t"}
        result = validate_event(event)
        assert result["severity"] == "info"

    def test_unknown_event_type_still_passes(self):
        """Unknown types pass through (future-proofing)."""
        event = {"type": "FUTURE_TYPE", "data": {"x": 1}, "timestamp": "t"}
        result = validate_event(event)
        assert result is not None

    def test_oversized_data_rejected(self):
        """Events with data payload > 64KB are dropped."""
        huge_data = {"payload": "x" * (MAX_DATA_SIZE + 1)}
        event = {"type": "PROCESS_CREATE", "data": huge_data, "timestamp": "t"}
        result = validate_event(event)
        assert result is None


class TestValidateEventStream:

    def test_empty_stream(self):
        assert validate_event_stream([]) == []

    def test_mixed_valid_invalid(self):
        events = [
            {"type": "PROCESS_CREATE", "data": {"pid": 1}},
            "invalid",
            {"type": "DNS_QUERY", "data": {"query": "x"}},
            {"data": {"missing_type": True}},
        ]
        result = validate_event_stream(events)
        assert len(result) == 2

    def test_event_cap(self):
        """Stream is capped at MAX_EVENTS_PER_JOB."""
        events = [{"type": "PROCESS_CREATE", "data": {"pid": i}} for i in range(MAX_EVENTS_PER_JOB + 100)]
        result = validate_event_stream(events)
        assert len(result) == MAX_EVENTS_PER_JOB


# ═══════════════════════════════════════════════════════════════════════
# Normalizer Tests
# ═══════════════════════════════════════════════════════════════════════

class TestNormalizeTelemetry:

    def test_empty_events(self):
        assert normalize_telemetry([]) == []

    def test_enriches_with_job_id(self):
        events = [{"type": "DNS_QUERY", "data": {"query": "evil.com"}}]
        result = normalize_telemetry(events, job_id="test-job-1")
        assert result[0]["job_id"] == "test-job-1"

    def test_deduplicates_same_process(self):
        events = [
            {"type": "PROCESS_CREATE", "data": {"pid": 123, "cmdline": "cmd.exe"}},
            {"type": "PROCESS_CREATE", "data": {"pid": 123, "cmdline": "cmd.exe"}},
        ]
        result = normalize_telemetry(events)
        assert len(result) == 1

    def test_does_not_dedup_different_pids(self):
        events = [
            {"type": "PROCESS_CREATE", "data": {"pid": 123, "cmdline": "cmd.exe"}},
            {"type": "PROCESS_CREATE", "data": {"pid": 456, "cmdline": "cmd.exe"}},
        ]
        result = normalize_telemetry(events)
        assert len(result) == 2

    def test_deduplicates_dns_queries(self):
        events = [
            {"type": "DNS_QUERY", "data": {"query": "evil.com"}},
            {"type": "DNS_QUERY", "data": {"query": "evil.com"}},
            {"type": "DNS_QUERY", "data": {"query": "other.com"}},
        ]
        result = normalize_telemetry(events)
        assert len(result) == 2

    def test_deduplicates_network_events(self):
        events = [
            {"type": "SOCKET_CONNECT", "data": {"dest_ip": "1.2.3.4", "dest_port": 443}},
            {"type": "SOCKET_CONNECT", "data": {"dest_ip": "1.2.3.4", "dest_port": 443}},
        ]
        result = normalize_telemetry(events)
        assert len(result) == 1

    def test_drops_invalid_in_stream(self):
        events = [
            {"type": "PROCESS_CREATE", "data": {"pid": 1}},
            "garbage",
            42,
            {"type": "DNS_QUERY", "data": {"query": "test.com"}},
        ]
        result = normalize_telemetry(events, job_id="j1")
        assert len(result) == 2

    def test_converts_dataclass_events(self):
        """Typed TelemetryProvider events should be converted to dicts."""
        from app.services.telemetry.provider import ProcessEvent, DnsEvent
        events = [
            ProcessEvent(pid=100, ppid=1, name="malware.exe", cmdline="malware.exe --drop"),
            DnsEvent(pid=100, query="c2.evil.com"),
        ]
        result = normalize_telemetry(events, job_id="typed-test")
        assert len(result) == 2
        assert result[0]["type"] == "PROCESS_CREATE"
        assert result[0]["data"]["pid"] == 100
        assert result[1]["type"] == "DNS_QUERY"
        assert result[1]["data"]["query"] == "c2.evil.com"


# ═══════════════════════════════════════════════════════════════════════
# Stats Tests
# ═══════════════════════════════════════════════════════════════════════

class TestTelemetryStats:

    def test_empty_events(self):
        stats = compute_telemetry_stats([])
        assert stats["total_events"] == 0
        assert stats["unique_pids"] == 0

    def test_counts_by_type(self):
        events = [
            {"type": "PROCESS_CREATE", "data": {"pid": 1}, "severity": "high"},
            {"type": "PROCESS_CREATE", "data": {"pid": 2}, "severity": "high"},
            {"type": "DNS_QUERY", "data": {"pid": 1, "query": "evil.com"}, "severity": "info"},
        ]
        stats = compute_telemetry_stats(events)
        assert stats["total_events"] == 3
        assert stats["by_type"]["PROCESS_CREATE"] == 2
        assert stats["by_type"]["DNS_QUERY"] == 1

    def test_unique_pids_and_domains(self):
        events = [
            {"type": "PROCESS_CREATE", "data": {"pid": 1}, "severity": "high"},
            {"type": "DNS_QUERY", "data": {"pid": 1, "query": "a.com"}, "severity": "info"},
            {"type": "DNS_QUERY", "data": {"pid": 2, "query": "b.com"}, "severity": "info"},
            {"type": "SOCKET_CONNECT", "data": {"pid": 1, "dest_ip": "1.2.3.4"}, "severity": "medium"},
        ]
        stats = compute_telemetry_stats(events)
        assert stats["unique_pids"] == 2
        assert stats["unique_domains"] == 2
        assert stats["unique_ips"] == 1
        assert stats["has_network"] is True

    def test_behavioral_flags(self):
        events = [
            {"type": "PERSISTENCE_EVENT", "data": {"pid": 1, "mechanism": "run_key"}, "severity": "high"},
            {"type": "MEMORY_INJECTION", "data": {"source_pid": 1, "target_pid": 2}, "severity": "high"},
        ]
        stats = compute_telemetry_stats(events)
        assert stats["has_persistence"] is True
        assert stats["has_injection"] is True
        assert stats["has_network"] is False
