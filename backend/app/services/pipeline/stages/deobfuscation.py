"""Deobfuscation Stage — Universal deobfuscation and normalization."""

import os
from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext


class DeobfuscationStage(PipelineStage):

    @property
    def name(self) -> str:
        return "Deobfuscation"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        from app.analysis.deobfuscation import UniversalDeobfuscator

        deobfuscator = UniversalDeobfuscator()

        # Deobfuscate telemetry (attaches decoded_cmdline, normalized_cmdline to events)
        context.deobfuscation_report = deobfuscator.process_telemetry(context.telemetry_events)

        # Deobfuscate static strings
        deobfuscator.process_static_strings(context.static_results)

        decoded_count = context.deobfuscation_report["total_fields_decoded"]
        layers_count = context.deobfuscation_report["total_encoding_layers_stripped"]
        iocs_recovered = len(context.deobfuscation_report.get("recovered_iocs", []))
        context.log(
            f"[Deobfuscation] Decoded {decoded_count} fields, "
            f"stripped {layers_count} layers, recovered {iocs_recovered} IOCs"
        )
        return context
