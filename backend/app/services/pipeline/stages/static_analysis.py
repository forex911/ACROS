"""Static Analysis Stage — Hash, PE, Python, String extraction."""

from app.services.pipeline.stage import PipelineStage
from app.services.pipeline.context import PipelineContext


class StaticAnalysisStage(PipelineStage):

    @property
    def name(self) -> str:
        return "Static Analysis"

    async def _run(self, context: PipelineContext) -> PipelineContext:
        from app.services.static_analysis.hash_analyzer import analyze_hashes
        from app.services.static_analysis.string_extractor import extract_strings
        from app.services.static_analysis.pe_analyzer import analyze_pe_file
        from app.services.static_analysis.python_analyzer import analyze_python_file

        context.static_results["hash"] = analyze_hashes(context.local_path)
        context.static_results["strings"] = extract_strings(context.local_path)

        if context.filename.endswith(".py"):
            context.static_results["python"] = analyze_python_file(context.local_path)
        else:
            context.static_results["pe"] = analyze_pe_file(context.local_path)

        context.log(f"[Static] Completed hash, strings, and format-specific analysis")
        return context
