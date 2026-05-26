from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

from app.api.routes.upload import router as upload_router
from app.api.routes.auth import router as auth_router
from app.api.routes.jobs import router as jobs_router
from app.api.routes.analysis import router as analysis_router
from app.api.routes.reports import router as report_router
from app.api.routes.graph import router as graph_router
from app.api.routes.hunting import router as hunting_router
from app.api.routes.integrations import router as integrations_router
from app.api.routes.workspace import router as workspace_router
from app.database.mongodb import init_db
import logging

# Setup OpenTelemetry
trace.set_tracer_provider(TracerProvider())
# In production, use OTLPSpanExporter to Jaeger/Tempo
trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

app = FastAPI(
    title="SentinelAI",
    version="1.0.0"
)

@app.on_event("startup")
async def on_startup():
    await init_db()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# OpenTelemetry Instrumentation
FastAPIInstrumentor.instrument_app(app)

# Prometheus Instrumentation
instrumentator = Instrumentator(
    should_group_status_codes=False,
    should_ignore_untemplated=True,
    should_respect_env_var=True,
    should_instrument_requests_inprogress=True,
    excluded_handlers=[".*admin.*", "/metrics"],
    env_var_name="ENABLE_METRICS",
    inprogress_name="inprogress",
    inprogress_labels=True,
)
instrumentator.instrument(app).expose(app)

# Routes
app.include_router(upload_router)
app.include_router(analysis_router)
app.include_router(report_router)
app.include_router(jobs_router)
app.include_router(auth_router)
app.include_router(graph_router)
app.include_router(hunting_router)
app.include_router(integrations_router)
app.include_router(workspace_router)

@app.get("/")
async def root():
    return {
        "message": "SentinelAI Backend Running"
    }