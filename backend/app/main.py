import sys
import asyncio
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
# from opentelemetry.sdk.trace.export import ConsoleSpanExporter
from app.api.routes.upload import router as upload_router
from app.api.routes.auth import router as auth_router
from app.api.routes.jobs import router as jobs_router
from app.api.routes.analysis import router as analysis_router
from app.api.routes.reports import router as report_router
from app.api.routes.graph import router as graph_router
from app.api.routes.hunting import router as hunting_router
from app.api.routes.integrations import router as integrations_router
from app.api.routes.workspace import router as workspace_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.observability import router as observability_router
from app.api.routes.threats import router as threats_router
from app.database.mongodb import init_db, client as mongo_client
from app.database.redis import redis_client
from app.database.neo4j import get_neo4j_async_session
from app.utils.object_store import s3_client
from app.core.config import settings
from app.core.limiter import setup_rate_limiting
from app.core.exceptions import AegisException, aegis_exception_handler, generic_exception_handler
import logging

# Setup OpenTelemetry
trace.set_tracer_provider(TracerProvider())
# In production, use OTLPSpanExporter to Jaeger/Tempo
# trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

app = FastAPI(
    title="ACROS",
    version="1.0.0"
)

@app.on_event("startup")
async def on_startup():
    await init_db()
    
    # Run startup diagnostics
    print("\n--- ACROS Infrastructure Diagnostics ---")
    
    # 1. MongoDB
    try:
        await asyncio.wait_for(mongo_client.admin.command("ping"), timeout=2.0)
        print("[OK] MongoDB")
    except Exception:
        print("[FAIL] MongoDB")

    # 2. Redis
    try:
        await asyncio.wait_for(redis_client.ping(), timeout=2.0)
        print("[OK] Redis")
    except Exception:
        print("[FAIL] Redis")

    # 3. Neo4j & Graph Schema Validation
    try:
        async def check_neo4j_schema():
            from app.models.graph_schema import RelType
            async with get_neo4j_async_session() as session:
                await session.run("RETURN 1")
                # Validate schema against actual database state
                res = await session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType) as types")
                record = await res.single()
                if record:
                    db_types = record["types"]
                    allowed_types = set(RelType.all())
                    unsupported = [t for t in db_types if t not in allowed_types]
                    if unsupported:
                        import logging
                        logging.getLogger("startup").warning(
                            f"Neo4j database contains unsupported relationship types: {unsupported}. "
                            "Ensure queries only reference validated schema constants."
                        )
                        print(f"[WARN] Neo4j Schema (unsupported types: {unsupported})")
                    else:
                        print("[OK] Neo4j")
        await asyncio.wait_for(check_neo4j_schema(), timeout=2.0)
    except Exception as e:
        print(f"[FAIL] Neo4j ({e})")

    # 4. MinIO
    try:
        minio_client = s3_client()
        await asyncio.wait_for(
            asyncio.to_thread(minio_client.head_bucket, Bucket=settings.S3_BUCKET),
            timeout=2.0
        )
        print("[OK] MinIO")
    except Exception as e:
        import botocore.exceptions
        if isinstance(e, botocore.exceptions.ClientError) and e.response['Error']['Code'] == '404':
            from app.utils.object_store import init_s3_lifecycle
            await asyncio.to_thread(init_s3_lifecycle)
            print("[OK] MinIO (Bucket Created & Lifecycle Set)")
        else:
            print(f"[FAIL] MinIO ({e})")

    # 5. YARA
    from app.services.yara_service import YaraService
    yara_svc = YaraService()
    if yara_svc.rules is not None:
        print(f"[OK] YARA (Rules loaded)")
    else:
        print("[WARN] YARA Rules Missing")
        
    print("-------------------------------------------\n")

# Rate Limiting setup
setup_rate_limiting(app)

# Global Exception Handlers
app.add_exception_handler(AegisException, aegis_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

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
app.include_router(dashboard_router)
app.include_router(observability_router)
app.include_router(threats_router)

@app.get("/")
async def root():
    return {
        "message": "ACROS Backend Running"
    }

@app.get("/health")
async def health():
    """
    Production-grade readiness and liveness probe endpoint.
    Checks connectivity to all core infrastructure components.
    """
    health_status = {"status": "ok", "components": {}}
    
    # 1. MongoDB
    try:
        await asyncio.wait_for(mongo_client.admin.command("ping"), timeout=2.0)
        health_status["components"]["mongodb"] = "ok"
    except Exception as e:
        health_status["components"]["mongodb"] = "error"
        health_status["status"] = "error"

    # 2. Redis
    try:
        await asyncio.wait_for(redis_client.ping(), timeout=2.0)
        health_status["components"]["redis"] = "ok"
    except Exception as e:
        health_status["components"]["redis"] = "error"
        health_status["status"] = "error"

    # 3. Neo4j
    try:
        async def check_neo4j():
            async with get_neo4j_async_session() as session:
                await session.run("RETURN 1")
        await asyncio.wait_for(check_neo4j(), timeout=2.0)
        health_status["components"]["neo4j"] = "ok"
    except Exception as e:
        health_status["components"]["neo4j"] = "error"
        health_status["status"] = "error"

    # 4. MinIO / S3
    try:
        minio_client = s3_client()
        await asyncio.wait_for(
            asyncio.to_thread(minio_client.head_bucket, Bucket=settings.S3_BUCKET),
            timeout=2.0
        )
        health_status["components"]["minio"] = "ok"
    except Exception as e:
        # It's possible the bucket doesn't exist yet, but connection is successful.
        # We catch the ClientError but distinguish it from generic connection error.
        import botocore.exceptions
        if isinstance(e, botocore.exceptions.ClientError) and e.response['Error']['Code'] == '404':
             health_status["components"]["minio"] = "ok_bucket_missing"
        else:
             health_status["components"]["minio"] = "error"
             health_status["status"] = "error"

    if health_status["status"] == "error":
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail=health_status)

    return health_status

@app.get("/health/neo4j")
async def neo4j_health():
    """Specific health check for the Neo4j Graph DB."""
    try:
        async with get_neo4j_async_session() as session:
            res = await session.run("MATCH (n) RETURN count(n) as node_count")
            node_record = await res.single()
            res_rel = await session.run("MATCH ()-[r]->() RETURN count(r) as rel_count")
            rel_record = await res_rel.single()
            
            return {
                "status": "healthy",
                "bolt": True,
                "nodes": node_record["node_count"],
                "relationships": rel_record["rel_count"]
            }
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail={"status": "error", "error": str(e)})

@app.get("/health/minio")
async def minio_health():
    """Specific health check for MinIO Object Storage."""
    try:
        minio_client = s3_client()
        # Verify bucket exists
        await asyncio.to_thread(minio_client.head_bucket, Bucket=settings.S3_BUCKET)
        
        # Test upload/download permissions
        test_key = "healthcheck/test.txt"
        await asyncio.to_thread(minio_client.put_object, Bucket=settings.S3_BUCKET, Key=test_key, Body=b"ok")
        await asyncio.to_thread(minio_client.delete_object, Bucket=settings.S3_BUCKET, Key=test_key)
        
        return {
            "status": "healthy",
            "bucket_access": True,
            "read_write": True
        }
    except Exception as e:
        import botocore.exceptions
        if isinstance(e, botocore.exceptions.ClientError) and e.response['Error']['Code'] == '404':
            from fastapi import HTTPException
            raise HTTPException(status_code=503, detail={"status": "degraded", "error": "Bucket missing. Run minio setup."})
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail={"status": "error", "error": str(e)})

@app.get("/health/yara")
async def yara_health():
    """Specific health check for YARA compilation."""
    from app.services.yara_service import YaraService
    yara_svc = YaraService()
    
    if yara_svc.rules is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail={"status": "error", "loaded_rules": 0})
        
    return {
        "status": "healthy",
        "loaded_rules": 1 # yara-python does not expose rule count easily on compiled objects, returning 1 for OK
    }

@app.get("/sandbox/firecracker/health")
async def firecracker_health():
    """
    Firecracker-specific health probe. Reports kernel, rootfs, vsock,
    and API socket availability. Only meaningful when SANDBOX_MODE=firecracker.
    """
    from app.core.config import settings
    import os

    if settings.SANDBOX_MODE != "firecracker":
        return {
            "status": "skipped",
            "reason": f"SANDBOX_MODE is '{settings.SANDBOX_MODE}', not 'firecracker'"
        }

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../vm-image"))
    kernel_path = os.path.join(base_dir, "vmlinux")
    rootfs_path = os.path.join(base_dir, "rootfs.ext4")

    checks = {
        "kernel": {"path": kernel_path, "exists": os.path.isfile(kernel_path)},
        "rootfs": {"path": rootfs_path, "exists": os.path.isfile(rootfs_path)},
        "firecracker_binary": {"available": await asyncio.to_thread(lambda: os.system("which firecracker > /dev/null 2>&1") == 0)},
    }

    # Check for any active vsock or API sockets from running VMs
    import glob
    active_api_sockets = glob.glob("/tmp/firecracker-*.socket")
    active_vsock_sockets = glob.glob("/tmp/v.sock-*")

    checks["active_vms"] = {
        "api_sockets": active_api_sockets,
        "vsock_sockets": active_vsock_sockets,
        "count": len(active_api_sockets)
    }

    all_ok = checks["kernel"]["exists"] and checks["rootfs"]["exists"]
    return {
        "status": "ok" if all_ok else "degraded",
        "components": checks
    }
