import os
import logging
import tempfile
import requests
import json
import time
from celery import Celery

from docker_runner import run_in_sandbox

import pymongo
from datetime import datetime
import redis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sandbox.worker")

# Celery configuration - use environment variables
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

celery_app = Celery('sandbox_worker', broker=CELERY_BROKER_URL)

# DB clients (synchronous pymongo and redis for worker process)
mongo_client = pymongo.MongoClient(MONGO_URI)
mongo_db = mongo_client.get_database(os.getenv('DATABASE_NAME', 'aegis_ai'))
jobs_coll = mongo_db.get_collection('jobs')

redis_client = redis.from_url(REDIS_URL)


def publish_update(job_id: str, status: str, progress: int = None, extra: dict = None):
    payload = {"job_id": job_id, "status": status, "ts": int(time.time())}
    if progress is not None:
        payload['progress'] = progress
    if extra:
        payload.update(extra)
    channel = f"job_updates:{job_id}"
    try:
        redis_client.publish(channel, json.dumps(payload))
    except Exception:
        logger.exception("failed publishing update to redis")


def update_job_status(job_id: str, status: str, extra: dict = None):
    update = {"status": status, "updated_at": datetime.utcnow()}
    if extra:
        update.update(extra)
    try:
        jobs_coll.update_one({"job_id": job_id}, {"$set": update})
    except Exception:
        logger.exception("failed updating mongo job status")
    publish_update(job_id, status, extra=(extra or {}))


@celery_app.task(bind=True, acks_late=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def run_sandbox_job(self, job_id: str, artifact_path: str, image: str = 'alpine:3.18', timeout: int = 60):
    """Download artifact (if URL) or use local path and execute in hardened container.

    This task updates MongoDB job states and publishes Redis pubsub events for WebSocket forwarding.
    """
    logger.info("Job %s: starting sandbox run (image=%s)", job_id, image)

    update_job_status(job_id, 'downloading')

    # prepare artifact: if artifact_path is URL, download; if local file exists, use it
    tmpdir = tempfile.mkdtemp(prefix='sandbox-')
    local_path = None
    try:
        if artifact_path.startswith('http'):
            r = requests.get(artifact_path, stream=True, timeout=30)
            r.raise_for_status()
            local_path = os.path.join(tmpdir, 'artifact.bin')
            with open(local_path, 'wb') as fh:
                for chunk in r.iter_content(8192):
                    fh.write(chunk)
        else:
            # assume local path
            if os.path.exists(artifact_path):
                local_path = artifact_path
            else:
                raise FileNotFoundError("artifact not found: %s" % artifact_path)

        update_job_status(job_id, 'initializing')

        # run containerized execution
        update_job_status(job_id, 'running')
        publish_update(job_id, 'running', progress=10)

        cmd = "/bin/sh -c 'ls -la /work && echo executed'"
        seccomp = os.getenv('SECCOMP_PROFILE_PATH')
        result = run_in_sandbox(image=image, command=cmd, artifact_path=local_path, seccomp_profile=seccomp, timeout=timeout)

        # sample metrics and logs
        update_job_status(job_id, 'monitoring')
        publish_update(job_id, 'monitoring', progress=60)

        # pretend to collect behavior & analyze
        update_job_status(job_id, 'analyzing')
        publish_update(job_id, 'analyzing', progress=80)

        # finalize
        jobs_coll.update_one({"job_id": job_id}, {"$push": {"logs": {"ts": datetime.utcnow(), "message": result.get('logs', '')}}})
        update_job_status(job_id, 'report_generating')
        publish_update(job_id, 'report_generating', progress=95)

        # store a small report stub
        jobs_coll.update_one({"job_id": job_id}, {"$set": {"report": {"summary": "execution completed", "exit_code": result.get('exit_code')}, "updated_at": datetime.utcnow()}})

        update_job_status(job_id, 'completed')
        publish_update(job_id, 'completed', progress=100)

        return result
    except Exception as exc:
        logger.exception("job %s failed", job_id)
        try:
            jobs_coll.update_one({"job_id": job_id}, {"$push": {"errors": {"ts": datetime.utcnow(), "error": str(exc)}}, "$set": {"status": "failed", "updated_at": datetime.utcnow()}})
        except Exception:
            logger.exception("failed recording job error")
        publish_update(job_id, 'failed', extra={'error': str(exc)})
        raise
    finally:
        try:
            if local_path and local_path.startswith(tmpdir):
                os.remove(local_path)
            os.rmdir(tmpdir)
        except Exception:
            pass
