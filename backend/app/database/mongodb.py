from motor.motor_asyncio import AsyncIOMotorClient
import pymongo
import logging
from app.core.config import MONGO_URI

logger = logging.getLogger(__name__)

client = AsyncIOMotorClient(MONGO_URI)
db = client["sentinel_ai"]

async def init_db():
    """
    Initialize database indexes and TTL policies.
    """
    try:
        # Users collection
        await db.users.create_index("username", unique=True)
        
        # Jobs collection
        await db.jobs.create_index("job_id", unique=True)
        await db.jobs.create_index("status")
        # 30-day TTL for completed/failed jobs
        await db.jobs.create_index("created_at", expireAfterSeconds=2592000)
        
        # Reports collection
        await db.reports.create_index("report_id", unique=True)
        await db.reports.create_index("job_id")
        await db.reports.create_index("file_hash")
        # 90-day TTL for analysis reports
        await db.reports.create_index("created_at", expireAfterSeconds=7776000)
        
        logger.info("MongoDB indexes and TTL policies initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize MongoDB indexes: {e}")