import os
import redis.asyncio as redis

REDIS_URL = os.getenv('CELERY_BROKER_URL', os.getenv('REDIS_URL', 'redis://localhost:6379/0'))

redis_client = redis.from_url(REDIS_URL)
