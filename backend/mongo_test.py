import asyncio
import pymongo
from motor.motor_asyncio import AsyncIOMotorClient

async def test_mongo():
    try:
        client = AsyncIOMotorClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
        db = client["sentinel_ai"]
        print("Pinging...")
        await db.command("ping")
        print("Connected to MongoDB!")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    asyncio.run(test_mongo())
