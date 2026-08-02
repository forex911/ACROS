"""Reset admin user and verify login works end-to-end."""
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

async def reset_admin():
    from app.database.mongodb import db
    from app.core.security import hash_password, verify_password
    
    coll = db["users"]
    
    # Delete existing admin
    result = await coll.delete_many({"username": "admin"})
    print(f"Deleted {result.deleted_count} existing admin user(s)")
    
    # Create fresh admin
    pw = "aegis123"
    hashed = hash_password(pw)
    
    await coll.insert_one({
        "username": "admin",
        "hashed_password": hashed,
        "roles": ["admin", "user"],
        "api_keys": [],
    })
    
    # Verify it's stored correctly
    user = await coll.find_one({"username": "admin"}, projection={"_id": False})
    print(f"Created user: {user['username']}")
    print(f"Roles: {user['roles']}")
    print(f"Hash stored: {user['hashed_password'][:30]}...")
    print(f"Password verify: {verify_password(pw, user['hashed_password'])}")
    
    # Test the exact same flow as the login endpoint
    import httpx
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                "http://127.0.0.1:8000/auth/login",
                json={"username": "admin", "password": "aegis123"},
                timeout=5.0
            )
            print(f"\nAPI Login test: {r.status_code}")
            print(f"Response: {r.text[:200]}")
    except Exception as e:
        print(f"\nAPI test failed (backend may be restarting): {e}")

if __name__ == "__main__":
    asyncio.run(reset_admin())
