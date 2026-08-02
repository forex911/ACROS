import asyncio, sys, os
sys.path.insert(0, os.path.dirname(__file__))

async def check():
    from app.database.mongodb import db
    from app.core.security import verify_password
    coll = db["users"]
    cursor = coll.find({})
    docs = await cursor.to_list(100)
    print(f"Total users in DB: {len(docs)}")
    for d in docs:
        ok = verify_password("aegis123", d.get("hashed_password", ""))
        print(f"  username={d['username']}  pw_verify={ok}  hash={d['hashed_password'][:30]}")

asyncio.run(check())
