import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import asyncio
from sqlalchemy import text
from app.db.session import AsyncSessionLocal

async def check():
    async with AsyncSessionLocal() as session:
        r = await session.execute(text("SELECT * FROM audits WHERE audit_id = 'AUD-973360';"))
        audit = r.mappings().fetchone()
        print("Audit record for AUD-973360:", dict(audit) if audit else None)

if __name__ == "__main__":
    asyncio.run(check())
