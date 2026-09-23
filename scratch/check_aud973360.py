import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import asyncio
from sqlalchemy import text
from app.db.session import AsyncSessionLocal

async def check():
    async with AsyncSessionLocal() as session:
        r = await session.execute(text("SELECT audit_id, control_id, status FROM compliance_results WHERE audit_id = 'AUD-973360' ORDER BY control_id;"))
        rows = r.fetchall()
        print(f"AUD-973360 compliance rows count: {len(rows)}")
        for row in rows:
            print(row)

if __name__ == "__main__":
    asyncio.run(check())
