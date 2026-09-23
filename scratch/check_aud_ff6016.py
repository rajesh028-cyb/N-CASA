import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import asyncio
from sqlalchemy import text
from app.db.session import AsyncSessionLocal
from app.services.audit_service import audit_service

async def check():
    async with AsyncSessionLocal() as session:
        r = await session.execute(text("SELECT * FROM audits WHERE audit_id = 'AUD-FF6016';"))
        audit = r.mappings().fetchone()
        print("Audit AUD-FF6016:", dict(audit) if audit else "NOT FOUND")

    if audit:
        try:
            summary = await audit_service.evaluate_compliance("AUD-FF6016")
            print("Evaluate compliance summary status:", summary.status)
            print("Total results count:", len(summary.results))
            controls = [r.control_id for r in summary.results]
            print("Unique control_ids count:", len(set(controls)))
            if len(controls) != len(set(controls)):
                from collections import Counter
                counts = Counter(controls)
                dups = [k for k, v in counts.items() if v > 1]
                print("DUPLICATE CONTROL IDS IN summary.results:", dups)
        except Exception as e:
            import traceback
            print("EXCEPTION IN EVALUATE COMPLIANCE:")
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(check())
