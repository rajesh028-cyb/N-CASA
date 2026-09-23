import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import asyncio
from sqlalchemy import text
from app.db.session import AsyncSessionLocal
from app.services.audit_service import audit_service

async def run_test():
    audit_id = "AUD-973360"
    print(f"Testing compliance for {audit_id}...")

    # First call to evaluate_compliance
    summary1 = await audit_service.evaluate_compliance(audit_id)
    print(f"Call 1 success! Controls evaluated: {summary1.summary.total_controls}")

    # Second call to evaluate_compliance (idempotency check)
    summary2 = await audit_service.evaluate_compliance(audit_id)
    print(f"Call 2 success! Controls evaluated: {summary2.summary.total_controls}")

    # Query database to verify unique constraints and row counts
    async with AsyncSessionLocal() as session:
        r = await session.execute(text("SELECT COUNT(*) FROM compliance_results WHERE audit_id = 'AUD-973360';"))
        count = r.scalar()
        print(f"Database compliance_results row count for {audit_id}: {count}")

        r_dup = await session.execute(text(
            "SELECT audit_id, control_id, COUNT(*) FROM compliance_results "
            "WHERE audit_id = 'AUD-973360' GROUP BY audit_id, control_id HAVING COUNT(*) > 1;"
        ))
        dups = r_dup.fetchall()
        print(f"Duplicate control rows count: {len(dups)}")
        assert len(dups) == 0, f"Found duplicate control rows: {dups}"

if __name__ == "__main__":
    asyncio.run(run_test())
