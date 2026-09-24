import asyncio
import sys
import os
import shutil

sys.path.insert(0, r"c:\Users\Rajesh\Desktop\N-CASA\backend")
from app.db.session import engine
from sqlalchemy import text

async def reset_db():
    tables = [
        "reports",
        "ai_explanations",
        "ai_analysis_results",
        "remediations",
        "assessment_limitations",
        "findings",
        "compliance_results",
        "normalized_configurations",
        "parsed_configurations",
        "vendor_detections",
        "audit_config_files",
        "audits",
    ]

    async with engine.begin() as conn:
        print("Truncating tables in dependency order...")
        for t in tables:
            try:
                await conn.execute(text(f"TRUNCATE TABLE {t} CASCADE;"))
                print(f"  Truncated {t}")
            except Exception as e:
                print(f"  Notice on {t}: {e}")

    # Check counts
    print("\nVerifying table counts:")
    async with engine.connect() as conn:
        for t in tables:
            try:
                res = await conn.execute(text(f"SELECT COUNT(*) FROM {t};"))
                cnt = res.scalar()
                print(f"  {t}: {cnt}")
            except Exception as e:
                print(f"  {t}: error {e}")

    # Clean local disk uploads and reports
    backend_storage = r"c:\Users\Rajesh\Desktop\N-CASA\backend\storage"
    root_storage = r"c:\Users\Rajesh\Desktop\N-CASA\storage"

    for base in [backend_storage, root_storage]:
        for folder in ["uploads", "reports"]:
            target_dir = os.path.join(base, folder)
            if os.path.exists(target_dir):
                for item in os.listdir(target_dir):
                    item_path = os.path.join(target_dir, item)
                    try:
                        if os.path.isdir(item_path):
                            shutil.rmtree(item_path)
                        else:
                            os.remove(item_path)
                    except Exception as err:
                        print(f"Could not delete {item_path}: {err}")
                print(f"Cleaned storage directory: {target_dir}")

    print("\nDatabase and storage reset complete! Ready for real dataset audit.")

if __name__ == "__main__":
    asyncio.run(reset_db())
