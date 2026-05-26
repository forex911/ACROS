import asyncio
import os
import sys

# Add backend dir to sys.path so 'app' module imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.services.report_generator import generate_report_pipeline

async def main():
    if len(sys.argv) < 2:
        print("Usage: python test_pipeline.py <file.py>")
        return
        
    file_path = sys.argv[1]
    filename = os.path.basename(file_path)
    job_id = "test-job-123"
    
    print(f"Running pipeline on {filename}...")
    report = await generate_report_pipeline(job_id, file_path, filename)
    
    import json
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
