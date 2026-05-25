from fastapi import APIRouter

router = APIRouter()

@router.get("/reports/{file_id}")

async def generate_report(file_id: str):

    return {
        "message": f"Report generated for {file_id}"
    }