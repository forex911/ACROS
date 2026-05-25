from fastapi import APIRouter

router = APIRouter()

@router.get("/analysis/{file_id}")

async def get_analysis(file_id: str):

    return {
        "file_id": file_id,
        "status": "completed"
    }