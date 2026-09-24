from fastapi import APIRouter

router = APIRouter()


@router.get("/campaigns")
def list_campaigns():
    return {"message": "Campaigns endpoint ready"}
