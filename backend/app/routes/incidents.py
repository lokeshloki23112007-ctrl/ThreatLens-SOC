from fastapi import APIRouter

router = APIRouter()


@router.get("/incidents")
def list_incidents():
    return {"message": "Incidents endpoint ready"}
