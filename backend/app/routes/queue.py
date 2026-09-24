from fastapi import APIRouter

router = APIRouter()


@router.get("/queue")
def queue_status():
    return {"message": "Queue endpoint ready"}
