from fastapi import APIRouter, Depends
router = APIRouter(prefix="/items")

@router.get("/")
def list_items():
    return []

@router.api_route("/{item_id}", methods=["GET", "DELETE"])
def item(item_id: int, user=Depends(require_admin)):
    return {}
