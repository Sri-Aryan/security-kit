from fastapi import FastAPI, Depends
from app.routers import items
from .deps import get_current_user

app = FastAPI()
app.include_router(items.router, prefix="/api")

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/me")
async def me(user=Depends(get_current_user)):
    return user
