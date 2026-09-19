from fastapi import FastAPI

from app.api.routes import router


app = FastAPI(
    title="Ransomware Detection and Response System",
    version="1.0"
)


app.include_router(router, prefix="/api")