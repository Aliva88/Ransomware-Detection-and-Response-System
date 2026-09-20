from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router


app = FastAPI(
    title="Ransomware Detection and Response System",
    version="1.0"
)


app.include_router(router, prefix="/api")


app.mount(
    "/dashboard",
    StaticFiles(directory="app/dashboard", html=True),
    name="dashboard"
)


@app.get("/")
def root():
    return FileResponse("app/dashboard/index.html")