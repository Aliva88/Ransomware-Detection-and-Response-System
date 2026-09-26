from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router


app = FastAPI(
    title="RansomShield | Ransomware Detection & Response",
    version="1.0"
)


# ============================================================
# API ROUTES
# ============================================================

for route in router.routes:
    app.add_api_route(
        "/api" + route.path,
        route.endpoint,
        methods=list(route.methods),
        name=route.name
    )


# ============================================================
# DASHBOARD STATIC FILES
# ============================================================

app.mount(
    "/dashboard",
    StaticFiles(
        directory="app/dashboard",
        html=True
    ),
    name="dashboard"
)


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return RedirectResponse(
        url="/dashboard/"
    )


# ============================================================
# API ROOT CHECK
# ============================================================

@app.get("/api")
def api_root():
    return {
        "status": "ok",
        "service": "RansomShield",
        "version": "1.0",
        "message": "RansomShield API is running."
    }