"""FastAPI Application Entry Point."""
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database.connection import init_db
from app.api.routes import router as api_router

# Try importing Jinja2Templates, fall back gracefully if not installed
try:
    from fastapi.templating import Jinja2Templates
    _has_jinja2 = True
except ImportError:
    _has_jinja2 = False

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

# Initialize FastAPI App
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Explainable Multi-Dimensional Database Anomaly Detection Using Behavioral Feature Fusion",
    lifespan=lifespan
)

# Enable CORS for local testing/dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static and Templates configuration
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

if _has_jinja2:
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
else:
    templates = None

# Include API Router
app.include_router(api_router)

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard(request: Request):
    if _has_jinja2 and templates is not None:
        return templates.TemplateResponse(request=request, name="index.html", context={"app_name": settings.APP_NAME})
    
    # Fallback if Jinja2 is not installed
    html_file = TEMPLATES_DIR / "index.html"
    if html_file.exists():
        content = html_file.read_text(encoding="utf-8")
        content = content.replace("{{ app_name }}", settings.APP_NAME)
        return HTMLResponse(content=content)
    return HTMLResponse("<h1>Dashboard template not found</h1>", status_code=404)
