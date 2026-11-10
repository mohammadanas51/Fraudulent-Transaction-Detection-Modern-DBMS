"""Application Runner: Launches FastAPI Server & Security Dashboard."""
import uvicorn
from app.config import settings

def main():
    print("=" * 70)
    print("  EXPLAINABLE MULTI-DIMENSIONAL DATABASE ANOMALY DETECTION")
    print("  Using Behavioral Feature Fusion & Isolation Forest")
    print("=" * 70)
    print(f"Starting server on http://localhost:{settings.APP_PORT} ...")
    print(f"Interactive Swagger Documentation: http://localhost:{settings.APP_PORT}/docs")
    print(f"Security Analyst SOC Dashboard: http://localhost:{settings.APP_PORT}/")
    print("=" * 70)
    uvicorn.run("app.main:app", host="127.0.0.1", port=settings.APP_PORT, reload=False)

if __name__ == "__main__":
    main()
