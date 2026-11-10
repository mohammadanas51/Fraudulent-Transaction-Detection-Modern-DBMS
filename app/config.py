"""Application configuration module."""
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import ConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = ConfigDict(extra="allow", env_file=".env")

    APP_NAME: str = "Explainable Database Anomaly Detection"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    DEBUG: bool = True
    APP_PORT: int = 8000
    APP_HOST: str = "0.0.0.0"
    
    # Storage Paths
    ORIGINAL_DB_PATH: Path = BASE_DIR / "data" / "access_logs.db"
    APP_DB_PATH: Path = BASE_DIR / "data" / "app_metadata.db"
    SYNTHETIC_DB_PATH: Path = BASE_DIR / "data" / "synthetic_sql.db"
    MODEL_DIR: Path = BASE_DIR / "models"
    DATA_DIR: Path = BASE_DIR / "data"
    
    # ML & Detection Defaults
    DEFAULT_CONTAMINATION: float = 0.03
    DEFAULT_ESTIMATORS: int = 200
    DEFAULT_RANDOM_STATE: int = 42
    DEFAULT_ALERT_THRESHOLD: float = 60.0  # 0 to 100 scale
    
    # Working Hours Policy
    WORKING_START_HOUR: int = 8
    WORKING_END_HOUR: int = 18
    OFF_HOURS_BUFFER_HOURS: int = 1
    
    # Inactivity Session Window (minutes)
    SESSION_INACTIVITY_MINUTES: int = 30

settings = Settings()
