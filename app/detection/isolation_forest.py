"""Isolation Forest Anomaly Detection Wrapper."""
from pathlib import Path
from typing import Optional, Dict, Any, List
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from app.config import settings
from app.detection.preprocessing import AnomalyPreprocessor

class AnomalyDetector:
    """Manages Isolation Forest training, persistence, and inference."""

    def __init__(
        self,
        n_estimators: int = settings.DEFAULT_ESTIMATORS,
        contamination: float = settings.DEFAULT_CONTAMINATION,
        random_state: int = settings.DEFAULT_RANDOM_STATE
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.preprocessor: Optional[AnomalyPreprocessor] = None

    def fit(self, X: pd.DataFrame, feature_names: List[str]):
        """Trains unsupervised Isolation Forest without labels."""
        if len(X) < 20:
            raise ValueError(f"Insufficient samples to train model. Expected at least 20, got {len(X)}.")

        self.preprocessor = AnomalyPreprocessor(feature_names=feature_names)
        X_scaled = self.preprocessor.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.model.fit(X_scaled)

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Returns binary predictions: 1 for anomaly, 0 for normal."""
        if self.model is None or self.preprocessor is None:
            raise RuntimeError("Model has not been trained or loaded.")
        X_scaled = self.preprocessor.transform(X)
        raw_preds = self.model.predict(X_scaled)
        # scikit-learn returns -1 for anomaly, 1 for normal -> convert to 1 for anomaly, 0 for normal
        return np.where(raw_preds == -1, 1, 0)

    def decision_function(self, X: pd.DataFrame) -> np.ndarray:
        """Returns raw anomaly scores: lower (more negative) is more anomalous."""
        if self.model is None or self.preprocessor is None:
            raise RuntimeError("Model has not been trained or loaded.")
        X_scaled = self.preprocessor.transform(X)
        return self.model.decision_function(X_scaled)

    def save(self, model_path: Path):
        """Persists model and preprocessor to disk."""
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self.model,
            "preprocessor": self.preprocessor,
            "params": {
                "n_estimators": self.n_estimators,
                "contamination": self.contamination,
                "random_state": self.random_state
            }
        }, model_path)

    @classmethod
    def load(cls, model_path: Path) -> "AnomalyDetector":
        """Loads serialized model and preprocessor from disk."""
        data = joblib.load(model_path)
        params = data["params"]
        obj = cls(
            n_estimators=params["n_estimators"],
            contamination=params["contamination"],
            random_state=params["random_state"]
        )
        obj.model = data["model"]
        obj.preprocessor = data["preprocessor"]
        return obj
