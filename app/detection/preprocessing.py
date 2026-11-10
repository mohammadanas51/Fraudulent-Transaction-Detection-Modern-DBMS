"""Data Preprocessing Pipeline: Scaling, Imputation, and Artifact Serialization."""
from pathlib import Path
from typing import List, Optional
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

class AnomalyPreprocessor:
    """Handles feature scaling and schema validation consistently across train and inference."""

    def __init__(self, feature_names: List[str]):
        self.feature_names = feature_names
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit_transform(self, X: pd.DataFrame) -> np.ndarray:
        """Fits scaler on training data and returns scaled numpy array."""
        self._validate_schema(X)
        X_clean = self._impute(X[self.feature_names])
        scaled = self.scaler.fit_transform(X_clean)
        self.is_fitted = True
        return scaled

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Transforms incoming inference data using fitted scaler."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before transforming data.")
        self._validate_schema(X)
        X_clean = self._impute(X[self.feature_names])
        return self.scaler.transform(X_clean)

    def _validate_schema(self, X: pd.DataFrame):
        missing_cols = [c for c in self.feature_names if c not in X.columns]
        if missing_cols:
            raise ValueError(f"Input data is missing expected feature columns: {missing_cols}")

    def _impute(self, df: pd.DataFrame) -> pd.DataFrame:
        clean = df.copy()
        for col in clean.columns:
            clean[col] = pd.to_numeric(clean[col], errors="coerce").fillna(0.0)
        return clean

    def save(self, filepath: Path):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"scaler": self.scaler, "feature_names": self.feature_names, "is_fitted": self.is_fitted}, filepath)

    @classmethod
    def load(cls, filepath: Path) -> "AnomalyPreprocessor":
        data = joblib.load(filepath)
        obj = cls(feature_names=data["feature_names"])
        obj.scaler = data["scaler"]
        obj.is_fitted = data["is_fitted"]
        return obj
