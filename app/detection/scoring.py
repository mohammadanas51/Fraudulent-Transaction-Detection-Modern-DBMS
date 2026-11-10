"""Anomaly Score Normalization and Calibrated Risk Classification."""
import numpy as np

class ScoreNormalizer:
    """Converts scikit-learn decision_function values to an explainable 0-100 risk score.
    
    Mathematical Formulation:
        Let s be the raw decision_function score from Isolation Forest.
        Higher s indicates denser / normal regions; lower negative s indicates sparse / anomalous regions.
        We apply a calibrated sigmoid transformation:
            z = -12.0 * s
            risk_score = 100.0 / (1.0 + exp(-z))
        
        Properties:
            - s = +0.20 -> Risk ~ 8.3   (Very Normal)
            - s = +0.05 -> Risk ~ 35.4  (Normal)
            - s =  0.00 -> Risk = 50.0  (Model Decision Boundary)
            - s = -0.05 -> Risk ~ 64.6  (High Anomaly)
            - s = -0.15 -> Risk ~ 85.8  (Critical Anomaly)
            
    Note:
        This score reflects empirical multi-dimensional isolation depth and baseline deviation.
        It does NOT represent a Bayesian probability of a cyber attack.
    """

    @staticmethod
    def raw_to_risk_score(raw_scores: np.ndarray) -> np.ndarray:
        """Converts raw decision scores to normalized 0-100 anomaly scores."""
        z = -12.0 * np.asarray(raw_scores, dtype=float)
        # Numerical stability clip for sigmoid
        z_clipped = np.clip(z, -30.0, 30.0)
        risk_scores = 100.0 / (1.0 + np.exp(-z_clipped))
        return np.round(risk_scores, 2)

    @staticmethod
    def get_severity(risk_score: float) -> str:
        """Categorizes 0-100 risk score into standard SOC alert severities."""
        if risk_score >= 80.0:
            return "CRITICAL"
        elif risk_score >= 60.0:
            return "HIGH"
        elif risk_score >= 45.0:
            return "MEDIUM"
        else:
            return "LOW"
