"""
detector.py — Real-Time Session Hijacking Detection
"""

import os
import sys
import joblib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.feature_extractor import FEATURE_COLUMNS, extract_features, apply_feature_settings

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'rf_model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(__file__), 'scaler.pkl')

_model = None
_scaler = None


def _load():
    global _model, _scaler
    if _model is None and os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH) if os.path.exists(SCALER_PATH) else None


def compute_risk_score(features: dict) -> float:
    score = 0.0

    if features.get('ip_mismatch'):
        score += 25
    if features.get('browser_change'):
        score += 20
    if features.get('cookie_reuse'):
        score += 20
    if features.get('os_change'):
        score += 15

    rate = features.get('request_rate', 0)
    if rate > 30:
        score += 15
    elif rate > 20:
        score += 8

    if features.get('admin_page_attempt'):
        score += 10
    if features.get('direct_page_access'):
        score += 5
    if features.get('night_activity_flag'):
        score += 5

    entropy = features.get('page_sequence_entropy', 1.0)
    if entropy < 0.2:
        score += 10
    elif entropy < 0.4:
        score += 5

    avg_click = features.get('click_interval_avg', 10)
    if avg_click < 0.5:
        score += 10
    elif avg_click < 1.5:
        score += 5

    return min(round(score, 1), 100.0)


def build_reason(features: dict) -> str:
    reasons = []
    if features.get('ip_mismatch') or features.get('ip_change'):
        reasons.append("IP address changed")
    if features.get('browser_change'):
        reasons.append("Browser changed")
    if features.get('os_change'):
        reasons.append("OS changed")
    if features.get('cookie_reuse'):
        reasons.append("Session cookie reused")
    if features.get('request_rate', 0) > 30:
        reasons.append(f"High request rate ({features['request_rate']:.1f}/min)")
    if features.get('admin_page_attempt'):
        reasons.append("Admin page accessed")
    if features.get('direct_page_access'):
        reasons.append("Direct page access (skipped login flow)")
    if features.get('night_activity_flag'):
        reasons.append("Unusual login time")
    if features.get('click_interval_avg', 10) < 1.5:
        reasons.append("Automated/bot-like click speed")
    if features.get('page_sequence_entropy', 1) < 0.3:
        reasons.append("Abnormal navigation pattern")

    return " | ".join(reasons) if reasons else "Behavioral anomaly detected"


def detect(session_obj, logs: list, enabled_features: dict | None = None) -> dict:
    _load()

    raw_features = extract_features(session_obj, logs)
    effective_features = apply_feature_settings(raw_features, enabled_features or {})

    risk_score = compute_risk_score(effective_features)
    reason = build_reason(effective_features)

    ml_prediction = 0
    if _model is not None:
        try:
            feature_vector = np.array([[effective_features[col] for col in FEATURE_COLUMNS]])
            if _scaler:
                feature_vector = _scaler.transform(feature_vector)
            ml_prediction = int(_model.predict(feature_vector)[0])
        except Exception as e:
            print(f"[DETECTOR] ML prediction error: {e}")

    is_hijacked = (ml_prediction == 1) or (risk_score >= 60)

    return {
        'prediction': 1 if is_hijacked else 0,
        'risk_score': risk_score,
        'is_hijacked': is_hijacked,
        'reason': reason,
        'features': effective_features,
        'raw_features': raw_features,
    }
