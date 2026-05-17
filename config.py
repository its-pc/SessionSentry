import os
import secrets

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database/database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = False  # Set True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

    # ML Model path
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml', 'rf_model.pkl')

    # Risk Score thresholds
    RISK_NORMAL = 30
    RISK_SUSPICIOUS = 60
