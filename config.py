import os
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-in-production-please-1234567890")
    SQLALCHEMY_DATABASE_URI = "sqlite:///wti.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8
