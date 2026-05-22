import os
from typing import ClassVar


class Config:
    SECRET_KEY: ClassVar[str] = os.environ.get("SECRET_KEY", "change-this-in-production-please-1234567890")
    SQLALCHEMY_DATABASE_URI: ClassVar[str] = os.environ.get(
        "DATABASE_URL",
        "postgresql://neondb_owner:npg_j1cxKDdeH0Ff@ep-wild-lake-aozilfkb.c-2.ap-southeast-1.aws.neon.tech/neondb?sslmode=require",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: ClassVar[bool] = False
    SESSION_COOKIE_HTTPONLY: ClassVar[bool] = True
    SESSION_COOKIE_SAMESITE: ClassVar[str] = "Lax"
    PERMANENT_SESSION_LIFETIME: ClassVar[int] = 60 * 60 * 8
