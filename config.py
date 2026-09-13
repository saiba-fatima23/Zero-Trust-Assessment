import os
from dotenv import load_dotenv

load_dotenv()


def _env(name, default=""):
    """Like os.getenv, but treats an explicitly-blank env var as unset too
    (Vercel/other dashboards can leave a variable present with an empty
    value, which os.getenv() alone would return as "" instead of falling
    back to the default)."""
    value = os.getenv(name)
    return value if value not in (None, "") else default


class Config:
    """Application configuration."""

    SECRET_KEY = _env(
        "SECRET_KEY",
        "development-secret-key-change-in-production"
    )

    # On Vercel the filesystem is read-only except /tmp, and /tmp is not
    # shared across function instances — so SQLite there is fine only for
    # quick smoke-testing, never for real multi-user data. Set DATABASE_URL
    # (e.g. to a Postgres URL from Neon/Supabase/Vercel Postgres) for
    # anything real.
    _default_db_uri = (
        "sqlite:////tmp/vulnerability.db"
        if os.getenv("VERCEL")
        else "sqlite:///vulnerability.db"
    )
    SQLALCHEMY_DATABASE_URI = _env("DATABASE_URL", _default_db_uri)
    # Some providers (e.g. older Heroku/Supabase URLs) hand out
    # "postgres://" which SQLAlchemy 1.4+ no longer accepts.
    if SQLALCHEMY_DATABASE_URI.startswith("postgres://"):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace(
            "postgres://", "postgresql://", 1
        )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_CONTENT_LENGTH = 16 * 1024 * 1024

    # Session / cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env("SESSION_COOKIE_SECURE", "True").lower() == "true"
    REMEMBER_COOKIE_DURATION = 60 * 60 * 24 * 7  # 7 days

    # Email Configuration — all optional. If MAIL_USERNAME is left unset,
    # auth.py logs the verification link instead of emailing it.
    MAIL_SERVER = _env("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(_env("MAIL_PORT", "587"))
    MAIL_USE_TLS = _env("MAIL_USE_TLS", "True").lower() == "true"
    MAIL_USERNAME = _env("MAIL_USERNAME", "")
    MAIL_PASSWORD = _env("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = _env("MAIL_DEFAULT_SENDER", MAIL_USERNAME)
