from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


def normalize_database_url(url: str) -> str:
    """Make a hosted provider's DSN usable by SQLAlchemy 2 + psycopg 3.

    Railway, Render, Heroku and Fly all hand out `postgres://...`, which
    SQLAlchemy does not recognise, and `postgresql://...`, which it maps to
    psycopg2 — a driver this project does not install. Both become
    `postgresql+psycopg://`.
    """
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "CyberShield AI"
    environment: str = "development"

    # sqlite by default so `uvicorn app.main:app` works with zero setup.
    # Docker and every cloud deploy override this with postgresql+psycopg://...
    database_url: str = "sqlite:///./cybershield.db"

    # Shared across uvicorn workers: WebSocket fan-out, rate-limit counters,
    # detection windows, alert correlation, simulator ownership. Empty means
    # single worker with in-process state, which is the zero-setup default.
    redis_url: str = ""

    # The port this process listens on. Defaults to the documented local port;
    # Docker and every cloud host inject `PORT`. The lab target URL below is
    # derived from it, so the attack runner always aims at this same process.
    port: int = 8010

    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 720

    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Requests per minute per client IP on the REST API.
    rate_limit_per_minute: int = 300

    # Serve the built SPA from `frontend/dist` when it is present, so a cloud
    # deploy is one service on one origin — no CORS, same-origin WebSocket.
    serve_frontend: bool = True

    # Optional: set ANTHROPIC_API_KEY to upgrade AI explanations from the
    # built-in analyst templates to live model output.
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-opus-5"

    seed_demo_events: int = 250

    # The ONLY host the real attack runner is ever allowed to hit. It is the
    # lab target running in this same deployment. This is server-side config; no
    # request can override it, so attacks can never be pointed at another host.
    # Empty means loopback on whatever port this process was given.
    target_base_url: str = ""

    def model_post_init(self, _context: object) -> None:
        object.__setattr__(self, "database_url", normalize_database_url(self.database_url))
        if not self.target_base_url:
            object.__setattr__(self, "target_base_url", f"http://127.0.0.1:{self.port}")

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_postgres(self) -> bool:
        return self.database_url.startswith("postgresql")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


if __name__ == "__main__":
    assert normalize_database_url("postgres://u:p@h:5432/d") == "postgresql+psycopg://u:p@h:5432/d"
    assert normalize_database_url("postgresql://u:p@h/d") == "postgresql+psycopg://u:p@h/d"
    assert normalize_database_url("postgresql+psycopg://u@h/d") == "postgresql+psycopg://u@h/d"
    assert normalize_database_url("sqlite:///./x.db") == "sqlite:///./x.db"
    print("config ok")
