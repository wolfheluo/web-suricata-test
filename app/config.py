"""Application settings loaded from .env via pydantic-settings."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # NAS
    NAS_HOST: str = "192.168.22.65"
    NAS_SHARE: str = "ctc_nas"
    NAS_USERNAME: str = ""
    NAS_PASSWORD: str = ""
    NAS_MOUNT_PATH: str = "/mnt/nas"

    # App
    SECRET_KEY: str = "changeme"
    DATABASE_URL: str = "mysql+aiomysql://suricata:pass@127.0.0.1:3306/suricata"

    # Redis
    REDIS_URL: str = "redis://127.0.0.1:6379/0"

    # Optional
    GEOIP_DB_PATH: str = "/www/wwwroot/suricata-web/GeoLite2-City.mmdb"
    MAX_WORKER_CONCURRENCY: int = 4
    ALLOWED_ORIGINS: str = "http://localhost:3000"

    # JWT
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
