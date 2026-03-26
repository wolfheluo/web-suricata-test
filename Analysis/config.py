"""應用程式配置 — 從環境變數或 .env 讀取"""

import os
from pathlib import Path

# 嘗試載入 .env 檔案
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

# NAS 設定
NAS_MOUNT_PATH = os.getenv("NAS_MOUNT_PATH", "/mnt/nas")

# 工具路徑
SURICATA_EXE = os.getenv("SURICATA_EXE", "/usr/bin/suricata")
TSHARK_EXE = os.getenv("TSHARK_EXE", "/usr/bin/tshark")

# GeoIP 資料庫路徑
GEOIP_DB_PATH = os.getenv(
    "GEOIP_DB_PATH",
    str(Path(__file__).parent / "GeoLite2-City.mmdb"),
)

# 分析結果儲存目錄
PROJECT_DIR = os.getenv(
    "PROJECT_DIR",
    str(Path(__file__).parent / "projects"),
)

# Flask
SECRET_KEY = os.getenv("SECRET_KEY", "analysis-standalone-secret-2025")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "5000"))
DEBUG = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")

# 分析設定
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "4"))
