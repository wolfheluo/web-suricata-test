# Suricata Web 服務 — AI Agent 實作計劃

## 文件說明
本文件供 AI 編碼 Agent 實作 Suricata web 服務使用。
開始寫任何程式碼前，請先閱讀整份文件，並嚴格遵守所有限制條件。

---

## 專案基本資訊
```yaml
project_name: suricata-web
base_language: Python 3.12
web_framework: FastAPI（純 REST API）+ React 18 + Tailwind CSS + Vite
task_runner: Celery + Redis
database: MySQL
deployment: aaPanel（Python 專案管理器 + Nginx + Supervisor）
source_data: NAS（SMB/CIFS 掛載）— 不提供檔案上傳功能
created: 2026-03-24
```

---

## 重要限制（禁止違反）

1. **禁止 PCAP 上傳端點。** PCAP 檔案直接從 NAS 讀取，絕對不能實作 PCAP 上傳功能。
2. **NAS 憑證為機密。** 禁止將憑證寫死在原始碼中，必須從環境變數讀取。
3. **NAS 路徑穿越防護。** 使用者提供的所有 NAS 資料夾路徑，必須驗證確保在 `NAS_MOUNT_PATH`（環境變數）範圍內。
4. **正式環境禁用 Uvicorn 單程序開發模式。** 必須使用 Gunicorn + UvicornWorker，且 worker 數量 ≥ 4。
5. **所有 Suricata / tshark 工作必須非同步執行**（透過 Celery）。禁止在 HTTP 請求中等待分析完成。
6. **JWT 存取 Token 有效期 15 分鐘。** 更新 Token 有效期 7 天。
7. **Celery 工作目錄用後必須清理。** 分析完成或失敗後，刪除 `/tmp/suricata-<task_id>/` 暫存目錄，避免磁碟空間耗盡。

---

## 環境變數（必要 — 從 `.env` 讀取）

```dotenv
# NAS 連線設定
NAS_HOST=192.168.22.65
NAS_SHARE=ctc_nas
NAS_USERNAME=<NAS 使用者名稱>
NAS_PASSWORD=<NAS 密碼>

# 應用程式設定
SECRET_KEY=<隨機 64 位元組十六進位字串>
DATABASE_URL=mysql+aiomysql://suricata:pass@127.0.0.1:3306/suricata

# Redis
REDIS_URL=redis://127.0.0.1:6379/0

# 選填
GEOIP_DB_PATH=/www/wwwroot/suricata-web/GeoLite2-City.mmdb
MAX_WORKER_CONCURRENCY=4
ALLOWED_ORIGINS=https://<你的域名>   # 多個來源用逗號分隔

# NAS 掛載點（由 OS 預先掛載，唯讀）
NAS_MOUNT_PATH=/mnt/nas
```

> **Agent 指示：** 產生 `.env.example` 時，`NAS_PASSWORD=` 留空並加上註解 `# 請填入 NAS 密碼`。

---

## 系統架構

```
瀏覽器 / API 用戶端
        │
        │ HTTPS（由同一主機上的 Nginx 反向代理）
        ▼
┌───────────────────────────┐
│   FastAPI (Gunicorn 4w)   │  ← REST API + WebSocket
│   app/                    │   監聽 127.0.0.1:8000
│   ├── routers/            │
│   ├── services/           │
│   ├── models/             │
│   └── workers/            │
└──────┬──────────┬─────────┘
       │          │
       ▼          ▼
┌──────────┐  ┌─────────────────────────────┐
│  MySQL   │  │  Celery Worker(s)            │
│localhost │  │  - 透過 /mnt/nas 存取 NAS    │
│port 3306 │  │  - 執行 suricata             │
│          │  │  - 執行 tshark              │
│          │  │  - 產生報告                  │
└──────────┘  └──────────────┬──────────────┘
                             │
                     ┌───────┴────────┐
                     │  NAS (SMB)     │
                     │  192.168.22.65 │
                     │  掛載於         │
                     │  /mnt/nas      │
                     │  （唯讀）       │
                     └────────────────┘
```

---

## 專案目錄結構（目標）

```
suricata-web/
├── app/                             # ── Python / FastAPI 後端 ──
│   ├── main.py                  # FastAPI 應用程式工廠，lifespan 鉤子
│   ├── config.py                # 透過 pydantic-settings 讀取 .env 設定
│   ├── database.py              # 非同步 SQLAlchemy 引擎 + Session 工廠
│   ├── routers/
│   │   ├── auth.py              # POST /api/v1/auth/login, /refresh
│   │   ├── nas.py               # GET /api/v1/nas/projects（瀏覽 NAS）
│   │   ├── tasks.py             # 分析任務 CRUD
│   │   ├── analysis.py          # GET 分析結果 API
│   │   └── reports.py           # GET /api/v1/tasks/{id}/report, /export
│   ├── services/
│   │   ├── nas_service.py       # SMB 掛載 / 資料夾列表 / 路徑驗證
│   │   ├── suricata_service.py  # Suricata 執行器 + 日誌過濾/去重邏輯
│   │   ├── tshark_service.py    # 基於 tshark 的 PCAP 分析邏輯
│   │   ├── pcap_deep_service.py # 深度封包分析（DNS / HTTP / TLS）
│   │   ├── report_service.py    # PNG 報告產生（matplotlib）
│   │   └── anomaly_service.py   # 異常偵測規則
│   ├── models/
│   │   ├── user.py              # SQLAlchemy User 模型
│   │   └── task.py              # SQLAlchemy Task + AnalysisResult 模型
│   ├── schemas/
│   │   ├── auth.py              # 認證用 Pydantic Schema
│   │   ├── nas.py               # NAS 資料夾列表用 Pydantic Schema
│   │   └── task.py              # 任務用 Pydantic Schema
│   └── workers/
│       ├── celery_app.py        # Celery 實例
│       └── analysis_task.py     # @celery.task: run_full_analysis()
├── frontend/                        # ── React 18 + Tailwind 前端 ──
│   ├── src/
│   │   ├── main.tsx             # React 進入點
│   │   ├── App.tsx              # 路由設定（React Router v6）
│   │   ├── api/
│   │   │   └── client.ts        # axios 實例 + JWT interceptor
│   │   ├── pages/
│   │   │   ├── LoginPage.tsx
│   │   │   ├── TaskListPage.tsx
│   │   │   ├── NewTaskPage.tsx  # NAS 專案選擇器
│   │   │   └── DashboardPage.tsx# 9 個分頁儀表板（含 DNS/HTTP/TLS）
│   │   └── components/
│   │       ├── ProgressModal.tsx# WebSocket 進度條
│   │       ├── FlowChart.tsx    # 流量趨勢圖（Recharts）
│   │       ├── TopIpTable.tsx
│   │       ├── GeoMap.tsx
│   │       ├── EventChart.tsx
│   │       ├── AnomalyList.tsx
│   │       ├── DnsPanel.tsx     # DNS 查詢排名 / NXDOMAIN / 隧道偵測
│   │       ├── HttpPanel.tsx    # HTTP Host/URI/Method/UA/狀態碼
│   │       └── TlsPanel.tsx     # TLS SNI / 版本分布 / Cipher Suite
│   ├── index.html
│   ├── tailwind.config.ts
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── package.json
├── deploy/
│   ├── suricata-api.service     # systemd unit — Gunicorn API（參考用）
│   ├── suricata-worker.service  # systemd unit — Celery worker（參考用）
│   └── nginx.conf               # Nginx 反向代理設定（參考用）
├── tests/                           # ── pytest 測試套件 ──
│   ├── conftest.py              # pytest fixtures（TestClient、DB、模擬資料）
│   ├── test_auth.py             # 認證流程測試
│   ├── test_nas.py              # NAS 路徑驗證測試
│   ├── test_tasks.py            # 任務 CRUD 測試
│   ├── test_cancel_delete.py    # Cancel / Delete 端點測試
│   ├── test_pcap_deep.py        # 深度封包分析单元測試
│   ├── test_suricata_service.py # SuricataService 單元測試
│   ├── test_anomaly.py          # 異常偵測規則測試
│   └── test_report.py           # 報告產生測試
├── .env.example
└── requirements.txt
```

---

## 標準 API 回應格式

### 成功回應
所有端點回傳統一結構（2xx）：
```json
{ "data": { ... }, "message": "ok" }
```
列表端點附加分頁欄位：
```json
{
  "data": [ ... ],
  "total": 42,
  "page": 1,
  "page_size": 20,
  "message": "ok"
}
```

### 錯誤回應
所有 4xx / 5xx 統一使用以下結構，禁止直接回傳 FastAPI 預設的 `detail` 字串：
```json
{ "error": "NOT_FOUND", "message": "任務 ID 不存在", "detail": null }
```

常用錯誤代碼：

| HTTP 狀態 | error 代碼 | 說明 |
|-----------|-----------|------|
| 400 | `VALIDATION_ERROR` | 請求參數格式錯誤 |
| 401 | `UNAUTHORIZED` | 未提供或 Token 無效 |
| 403 | `FORBIDDEN` | 無此資源權限 |
| 404 | `NOT_FOUND` | 資源不存在 |
| 409 | `CONFLICT` | 任務狀態衝突（例如重複啟動） |
| 422 | `INVALID_PCAP` | PCAP 魔術位元組驗證失敗 |
| 429 | `RATE_LIMITED` | 超過頻率限制 |
| 500 | `INTERNAL_ERROR` | 伺服器內部錯誤 |

> **Agent 指示：** 在 `app/main.py` 中使用 `@app.exception_handler` 統一攔截並轉換所有例外為上述格式。

### 健康檢查端點

```
GET /health
回應（不需 JWT）：
{
  "status": "ok",
  "database": "ok" | "error",
  "redis": "ok" | "error",
  "nas_mount": "ok" | "error"
}
HTTP 200：全部正常 / HTTP 503：任一元件異常
```

> **Agent 指示：** 此端點供 aaPanel / Nginx / 監控系統探測服務存活。不計入頻率限制。

---

## 第一階段 — NAS 整合與核心 API

### 1.1 NAS 連線（`app/services/nas_service.py`）

**掛載策略：** 透過 `/etc/fstab`（CIFS）在 OS 層級將 NAS 分享資料夾掛載為唯讀。應用程式從環境變數讀取 `NAS_MOUNT_PATH`。

**`/etc/fstab` 項目（在部署主機上新增）：**
```
//192.168.22.65/ctc_nas  /mnt/nas  cifs  credentials=/etc/nas-credentials,uid=suricata,gid=suricata,ro,noauto,x-systemd.automount,vers=3.0  0  0
```

**`/etc/nas-credentials`（權限 600，擁有者 root:root）：**
```
username=ah_user
password=<NAS_PASSWORD 的值>
```

```python
# nas_service.py 實作規格

import re
from pathlib import Path
from app.config import settings

class NASService:
    """
    透過預先掛載的 NAS 分享資料夾，提供安全的資料夾/檔案列表功能。
    BASE_PATH = settings.NAS_MOUNT_PATH  (預設: /mnt/nas)
    """
    BASE_PATH: Path = Path(settings.NAS_MOUNT_PATH)
    _SAFE_NAME = re.compile(r'^[a-zA-Z0-9_\-.\s]+$')

    def list_project_folders(self) -> list[str]:
        """回傳 BASE_PATH 下的直接子目錄名稱列表。"""
        return [
            p.name for p in sorted(self.BASE_PATH.iterdir())
            if p.is_dir()
        ]

    def get_pcap_files(self, project_folder: str) -> list[str]:
        """回傳已驗證專案資料夾內的 *.pcap / *.pcapng 檔名列表。"""
        base = self._validate_path(project_folder)
        return [
            p.name for p in sorted(base.iterdir())
            if p.suffix.lower() in ('.pcap', '.pcapng')
        ]

    def _validate_path(self, folder_name: str) -> Path:
        """
        安全性：白名單字元驗證、路徑解析，並確保結果在 BASE_PATH 範圍內。
        使用 Path.is_relative_to()（Python 3.9+）取代 startswith，
        避免 /mnt/nas 與 /mnt/nasty 等前綴誤判。
        違反時拋出 ValueError。
        """
        if not self._SAFE_NAME.match(folder_name):
            raise ValueError(f"無效的資料夾名稱：{folder_name!r}")
        resolved = (self.BASE_PATH / folder_name).resolve()
        if not resolved.is_relative_to(self.BASE_PATH.resolve()):
            raise ValueError("偵測到路徑穿越攻擊")
        return resolved
```

---

### 1.2 NAS 瀏覽 API（`app/routers/nas.py`）

```
GET  /api/v1/nas/projects
     → 回傳 NAS 上的專案資料夾名稱列表
     → 回應：{ "projects": ["project_A", "project_B", ...] }

GET  /api/v1/nas/projects/{project_name}/files
     → 回傳專案資料夾內的 PCAP 檔案列表，含每個檔案的大小（位元組）
     → 回應：
       {
         "project": "project_A",
         "files": [
           { "name": "capture1.pcap", "size_bytes": 104857600 },
           { "name": "capture2.pcapng", "size_bytes": 52428800 }
         ],
         "total": 2
       }
```

> **Agent 指示：** `NASService.get_pcap_files()` 需同時回傳 `name` 和 `size_bytes`（透過 `p.stat().st_size` 取得），前端可據此顯示「已選擇 X 個檔案，共 Y MB」。

兩個端點均需要 JWT 驗證。

---

### 1.3 任務模型（`app/models/task.py`）

```python
# SQLAlchemy 模型 — 嚴格按照此 Schema 實作

class Task(Base):
    __tablename__ = "tasks"

    id            : UUID         # 主鍵
    name          : str          # 使用者自訂的分析任務標籤
    owner_id      : UUID         # FK → users.id
    nas_project   : str          # NAS 上的資料夾名稱（例如 "project_A"）
    pcap_files    : list[str]    # JSON — 已選擇的 pcap 檔名列表
    status        : str          # "pending" | "running" | "done" | "failed"
    celery_task_id: str | None   # 用於狀態查詢的 Celery 任務 ID
    pcap_count    : int
    created_at    : datetime
    finished_at   : datetime | None
    error_msg     : str | None

class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    task_id    : UUID    # FK → tasks.id（主鍵）
    summary    : dict    # JSON — analysis_summary.json 的內容
    alerts     : list    # JSON — 解析後的 fast.log 項目
    updated_at : datetime
```

---

### 1.4 任務建立流程（無上傳）

```
POST /api/v1/tasks
Body: {
  "name": "Project Alpha 分析",
  "nas_project": "project_A",               ← NAS 瀏覽 API 回傳的資料夾名稱
  "pcap_files": ["cap1.pcap", "cap2.pcap"]  ← 選填；省略時使用資料夾內所有 PCAP
}

步驟：
1. 使用 NASService._validate_path() 驗證 nas_project
2. 確認 NAS 上的檔案存在
3. 插入狀態為 "pending" 的 Task 記錄
4. 立即回傳 task id（202 Accepted）

POST /api/v1/tasks/{id}/start
步驟：
1. 更新任務狀態 → "running"
2. 派送 Celery 任務：run_full_analysis.delay(task_id)
3. 將 celery_task_id 儲存至資料庫
4. 回傳 202 Accepted
```

---

### 1.5 Celery 分析任務（`app/workers/analysis_task.py`）

```python
@celery.task(bind=True, max_retries=0, time_limit=3600)
def run_full_analysis(self, task_id: str):
    """
    執行步驟（按順序執行，每步驟更新任務狀態）：

    1. 從資料庫載入任務，設定 status = "running"
    2. 取得任務 pcap_files 的 NAS 路徑；work_dir = /tmp/suricata-{task_id}/
    3. 執行 suricata_service.process(task_id, pcap_paths)
       - 內部呼叫 SuricataService.run_analysis()
         發送 WebSocket 事件：{"step": "suricata", "progress": 30}
    4. 執行 TsharkService.analyze(task_id, pcap_paths)
       - 內部呼叫 TsharkService 各方法
         發送 WebSocket 事件：{"step": "tshark", "progress": 70}
    5. 執行 ReportService.generate(task_id)
       - 內部呼叫 ReportService 各方法
         發送 WebSocket 事件：{"step": "report", "progress": 90}
    6. 將結果儲存至 AnalysisResult 資料表（summary + alerts 為 JSON）
    7. 設定 task status = "done"，finished_at = 現在時間
       發送 WebSocket 事件：{"step": "done", "progress": 100}
    8. 清理 work_dir（shutil.rmtree(work_dir, ignore_errors=True)）

    發生任何例外時：
    - 設定 task status = "failed"，error_msg = str(exception)
    - 發送 WebSocket 事件：{"step": "error", "message": str(exception)}
    - 清理 work_dir（finally 區塊中執行，確保無論成功或失敗皆清除）
    - 重新拋出例外，讓 Celery 將任務標記為 FAILURE
    """
```

> **Agent 指示：** work_dir 清理使用 `finally` 區塊（不是只在成功路徑），確保即使分析失敗也不殘留暫存檔案。

---

### 1.6 WebSocket 進度（`app/main.py`）

```
WS  /ws/task/{task_id}

- 用戶端在 POST /start 後連線
- 伺服器推送 JSON 訊框：
  {"step": "suricata"|"tshark"|"report"|"done"|"error", "progress": 0-100, "message": "..."}
- 在 step="done" 或 step="error" 後關閉連線
- 需要在查詢參數中提供 JWT token：?token=<jwt>
  （WebSocket 握手不支援自訂 HTTP Header，故以 Query Param 傳遞 token 為常見作法）
```

> **安全注意（WebSocket JWT）：** Query Param 中的 token 可能出現在 Nginx access log。  
> 請在 Nginx 設定中將 `/ws/` 的 access_log 設為 off，或使用自訂 log_format 遮蔽 token 值：  
> ```nginx
> location /ws/ {
>     access_log off;   # 避免 JWT token 寫入存取日誌
>     proxy_pass http://127.0.0.1:8000;
>     proxy_http_version 1.1;
>     proxy_set_header Upgrade $http_upgrade;
>     proxy_set_header Connection "upgrade";
> }
> ```
> Token 驗證後立即從記憶體清除，不記錄至應用程式日誌。

**CORS 設定（`app/main.py`）：**
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://<你的域名>"],  # 正式環境勿使用 "*"
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
```

> **Agent 指示：** `allow_origins` 從環境變數 `ALLOWED_ORIGINS`（逗號分隔）讀取，預設值 `["http://localhost:3000"]` 僅供開發環境使用。

---

### 1.7 認證系統（`app/routers/auth.py`）

```
POST /api/v1/auth/login
Body: { "username": "...", "password": "..." }
回應：{ "access_token": "...", "refresh_token": "...", "token_type": "bearer" }

POST /api/v1/auth/refresh
Body: { "refresh_token": "..." }
回應：{ "access_token": "..." }
```

- 存取 Token 有效期：**15 分鐘**
- 更新 Token 有效期：**7 天**（儲存於資料庫以供撤銷）
- 雜湊演算法：**HS256**
- 密碼雜湊：**bcrypt**（`passlib`）

角色權限：
| 角色 | 權限 |
|------|------|
| `admin` | 所有任務 + 使用者管理 |
| `analyst` | 建立任務、查看自己的任務 |
| `viewer` | 唯讀存取已指派的任務 |

---

## 第二階段 — 結果 API 與匯出

### 2.1 分析結果端點

所有端點均需 JWT 驗證。結果從 `AnalysisResult.summary`（MySQL 的 JSON 欄位）提供。

```
GET /api/v1/tasks
    → 查詢目前使用者的任務列表（admin 可查全部）
    → Query Params：?page=1&page_size=20&status=done
    → 回應：{ "data": [...], "total": 42, "page": 1, "page_size": 20 }

GET /api/v1/tasks/{id}/flow
    → 流量時間軸（每 10 分鐘一個桶）來自 summary["flow_data"]

GET /api/v1/tasks/{id}/flow/{time_period}
    → 特定 10 分鐘桶的詳細連線資訊

GET /api/v1/tasks/{id}/top_ip
    → 依流量位元組數排名的前 10 個 IP 連線

GET /api/v1/tasks/{id}/geo
    → 地理分布（排除 RFC1918 私有 IP）

GET /api/v1/tasks/{id}/events
    → 協定事件計數（TCP/UDP/DNS/TLS/HTTP/ICMP）

GET /api/v1/tasks/{id}/events/{protocol}
    → 各協定詳細資訊

GET /api/v1/tasks/{id}/anomaly
    → 異常偵測結果
    → 規則（參見本文件 AnomalyService.detect_anomalies() 規格）：
       - 單一連線 > 100MB → HIGH（高）
       - TLS 流量比例 > 80% → MEDIUM（中）
       - 非白名單國家流量 > 30% → MEDIUM（中）
```

### 2.2 任務管理新端點

#### `POST /api/v1/tasks/{id}/cancel` — 撤銷執行中的任務

```
POST /api/v1/tasks/{id}/cancel

驗證流程：
1. 從資料庫載入任務；404 → NOT_FOUND
2. 確認呼叫者為任務擁有者或 admin；否則 403 → FORBIDDEN
3. 若任務 status 不為 "running"，回傳 409 → CONFLICT
   { "error": "CONFLICT", "message": "任務非執行中狀態，無法撤銷" }
4. 呼叫 Celery：celery_app.control.revoke(task.celery_task_id, terminate=True)
5. 更新資料庫：status = "failed"，error_msg = "使用者手動撤銷"，finished_at = 現在時間
6. 回傳 200：{ "data": { "task_id": "<id>", "status": "failed" }, "message": "ok" }
```

> **Agent 指示：** `terminate=True` 會對 Worker 程序發送 SIGTERM（Unix）/TerminateProcess（Windows）。
> 確保 Celery Worker 的 `finally` 區塊能正確清理 work_dir（見步驟 1.5）。

#### `DELETE /api/v1/tasks/{id}` — 刪除任務（含運行中）

```
DELETE /api/v1/tasks/{id}

驗證流程：
1. 從資料庫載入任務；404 → NOT_FOUND
2. 確認呼叫者為任務擁有者或 admin；否則 403 → FORBIDDEN
3. 若任務 status = "running"：
   a. 呼叫 celery_app.control.revoke(task.celery_task_id, terminate=True)
   b. 更新 status = "failed"，error_msg = "任務刪除時強制終止"
4. 從資料庫刪除任務及關聯的 AnalysisResult（CASCADE）
5. 回傳 204 No Content
```

> **注意：** 回傳 204 時，回應主體為空（不套用標準 JSON 包裝格式）。

---

### 2.3 匯出端點

```
GET /api/v1/tasks/{id}/report
    Content-Type: image/png
    → 來自 ReportService.generate() 輸出的 PNG 報告

GET /api/v1/tasks/{id}/export?format=json
    → 原始 analysis_summary.json

GET /api/v1/tasks/{id}/export?format=csv
    → 告警 CSV（欄位：timestamp, priority, event, src_ip, src_port, dst_ip, dst_port, protocol）
```

---

## 第三階段 — 部署（aaPanel 寶塔面板）

> **部署平台：** [aaPanel](https://www.aapanel.com/)（寶塔面板）。  
> aaPanel 透過網頁介面管理 Nginx、MySQL、Redis、Python 環境及 Supervisor 程序監控。  
> 以下指令假設伺服器為 Ubuntu 22.04 / Debian 11，且已安裝 aaPanel。

### 3.1 透過 aaPanel 安裝必要軟體

1. 登入 aaPanel 網頁介面。
2. 前往**軟體商店**並安裝：
   - **Nginx**（最新穩定版）
   - **MySQL 8.0+**
   - **Redis**
   - **Python 3.12**（透過 Python 管理器）
3. 透過 SSH 安裝 aaPanel 中沒有的系統套件：

```bash
sudo apt update
sudo apt install -y suricata tshark cifs-utils
```

### 3.2 NAS 掛載（主機一次性設定）

```bash
# 安全儲存 NAS 憑證（禁止在 aaPanel GUI 中暴露）
sudo tee /etc/nas-credentials << 'EOF'
username=ah_user
password=請填入真實密碼
EOF
sudo chmod 600 /etc/nas-credentials
sudo chown root:root /etc/nas-credentials

# 建立掛載點
sudo mkdir -p /mnt/nas

# 新增至 /etc/fstab（唯讀，自動掛載）
# //192.168.22.65/ctc_nas  /mnt/nas  cifs  credentials=/etc/nas-credentials,uid=www,gid=www,ro,noauto,x-systemd.automount,vers=3.0  0  0
sudo systemctl daemon-reload
sudo mount /mnt/nas
```

> **注意：** aaPanel 預設以 `www` 使用者執行網頁應用程式。  
> fstab 中請使用 `uid=www,gid=www`，使應用程式程序可以讀取 NAS 掛載點。

### 3.3 在 aaPanel 建立 Python 專案

1. 在 aaPanel 前往 **Python 專案 → 新增專案**。
2. 填寫欄位：
   - **專案名稱：** `suricata-web`
   - **Python 版本：** `3.12`
   - **框架：** `FastAPI`
   - **專案根目錄：** `/www/wwwroot/suricata-web`
   - **啟動檔案/入口：** `app.main:app`
   - **啟動指令：** `gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 127.0.0.1:8000`
3. aaPanel 會自動在 `/www/wwwroot/suricata-web/.venv` 建立虛擬環境。

### 3.4 應用程式設定（SSH）

```bash
cd /www/wwwroot/suricata-web

# 上傳專案檔案（git clone 或透過 aaPanel 檔案管理器 SFTP）
git clone <你的倉庫網址> .

# 在 aaPanel 建立的 venv 中安裝相依套件
/www/wwwroot/suricata-web/.venv/bin/pip install -r requirements.txt

# 從範例建立 .env（禁止將真實密碼提交至 git）
cp .env.example .env
chmod 600 .env
# 編輯 .env 並填入真實設定值
```

### 3.5 設定 MySQL 資料庫

1. 在 aaPanel 前往**資料庫 → MySQL → 新增資料庫**。
2. 建立：
   - **資料庫名稱：** `suricata`
   - **使用者名稱：** `suricata`
   - **密碼：**（設定強密碼，記錄在 `.env` 中）
   - **字元集：** `utf8mb4` / **排序規則：** `utf8mb4_unicode_ci`

### 3.6 執行資料庫遷移

```bash
cd /www/wwwroot/suricata-web
/www/wwwroot/suricata-web/.venv/bin/alembic init alembic
/www/wwwroot/suricata-web/.venv/bin/alembic revision --autogenerate -m "initial schema"
/www/wwwroot/suricata-web/.venv/bin/alembic upgrade head
```

### 3.7 透過 aaPanel Supervisor 設定 Celery Worker

1. 在 aaPanel 前往**軟體商店 → Supervisor → 新增守護程序**。
2. 設定 Celery worker 守護程序：
   - **名稱：** `suricata-celery-worker`
   - **執行使用者：** `www`
   - **指令：**
     ```
     /www/wwwroot/suricata-web/.venv/bin/celery -A app.workers.celery_app worker --concurrency=2 -Q analysis --loglevel=info
     ```
   - **目錄：** `/www/wwwroot/suricata-web`
   - **日誌檔案：** `/www/wwwlogs/suricata-worker.log`
3. 點選**確定** — Supervisor 將持續運行 worker，當程序失敗時自動重啟。

### 3.8 透過 aaPanel 設定 Nginx 反向代理

1. 在 aaPanel 前往**網站 → 新增站點**。
   - **域名：** 你的域名或伺服器 IP
   - **根目錄：** `/www/wwwroot/suricata-web/static`（僅靜態檔案）
   - **PHP 版本：** 純靜態（不需要 PHP）
2. 建立站點後，點選**設定 → 設定檔**，將 `location` 區塊替換為：

```nginx
# 頻率限制區域（如需要，可在 aaPanel 全域 Nginx 設定的 http{} 中新增）
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=60r/m;

location /api/v1/auth/ {
    limit_req zone=login burst=5 nodelay;
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location /ws/ {
    proxy_pass http://127.0.0.1:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}

location / {
    limit_req zone=api burst=20 nodelay;
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

# React 建置產物（npm run build 輸出至 frontend/dist）
location / {
    root /www/wwwroot/suricata-web/frontend/dist;
    try_files $uri $uri/ /index.html;  # SPA fallback
    expires 1d;
}
```

3. 在 aaPanel **網站 → SSL** 中，啟用 Let's Encrypt 或上傳你的憑證。

### 3.9 啟動 / 重啟服務

- **API 伺服器：** aaPanel → Python 專案管理器 → 啟動/重啟 `suricata-web`。
- **Celery worker：** aaPanel → Supervisor → 啟動/重啟 `suricata-celery-worker`。
- **Nginx：** aaPanel → Nginx → 重載。

> 專案中的 `deploy/` 目錄仍保留參考用的 `nginx.conf` 和 systemd unit 檔案。  
> 在 aaPanel 環境下，這些設定透過圖形介面管理，不需要手動使用這些檔案。

---

## 第四階段 — React 前端整合

> **前端技術棧：** React 18 + TypeScript + Tailwind CSS + Vite + React Router v6 + Recharts

### 4.0 前端建置流程

```bash
cd frontend
npm install
npm run dev        # 開發模式（Vite proxy → http://localhost:8000）
npm run build      # 產生 dist/ — 部署至 Nginx
```

**`vite.config.ts` — 開發代理設定（避免 CORS）：**
```ts
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/ws':  { target: 'ws://localhost:8000', ws: true },
    },
  },
})
```

### 4.1 前端：NAS 專案選擇器（`frontend/src/pages/NewTaskPage.tsx`）

新建任務的 UI 操作流程：

```
步驟 1 — 使用者點選「新增分析任務」
步驟 2 — UI 呼叫 GET /api/v1/nas/projects
         → 顯示 NAS 專案資料夾的下拉選單（Tailwind select）
步驟 3 — 使用者選擇一個專案資料夾（例如 "project_A"）
步驟 4 — UI 呼叫 GET /api/v1/nas/projects/project_A/files
         → 顯示含檔案大小的 PCAP 檔案核取清單（checkbox list）
步驟 5 — 使用者可選擇性取消勾選特定檔案（預設全選）
步驟 6 — 使用者輸入任務名稱，點選「開始分析」
步驟 7 — UI 呼叫 POST /api/v1/tasks，再呼叫 POST /api/v1/tasks/{id}/start
步驟 8 — UI 開啟 WebSocket /ws/task/{id}，顯示 <ProgressModal> 進度條
步驟 9 — 完成後：React Router 跳轉至 /dashboard/:id
```

> **Agent 指示：** 在 `frontend/src/pages/NewTaskPage.tsx` 中實作此流程。  
> JWT token 儲存於 `localStorage`，由 `api/client.ts` 的 axios interceptor 自動附加至 Header。

### 4.2 儀表板（`frontend/src/pages/DashboardPage.tsx`）

實作 9 個分頁，以 Tailwind Tab 元件切換，資料來源為 FastAPI REST 端點：

| 分頁 | React 元件 | API 端點 |
|------|-----------|----------|
| 總覽 | 統計卡片 | `GET /api/v1/tasks/{id}/flow` |
| 流量趨勢 | `<FlowChart>`（Recharts AreaChart）| `GET /api/v1/tasks/{id}/flow` |
| Top IP | `<TopIpTable>` | `GET /api/v1/tasks/{id}/top_ip` |
| 地理分布 | `<GeoMap>`（react-simple-maps）| `GET /api/v1/tasks/{id}/geo` |
| 事件分析 | `<EventChart>`（Recharts BarChart）| `GET /api/v1/tasks/{id}/events` |
| 異常偵測 | `<AnomalyList>` | `GET /api/v1/tasks/{id}/anomaly` |
| DNS 分析 | `<DnsPanel>` | `GET /api/v1/tasks/{id}/deep/dns` |
| HTTP 分析 | `<HttpPanel>` | `GET /api/v1/tasks/{id}/deep/http` |
| TLS 分析 | `<TlsPanel>` | `GET /api/v1/tasks/{id}/deep/tls` |

**新增元件規格：**

- **`<DnsPanel>`**：展示 DNS 前 20 查詢排名表格、NXDOMAIN 列表，以及疑似 DNS 隧道的警示卡片（標示 reason）。
- **`<HttpPanel>`**：展示前 20 Host/URI 表格、Method 分布（Recharts PieChart）、User-Agent 表格、狀態碼分布（BarChart）。
- **`<TlsPanel>`**：展示前 20 SNI 排名表格、TLS 版本分布（PieChart）、Cipher Suite 表格。

> **Agent 指示：** 新增三個深度分析結果端點至 `app/routers/analysis.py`：
> ```
> GET /api/v1/tasks/{id}/deep/dns   → AnalysisResult.summary["deep"]["dns"]
> GET /api/v1/tasks/{id}/deep/http  → AnalysisResult.summary["deep"]["http"]
> GET /api/v1/tasks/{id}/deep/tls   → AnalysisResult.summary["deep"]["tls"]
> ```

---

## 實作順序（供 AI Agent 使用）

請嚴格依照以下順序執行，不可跳過步驟。

```
[ ] 步驟 1:  建立 app/config.py — pydantic-settings，讀取所有環境變數
[ ] 步驟 2:  建立 app/database.py — 非同步 SQLAlchemy 引擎
[ ] 步驟 3:  建立 app/models/user.py、app/models/task.py
[ ] 步驟 4:  建立 app/schemas/auth.py、app/schemas/nas.py、app/schemas/task.py — Pydantic Schema
[ ] 步驟 5:  建立 Alembic 模型遷移
[ ] 步驟 6:  建立 app/services/nas_service.py — SMB/CIFS 列表 + 路徑驗證（含 size_bytes）
[ ] 步驟 7:  建立 app/routers/auth.py — JWT 登入/更新
[ ] 步驟 8:  建立 app/routers/nas.py — 專案/檔案列表端點
[ ] 步驟 9:  建立 app/routers/tasks.py — 任務 CRUD（不上傳，使用 NAS）+ 分頁支援
[ ] 步驟 10: 建立 app/workers/celery_app.py + app/workers/analysis_task.py（含 work_dir 清理）
[ ] 步驟 11: 實作 app/services/suricata_service.py — 依下方規格
[ ] 步驟 12: 實作 app/services/tshark_service.py — 依下方規格
[ ] 步驟 13: 實作 app/services/report_service.py — 依下方規格
[ ] 步驟 14: 實作 app/services/anomaly_service.py — 依下方規格
[ ] 步驟 15: 建立 app/routers/analysis.py — 所有結果端點（flow/top_ip/geo/events/anomaly）
[ ] 步驟 16: 建立 app/routers/reports.py — 報告與匯出端點（PNG/JSON/CSV）
[ ] 步驟 17: 在 app/main.py 新增 WebSocket 端點、/health 端點及統一例外處理器
[ ] 步驟 18: 初始化 frontend/ — Vite + React 18 + TypeScript + Tailwind CSS
[ ] 步驟 19: 建立 frontend/src/api/client.ts — axios + JWT interceptor
[ ] 步驟 20: 實作 LoginPage、TaskListPage（含分頁）、NewTaskPage（含 NAS 選擇器 + 檔案大小 + WebSocket 進度）
[ ] 步驟 21: 實作 DashboardPage — 6 個 Recharts / react-simple-maps 分頁
[ ] 步驟 22: 建立 deploy/nginx.conf（aaPanel 參考用 Nginx 設定，含 SPA fallback + /ws/ access_log off）
[ ] 步驟 23: 記錄 aaPanel Supervisor 的 Celery worker 設定
[ ] 步驟 24: 建立 .env.example（不含真實密碼）
[ ] 步驟 25: 更新 requirements.txt，新增相依套件
[ ] 步驟 26: 建立 frontend/package.json 並列出前端相依套件
[ ] 步驟 27: 實作 app/services/pcap_deep_service.py — 依第四.深度服務規格
[ ] 步驟 28: 將 deep_analyze() 整合至 app/workers/analysis_task.py
            （tshark 70% → deep_analyze 60→80% → report 90% → done 100%）
[ ] 步驟 29: 在 app/routers/analysis.py 新增三個深度結果端點
            GET /api/v1/tasks/{id}/deep/dns
            GET /api/v1/tasks/{id}/deep/http
            GET /api/v1/tasks/{id}/deep/tls
[ ] 步驟 30: 在 app/routers/tasks.py 新增 Cancel 端點
            POST /api/v1/tasks/{id}/cancel
[ ] 步驟 31: 在 app/routers/tasks.py 更新 Delete 端點，支援強制終止執行中任務
            DELETE /api/v1/tasks/{id}（先 cancel 再刪）
[ ] 步驟 32: 實作前端 DNS/HTTP/TLS 三個新分頁元件（DnsPanel/HttpPanel/TlsPanel）
[ ] 步驟 33: 撰寫 tests/ 測試套件（conftest + 8 個測試檔案，見第五階段）
```

---

## 第五階段 — 測試策略

> **測試框架：** pytest + pytest-asyncio + httpx（AsyncClient）

### 5.1 測試目錄結構

```
tests/
├── conftest.py              # 共用 fixtures：AsyncClient、測試 DB Session、模擬資料
├── test_auth.py             # 認證流程（登入、刷新 Token、無效憑證）
├── test_nas.py              # NAS 路徑驗證（正常路徑、路徑穿越攻擊、無效字元）
├── test_tasks.py            # 任務 CRUD（建立、查詢、分頁）
├── test_cancel_delete.py    # Cancel / Delete 端點（狀態機、權限）
├── test_pcap_deep.py        # pcap_deep_service 單元測試（DNS/HTTP/TLS 分析函式）
├── test_suricata_service.py # suricata_service 單元測試（魔術位元組、日誌過濾/去重）
├── test_anomaly.py          # anomaly_service 單元測試（三條規則臨界值）
└── test_report.py           # report_service 單元測試（PNG 輸出、_parse_priorities）
```

### 5.2 11 個關鍵測試情境

| # | 測試檔案 | 情境描述 |
|---|---------|---------|
| 1 | `test_auth.py` | 登入成功 → 回傳 access_token + refresh_token |
| 2 | `test_auth.py` | 錯誤密碼 → 401 UNAUTHORIZED |
| 3 | `test_nas.py` | `_validate_path("../etc")` → ValueError（路徑穿越防護） |
| 4 | `test_nas.py` | `_validate_path("project_A")` → 回傳正確 Path |
| 5 | `test_tasks.py` | `POST /api/v1/tasks` 建立任務 → 202、status = "pending" |
| 6 | `test_cancel_delete.py` | `POST /cancel` 對 pending 任務 → 409 CONFLICT |
| 7 | `test_cancel_delete.py` | `DELETE` 對 running 任務 → Celery revoke 被呼叫 + 204 |
| 8 | `test_pcap_deep.py` | `_detect_dns_tunnel("AAAAAAAAAAAAAAAAAAAAAAAAA.evil.com")` → True |
| 9 | `test_pcap_deep.py` | `_detect_dns_tunnel("google.com")` → False |
| 10 | `test_suricata_service.py` | `verify_pcap_magic()` 對有效 pcap LE 魔術位元組 → True |
| 11 | `test_anomaly.py` | 單一連線 bytes > 100 MB → HIGH 嚴重性 |

### 5.3 conftest.py 重點 Fixtures

```python
# tests/conftest.py 規格

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest_asyncio.fixture
async def client() -> AsyncClient:
    """提供使用測試資料庫的非同步 HTTP 用戶端。"""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac

@pytest.fixture
def valid_pcap_le_bytes() -> bytes:
    """pcap little-endian 魔術位元組，用於 verify_pcap_magic 測試。"""
    return b"\xd4\xc3\xb2\xa1"

@pytest.fixture
def analysis_summary_with_large_conn() -> dict:
    """含單一 > 100 MB 連線的 summary，用於 anomaly 測試。"""
    return {
        "top_ip": [{"connection": "1.2.3.4:80 -> 5.6.7.8:443",
                    "bytes": 110 * 1024 * 1024}],
        "event": {},
        "geo": {},
    }
```

### 5.4 pytest 執行指令

```bash
# 安裝測試相依套件
pip install httpx pytest pytest-asyncio Faker

# 執行全部測試（詳細輸出）
pytest tests/ -v

# 僅執行特定測試檔案
pytest tests/test_pcap_deep.py -v

# 產生 HTML 覆蓋率報告（需安裝 pytest-cov）
pip install pytest-cov
pytest tests/ --cov=app --cov-report=html --cov-report=term-missing

# 以非同步模式執行（pytest-asyncio auto 模式）
# 在 pytest.ini 或 pyproject.toml 中設定：
# [pytest]
# asyncio_mode = auto
```

> **Agent 指示：** 在專案根目錄建立 `pytest.ini`，包含以下內容：
> ```ini
> [pytest]
> asyncio_mode = auto
> testpaths = tests
> ```

---

## 安全性需求

| 需求 | 實作方式 |
|------|---------|
| 無寫死憑證 | 所有機密在 `.env`（模式 600）和 `/etc/nas-credentials`（模式 600）中 |
| NAS 路徑穿越防護 | NASService 的 `_validate_path()` — 路徑解析 + 前綴驗證 |
| PCAP 魔術位元組檢查 | 傳給 Suricata 前驗證前 4 個位元組 |
| SQL 注入防護 | 僅使用 SQLAlchemy ORM — 禁止原始 SQL 字串插值 |
| 頻率限制 | Nginx：登入 5 req/min，API 60 req/min |
| JWT 密鑰輪換 | 透過 `SECRET_KEY` 環境變數設定 |
| 應用程式以非 root 執行 | aaPanel 以 `www` 使用者執行應用程式；Supervisor 守護程序也以 `www` 執行 |
| NAS 唯讀掛載 | `/etc/fstab` CIFS 掛載選項中的 `ro` 旗標 |

---

## 需新增至 `requirements.txt` 的相依套件

```
# 正式環境相依套件（不鎖定版本，pip install 時自動抓最新穩定版）
fastapi
uvicorn[standard]
gunicorn
pydantic-settings
sqlalchemy[asyncio]
aiomysql
pymysql
alembic
celery[redis]
redis
python-jose[cryptography]
passlib[bcrypt]
python-multipart
websockets
geoip2           # analyze_geo() 所需
maxminddb        # geoip2 相依
matplotlib       # report_service.py 所需

# 測試相依套件（開發 / CI 環境）
httpx            # pytest 非同步 HTTP 用戶端（AsyncClient）
pytest
pytest-asyncio
Faker
pytest-cov       # 覆蓋率報告（選填）
```

> **Agent 指示：** 若需要鎖定可重現的部署版本，執行 `pip freeze > requirements.lock` 並在正式環境使用 `pip install -r requirements.lock`。開發時使用無版本約束的 `requirements.txt` 以保持套件最新。

---

## Agent 注意事項

- 服務實作請遵循本文件下方**服務函式規格**中的內嵌函式規格。
- `backup/` 和 `pcap-cool/` 目錄：**不要遷移**，已由新服務取代。
- GeoLite2-City.mmdb 路徑可透過 `GEOIP_DB_PATH` 環境變數設定，預設為 `/www/wwwroot/suricata-web/GeoLite2-City.mmdb`。
- `pysmb` 已不再需要 — NAS 在 OS 層級預先掛載；從 requirements 中移除。
- **前端為獨立 SPA**：FastAPI 後端不渲染任何 HTML，不需要 Jinja2。
- 部署時執行 `npm run build`，將 `frontend/dist/` 交由 Nginx 靜態伺服。
- 前端相依套件（`frontend/package.json`）：
  ```json
  {
    "dependencies": {
      "react": "^18.3.0",
      "react-dom": "^18.3.0",
      "react-router-dom": "^6.23.0",
      "axios": "^1.7.0",
      "recharts": "^2.12.0",
      "react-simple-maps": "^3.0.0"
    },
    "devDependencies": {
      "typescript": "^5.4.0",
      "vite": "^5.2.0",
      "@vitejs/plugin-react": "^4.2.0",
      "tailwindcss": "^3.4.0",
      "autoprefixer": "^10.4.0",
      "postcss": "^8.4.0",
      "@types/react": "^18.3.0",
      "@types/react-dom": "^18.3.0"
    }
  }
  ```

---

## 服務函式規格

以下是寫入服務檔案的**權威、最佳化**實作，不要新增超出此處所示的額外抽象。

---

### `app/services/suricata_service.py`

```python
import glob
import os
import re
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


PRIORITY_FILTER = {3}  # 丟棄 Priority 3 事件
NOISE_PATTERNS = [
    re.compile(r"ET INFO HTTP Request to a.*\.tw domain"),
    re.compile(r"ET DNS Query for \.cc TLD"),
]
IP_PAIR_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+\s*->\s*"
    r"(\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+):\d+"
)
PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
              b"\x0a\x0d\x0d\x0a", b"\x4d\x3c\xb2\xa1"}
# ↑ 依序為：pcap LE、pcap BE、pcapng、pcap nanosecond LE


def verify_pcap_magic(pcap_path: str) -> bool:
    """僅當檔案以已知 PCAP/pcapng 魔術位元組開頭時回傳 True。"""
    with open(pcap_path, "rb") as f:
        header = f.read(4)
    return header in PCAP_MAGIC


def _extract_key_fields(line: str):
    """
    回傳用於唯一去重鍵的 (event_str, src_ip, dst_ip)，或回傳 None 表示丟棄。
    丟棄 Priority-3 和雜訊模式的行。
    """
    if "Priority: 3" in line:
        return None
    for pat in NOISE_PATTERNS:
        if pat.search(line):
            return None
    if "[**]" not in line:
        return None
    m = IP_PAIR_RE.search(line)
    if not m:
        return None
    event_start = line.find("[**]")
    return (line[event_start:], m.group(1), m.group(2))


def filter_log(input_path: str, output_path: str) -> int:
    """
    過濾並去重 fast.log。
    回傳保留的行數。
    丟棄 Priority-3 和結構無效的行；保留唯一的 (event, src, dst)。
    """
    seen: set = set()
    kept = 0
    with open(input_path, "r", encoding="utf-8", errors="replace") as fin, \
         open(output_path, "w", encoding="utf-8") as fout:
        for line in fin:
            key = _extract_key_fields(line)
            if key and key not in seen:
                seen.add(key)
                fout.write(line)
                kept += 1
    return kept


def _run_suricata(pcap_path: str, out_dir: str, suricata_exe: str) -> str:
    """對單一 PCAP 執行 Suricata；回傳狀態訊息。"""
    os.makedirs(out_dir, exist_ok=True)
    tid = threading.current_thread().name
    result = subprocess.run(
        [suricata_exe, "-r", pcap_path, "-l", out_dir],
        capture_output=True, text=True, encoding="utf-8"
    )
    if result.returncode == 0:
        return f"[{tid}] OK: {pcap_path}"
    return f"[{tid}] FAIL: {pcap_path}\n{result.stderr[:500]}"


def run_analysis(
    task_id: str,
    pcap_paths: list[str],
    work_dir: str,
    suricata_exe: str = "suricata",
    max_workers: int = 4,
) -> str:
    """
    對 pcap_paths 中的每個 PCAP 並行執行 Suricata，然後將所有 fast.log
    合併並過濾至 {work_dir}/merged_fast.log。

    回傳合併後過濾日誌的路徑。
    若沒有產生任何 fast.log，則拋出 RuntimeError。
    """
    for p in pcap_paths:
        if not verify_pcap_magic(p):
            raise ValueError(f"非有效的 PCAP 檔案：{p}")

    workers = min(max_workers, len(pcap_paths)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_run_suricata, p, os.path.join(work_dir, Path(p).stem), suricata_exe): p
            for p in pcap_paths
        }
        for fut in as_completed(futures):
            fut.result()  # 傳播例外

    # 合併所有 fast.log → merged_fast.log
    raw_path = os.path.join(work_dir, "_raw_fast.log")
    fast_logs = glob.glob(os.path.join(work_dir, "*", "fast.log"))
    if not fast_logs:
        raise RuntimeError(f"Suricata 在 {work_dir} 中未產生任何 fast.log")

    with open(raw_path, "w", encoding="utf-8") as out:
        for log_path in fast_logs:
            with open(log_path, encoding="utf-8", errors="replace") as f:
                out.write(f.read())

    merged_path = os.path.join(work_dir, "merged_fast.log")
    kept = filter_log(raw_path, merged_path)
    os.unlink(raw_path)
    return merged_path
```

---

### `app/services/tshark_service.py`

```python
import ipaddress
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import geoip2.database
import geoip2.errors


def _run_tshark(tshark_exe: str, pcap: str, fields: list[str],
                filter_expr: str = "") -> list[str]:
    cmd = [tshark_exe, "-r", pcap, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd += ["-e", f]
    if filter_expr:
        cmd += ["-Y", filter_expr]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return r.stdout.strip().splitlines() if r.stdout.strip() else []


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _10min_key(epoch: float) -> str:
    dt = datetime.fromtimestamp(epoch)
    return dt.replace(minute=(dt.minute // 10) * 10, second=0,
                      microsecond=0).strftime("%Y-%m-%d %H:%M")


def analyze_flow(tshark_exe: str, pcap_paths: list[str]) -> dict:
    """
    統計每 10 分鐘的流量位元組及每個桶的前 5 個連線。
    回傳與 AnalysisResult.summary["flow"] 相容的 flow 字典。
    """
    fields = ["frame.time_epoch", "frame.len", "ip.src", "ip.dst",
              "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]
    per_10m: dict[str, int] = defaultdict(int)
    top_ip_per_10m: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    timestamps: list[float] = []
    total_bytes = 0

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields):
            parts = line.split("|")
            if len(parts) < 8:
                continue
            try:
                ts = float(parts[0])
                size = int(parts[1])
                src, dst = parts[2], parts[3]
                src_port = parts[4] or parts[6]
                dst_port = parts[5] or parts[7]
            except (ValueError, IndexError):
                continue
            timestamps.append(ts)
            total_bytes += size
            key = _10min_key(ts)
            per_10m[key] += size
            if src and dst:
                conn = f"{src}:{src_port} -> {dst}:{dst_port}"
                top_ip_per_10m[key][conn] += size

    if not timestamps:
        return {}

    top5 = {
        k: [{"connection": c, "bytes": b}
            for c, b in sorted(v.items(), key=lambda x: x[1], reverse=True)[:5]]
        for k, v in top_ip_per_10m.items()
    }

    return {
        "start_time": datetime.fromtimestamp(min(timestamps)).isoformat(),
        "end_time": datetime.fromtimestamp(max(timestamps)).isoformat(),
        "total_bytes": total_bytes,
        "per_10_minutes": dict(sorted(per_10m.items())),
        "top_ip_per_10_minutes": dict(sorted(top5.items())),
    }


def analyze_top_ip(tshark_exe: str, pcap_paths: list[str]) -> list[dict]:
    """
    回傳依位元組數排名的前 10 個連線，含協定及各時段分析。
    """
    fields = ["frame.time_epoch", "ip.src", "ip.dst",
              "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "frame.len"]
    conn_bytes: dict[str, int] = defaultdict(int)
    conn_proto: dict[str, str] = {}
    conn_time: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    total = 0

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields):
            parts = line.split("|")
            if len(parts) < 8:
                continue
            try:
                ts, src, dst = float(parts[0]), parts[1], parts[2]
                tcp_sp, tcp_dp = parts[3], parts[4]
                udp_sp, udp_dp = parts[5], parts[6]
                size = int(parts[7])
            except (ValueError, IndexError):
                continue
            proto = "TCP" if tcp_sp else ("UDP" if udp_sp else "OTHER")
            sp = tcp_sp or udp_sp
            dp = tcp_dp or udp_dp
            conn = f"{src}:{sp} -> {dst}:{dp}"
            conn_bytes[conn] += size
            conn_proto[conn] = proto
            conn_time[conn][_10min_key(ts)] += size
            total += size

    top10 = sorted(conn_bytes.items(), key=lambda x: x[1], reverse=True)[:10]
    return [
        {
            "connection": c,
            "bytes": b,
            "protocol": conn_proto.get(c, "UNKNOWN"),
            "top_3_time_periods": [
                {"rank": i + 1, "time_period": tp,
                 "bytes": tb,
                 "percentage_of_total": round(tb / total * 100, 2) if total else 0}
                for i, (tp, tb) in enumerate(
                    sorted(conn_time[c].items(), key=lambda x: x[1], reverse=True)[:3]
                )
            ],
        }
        for c, b in top10
    ]


TARGET_PROTOCOLS = {"DNS", "DHCP", "SMTP", "TCP", "TLS", "SNMP",
                    "HTTP", "FTP", "SMB3", "SMB2", "SMB", "HTTPS", "ICMP"}


def analyze_protocols(tshark_exe: str, pcap_paths: list[str]) -> dict:
    """回傳各協定的封包計數、top_ip 及依位元組數排名的前 5 個連線。"""
    fields = ["frame.protocols", "ip.src", "ip.dst", "frame.len"]
    stats: dict[str, dict] = {}

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields):
            parts = line.split("|")
            if len(parts) < 4:
                continue
            try:
                protos = parts[0].upper().split(":")
                src, dst = parts[1], parts[2]
                size = int(parts[3]) if parts[3] else 0
            except (ValueError, IndexError):
                continue
            proto = next((p for p in reversed(protos) if p in TARGET_PROTOCOLS), "OTHER")
            entry = stats.setdefault(proto, {
                "count": 0, "_ip": defaultdict(int),
                "_conns": defaultdict(lambda: {"packets": 0, "bytes": 0})
            })
            entry["count"] += 1
            if src:
                entry["_ip"][src] += 1
            if dst:
                entry["_ip"][dst] += 1
            if src and dst:
                k = f"{src} -> {dst}"
                entry["_conns"][k]["packets"] += 1
                entry["_conns"][k]["bytes"] += size

    result = {}
    for proto, entry in stats.items():
        top_ip = max(entry["_ip"], key=entry["_ip"].get) if entry["_ip"] else ""
        conns = sorted(entry["_conns"].items(),
                       key=lambda x: x[1]["bytes"], reverse=True)[:5]
        result[proto] = {
            "count": entry["count"],
            "top_ip": top_ip,
            "detailed_stats": [
                {"src_ip": k.split(" -> ")[0], "dst_ip": k.split(" -> ")[1],
                 "packet_count": v["packets"], "packet_size": v["bytes"]}
                for k, v in conns
            ],
        }
    return result


def analyze_geo(tshark_exe: str, pcap_paths: list[str],
                geoip_db_path: str) -> dict[str, int]:
    """回傳依降序排列的 {國家代碼: 位元組數}；私有 IP → 'LOCAL'。"""
    fields = ["ip.src", "ip.dst", "frame.len"]
    country_bytes: dict[str, int] = defaultdict(int)

    with geoip2.database.Reader(geoip_db_path) as reader:
        for pcap in pcap_paths:
            for line in _run_tshark(tshark_exe, pcap, fields):
                parts = line.split("|")
                if len(parts) < 3:
                    continue
                try:
                    src, dst, size = parts[0], parts[1], int(parts[2])
                except (ValueError, IndexError):
                    continue
                for ip in (src, dst):
                    if not ip:
                        continue
                    if _is_private(ip):
                        country_bytes["LOCAL"] += size
                        continue
                    try:
                        cc = reader.city(ip).country.iso_code or "UNKNOWN"
                    except Exception:
                        cc = "UNKNOWN"
                    country_bytes[cc] += size

    return dict(sorted(country_bytes.items(), key=lambda x: x[1], reverse=True))


def analyze(task_id: str, pcap_paths: list[str],
            geoip_db_path: str, tshark_exe: str = "tshark") -> dict:
    """
    執行所有 tshark 分析並回傳組合後的 summary 字典。
    這是 Celery 任務呼叫的單一進入點。

    注意：task_id 僅供呼叫方記錄/追蹤，本函式不直接使用。
    """
    return {
        "flow": analyze_flow(tshark_exe, pcap_paths),
        "top_ip": analyze_top_ip(tshark_exe, pcap_paths),
        "event": analyze_protocols(tshark_exe, pcap_paths),
        "geo": analyze_geo(tshark_exe, pcap_paths, geoip_db_path),
    }
```

---

### `app/services/anomaly_service.py`

```python
TRUSTED_COUNTRIES = {"LOCAL", "TW", "US"}   # 可透過設定調整
HIGH_TRAFFIC_THRESHOLD = 100 * 1024 * 1024  # 單一連線 100 MB
TLS_RATIO_THRESHOLD = 0.80                  # 所有協定事件的 80%
FOREIGN_RATIO_THRESHOLD = 0.30              # 來自非信任國家的 30%


def detect_anomalies(summary: dict) -> list[dict]:
    """
    檢查分析 summary 字典並回傳異常字典列表。
    每個異常：{ "type": str, "severity": "HIGH"|"MEDIUM"|"LOW",
                "detail": str }
    """
    anomalies = []

    # 1. 單一連線 > 100 MB
    for conn in summary.get("top_ip", []):
        if conn.get("bytes", 0) > HIGH_TRAFFIC_THRESHOLD:
            anomalies.append({
                "type": "large_connection",
                "severity": "HIGH",
                "detail": f"{conn['connection']} 傳輸了 "
                          f"{conn['bytes'] / 1048576:.1f} MB",
            })

    # 2. TLS 佔所有協定事件超過 80%
    events = summary.get("event", {})
    total_events = sum(v.get("count", 0) for v in events.values())
    if total_events > 0:
        tls_ratio = events.get("TLS", {}).get("count", 0) / total_events
        if tls_ratio > TLS_RATIO_THRESHOLD:
            anomalies.append({
                "type": "high_tls_ratio",
                "severity": "MEDIUM",
                "detail": f"TLS 佔所有流量的 {tls_ratio:.0%}",
            })

    # 3. 來自非信任國家的流量超過 30%
    geo = summary.get("geo", {})
    total_geo = sum(geo.values())
    if total_geo > 0:
        foreign = sum(b for cc, b in geo.items() if cc not in TRUSTED_COUNTRIES)
        if foreign / total_geo > FOREIGN_RATIO_THRESHOLD:
            anomalies.append({
                "type": "foreign_traffic",
                "severity": "MEDIUM",
                "detail": f"{foreign / total_geo:.0%} 的流量來自非信任國家",
            })

    return anomalies
```

---

### `app/services/pcap_deep_service.py`

```python
import base64
import re
import subprocess
from collections import Counter, defaultdict
from typing import Any

# ── DNS 隧道偵測閾值 ──────────────────────────────────────────────────────────
DNS_TUNNEL_LENGTH_THRESHOLD = 52   # 單一 DNS 查詢名稱超過此長度視為可疑
# Base32：只含 A-Z 和 2-7；Base64：含 A-Za-z0-9+/=
_B32_RE = re.compile(r'^[A-Z2-7]{20,}$')
_B64_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')

# ── TLS 版本映射（tshark 回傳的 0x0NNN 整數 → 人類可讀字串）──────────────────
TLS_VERSION_MAP: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


def _run_tshark(tshark_exe: str, pcap: str, fields: list[str],
                filter_expr: str = "") -> list[str]:
    """重複使用 tshark_service 中相同的輔助函式，避免循環匯入。"""
    cmd = [tshark_exe, "-r", pcap, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd += ["-e", f]
    if filter_expr:
        cmd += ["-Y", filter_expr]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return r.stdout.strip().splitlines() if r.stdout.strip() else []


# ─────────────────────────────────────────────────────────────────────────────
# DNS 分析
# ─────────────────────────────────────────────────────────────────────────────

def _detect_dns_tunnel(qname: str) -> bool:
    """
    若 DNS 查詢名稱符合以下任一條件，回傳 True（疑似 DNS 隧道）：
    1. 長度超過 DNS_TUNNEL_LENGTH_THRESHOLD
    2. 最長的標籤（以 '.' 分隔）符合 Base32 或 Base64 特徵
    """
    if len(qname) > DNS_TUNNEL_LENGTH_THRESHOLD:
        return True
    labels = qname.rstrip(".").split(".")
    longest = max(labels, key=len) if labels else ""
    return bool(_B32_RE.match(longest.upper()) or _B64_RE.match(longest))


def analyze_dns(tshark_exe: str, pcap_paths: list[str]) -> dict[str, Any]:
    """
    深度分析 DNS 流量，回傳以下結構：

    {
      "top_queries":    [{"qname": str, "count": int}, ...],   # 前 20 名查詢
      "nxdomain_list":  [{"qname": str, "count": int}, ...],   # 所有 NXDOMAIN
      "tunnel_suspects":[{"qname": str, "reason": str}, ...],  # 疑似 DNS 隧道
      "total_queries":  int,
      "unique_qnames":  int,
    }

    tshark 欄位：dns.qry.name, dns.flags.rcode
    過濾器：dns（僅 DNS 協定封包）
    """
    fields = ["dns.qry.name", "dns.flags.rcode"]
    query_counter: Counter = Counter()
    nxdomain_counter: Counter = Counter()
    tunnel_suspects: dict[str, str] = {}  # qname → reason

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields, filter_expr="dns"):
            parts = line.split("|")
            if len(parts) < 2:
                continue
            qname = parts[0].strip().lower()
            rcode = parts[1].strip()
            if not qname:
                continue

            query_counter[qname] += 1

            # rcode 3 = NXDOMAIN
            if rcode == "3":
                nxdomain_counter[qname] += 1

            # DNS 隧道偵測（每個唯一 qname 只偵測一次）
            if qname not in tunnel_suspects and _detect_dns_tunnel(qname):
                if len(qname) > DNS_TUNNEL_LENGTH_THRESHOLD:
                    reason = f"查詢名稱長度 {len(qname)} > 閾值 {DNS_TUNNEL_LENGTH_THRESHOLD}"
                else:
                    reason = "標籤符合 Base32/Base64 編碼特徵"
                tunnel_suspects[qname] = reason

    top_queries = [
        {"qname": q, "count": c}
        for q, c in query_counter.most_common(20)
    ]
    nxdomain_list = [
        {"qname": q, "count": c}
        for q, c in nxdomain_counter.most_common()
    ]
    tunnel_list = [
        {"qname": q, "reason": r}
        for q, r in tunnel_suspects.items()
    ]

    return {
        "top_queries": top_queries,
        "nxdomain_list": nxdomain_list,
        "tunnel_suspects": tunnel_list,
        "total_queries": sum(query_counter.values()),
        "unique_qnames": len(query_counter),
    }


# ─────────────────────────────────────────────────────────────────────────────
# HTTP 分析
# ─────────────────────────────────────────────────────────────────────────────

def analyze_http(tshark_exe: str, pcap_paths: list[str]) -> dict[str, Any]:
    """
    統計 HTTP 流量特徵，回傳以下結構：

    {
      "top_hosts":        [{"host": str, "count": int}, ...],          # 前 20
      "top_uris":         [{"uri": str, "count": int}, ...],           # 前 20
      "method_dist":      {"GET": int, "POST": int, ...},
      "user_agent_dist":  [{"user_agent": str, "count": int}, ...],    # 前 10
      "status_code_dist": {"200": int, "404": int, ...},
      "total_requests":   int,
    }

    tshark 欄位：http.host, http.request.uri, http.request.method,
                 http.user_agent, http.response.code
    過濾器：http（僅 HTTP 協定封包）
    """
    fields = [
        "http.host",
        "http.request.uri",
        "http.request.method",
        "http.user_agent",
        "http.response.code",
    ]
    host_counter:    Counter = Counter()
    uri_counter:     Counter = Counter()
    method_counter:  Counter = Counter()
    ua_counter:      Counter = Counter()
    status_counter:  Counter = Counter()
    total_requests = 0

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields, filter_expr="http"):
            parts = line.split("|")
            if len(parts) < 5:
                continue
            host, uri, method, ua, status = (p.strip() for p in parts[:5])

            if method:   # 有 method 代表這是 Request 封包
                total_requests += 1
                if host:   host_counter[host] += 1
                if uri:    uri_counter[uri] += 1
                if method: method_counter[method] += 1
                if ua:     ua_counter[ua] += 1
            if status:
                status_counter[status] += 1

    return {
        "top_hosts":       [{"host": h, "count": c} for h, c in host_counter.most_common(20)],
        "top_uris":        [{"uri": u, "count": c} for u, c in uri_counter.most_common(20)],
        "method_dist":     dict(method_counter),
        "user_agent_dist": [{"user_agent": u, "count": c} for u, c in ua_counter.most_common(10)],
        "status_code_dist": dict(status_counter),
        "total_requests":  total_requests,
    }


# ─────────────────────────────────────────────────────────────────────────────
# TLS 分析
# ─────────────────────────────────────────────────────────────────────────────

def analyze_tls(tshark_exe: str, pcap_paths: list[str]) -> dict[str, Any]:
    """
    統計 TLS/SSL 流量特徵，回傳以下結構：

    {
      "top_sni":         [{"sni": str, "count": int}, ...],   # 前 20 個 SNI
      "version_dist":    {"TLS 1.2": int, "TLS 1.3": int, ...},
      "cipher_suite_dist":[{"cipher": str, "count": int}, ...], # 前 15
      "total_handshakes": int,
    }

    tshark 欄位：tls.handshake.extensions_server_name,
                 tls.record.version, tls.handshake.ciphersuite
    過濾器：tls.handshake（僅 TLS Handshake 封包）
    """
    fields = [
        "tls.handshake.extensions_server_name",
        "tls.record.version",
        "tls.handshake.ciphersuite",
    ]
    sni_counter:    Counter = Counter()
    version_counter: Counter = Counter()
    cipher_counter: Counter = Counter()
    total_handshakes = 0

    for pcap in pcap_paths:
        for line in _run_tshark(tshark_exe, pcap, fields,
                                filter_expr="tls.handshake"):
            parts = line.split("|")
            if len(parts) < 3:
                continue
            sni, raw_version, cipher = (p.strip() for p in parts[:3])
            total_handshakes += 1

            if sni:
                sni_counter[sni] += 1

            # 將 tshark 回傳的十六進位整數字串轉換為人類可讀的版本名稱
            if raw_version:
                try:
                    ver_int = int(raw_version, 16) if raw_version.startswith("0x") \
                              else int(raw_version)
                    ver_str = TLS_VERSION_MAP.get(ver_int, f"Unknown(0x{ver_int:04x})")
                except ValueError:
                    ver_str = raw_version
                version_counter[ver_str] += 1

            if cipher:
                cipher_counter[cipher] += 1

    return {
        "top_sni":          [{"sni": s, "count": c} for s, c in sni_counter.most_common(20)],
        "version_dist":     dict(version_counter),
        "cipher_suite_dist":[{"cipher": c, "count": n}
                              for c, n in cipher_counter.most_common(15)],
        "total_handshakes": total_handshakes,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Celery 統一入口
# ─────────────────────────────────────────────────────────────────────────────

def deep_analyze(
    task_id: str,
    pcap_paths: list[str],
    tshark_exe: str = "tshark",
    progress_callback=None,
) -> dict[str, Any]:
    """
    深度封包分析的 Celery 統一入口。
    依序執行 DNS → HTTP → TLS，並透過 progress_callback 回報進度。

    progress_callback 簽名：
        callback(step: str, progress: int)
        step 值："dns" | "http" | "tls"
        progress 範圍：60 → 80（整合至全體任務進度）

    回傳：
        {
          "dns": { ... },   # analyze_dns() 的輸出
          "http": { ... },  # analyze_http() 的輸出
          "tls": { ... },   # analyze_tls() 的輸出
        }

    Integration 注意：
    - 在 analysis_task.py 的 run_full_analysis() 中，
      於 tshark_service.analyze()（進度 70%）之後呼叫本函式。
    - 本函式執行完成後，整體進度推進至 80%。
    - 進度 60% 由呼叫方在呼叫本函式前設定；
      本函式負責推送 60→67（dns）、67→74（http）、74→80（tls）。
    """
    steps = [
        ("dns",  analyze_dns,  60, 67),
        ("http", analyze_http, 67, 74),
        ("tls",  analyze_tls,  74, 80),
    ]
    results: dict[str, Any] = {}

    for step_name, func, prog_start, prog_end in steps:
        if progress_callback:
            progress_callback(step_name, prog_start)
        results[step_name] = func(tshark_exe, pcap_paths)
        if progress_callback:
            progress_callback(step_name, prog_end)

    return results
```

---

### `app/services/report_service.py`

```python
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle


def _parse_priorities(log_path: str) -> Counter:
    """統計 fast.log 檔案中 Priority: N 的出現次數。"""
    counter: Counter = Counter()
    if not os.path.exists(log_path):
        return counter
    with open(log_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.search(r"\[Priority:\s*(\d+)\]", line)
            if m:
                counter[int(m.group(1))] += 1
    return counter


def _fmt_bytes(n: int) -> str:
    for unit, threshold in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= threshold:
            return f"{n / threshold:.2f} {unit}"
    return f"{n} B"


def _fmt_duration(start: str, end: str) -> str:
    try:
        delta = (datetime.fromisoformat(end.replace("Z", "+00:00")) -
                 datetime.fromisoformat(start.replace("Z", "+00:00")))
        h, rem = divmod(delta.seconds, 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")
    except Exception:
        return "N/A"


def generate(task_id: str, summary: dict, fast_log_path: str,
             output_path: str) -> bool:
    """
    為指定任務渲染 PNG 報告並儲存至 output_path。
    成功時回傳 True。

    參數
    ----------
    task_id       : 報告上顯示的人類可讀專案/任務標籤
    summary       : AnalysisResult.summary 字典（flow + event 子鍵）
    fast_log_path : merged_fast.log 的路徑，用於 Priority 統計
    output_path   : report.png 的絕對儲存路徑
    """
    flow = summary.get("flow", {})
    events = summary.get("event", {})
    priorities = _parse_priorities(fast_log_path)

    start_time = flow.get("start_time", "N/A")
    end_time = flow.get("end_time", "N/A")
    total_bytes = flow.get("total_bytes", 0)
    total_events = sum(v.get("count", 0) for v in events.values())

    try:
        fmt_start = datetime.fromisoformat(
            start_time.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        fmt_start = start_time

    rows = [
        ("專案代號",        task_id,                             "#3498db"),
        ("開始時間",        fmt_start,                           "#2ecc71"),
        ("掃描時長",        _fmt_duration(start_time, end_time), "#f39c12"),
        ("總流量",          _fmt_bytes(total_bytes),             "#9b59b6"),
        ("協定事件數",      f"{total_events:,}",                 "#e74c3c"),
        ("Priority 1 告警", f"{priorities.get(1, 0):,}",        "#e74c3c"),
        ("Priority 2 告警", f"{priorities.get(2, 0):,}",        "#f39c12"),
        ("Priority 3 告警", f"{priorities.get(3, 0):,}",        "#95a5a6"),
    ]

    fig, ax = plt.subplots(figsize=(14, 8))
    ax.axis("off")
    fig.patch.set_facecolor("#f8f9fa")
    plt.rcParams.update({"font.family": "DejaVu Sans", "axes.unicode_minus": False})

    # 標題列
    ax.add_patch(Rectangle((0.05, 0.90), 0.90, 0.08,
                            transform=ax.transAxes, facecolor="#2c3e50"))
    ax.text(0.5, 0.94, f"分析報告 — {task_id}",
            ha="center", va="center", fontsize=22, fontweight="bold",
            color="white", transform=ax.transAxes)

    # 內容框
    ax.add_patch(Rectangle((0.08, 0.08), 0.84, 0.80,
                            transform=ax.transAxes,
                            facecolor="white", edgecolor="#dee2e6", linewidth=2))

    y, step = 0.85, 0.09
    for i, (label, value, color) in enumerate(rows):
        if i % 2 == 0:
            ax.add_patch(Rectangle((0.10, y - 0.035), 0.80, 0.06,
                                   transform=ax.transAxes,
                                   facecolor="#f8f9fa", zorder=1))
        ax.text(0.15, y, label, fontsize=13, color="#555",
                transform=ax.transAxes, zorder=2)
        ax.text(0.60, y, value, fontsize=13, fontweight="bold",
                color=color, transform=ax.transAxes, zorder=2)
        y -= step

    plt.tight_layout()
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return True
```
