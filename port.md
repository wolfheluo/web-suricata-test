# 服務 Port 與啟動方式

| 服務 | Port | 綁定位址 | 啟動方式 |
|------|------|----------|----------|
| **MySQL** | 3306 | 127.0.0.1 | 寶塔面板自管（系統服務） |
| **Redis** | 6379 | 127.0.0.1 | 寶塔面板自管（系統服務） |
| **FastAPI (suricata-api)** | 8000 | 127.0.0.1 | Supervisor：`supervisorctl restart suricata:*` |
| **Celery Worker** | 無（透過 Redis 通訊） | — | Supervisor：`supervisorctl restart suricata-worker:*` |
| **Nginx 反向代理** | 80 | 0.0.0.0 | 寶塔面板自管（系統服務） |
| **Vite 開發伺服器** | 5173 | localhost | `cd frontend && npm run dev`（僅開發用） |
| **NAS (CIFS/SMB)** | 445（遠端） | 192.168.22.65 → /mnt/nas | `mount -a`（fstab `_netdev` 開機自動掛載） |

## Supervisor 完整指令

```bash
sudo /www/server/panel/pyenv/bin/supervisorctl -c /etc/supervisor/supervisord.conf <status|restart|stop> <程式名>
```

## 流量路徑

```
瀏覽器 → Nginx(:80) → FastAPI(:8000) → MySQL(:3306) + Redis(:6379) + Celery Worker
```
