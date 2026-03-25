#!/bin/bash
# 停止所有 Suricata 相關服務
# 用法: sudo bash kill_services.sh

SUPERVISORCTL="/www/server/panel/pyenv/bin/supervisorctl"
CONF="/etc/supervisor/supervisord.conf"

echo "=== 停止 Supervisor 管理的服務 ==="
$SUPERVISORCTL -c $CONF stop suricata:*
$SUPERVISORCTL -c $CONF stop suricata-worker:*

echo ""
echo "=== 清除殘留 gunicorn 進程 ==="
pkill -9 -f "gunicorn.*app.main:app" 2>/dev/null && echo "已清除 gunicorn" || echo "無殘留 gunicorn"

echo ""
echo "=== 清除殘留 celery 進程 ==="
pkill -9 -f "celery.*worker" 2>/dev/null && echo "已清除 celery" || echo "無殘留 celery"

echo ""
echo "=== 釋放 port 8000 ==="
fuser -k 8000/tcp 2>/dev/null && echo "已釋放 port 8000" || echo "port 8000 無佔用"

echo ""
echo "=== 當前狀態 ==="
$SUPERVISORCTL -c $CONF status
echo ""
echo "完成。如需重新啟動："
echo "  sudo $SUPERVISORCTL -c $CONF start suricata:*"
echo "  sudo $SUPERVISORCTL -c $CONF start suricata-worker:*"
