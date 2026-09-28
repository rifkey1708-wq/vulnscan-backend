#!/bin/bash
# Keepalive — ping self every 14 minutes to prevent Render free-tier sleep
SELF_URL="${SELF_URL:-http://localhost:8000}"
echo "[keepalive] Starting — pinging $SELF_URL every 14 minutes"
while true; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$SELF_URL/ping" 2>/dev/null)
  echo "[keepalive] $(date -u +%H:%M:%S) — ping /ping → HTTP $STATUS"
  sleep 840  # 14 minutes
done
