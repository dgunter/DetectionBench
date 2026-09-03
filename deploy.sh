#!/usr/bin/env bash
# DetectionBench deploy — run on the production host:
#   ssh root@host 'bash /opt/detectionbench/deploy.sh'            # deploy origin/main
#   ssh root@host 'bash -s -- some-branch' < deploy.sh            # deploy a branch before it merges
# Fetch the ref, build frontend, sync backend deps, run tests (abort on red), restart, verify it actually serves.
set -euo pipefail

REF="${1:-main}"

APP_DIR=/opt/detectionbench
WEB_ROOT=/var/www/detectionbench
SVC=detectionbench-backend
SVC_USER=detectionbench
HEALTH_LOCAL=http://127.0.0.1:8000/api/health
HEALTH_PUBLIC=https://detectionbench.ai/api/health

log() { printf '\n==> %s\n' "$*"; }
# Run as the service user with a minimal environment. uv-managed Python lives in a
# shared install dir so the (nologin) service user can use it.
as_app() { sudo -u "$SVC_USER" -H env PATH="/usr/local/bin:/usr/bin:/bin" UV_PYTHON_INSTALL_DIR=/opt/uv/python "$@"; }

cd "$APP_DIR"

log "fetch $REF"
as_app git -C "$APP_DIR" fetch -q origin "$REF"
as_app git -C "$APP_DIR" reset -q --hard FETCH_HEAD
as_app git -C "$APP_DIR" log --oneline -1

log "frontend: install + build"
as_app npm --prefix "$APP_DIR/frontend" ci --no-audit --no-fund --silent
as_app npm --prefix "$APP_DIR/frontend" run build --silent

log "backend: sync deps (no-op if lockfile unchanged)"
as_app uv sync --project "$APP_DIR/backend" --frozen -q

log "backend: tests (deploy aborts on red)"
as_app uv run --project "$APP_DIR/backend" --frozen pytest -q --cov=app --cov-report=xml:"$APP_DIR/backend/coverage.xml"

log "publish frontend build"
rsync -a --delete "$APP_DIR/frontend/dist/" "$WEB_ROOT/"

log "restart $SVC"
systemctl restart "$SVC"

log "health: local"
ok=0
for i in $(seq 1 10); do
  if curl -fsS "$HEALTH_LOCAL"; then ok=1; echo; break; fi
  sleep 1
done
if [ "$ok" -ne 1 ]; then
  echo "backend did not become healthy; last 40 journal lines:" >&2
  journalctl -u "$SVC" --no-pager -n 40 >&2
  exit 1
fi

log "health: through Caddy"
curl -fsS "$HEALTH_PUBLIC"; echo

log "deployed $(as_app git -C "$APP_DIR" rev-parse --short HEAD)"
