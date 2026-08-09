# Single-image build for cloud hosts (Railway, Render, Fly, any Docker runner).
#
# One service: FastAPI serves both the API and the built SPA, so students get
# one URL, the WebSocket is same-origin, and there is no CORS to configure.
# `docker-compose.yml` still runs the split nginx + API layout for local work.

FROM node:22-alpine AS web

WORKDIR /web
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build


FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    # Two workers is the sweet spot for a small cloud instance. Raising it
    # requires REDIS_URL — without it the workers cannot share detection
    # windows, rate limits or WebSocket clients, and the app says so at boot.
    WEB_CONCURRENCY=2

WORKDIR /app

# Requirements first so the layer caches across source edits.
COPY backend/requirements.txt ./backend/requirements.txt
# Generous retries: a slow or lossy connection otherwise fails the build on one
# timed-out wheel download.
RUN pip install --no-cache-dir --retries 5 --timeout 120 -r backend/requirements.txt

COPY backend/app ./backend/app
# app/main.py looks for the SPA two levels above the package: /app/frontend/dist.
COPY --from=web /web/dist ./frontend/dist

RUN useradd --create-home --uid 10001 cybershield && chown -R cybershield /app
USER cybershield

WORKDIR /app/backend

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8000')).status==200 else 1)"

# Shell form so ${PORT} and ${WEB_CONCURRENCY} expand; `exec` so uvicorn takes
# over PID 1 and receives the platform's SIGTERM directly. Without it the shell
# holds PID 1, uvicorn never sees the signal, and every redeploy ends in a kill.
#
# --proxy-headers so the platform's load balancer scheme and client address
# reach the app; without it every student shares one rate-limit bucket.
CMD exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --workers ${WEB_CONCURRENCY} \
    --proxy-headers --forwarded-allow-ips='*'
