FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    WEB_CONCURRENCY=1

WORKDIR /app

# Requirements first so the layer caches across source edits.
COPY requirements.txt .
# Generous retries: a slow or lossy connection otherwise fails the build on one
# timed-out wheel download.
RUN pip install --no-cache-dir --retries 5 --timeout 120 -r requirements.txt

COPY app ./app

# Run as a non-root user — the container has no reason to be root.
RUN useradd --create-home --uid 10001 cybershield && chown -R cybershield /app
USER cybershield

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8000')).status==200 else 1)"

# WEB_CONCURRENCY > 1 requires REDIS_URL: the detection engine's sliding
# windows, the alert-correlation cache, the rate-limit counters and the
# WebSocket client set are shared through Redis when it is set, and in-process
# when it is not. The app logs an error at boot if you scale out without it.
#
# `exec` so uvicorn takes over PID 1 and receives SIGTERM directly instead of
# the shell swallowing it and the container being killed on every restart.
#
# --proxy-headers so the client address nginx forwards reaches the app; without
# it every student lands in the same rate-limit bucket.
CMD exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --workers ${WEB_CONCURRENCY} \
    --proxy-headers --forwarded-allow-ips='*'
