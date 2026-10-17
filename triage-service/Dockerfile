# Hardened container image for the triage service.
# - Slim base image (smaller attack surface)
# - Dependencies installed without cache; no build tools left behind
# - Runs as an unprivileged, non-login user (never root)
# - Healthcheck for orchestrators
# Next hardening step: pin the base image by digest and let Dependabot update it.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY triage.py threat_intel.py ./

USER app

EXPOSE 5050

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5050/healthz', timeout=3)"]

# Inside a container the service must listen on all container interfaces;
# exposure is controlled by the container runtime's port mapping, and every
# request still requires the X-API-Token header (see triage.py).
CMD ["gunicorn", "--bind", "0.0.0.0:5050", "--workers", "2", "--access-logfile", "-", "triage:app"]
