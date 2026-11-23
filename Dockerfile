# bookworm: newer Debian releases use syscalls that older NAS kernels (e.g. QNAP) reject
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data PORT=8089
WORKDIR /srv
# iproute2: `ip neigh` shows which addresses answered ARP (reachable vs. failed)
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --system --uid 10002 inventory \
 && mkdir -p /data && chown inventory /data
COPY --chown=10002:10002 app ./app
USER inventory
EXPOSE 8089
VOLUME ["/data"]
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8089'))" || exit 1
CMD ["python", "-m", "app.server"]
