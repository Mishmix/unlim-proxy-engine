FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so source edits do not invalidate the layer.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

COPY config.toml ./

# 400+ concurrent checks blow straight past the default 1024 descriptors.
RUN echo '* soft nofile 65535' >> /etc/security/limits.conf \
 && echo '* hard nofile 65535' >> /etc/security/limits.conf

VOLUME /app/data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

CMD ["python", "-m", "unlimproxy"]
