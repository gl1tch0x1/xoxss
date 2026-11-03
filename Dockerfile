FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XOXSS_STATE_DIR=/data

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY xoxss ./xoxss
COPY xoxss.py ./

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 scanner \
    && mkdir -p /data \
    && chown scanner:scanner /data

USER scanner
VOLUME ["/data"]
ENTRYPOINT ["xoxss"]
# Browser verification is unavailable in this image; use --no-browser or mount a
# separate browser service. Payload downloads can be disabled with
# --no-remote-payloads for fully offline runs.
CMD ["--help"]
