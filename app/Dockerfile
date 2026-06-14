FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /srv/mojodns

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY mojodns ./mojodns
COPY scripts ./scripts

EXPOSE 8000
# Trust X-Forwarded-* only from the reverse proxy (FORWARDED_ALLOW_IPS), never
# '*' — otherwise any client could spoof its source IP. shell form + exec so the
# env var expands while uvicorn still receives signals as PID 1.
CMD ["sh", "-c", "exec uvicorn mojodns.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
