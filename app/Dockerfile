FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /srv/mojodns

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY mojodns ./mojodns
COPY scripts ./scripts

EXPOSE 8000
CMD ["uvicorn", "mojodns.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
