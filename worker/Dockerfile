FROM python:3.12-slim

WORKDIR /app

COPY worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared ./shared
COPY worker/*.py ./

CMD ["sh", "-c", "rq worker --url \"$REDIS_URL\" scans"]
