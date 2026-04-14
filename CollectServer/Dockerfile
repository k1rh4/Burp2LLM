FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

RUN mkdir -p /data/packets

EXPOSE 8888

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8888", "--workers", "1"]
