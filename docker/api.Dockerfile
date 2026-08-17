FROM python:3.13-slim

WORKDIR /app

COPY requirements-serve.txt .
RUN pip install --no-cache-dir -r requirements-serve.txt

COPY src/ ./src/

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["sh", "-c", "uvicorn src.dashboard.api:app --host 0.0.0.0 --port 8000 --root-path \"${API_ROOT_PATH:-}\""]
