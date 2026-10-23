# =========================================================================
# Multi-stage Dockerfile for DeepLog SIEM (FastAPI + React SOC Dashboard)
# =========================================================================

# Stage 1: Build the React Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Production Python Backend Server
FROM python:3.11-slim AS runner

WORKDIR /app

# Install security certificates & minimal dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir cryptography python-jose pyotp

# Copy backend application code and ML models
COPY app/ ./app/
COPY feature_exactor.py predictor.py ./
COPY deeplog_features.pkl ./
COPY deeplog_web_attack_model.pkl.gz ./
COPY csic_database.csv ./

# Copy built frontend assets from Stage 1 into frontend/dist
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Non-root user execution for container hardening (OWASP principle)
RUN adduser --disabled-password --gecos "" deeplog \
    && chown -R deeplog:deeplog /app
USER deeplog

EXPOSE 8000

ENV PORT=8000 \
    PYTHONUNBUFFERED=1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
