# VeriGuard API image — build from the PROJECT ROOT:
#   docker build --platform linux/amd64 -f api/Dockerfile -t <acr>.azurecr.io/veriguard-api:v1 .
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt requirements-azure.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-azure.txt
COPY veriguard ./veriguard
COPY api ./api
# templates, labels, security sets and the manifest; documents and dcb_core.sql are synced from Blob at start-up
COPY datapack/03_alerts ./datapack/03_alerts
COPY datapack/04_evaluation ./datapack/04_evaluation
COPY datapack/05_security ./datapack/05_security
COPY datapack/06_templates ./datapack/06_templates
COPY datapack/02_structured_data/risk_scoring_points.json ./datapack/02_structured_data/
ENV VERIGUARD_MODE=live PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["sh", "-c", "python -m veriguard.sync --week 2 && uvicorn api.app:app --host 0.0.0.0 --port 8000"]
