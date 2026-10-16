# VeriGuard MCP server image — build from the PROJECT ROOT:
#   docker build --platform linux/amd64 -f mcp_server/Dockerfile -t <acr>.azurecr.io/veriguard-mcp:v1 .
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt requirements-azure.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-azure.txt
COPY veriguard ./veriguard
COPY mcp_server ./mcp_server
# the data pack ships everything except the core-banking database, which is pulled from Blob at start-up (live)
COPY datapack/03_alerts ./datapack/03_alerts
COPY datapack/02_structured_data/risk_scoring_points.json ./datapack/02_structured_data/
COPY datapack/06_templates ./datapack/06_templates
COPY datapack/01_documents/corpus_manifest.csv ./datapack/01_documents/
ENV VERIGUARD_MODE=live PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["uvicorn", "mcp_server.server:app", "--host", "0.0.0.0", "--port", "8080"]
