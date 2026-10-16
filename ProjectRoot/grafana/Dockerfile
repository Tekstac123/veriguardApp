# VeriGuard Part 4B - Grafana with the data source and dashboard baked in.
#   az acr build -r $ACR -t veriguard-grafana:v1 -f grafana/Dockerfile grafana
FROM grafana/grafana:11.2.0
COPY provisioning /etc/grafana/provisioning
COPY dashboards   /var/lib/grafana/dashboards
