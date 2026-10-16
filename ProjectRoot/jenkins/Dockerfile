# VeriGuard Part 4B - Jenkins controller with Azure CLI and Python.
# Build in Azure (no Docker needed on the lab machine):
#   az acr build -r $ACR -t veriguard-jenkins:v1 -f jenkins/Dockerfile jenkins
FROM jenkins/jenkins:lts-jdk21
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv python3-pip curl ca-certificates git \
 && curl -sL https://aka.ms/InstallAzureCLIDeb | bash \
 && rm -rf /var/lib/apt/lists/*
USER jenkins
# Plugins: pipeline, git, timestamps. No credentials plugin needed: the identity signs in.
RUN jenkins-plugin-cli --plugins workflow-aggregator git timestamper
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=true"
