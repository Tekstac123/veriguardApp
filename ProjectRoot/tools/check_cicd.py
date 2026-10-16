"""Offline check of the Part 4B files (Task 4). Usage: python tools/check_cicd.py"""
import json, pathlib, sys
root = pathlib.Path(__file__).resolve().parent.parent
bad = 0
def ok(c, m):
    global bad
    print(("OK   " if c else "FAIL ") + m); bad += (not c)
jf = root / "Jenkinsfile"
t = jf.read_text() if jf.exists() else ""
ok(jf.exists(), "Jenkinsfile exists")
for s in ["Checkout","Prepare environment","Quality checks","Release gate","Build image","Deploy","Smoke test"]:
    ok(f"stage('{s}')" in t, f"Jenkinsfile stage: {s}")
ok("az login --identity" in t, "Jenkinsfile uses the managed identity")
ok("az acr build" in t and "api/Dockerfile" in t, "Jenkinsfile builds api/Dockerfile in ACR")
ok("post {" in t and "failure" in t, "Jenkinsfile has a rollback on failure")
jd = root / "jenkins/Dockerfile"
ok(jd.exists() and "InstallAzureCLI" in jd.read_text(), "jenkins/Dockerfile installs the Azure CLI")
dj = root / "grafana/dashboards/veriguard.json"
if dj.exists():
    d = json.loads(dj.read_text()); titles = " ".join(p["title"] for p in d["panels"])
    ok(len(d["panels"]) >= 5, f"dashboard has {len(d['panels'])} panels")
    for k in ["Cost","Latency","Traces","budget_exceeded","errors"]:
        ok(k.lower() in titles.lower(), f"dashboard panel: {k}")
else:
    ok(False, "grafana/dashboards/veriguard.json exists")
ok((root/"grafana/provisioning/datasources/azure-monitor.yaml").exists(), "Azure Monitor data source file exists")
sys.exit(1 if bad else 0)
