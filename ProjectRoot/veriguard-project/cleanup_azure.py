#!/usr/bin/env python3
"""cleanup_azure.py — remove a project's Azure and Microsoft Foundry resources, safely.

Works for any project: it finds "project" resources by NAME PATTERN and TAG (defaults match the VeriGuard capstone and the
earlier FinSight/fde-foundry lab), deletes them in dependency order, purges the soft-deleted leftovers that would block a
re-deploy, and can also remove the Microsoft Entra objects and local generated files. Needs only Python 3.8+ and the Azure CLI.

    python cleanup_azure.py                          # DRY RUN: lists what would be removed, deletes nothing
    python cleanup_azure.py --execute                # delete the project resources inside every project resource group
    python cleanup_azure.py --execute --delete-groups   # also delete resource groups that contain ONLY project resources
    python cleanup_azure.py -g lab-learner1 --execute --all-resources --delete-groups   # wipe one named group completely
    python cleanup_azure.py --execute --entra --clean-local ../solution                 # + Entra apps/groups + local files

WHAT IT REMOVES (in this order, per resource group)
  1. Foundry agents of every project (Agent Service data plane: SDK first, REST fallback), then Foundry projects
     (their connections, incl. the MCP connection), model deployments, and the Foundry (AI Services / OpenAI) account
  2. Container Apps (the MCP server, the API), Container Apps environments
  3. Azure AI Search services (their indexes, knowledge sources and knowledge bases go with them)
  4. Container registries (images), Key Vaults, Storage accounts (unlocked time-based retention policies are removed first)
  5. Application Insights, Log Analytics workspaces, user-assigned managed identities, then any other matching resource
  6. Resource-group scope: policy assignments and budgets whose NAME contains a project prefix (when the group is kept; never other policies)
  7. --delete-groups: the resource group itself.  Then: PURGE of soft-deleted AI Services accounts and Key Vaults
     (with -g, only accounts and vaults that lived in the named groups are purged; without -g, project-named ones anywhere)
  8. --entra: app registrations (veriguard-api, veriguard-ci) and groups (grp-aml-*, grp-internal-audit, ...)
  9. --clean-local DIR: veriguard-lab.json, veriguard-mcp-key.txt, veriguard-entra.env, .azure_cache, reports/ (never code or .env)

SAFETY: dry run unless --execute · typed confirmation unless --yes · protected resource groups are never touched · a group is deleted only
if every resource in it is a project resource (override: --all-resources / --force-groups) · locks block deletion unless --remove-locks ·
Azure RBAC role assignments of the signed-in user are never removed.  Exit code 0 = done, 1 = something failed, 2 = refused / bad usage.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ------------------------------------------------------------------------------------------------ defaults (edit or override)
DEFAULT_PREFIXES = [
    "veriguard",
    "fde-foundry",
    "finsight",
]  # matched anywhere in a resource / group name, case-insensitive
DEFAULT_TAGS = {"project": "veriguard", "cost-center": "aml-compliance"}
ENTRA_APPS = ["veriguard-api", "veriguard-ci"]
ENTRA_GROUPS = [
    "grp-aml-analysts",
    "grp-aml-investigators",
    "grp-internal-audit",
    "grp-principal-officer",
    "grp-platform-admins",
]
PROTECTED_GROUPS = [
    "NetworkWatcherRG*",
    "DefaultResourceGroup-*",
    "MC_*",
    "cloud-shell-storage*",
    "AzureBackupRG*",
    "LogAnalyticsDefaultResources",
    "databricks-rg-*",
    "Default-*",
]
LOCAL_ITEMS = [
    "veriguard-lab.json",
    "veriguard-mcp-key.txt",
    "veriguard-entra.env",
    ".azure_cache",
    "reports",
]
AGENT_API_VERSIONS = [
    "v1",
    "2025-11-15-preview",
    "2025-05-15-preview",
]  # tried in turn: the Agent Service API is still in preview
CLASSIC_AGENT_API = "2025-05-01"
ARM = "https://management.azure.com"

# delete order (lower first); anything not listed goes last (100)
ORDER = {
    "microsoft.app/containerapps": 10,
    "microsoft.app/jobs": 12,
    "microsoft.app/managedenvironments": 20,
    "microsoft.cognitiveservices/accounts": 30,
    "microsoft.search/searchservices": 40,
    "microsoft.containerregistry/registries": 50,
    "microsoft.keyvault/vaults": 60,
    "microsoft.storage/storageaccounts": 70,
    "microsoft.insights/components": 80,
    "microsoft.operationalinsights/workspaces": 90,
    "microsoft.managedidentity/userassignedidentities": 95,
}

STATS = {"deleted": 0, "failed": [], "skipped": 0, "purged": 0}
OPTS: argparse.Namespace


# ------------------------------------------------------------------------------------------------ helpers
def say(msg: str = "") -> None:
    print(msg, flush=True)


def die(msg: str, code: int = 2):
    """Refuse / cannot start: exit code 2 (1 is reserved for 'something failed while deleting')."""
    print(msg, file=sys.stderr, flush=True)
    sys.exit(code)


def az(*args: str, parse: bool = True, check: bool = False):
    """Run the Azure CLI. Returns (ok, data_or_text, error_text). Never raises."""
    cmd = ["az", *args] + (
        ["-o", "json"]
        if parse and "-o" not in args and "--output" not in args and args[0] != "rest"
        else []
    )
    if OPTS.debug:
        say("    $ " + " ".join(cmd))
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=os.name == "nt",
            timeout=OPTS.timeout,
        )
    except subprocess.TimeoutExpired:
        return False, None, f"timed out after {OPTS.timeout}s"
    except FileNotFoundError:
        die(
            "The Azure CLI ('az') was not found. Install it, run 'az login --use-device-code' and try again."
        )
    out = (r.stdout or "").strip()
    if r.returncode != 0:
        return (
            False,
            None,
            (r.stderr or out or f"exit code {r.returncode}")
            .strip()
            .splitlines()[-1][:300],
        )
    if parse and out:
        try:
            return True, json.loads(out), ""
        except json.JSONDecodeError:
            pass
    return True, out, ""


def azj(*args: str):
    ok, data, err = az(*args)
    return data if ok and data is not None else []


def attempt(desc: str, fn, tries: int | None = None) -> bool:
    """Run fn() -> (ok, error) with retries (dependencies and propagation make the first try fail now and then)."""
    tries = tries or OPTS.retries
    err = ""
    for i in range(1, tries + 1):
        ok, err = fn()
        if ok:
            STATS["deleted"] += 1
            say(f"    ✓ {desc}")
            return True
        if i < tries:
            time.sleep(OPTS.retry_wait)
    STATS["failed"].append((desc, err))
    say(f"    ✗ {desc} — {err}")
    return False


def az_delete(desc: str, *args: str) -> bool:
    return attempt(desc, lambda: (lambda r: (r[0], r[2]))(az(*args, parse=False)))


# ------------------------------------------------------------------------------------------------ selection
def project_resource(res: dict) -> bool:
    if OPTS.all_resources:
        return True
    name = (res.get("name") or "").lower()
    tags = res.get("tags") or {}
    return any(p.lower() in name for p in OPTS.prefix) or any(
        tags.get(k) == v for k, v in OPTS.tags.items()
    )


def protected(group: str) -> bool:
    return any(
        fnmatch.fnmatch(group, pat) or fnmatch.fnmatch(group.lower(), pat.lower())
        for pat in PROTECTED_GROUPS + OPTS.protect
    )


def rtype(res: dict) -> str:
    return (res.get("type") or "").lower()


def plan_groups() -> list[dict]:
    groups = azj("group", "list")
    explicit = OPTS.resource_group
    plan = []
    for g in groups:
        name = g["name"]
        if explicit and not any(
            fnmatch.fnmatch(name.lower(), pat.lower()) for pat in explicit
        ):
            continue
        if protected(name):  # never touched, even when named with -g
            continue
        resources = azj("resource", "list", "-g", name)
        mine = [r for r in resources if project_resource(r)]
        tagged = any(
            (g.get("tags") or {}).get(k) == v for k, v in OPTS.tags.items()
        ) or any(p.lower() in name.lower() for p in OPTS.prefix)
        if not explicit and not mine and not tagged:
            continue
        # nested child resources are removed with their parent; do not list them as separate deletes
        top = [r for r in mine if not is_child(r)]
        others = [r for r in resources if r not in mine]
        locks = azj("lock", "list", "-g", name)
        delete_group = OPTS.delete_groups and not protected(name)
        reason = ""
        if delete_group and others and not OPTS.force_groups:
            delete_group, reason = (
                False,
                f"{len(others)} non-project resource(s) in it (e.g. {', '.join(o['name'] for o in others[:3])}); use --all-resources or --force-groups",
            )
        plan.append(
            {
                "name": name,
                "location": g.get("location"),
                "resources": sorted(
                    top, key=lambda r: (ORDER.get(rtype(r), 100), r["name"])
                ),
                "others": others,
                "locks": locks,
                "delete_group": delete_group,
                "group_reason": reason,
                "tags": g.get("tags") or {},
            }
        )
    return plan


def is_child(res: dict) -> bool:
    t = res.get("type") or ""
    parts = t.split("/")
    return len(parts) > 2 and rtype(res).startswith(
        (
            "microsoft.cognitiveservices/accounts/",
            "microsoft.storage/storageaccounts/",
            "microsoft.search/searchservices/",
            "microsoft.keyvault/vaults/",
        )
    )


# ------------------------------------------------------------------------------------------------ Foundry data plane
def http(method: str, url: str, token: str, body: dict | None = None):
    req = urllib.request.Request(
        url,
        method=method,
        data=json.dumps(body).encode() if body else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode() or "{}"
            return r.status, (
                json.loads(raw) if raw.strip().startswith(("{", "[")) else raw
            )
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode(errors="replace")[:200])
    except Exception as e:  # noqa: BLE001 — network problems are reported, never raised
        return 0, str(e)[:200]


def foundry_token() -> str:
    ok, tok, _ = az(
        "account",
        "get-access-token",
        "--resource",
        "https://ai.azure.com",
        "--query",
        "accessToken",
        "-o",
        "tsv",
        parse=False,
    )
    return tok if ok else ""


def account_projects(acct: dict) -> list[str]:
    data = azj(
        "rest",
        "--method",
        "get",
        "--url",
        f"{ARM}{acct['id']}/projects?api-version=2025-06-01",
    )
    return [
        p["name"].split("/")[-1]
        for p in (data.get("value", []) if isinstance(data, dict) else [])
    ]


def project_base(acct: dict) -> str:
    props = acct.get("properties") or {}
    ep = (
        (props.get("endpoints") or {}).get("AI Foundry API")
        or f"https://{props.get('customSubDomainName') or acct['name']}.services.ai.azure.com/"
    )
    return ep.rstrip("/")


def agents_of(base: str, project: str, token: str):
    """Return (names, how). Tries the azure-ai-projects SDK, then the REST API with several api-versions, then classic assistants."""
    endpoint = f"{base}/api/projects/{project}"
    try:  # 1. SDK (what create_agents.py uses)
        from azure.ai.projects import AIProjectClient  # type: ignore
        from azure.identity import AzureCliCredential  # type: ignore

        client = AIProjectClient(endpoint=endpoint, credential=AzureCliCredential())
        return [a.name for a in client.agents.list()], ("sdk", client)
    except Exception:  # noqa: BLE001 — SDK missing or different version: fall through to REST
        pass
    for v in AGENT_API_VERSIONS:  # 2. REST, new Agent Service
        st, body = http("GET", f"{endpoint}/agents?api-version={v}", token)
        if st == 200 and isinstance(body, dict):
            items = body.get("data") or body.get("value") or []
            return [
                i.get("name") or i.get("id") for i in items if isinstance(i, dict)
            ], ("rest", (endpoint, v))
    st, body = http(
        "GET", f"{endpoint}/assistants?api-version={CLASSIC_AGENT_API}", token
    )  # 3. classic assistants
    if st == 200 and isinstance(body, dict):
        return [i.get("id") for i in body.get("data", [])], ("classic", endpoint)
    return None, ("none", f"could not list agents (HTTP {st}: {body})")


def delete_agent(name: str, how, token: str) -> tuple[bool, str]:
    kind, ref = how
    if kind == "sdk":
        try:
            ref.agents.delete(name)
            return True, ""
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)[:200]
    if kind == "rest":
        endpoint, v = ref
        st, body = http("DELETE", f"{endpoint}/agents/{name}?api-version={v}", token)
    else:
        st, body = http(
            "DELETE", f"{ref}/assistants/{name}?api-version={CLASSIC_AGENT_API}", token
        )
    return (st in (200, 202, 204, 404)), (
        "" if st in (200, 202, 204, 404) else f"HTTP {st}: {body}"
    )


# ------------------------------------------------------------------------------------------------ per-type deletion
def clean_account(group: str, res: dict, token: str) -> None:
    ok, acct, err = az(
        "cognitiveservices", "account", "show", "-g", group, "-n", res["name"]
    )
    if not ok:
        say(f"    · {res['name']}: cannot read the account ({err})")
        acct = None
    if acct:
        for project in account_projects(acct):
            names, how = agents_of(project_base(acct), project, token)
            if names is None:
                say(
                    f"    · agents of {res['name']}/{project}: {how[1]} (the account delete below removes them anyway)"
                )
            for n in names or []:
                attempt(
                    f"Foundry agent {res['name']}/{project}/{n}",
                    lambda n=n, how=how: delete_agent(n, how, token),
                )
            attempt(
                f"Foundry project {res['name']}/{project} (connections incl. the MCP connection)",
                lambda project=project: (lambda r: (r[0], r[2]))(
                    az(
                        "rest",
                        "--method",
                        "delete",
                        "--url",
                        f"{ARM}{acct['id']}/projects/{project}?api-version=2025-06-01",
                        parse=False,
                    )
                ),
            )
        for d in azj(
            "cognitiveservices",
            "account",
            "deployment",
            "list",
            "-g",
            group,
            "-n",
            res["name"],
        ):
            az_delete(
                f"model deployment {res['name']}/{d['name']}",
                "cognitiveservices",
                "account",
                "deployment",
                "delete",
                "-g",
                group,
                "-n",
                res["name"],
                "--deployment-name",
                d["name"],
            )
    az_delete(
        f"AI Services account {res['name']}",
        "cognitiveservices",
        "account",
        "delete",
        "-g",
        group,
        "-n",
        res["name"],
    )


def clean_storage(group: str, res: dict) -> None:
    sa = res["name"]
    for c in azj(
        "storage", "container-rm", "list", "--storage-account", sa, "-g", group
    ):
        ok, pol, _ = az(
            "storage",
            "container",
            "immutability-policy",
            "show",
            "--account-name",
            sa,
            "-g",
            group,
            "-c",
            c["name"],
        )
        if (
            ok
            and isinstance(pol, dict)
            and pol.get("immutabilityPeriodSinceCreationInDays") is not None
        ):
            if (pol.get("state") or "").lower() == "locked":
                say(
                    f"    ! container {c['name']} has a LOCKED retention policy — it cannot be removed until the retention period ends"
                )
                continue
            etag = pol.get("etag") or "*"
            az_delete(
                f"retention policy of container {c['name']}",
                "storage",
                "container",
                "immutability-policy",
                "delete",
                "--account-name",
                sa,
                "-g",
                group,
                "-c",
                c["name"],
                "--if-match",
                etag,
            )
        ok, hold, _ = az(
            "storage",
            "container",
            "legal-hold",
            "show",
            "--account-name",
            sa,
            "-g",
            group,
            "-c",
            c["name"],
        )
        if ok and isinstance(hold, dict) and hold.get("tags"):
            az_delete(
                f"legal hold of container {c['name']}",
                "storage",
                "container",
                "legal-hold",
                "clear",
                "--account-name",
                sa,
                "-g",
                group,
                "-c",
                c["name"],
                "--tags",
                *[t["tag"] if isinstance(t, dict) else t for t in hold["tags"]],
            )
    az_delete(
        f"storage account {sa}",
        "storage",
        "account",
        "delete",
        "-n",
        sa,
        "-g",
        group,
        "--yes",
    )


HANDLERS = {
    "microsoft.app/containerapps": lambda g, r, t: az_delete(
        f"container app {r['name']}",
        "containerapp",
        "delete",
        "-n",
        r["name"],
        "-g",
        g,
        "--yes",
    ),
    "microsoft.app/jobs": lambda g, r, t: az_delete(
        f"container apps job {r['name']}",
        "containerapp",
        "job",
        "delete",
        "-n",
        r["name"],
        "-g",
        g,
        "--yes",
    ),
    "microsoft.app/managedenvironments": lambda g, r, t: az_delete(
        f"container apps environment {r['name']}",
        "containerapp",
        "env",
        "delete",
        "-n",
        r["name"],
        "-g",
        g,
        "--yes",
    ),
    "microsoft.cognitiveservices/accounts": lambda g, r, t: clean_account(g, r, t),
    "microsoft.search/searchservices": lambda g, r, t: az_delete(
        f"AI Search service {r['name']} (indexes, knowledge bases)",
        "search",
        "service",
        "delete",
        "-n",
        r["name"],
        "-g",
        g,
        "--yes",
    ),
    "microsoft.containerregistry/registries": lambda g, r, t: az_delete(
        f"container registry {r['name']} (images)",
        "acr",
        "delete",
        "-n",
        r["name"],
        "-g",
        g,
        "--yes",
    ),
    "microsoft.keyvault/vaults": lambda g, r, t: az_delete(
        f"Key Vault {r['name']}", "keyvault", "delete", "-n", r["name"], "-g", g
    ),
    "microsoft.storage/storageaccounts": lambda g, r, t: clean_storage(g, r),
    "microsoft.insights/components": lambda g, r, t: az_delete(
        f"Application Insights {r['name']}",
        "monitor",
        "app-insights",
        "component",
        "delete",
        "--app",
        r["name"],
        "-g",
        g,
    ),
    "microsoft.operationalinsights/workspaces": lambda g, r, t: az_delete(
        f"Log Analytics workspace {r['name']}",
        "monitor",
        "log-analytics",
        "workspace",
        "delete",
        "-g",
        g,
        "-n",
        r["name"],
        "--yes",
        "--force",
        "true",
    ),
    "microsoft.managedidentity/userassignedidentities": lambda g, r, t: az_delete(
        f"managed identity {r['name']}", "identity", "delete", "-n", r["name"], "-g", g
    ),
}


def clean_group(g: dict, token: str) -> None:
    name = g["name"]
    say(f"\n▶ resource group {name}")
    if g["locks"]:
        for lk in g["locks"]:
            if OPTS.remove_locks:
                az_delete(f"lock {lk['name']}", "lock", "delete", "--ids", lk["id"])
            else:
                say(
                    f"    ! lock '{lk['name']}' ({lk.get('level')}) may block deletion — re-run with --remove-locks to remove it"
                )
    for res in g["resources"]:
        handler = HANDLERS.get(rtype(res))
        if handler:
            handler(name, res, token)
        else:
            az_delete(
                f"{res['type']} {res['name']}", "resource", "delete", "--ids", res["id"]
            )
    if not g["delete_group"]:  # group is kept: remove project-scope artefacts
        for pa in azj("policy", "assignment", "list", "-g", name):
            # NAME match only, even with --all-resources: policy assignments on a group are usually the lab's governance, not ours
            if any(p.lower() in (pa.get("name") or "").lower() for p in OPTS.prefix):
                az_delete(
                    f"policy assignment {pa['name']}",
                    "policy",
                    "assignment",
                    "delete",
                    "-n",
                    pa["name"],
                    "--resource-group",
                    name,
                )
        sub = (
            az("account", "show", "--query", "id", "-o", "tsv", parse=False)[1] or ""
        ).strip()
        data = azj(
            "rest",
            "--method",
            "get",
            "--url",
            f"{ARM}/subscriptions/{sub}/resourceGroups/{name}/providers/Microsoft.Consumption/budgets?api-version=2023-05-01",
        )
        for b in data.get("value", []) if isinstance(data, dict) else []:
            if any(p in b["name"].lower() for p in OPTS.prefix):
                az_delete(
                    f"budget {b['name']}",
                    "rest",
                    "--method",
                    "delete",
                    "--url",
                    f"{ARM}{b['id']}?api-version=2023-05-01",
                )
    else:
        attempt(
            f"resource group {name}",
            lambda: (lambda r: (r[0], r[2]))(
                az(
                    "group",
                    "delete",
                    "-n",
                    name,
                    "--yes",
                    *([] if OPTS.wait else ["--no-wait"]),
                    parse=False,
                )
            ),
        )


def purge(groups: list[str], scoped: bool) -> None:
    if OPTS.keep_soft_deleted:
        return
    say("\n▶ purging soft-deleted leftovers")
    gl = [x.lower() for x in groups]

    def mine(item: dict) -> bool:
        rid = (
            (item.get("id") or "")
            + " "
            + ((item.get("properties") or {}).get("vaultId") or "")
        ).lower()
        in_selected = any(f"/resourcegroups/{g}/" in rid for g in gl)
        if scoped:  # -g or --all-resources: only what lived in the selected groups
            return in_selected
        return in_selected or project_resource(
            {"name": item.get("name", ""), "tags": item.get("tags")}
        )

    for a in azj("cognitiveservices", "account", "list-deleted"):
        if mine(a):
            loc = a.get("location") or (a.get("properties") or {}).get("location") or ""
            rg = (
                (a.get("id") or "").split("/resourceGroups/")[-1].split("/")[0]
                if a.get("id")
                else a.get("resourceGroup", "")
            )
            if az_delete(
                f"purge AI Services account {a['name']}",
                "cognitiveservices",
                "account",
                "purge",
                "--name",
                a["name"],
                "--resource-group",
                rg,
                "--location",
                loc,
            ):
                STATS["purged"] += 1
    for v in azj("keyvault", "list-deleted"):
        if mine(v):
            loc = v.get("properties", {}).get("location") or v.get("location") or ""
            if az_delete(
                f"purge Key Vault {v['name']}",
                "keyvault",
                "purge",
                "--name",
                v["name"],
                "--location",
                loc,
            ):
                STATS["purged"] += 1


def clean_entra() -> None:
    say("\n▶ Microsoft Entra ID")
    for app in OPTS.entra_app:
        for a in azj("ad", "app", "list", "--display-name", app):
            if a.get("displayName") == app:
                az_delete(
                    f"app registration {app} ({a['appId']})",
                    "ad",
                    "app",
                    "delete",
                    "--id",
                    a["appId"],
                )
    for grp in OPTS.entra_group:
        for g in azj("ad", "group", "list", "--display-name", grp):
            if g.get("displayName") == grp:
                az_delete(f"group {grp}", "ad", "group", "delete", "--group", g["id"])


def clean_local(folder: str) -> None:
    say(f"\n▶ local files in {folder}")
    base = Path(folder).resolve()
    for item in LOCAL_ITEMS:
        p = base / item
        if p.is_file() or p.is_dir():
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink()
            STATS["deleted"] += 1
            say(f"    ✓ {p}")


# ------------------------------------------------------------------------------------------------ main
def show_plan(plan: list[dict], token_ok: bool) -> int:
    n = 0
    for g in plan:
        say(
            f"\n▶ resource group {g['name']}  ({g['location']})"
            + (
                "   ← GROUP WILL BE DELETED"
                if g["delete_group"]
                else "   (group is kept)"
            )
        )
        if g["group_reason"]:
            say(f"    ! group kept: {g['group_reason']}")
        for lk in g["locks"]:
            say(
                f"    ! lock '{lk['name']}' ({lk.get('level')})"
                + (
                    "  → will be removed"
                    if OPTS.remove_locks
                    else "  → blocks deletion; use --remove-locks"
                )
            )
        for r in g["resources"]:
            say(f"    [delete] {r['type']:<52} {r['name']}")
            n += 1
            if rtype(r) == "microsoft.cognitiveservices/accounts" and token_ok:
                ok, acct, _ = az(
                    "cognitiveservices",
                    "account",
                    "show",
                    "-g",
                    g["name"],
                    "-n",
                    r["name"],
                )
                if ok and acct:
                    for project in account_projects(acct):
                        names, how = agents_of(
                            project_base(acct), project, foundry_token()
                        )
                        say(
                            f"        Foundry project {project}: "
                            + (
                                f"{len(names)} agent(s) {names}"
                                if names is not None
                                else how[1]
                            )
                        )
        for r in g["others"]:
            say(f"    [keep]   {r['type']:<52} {r['name']}  (not a project resource)")
    return n


def main() -> None:
    global OPTS
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--execute", action="store_true", help="actually delete (default: dry run)"
    )
    ap.add_argument(
        "--yes",
        action="store_true",
        help="skip the typed confirmation (for automation)",
    )
    ap.add_argument(
        "--subscription", help="subscription id or name (default: the current one)"
    )
    ap.add_argument(
        "-g",
        "--resource-group",
        action="append",
        default=[],
        metavar="NAME",
        help="resource group name or glob, repeatable (default: every project group)",
    )
    ap.add_argument(
        "--prefix",
        action="append",
        default=None,
        help="name fragment that marks a project resource, repeatable (default: "
        + ", ".join(DEFAULT_PREFIXES)
        + ")",
    )
    ap.add_argument(
        "--tag",
        action="append",
        default=None,
        metavar="KEY=VALUE",
        help="tag that marks a project resource, repeatable (default: "
        + ", ".join(f"{k}={v}" for k, v in DEFAULT_TAGS.items())
        + ")",
    )
    ap.add_argument(
        "--all-resources",
        action="store_true",
        help="treat EVERY resource in the selected groups as a project resource",
    )
    ap.add_argument(
        "--delete-groups",
        action="store_true",
        help="also delete the resource groups (only if they hold nothing but project resources)",
    )
    ap.add_argument(
        "--force-groups",
        action="store_true",
        help="with --delete-groups: delete groups even when they hold non-project resources",
    )
    ap.add_argument(
        "--protect",
        action="append",
        default=[],
        metavar="GLOB",
        help="extra resource-group names that are never touched",
    )
    ap.add_argument(
        "--remove-locks",
        action="store_true",
        help="delete resource locks that would block deletion",
    )
    ap.add_argument(
        "--keep-soft-deleted",
        action="store_true",
        help="do not purge soft-deleted AI Services accounts and Key Vaults (frees names/quota only when purged)",
    )
    ap.add_argument(
        "--entra",
        action="store_true",
        help="also delete the Entra app registrations and groups",
    )
    ap.add_argument(
        "--entra-app",
        action="append",
        default=None,
        help="app display name (default: " + ", ".join(ENTRA_APPS) + ")",
    )
    ap.add_argument(
        "--entra-group",
        action="append",
        default=None,
        help="group display name (default: " + ", ".join(ENTRA_GROUPS) + ")",
    )
    ap.add_argument(
        "--clean-local",
        metavar="DIR",
        help="delete generated files in DIR (veriguard-lab.json, key and entra files, .azure_cache, reports/)",
    )
    ap.add_argument(
        "--no-wait",
        dest="wait",
        action="store_false",
        help="do not wait for resource-group deletion",
    )
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--retry-wait", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=1800, help="per az command, seconds")
    ap.add_argument("--debug", action="store_true", help="print every az command")
    OPTS = ap.parse_args()
    OPTS.prefix = OPTS.prefix or DEFAULT_PREFIXES
    OPTS.tags = dict(t.split("=", 1) for t in OPTS.tag) if OPTS.tag else DEFAULT_TAGS
    OPTS.entra_app = OPTS.entra_app or ENTRA_APPS
    OPTS.entra_group = OPTS.entra_group or ENTRA_GROUPS
    if (OPTS.all_resources or OPTS.force_groups) and not OPTS.resource_group:
        die(
            "--all-resources and --force-groups delete things that are NOT recognisably part of the project, so they need an explicit -g <group>."
        )
    if OPTS.force_groups and not OPTS.delete_groups:
        die("--force-groups only makes sense together with --delete-groups")

    ok, acct, err = az("account", "show")
    if not ok:
        die(f"Not signed in to Azure ({err}). Run: az login --use-device-code")
    previous = acct["id"]
    if OPTS.subscription:
        ok, _, err = az(
            "account", "set", "--subscription", OPTS.subscription, parse=False
        )
        if not ok:
            die(f"Cannot select subscription {OPTS.subscription}: {err}")
        acct = az("account", "show")[1]
    say(
        f"Subscription : {acct['name']} ({acct['id']})   signed in as {acct['user']['name']}"
    )
    say(
        "Mode         : "
        + (
            "EXECUTE — resources WILL be deleted"
            if OPTS.execute
            else "DRY RUN — nothing is deleted (add --execute)"
        )
    )
    say(
        f"Project match: name contains any of {OPTS.prefix}  or tags {OPTS.tags}"
        + ("  or ANY resource (--all-resources)" if OPTS.all_resources else "")
    )
    try:
        plan = plan_groups()
        token = foundry_token()
        n = show_plan(plan, bool(token))
        say("")
        if OPTS.entra:
            say(f"Entra ID     : apps {OPTS.entra_app}, groups {OPTS.entra_group}")
        if OPTS.clean_local:
            say(f"Local files  : {', '.join(LOCAL_ITEMS)} in {OPTS.clean_local}")
        say(
            f"Plan         : {n} resource(s) in {len(plan)} resource group(s); {sum(g['delete_group'] for g in plan)} group(s) deleted; soft-deleted AI Services accounts / Key Vaults "
            + ("kept" if OPTS.keep_soft_deleted else "purged")
        )
        if not plan and not (OPTS.entra or OPTS.clean_local):
            say("Nothing to do.")
            return
        if not OPTS.execute:
            say("\nDry run only. Re-run with --execute to delete.")
            return
        if not OPTS.yes:
            if not sys.stdin.isatty():
                die(
                    "Refusing to delete without a terminal to confirm. Re-run interactively or add --yes."
                )
            if (
                input(
                    f"\nType DELETE to remove the {n} resource(s) above from '{acct['name']}': "
                ).strip()
                != "DELETE"
            ):
                say("Aborted — nothing was deleted.")
                sys.exit(2)
        for g in plan:
            clean_group(g, token)
        purge(
            [g["name"] for g in plan],
            scoped=bool(OPTS.resource_group) or OPTS.all_resources,
        )
        if OPTS.entra:
            clean_entra()
        if OPTS.clean_local:
            clean_local(OPTS.clean_local)
    finally:
        if OPTS.subscription and previous != acct["id"]:
            az("account", "set", "--subscription", previous, parse=False)
    say(
        f"\nDone: {STATS['deleted']} deleted, {STATS['purged']} purged, {len(STATS['failed'])} failed."
    )
    for desc, err in STATS["failed"]:
        say(f"  ✗ {desc}: {err}")
    if STATS["failed"]:
        hints = []
        if any("lock" in e.lower() for _, e in STATS["failed"]):
            hints.append("a resource lock blocks deletion: add --remove-locks")
        if any(
            "purgeprotection" in e.lower().replace(" ", "")
            or "purge protection" in e.lower()
            for _, e in STATS["failed"]
        ):
            hints.append(
                "a Key Vault has purge protection on: it cannot be purged before its retention period ends"
            )
        if any("immutab" in e.lower() for _, e in STATS["failed"]):
            hints.append(
                "a LOCKED retention policy cannot be removed until the retention period ends"
            )
        for h in hints:
            say("  hint: " + h)
        say(
            "Re-run the same command: it only touches what is still there (dependencies often clear on the second pass)."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
