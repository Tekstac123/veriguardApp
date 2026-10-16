#!/usr/bin/env python3
"""Compare the three files that must agree: config/project.json, config/main.parameters.json and the project's .env.

    python iac_tools/check_names.py [--env ../.env] [--params config/main.parameters.json] [-g <rg>]

Prints one line per name: OK, or what differs. Exit code 1 if anything differs. Placeholders (<...>) and empty values that a later step fills in are reported as "pending".
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read_env(path: Path) -> dict:
    out = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k, _, v = s.partition("=")
            out.setdefault(k.strip(), v.strip())
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", default=str(ROOT.parent / ".env"))
    ap.add_argument("--params", default=str(ROOT / "config" / "main.parameters.json"))
    ap.add_argument("-g", "--resource-group")
    a = ap.parse_args()
    cfg = json.loads((ROOT / "config" / "project.json").read_text(encoding="utf-8"))
    par = {
        k: v["value"]
        for k, v in json.loads(Path(a.params).read_text(encoding="utf-8"))[
            "parameters"
        ].items()
    }
    env = read_env(Path(a.env))
    rg = a.resource_group or cfg.get("resourceGroup")
    sub = cfg.get("subscriptionId")
    f, s, st, k, r = (
        cfg["foundry"]["name"],
        cfg["search"]["serviceName"],
        cfg["storage"]["accountName"],
        cfg["week2"]["keyVaultName"],
        cfg["week2"]["registryName"],
    )
    # (label, config value, parameters-file key, .env key, expected .env value)
    rows = [
        ("foundry name", f, "foundryName", "FOUNDRY_RESOURCE_NAME", f),
        (
            "project endpoint",
            None,
            None,
            "AZURE_AI_PROJECT_ENDPOINT",
            f"https://{f}.services.ai.azure.com/api/projects/{cfg['foundry']['projectName']}",
        ),
        (
            "openai endpoint",
            None,
            None,
            "AZURE_OPENAI_ENDPOINT",
            f"https://{f}.openai.azure.com",
        ),
        (
            "ai services endpoint",
            None,
            None,
            "AZURE_AI_SERVICES_ENDPOINT",
            f"https://{f}.cognitiveservices.azure.com",
        ),
        ("storage account", st, "storageAccountName", "AZURE_STORAGE_ACCOUNT", st),
        (
            "search service",
            s,
            "searchServiceName",
            "AZURE_SEARCH_ENDPOINT",
            f"https://{s}.search.windows.net",
        ),
        (
            "search index",
            cfg["search"]["indexName"],
            "searchIndexName",
            "AZURE_SEARCH_INDEX",
            cfg["search"]["indexName"],
        ),
        ("key vault", k, "keyVaultName", "AZURE_KEY_VAULT_NAME", k),
        ("registry", r, "registryName", "ACR_NAME", r),
        ("location", cfg["location"], "location", "LOCATION", cfg["location"]),
        ("resource group", rg, None, "AZURE_RESOURCE_GROUP", rg),
        ("subscription", sub, None, "AZURE_SUBSCRIPTION_ID", sub),
        (
            "project resource id",
            None,
            None,
            "FOUNDRY_PROJECT_RESOURCE_ID",
            f"/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.CognitiveServices/accounts/{f}/projects/{cfg['foundry']['projectName']}"
            if sub
            else None,
        ),
    ]
    problems = 0
    limits = {"storage account": 24, "key vault": 24}
    for label, cval, pkey, ekey, eexp in rows:
        notes = []
        if pkey and cval is not None and par.get(pkey) != cval:
            notes.append(
                f"parameters file has {par.get(pkey)!r}, project.json has {cval!r}"
            )
        have = env.get(ekey, "")
        if eexp is not None and have != eexp:
            pending = (not have) or ("<" in have)
            notes.append(
                ("pending: " if pending else "")
                + f".env {ekey}={have!r}, expected {eexp!r}"
            )
            problems += 0 if pending else 1
        if label in limits and cval and len(cval) > limits[label]:
            notes.append(f"{len(cval)} characters - the limit is {limits[label]}")
            problems += 1
        if pkey and cval is not None and par.get(pkey) != cval:
            problems += 1
        print(
            f"{'OK     ' if not notes else ('pending' if all(n.startswith('pending') for n in notes) else 'DIFFERS')}  {label:<20} {cval if cval is not None else eexp or ''}"
        )
        for n in notes:
            print(f"           - {n}")
    for var in (
        "AZURE_TENANT_ID",
        "VERIGUARD_MCP_URL",
        "VERIGUARD_API_URL",
        "APPLICATIONINSIGHTS_CONNECTION_STRING",
        "ENTRA_GROUP_ANALYST",
    ):
        v = env.get(var, "")
        if not v or "<" in v:
            print(
                f"pending  {var:<38} filled by a later step (see the comment above it in .env)"
            )
    print(
        "\nAll names agree." if not problems else f"\n{problems} difference(s) found."
    )
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
