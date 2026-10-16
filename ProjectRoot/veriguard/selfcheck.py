"""Shared helpers for check_week1.py … check_week4.py (PROVIDED, do not modify)."""
from __future__ import annotations

import os
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS: list[tuple[str, bool]] = []

# every name the Azure parts ask you to copy into .env, by the week that introduces it
ENV_BY_WEEK = {
    1: ["AZURE_SUBSCRIPTION_ID", "AZURE_RESOURCE_GROUP", "AZURE_TENANT_ID", "FOUNDRY_RESOURCE_NAME",
        "AZURE_AI_PROJECT_ENDPOINT", "AZURE_OPENAI_ENDPOINT", "AZURE_AI_SERVICES_ENDPOINT",
        "AZURE_AI_MODEL_DEPLOYMENT_NAME", "AZURE_AI_EMBEDDING_DEPLOYMENT_NAME", "FOUNDRY_PROJECT_RESOURCE_ID",
        "AZURE_STORAGE_ACCOUNT", "AZURE_SEARCH_ENDPOINT", "AZURE_SEARCH_INDEX"],
    2: ["AZURE_KEY_VAULT_NAME", "VERIGUARD_MCP_URL", "VERIGUARD_MCP_CONNECTION", "ACR_NAME", "CONTAINERAPPS_ENV",
        "LOCATION"],
    3: ["VERIGUARD_API_AUDIENCE", "ENTRA_GROUP_ANALYST", "ENTRA_GROUP_INVESTIGATOR", "ENTRA_GROUP_AUDITOR",
        "ENTRA_GROUP_PRINCIPALOFFICER", "ENTRA_GROUP_ADMIN"],
    4: ["APPLICATIONINSIGHTS_CONNECTION_STRING", "VERIGUARD_API_URL"],
}
WHERE = {   # the guide step whose last item records the values — shown in the error message
    1: "Azure Part 1, step 'Record the Environment Values'", 2: "Azure Part 2, step 'Record the Environment Values'",
    3: "Azure Part 3, step 'Record the Environment Values'", 4: "Azure Part 4, step 'Record the Environment Values'"}


def check(task: str, label: str, fn) -> None:
    try:
        out = fn()
        ok, why = (out, "") if isinstance(out, bool) else (False, str(out))
    except NotImplementedError as exc:
        ok, why = False, f"still a stub ({exc})"
    except AssertionError as exc:
        ok, why = False, str(exc) or "assertion failed"
    except Exception as exc:  # noqa: BLE001 — every failure is reported, never raised
        ok, why = False, f"{type(exc).__name__}: {exc}"
        if os.getenv("VERIGUARD_DEBUG"):
            traceback.print_exc()
    RESULTS.append((task, ok))
    print(f"  {'✅' if ok else '❌'} [{task}] {label}" + (f"\n        → {why}" if not ok else ""))


def env_problems(root: Path = ROOT) -> tuple[dict, list[str]]:
    """Read .env the way python-dotenv does and report the classic mistakes. Returns (values, problems)."""
    problems: list[str] = []
    if (root / ".env.txt").exists() and not (root / ".env").exists():
        problems.append("the file is named .env.txt — rename it to .env (Windows hides the extension)")
    path = root / ".env"
    if not path.exists():
        return {}, ["no .env in the project root — copy .env.example to .env (Windows: copy .env.example .env)"]
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        problems.append(".env is saved as UTF-16 — in VS Code choose Save with Encoding → UTF-8")
        return {}, problems
    text = raw.decode("utf-8-sig")
    if raw.startswith(b"\xef\xbb\xbf"):
        problems.append(".env starts with a BOM — Save with Encoding → UTF-8 (without BOM)")
    seen: dict[str, str] = {}
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        k, v = k.strip(), v.strip()
        if k in seen:
            problems.append(f"{k} is defined twice (line {n}) — the first definition wins; delete the extra line")
            continue
        if " #" in v:
            problems.append(f"{k} (line {n}) has an inline comment — comments must go on their own line")
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            problems.append(f"{k} (line {n}) is wrapped in quotes — remove the quotes")
        seen[k] = v
    for k, v in seen.items():
        if v == "" and os.environ.get(k):
            problems.append(f"{k} is empty in .env but already set in your terminal environment — the terminal value is used")
    return seen, problems


def azure_env_check(week: int) -> bool:
    """Every Azure value of weeks 1…week must be filled in .env, with the exact name the guide gives."""
    vals, problems = env_problems()
    missing = [f"{n} (Week {w})" for w in range(1, week + 1) for n in ENV_BY_WEEK[w] if not vals.get(n)]
    msg = problems + ([f"not filled in .env: {', '.join(missing)} — see {WHERE[week]} (copy it from the Azure portal)"]
                      if missing else [])
    assert not msg, " | ".join(msg)
    return True


def summary(week: int) -> int:
    passed = sum(ok for _, ok in RESULTS)
    print(f"\nWeek {week} self-check: {passed}/{len(RESULTS)} checks passing"
          + (" — all green ✅  (now click Evaluate)" if passed == len(RESULTS) else " — fix the ❌ lines above"))
    return 0 if passed == len(RESULTS) else 1
