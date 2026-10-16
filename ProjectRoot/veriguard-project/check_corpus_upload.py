#!/usr/bin/env python3
"""check_corpus_upload.py - compare the corpus manifest with what is really in Blob Storage, and upload what is missing.

Why: the API builds its index from EVERY document in datapack/01_documents/corpus_manifest.csv. If one file is missing in Blob
Storage, every /ask and /investigate call fails with a plain-text "Internal Server Error" (the browser then reports
"SyntaxError: JSON.parse: unexpected character at line 1 column 1") and /ready fails with
FileNotFoundError: /app/.azure_cache/01_documents/<file>.

Run from ProjectRoot, after  az login --use-device-code :

    python check_corpus_upload.py            # report only
    python check_corpus_upload.py --fix      # upload the missing files (never overwrites, never deletes)

Needs the Azure CLI and the role "Storage Blob Data Contributor" for your user on the storage account.
The storage account comes from AZURE_STORAGE_ACCOUNT in .env (or --account NAME).
"""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DOCS = ROOT / "datapack" / "01_documents"


def env_value(name: str) -> str:
    path = ROOT / ".env"
    if not path.exists():
        return ""
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k, _, v = s.partition("=")
            if k.strip() == name:
                return v.strip().strip("\"'")
    return ""


def container_of(row: dict) -> str:
    if row["status"].strip().lower() == "superseded":
        return "superseded"
    c = row["classification"].strip().lower()
    return {
        "confidential": "confidential-corpus",
        "board-restricted": "board-restricted",
    }.get(c, "approved-corpus")


def az(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["az", *args], capture_output=True, text=True, stdin=subprocess.DEVNULL
    )


def blobs(account: str, container: str) -> set[str] | None:
    r = az(
        "storage",
        "blob",
        "list",
        "--account-name",
        account,
        "-c",
        container,
        "--auth-mode",
        "login",
        "--query",
        "[].name",
        "-o",
        "tsv",
    )
    if r.returncode != 0:
        print(f"  cannot read container {container}: {r.stderr.strip()[:200]}")
        return None
    return {n.strip() for n in r.stdout.splitlines() if n.strip()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fix", action="store_true", help="upload the missing files")
    ap.add_argument("--account", default="")
    a = ap.parse_args()
    account = a.account or env_value("AZURE_STORAGE_ACCOUNT")
    if not account:
        print("AZURE_STORAGE_ACCOUNT is not set in .env (or pass --account NAME)")
        return 2
    rows = list(csv.DictReader(open(DOCS / "corpus_manifest.csv", encoding="utf-8")))
    wanted: dict[str, list[str]] = {
        c: []
        for c in (
            "approved-corpus",
            "confidential-corpus",
            "board-restricted",
            "superseded",
        )
    }
    for r in rows:
        wanted[container_of(r)].append(r["file"])
    wanted["corpus-manifest"] = ["corpus_manifest.csv"]
    missing: list[tuple[str, str]] = []
    unreadable = False
    print(f"storage account {account}")
    for container, files in wanted.items():
        have = blobs(account, container)
        if have is None:
            unreadable = True
            continue
        gone = [f for f in files if f not in have]
        print(
            f"  {container:<20} expected {len(files):>2}  found {len(files) - len(gone):>2}"
            + (f"  MISSING: {', '.join(gone)}" if gone else "  ok")
        )
        missing += [(container, f) for f in gone]
    if unreadable:
        print(
            "\nSome containers could not be read - check az login and the role Storage Blob Data Contributor (wait 5-10 min after assigning it)."
        )
        return 2
    if not missing:
        print(
            "\nEvery document of the manifest is in Blob Storage. If the API still fails, restart it so that it syncs again:"
        )
        print(
            "  az containerapp revision restart -n <api app> -g <resource group> --revision <active revision>"
        )
        return 0
    if not a.fix:
        print(f"\n{len(missing)} file(s) missing. Run again with --fix to upload them.")
        return 1
    for container, f in missing:
        r = az(
            "storage",
            "blob",
            "upload",
            "--account-name",
            account,
            "-c",
            container,
            "-f",
            str(DOCS / f),
            "-n",
            f,
            "--auth-mode",
            "login",
            "--overwrite",
            "false",
        )
        print(
            f"  upload {container}/{f}: "
            + ("ok" if r.returncode == 0 else "FAILED " + r.stderr.strip()[:200])
        )
    print("\nNow restart the API so that its start-up sync downloads the new files:")
    print(
        "  az containerapp revision restart -n <api app> -g <resource group> --revision <active revision>"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
