"""Download what YOUR identity may read from Blob Storage into .azure_cache/ — live mode reads from there (PROVIDED).

    python -m veriguard.sync              # Week 1: corpus containers + manifest
    python -m veriguard.sync --week 2     # + core-banking (dcb_core.sql)
"""
from __future__ import annotations

import sys
from pathlib import Path

from . import azure
from .common import AZURE_CACHE


def main() -> None:
    report = azure.sync_corpus(AZURE_CACHE / "01_documents")
    for container, result in report.items():
        print(f"  {container:<20} {result}")
    if "--week" in sys.argv and int(sys.argv[sys.argv.index("--week") + 1]) >= 2:
        dest = Path(AZURE_CACHE) / "02_structured_data"
        dest.mkdir(parents=True, exist_ok=True)
        for name in azure.list_blobs("core-banking"):
            (dest / Path(name).name).write_bytes(azure.download_blob("core-banking", name))
            print(f"  core-banking         {name}")
    print(f"Cache: {AZURE_CACHE}  (VERIGUARD_MODE=live reads documents and dcb_core.sql from here)")


if __name__ == "__main__":
    main()
