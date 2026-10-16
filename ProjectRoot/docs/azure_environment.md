# VeriGuard — Azure environment record (configuration values only — NEVER key values)

| Week | Item | Value |
|---|---|---|
| 1 | Subscription / resource group / region | |
| 1 | Foundry resource / project | veriguard-foundry / proj-veriguard |
| 1 | Project endpoint | |
| 1 | Chat / embedding deployments | gpt-4.1-mini / text-embedding-3-small |
| 1 | Storage account / containers | veriguardcorpus / approved-corpus, confidential-corpus, board-restricted, superseded, corpus-manifest |
| 1 | Search endpoint / your index / semantic config | / veriguard-m1 / veriguard-m1-semantic |
| 1 | Foundry IQ knowledge source / knowledge base / agent | ks-veriguard-approved / kb-veriguard-m1 / veriguard-policy-qa |
| 1 | Golden dataset (version) | veriguard-golden v1 → v2 |
| 2 | Key Vault / secret names | veriguard-kv / veriguard-mcp-api-key |
| 2 | Container registry / Container Apps environment | veriguardacr / veriguard-env |
| 2 | MCP server URL / project connection | / veriguard-tools-mcp |
| 2 | Foundry agents | veriguard-txn-monitor, veriguard-risk, veriguard-investigator |
| 2 | Case store containers / notes TTL rule | case-files, investigator-notes / delete after 90 days |
| 3 | App registration / audience / app roles | veriguard-api / api://veriguard-api / Analyst, Investigator, Auditor, PrincipalOfficer, Admin |
| 3 | Security groups (object ids) | |
| 3 | Content filter / blocklist | veriguard-strict / veriguard-tipping-off |
| 3 | Audit container / immutability policy | audit-log / time-based retention, days: |
| 4 | Application Insights | appi-veriguard |
| 4 | Budget / Azure Policy assignments | |
| 4 | API Container App / identities | veriguard-api / system-assigned + id-veriguard-pull |

## Evidence log
| Week | Check | Result (paste the last line of tools/verify_azure.py --week N) |
|---|---|---|
