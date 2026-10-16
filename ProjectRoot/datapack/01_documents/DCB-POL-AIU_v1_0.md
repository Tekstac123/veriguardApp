---
doc_id: DCB-POL-AIU
version: "1.0"
status: Current
effective_date: 2026-07-01
classification: Internal
---

# Responsible AI Usage Policy
*Deccan Commonwealth Bank - synthetic training data*

## 1. Advisory Nature of AI Outputs

AI systems used in compliance and investigations provide advisory outputs only. They must not file regulatory reports, restrict accounts or communicate with customers autonomously.

## 2. Grounding and Citations

Answers on policy or regulation must cite the source document ID, section and version. If the evidence is insufficient, the system must say so rather than infer an answer.

## 3. Access and Privacy

AI systems must enforce the user's own access rights when retrieving documents or calling tools. Personal data must be masked before being sent to a model.

## 4. Security Testing

Before production use, AI systems must pass red-team testing covering prompt injection, jailbreaks, data exfiltration and privilege escalation. Results are reviewed by the CISO.

## 5. Logging and Monitoring

All prompts, responses, tool calls and approval decisions are logged in an append-only audit store. Quality and safety metrics are monitored continuously.
