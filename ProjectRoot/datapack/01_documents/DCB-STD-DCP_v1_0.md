---
doc_id: DCB-STD-DCP
version: "1.0"
status: Current
effective_date: 2025-12-01
classification: Internal
owner: Information Security
---

# Data Classification and Personal Data Handling Standard
*Deccan Commonwealth Bank - synthetic training data*

## 1. Classification Levels

Internal: available to all staff. Confidential: available to named roles with a business need. Restricted: available to specific named individuals. Board-Restricted: available only to the Board, Audit Committee and Head of Internal Audit.

## 2. Personal Data Masking

Aadhaar numbers must be displayed with only the last 4 digits visible. PAN must be displayed with the middle five characters masked. Account numbers must be displayed with only the last 4 digits visible. Full phone numbers and residential addresses must not appear in reports, dashboards, logs or prompts sent to external services.

## 3. Data Minimisation

Systems must process only the personal data needed for the stated purpose. Personal data must not be used to train or fine-tune models without approval from the Data Protection Officer.

## 4. Retention of Logs

Application and AI interaction logs must not contain unmasked personal data. Audit logs of decisions are retained for 8 years.
