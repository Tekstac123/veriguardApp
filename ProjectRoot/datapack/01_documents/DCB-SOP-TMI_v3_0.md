---
doc_id: DCB-SOP-TMI
version: "3.0"
status: Current
effective_date: 2026-01-15
classification: Internal
owner: AML Investigations
---

# Transaction Monitoring and Investigation Standard Operating Procedure
*Deccan Commonwealth Bank - synthetic training data*

## 1. Alert Lifecycle

An alert moves through the states: New, In Triage, Under Investigation, Escalated to Principal Officer, Closed - No Further Action, Closed - STR Filed. Every state change is logged with user, timestamp and reason.

## 2. Triage Steps

At triage the analyst: (1) reviews the rule that fired and the triggering transactions; (2) checks KYC risk category and last KYC update date; (3) reviews 90 days of account history against the customer's baseline; (4) checks sanctions and watchlist screening status; (5) decides whether to close as a false positive or open an investigation.

## 3. Investigation Steps

The investigator: (1) maps activity to typologies in the AML Typology Handbook (DCB-HB-TYP); (2) computes the customer risk score using DCB-MTH-CRR; (3) identifies counterparties and linked accounts; (4) documents supporting and mitigating evidence; (5) records a recommendation of Close, Continue Monitoring, or Escalate to Principal Officer.

## 4. Case File Contents

A complete case file contains: alert details, customer profile summary with masked identifiers, transaction extract, typology assessment, risk score with factor breakdown, policy references with document ID, section and version, mitigating factors, recommendation and rationale, and reviewer sign-off.

## 5. Human Approval Requirements

Any case with a risk score of 70 or above, or any recommendation to escalate or report, must be approved by the Principal Officer before action. System-generated recommendations are advisory and must be reviewed by a human investigator.
