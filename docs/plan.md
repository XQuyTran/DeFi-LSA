# G05.C3 – Final 7-Day Execution Plan (Revised Epic Structure)

## Project Title

Flow Analysis and Incident Alerting Around DeFi Security Events

## Execution Mode

Implementation-Ready

## Main Objective

Deliver a defendable MSc project by producing:

1. A verified and reproducible DeFi incident dataset.
2. A flow-leg based capital flow reconstruction methodology.
3. A frozen hourly research dataset.
4. A no-look-ahead incident alert replay framework.
5. Thesis-ready evidence, figures, report, and defense slides.

---

# Scope Decision

## Included

### Primary Case (Mandatory)

- Euler Finance
- Ethereum
- T-7 days → T+3 days

### Secondary Case (Conditional Validation)

- KyberSwap Elastic
- Ethereum only
- Activated only if Data Readiness Gate passes before Day 2 completion.

---

## Excluded

### Case Studies

- Curve Finance
- EVT_002
- EVT_004
- EVT_008

### Methods

- BSTS
- VAR
- Granger Causality
- Isolation Forest
- Machine Learning Extensions
- Deep Learning Models
- Sentiment Models

---

# Research Questions

## RQ1

How does flow-leg classification change the estimation of liquidity loss around DeFi security incidents?

### Evidence

- Naive flow estimation
- Classified flow estimation
- Misclassification ratio

---

## RQ2

How does user capital outflow differ between baseline periods and the first 24h after a security incident?

### Evidence

- User Net Outflow
- Mann-Whitney U Test
- Cliff's Delta
- Median and IQR comparison

---

## RQ3

When would a no-look-ahead incident detection rule trigger relative to:

- exploit occurrence
- verified public alerts

### Evidence

- Detection delay
- Alert lag
- False alert rate
- Sensitivity analysis

---

# Epic Overview

| Epic | Name | Priority |
|--------|--------|--------|
| E0 | Scope Freeze & Evidence Registry | P0 |
| E1 | Euler Data Readiness | P0 |
| E2 | Flow-Leg Decoding & Classification | P0 |
| E3 | Hourly Dataset Freeze | P0 |
| E4 | Descriptive & Statistical Analysis | P0 |
| E5 | No-Look-Ahead Alert Replay | P0 |
| E6 | Kyber Conditional Validation | P1 |
| E7 | Final Submission Package | P0 |

---

# EPIC E0
# Scope Freeze & Evidence Registry

## Goal

Freeze research scope, incident anchors, and alert benchmarks.

## Owner

TV1

## Tasks

### E0.1 Verify Exploit Anchors

For each case:

- exploit_tx_hash
- exploit_block
- exploit_timestamp_utc
- evidence_url

### E0.2 Verify Alert Benchmarks

Collect:

- source account
- platform
- timestamp
- URL
- alert category

Categories:

- initial_suspicion
- confirmed_exploit
- protocol_acknowledgement
- postmortem

### E0.3 Event Exclusion Log

Document:

- EVT_002
- EVT_004
- EVT_008
- Curve

and why they are excluded.

## Outputs

events_master_verified.csv

event_exclusion_log.md

research_scope_v1.md

## Acceptance Criteria

- Euler anchor verified
- UTC timestamps verified
- Alert benchmark documented
- Scope frozen

---

# EPIC E1
# Euler Data Readiness

## Goal

Create a usable raw dataset for Euler.

## Owner

TV2

## Tasks

### E1.1 Full Collection

Run:

```bash
python -m defi_lsa collect \
 --event euler \
 --stage all \
 --source auto \
 --resume
```