# Implementation Status (Aligned with Revised Epic Plan)

**Reference Plan:** [`docs/plan.md`](plan.md)
**Branch:** `feature/epic-revised`
**Test Baseline:** `440 passed` (`.\.venv\Scripts\python.exe -m pytest -q`)

---

## Epic Status Overview

| Epic | Name | Priority | Status | Notes |
|------|------|----------|--------|-------|
| E0 | Scope Freeze & Evidence Registry | P0 | **Complete** | Scope, anchors, alert benchmarks, and exclusion log frozen |
| E1 | Euler Data Readiness | P0 | **In Progress** | Collection pipeline & AWS/RPC/DefiLlama fixes complete; full 10-day Kaggle run pending |
| E2 | Flow-Leg Decoding & Classification | P0 | **Implemented (Pending Live Run)** | D3 decoding, flow classification, and pipeline tested; awaiting E1 full artifacts & manual tx audit |
| E3 | Hourly Dataset Freeze | P0 | **Implemented (Pending Live Run)** | `d3_hourly.py` panel builder & freeze logic tested; awaiting E2 live outputs |
| E4 | Descriptive & Statistical Analysis | P0 | **Not Started** | RQ1 & RQ2 statistical modules and thesis figures pending |
| E5 | No-Look-Ahead Alert Replay | P0 | **Not Started** | RQ3 rule-based replay engine and latency benchmark pending |
| E6 | Kyber Conditional Validation | P1 | **Deferred (Conditional)** | Activated only after Euler E1–E5 gates pass |
| E7 | Final Submission Package | P0 | **Not Started** | Reproduction script, traceability matrix, report, and slides pending |

---

## Detailed Epic Breakdown

### E0 — Scope Freeze & Evidence Registry (Complete)
- **Verified Master Events:** [`data/evidence/events_master_verified.csv`](../data/evidence/events_master_verified.csv) freezes Euler Finance (`euler_2023-03-13`, exploit block `16818024`, `2023-03-13T08:56:35Z`) and the 10-day collection window (`2023-03-06T08:56:35Z` to `2023-03-16T08:56:35Z`, blocks `16773224`–`16845224`).
- **Registry Configs:** [`configs/events.json`](../configs/events.json), [`configs/contract_scopes.json`](../configs/contract_scopes.json), [`configs/incident_legs.json`](../configs/incident_legs.json), [`configs/tokens.json`](../configs/tokens.json), [`configs/public_sources.json`](../configs/public_sources.json), and [`configs/registry_manifest.json`](../configs/registry_manifest.json) are updated and validated.
- **Alert Benchmarks:** [`configs/alert_benchmarks.json`](../configs/alert_benchmarks.json) documents verified public alerts (PeckShield, BlockSec, Euler Finance) with UTC timestamps, platforms, URLs, and categories.
- **Scope & Exclusions:** [`docs/research_scope_v1.md`](research_scope_v1.md) and [`docs/event_exclusion_log.md`](event_exclusion_log.md) document the Euler primary case, conditional Kyber scope, and exclusions (Curve, EVT_002, EVT_004, EVT_008).

### E1 — Euler Data Readiness (In Progress)
- **Implemented:**
  - AWS Public Blockchain S3 Parquet adapter ([`src/defi_lsa/aws.py`](../src/defi_lsa/aws.py)) with `estimate_block_date` fallback and `start_date`/`end_date` partition wiring in [`src/defi_lsa/orchestration.py`](../src/defi_lsa/orchestration.py) for `logs`, `transactions`, and extended AWS tables.
  - DefiLlama price anchor integration tested via `tests/test_d3_defillama.py`.
  - `json_rpc_client` in [`src/defi_lsa/collectors.py`](../src/defi_lsa/collectors.py) updated to read HTTP `400`/`413`/`422` JSON-RPC error payloads so adaptive chunk shrinking triggers on provider range limits.
  - Kaggle notebook [`src/DeFi_LSA.ipynb`](../src/DeFi_LSA.ipynb) Cell 5 updated to inherit `aws_public_blockchain` and `source_priority` from [`configs/sources.json`](../configs/sources.json).
- **Remaining:**
  - Re-run [`src/DeFi_LSA.ipynb`](../src/DeFi_LSA.ipynb) in Kaggle to complete the full 10-day Euler collection (`--stage all --source auto --resume`) and verify a passing `d2_collection_audit.json` gate.

### E2 — Flow-Leg Decoding & Classification (Implemented, Pending Live Run)
- **Implemented:**
  - Event/call decoding, transaction classification, actor role attribution, incident-leg validation, and balance-input generation in [`src/defi_lsa/d3_decoding.py`](../src/defi_lsa/d3_decoding.py), [`src/defi_lsa/d3_flow.py`](../src/defi_lsa/d3_flow.py), [`src/defi_lsa/d3_pipeline.py`](../src/defi_lsa/d3_pipeline.py), and [`src/defi_lsa/d3_schemas.py`](../src/defi_lsa/d3_schemas.py).
  - Unit tests passing across `tests/test_d3_decoding.py`, `tests/test_d3_flow.py`, `tests/test_d3_orchestration.py`, and `tests/test_d3_schemas.py`.
- **Remaining:**
  - Execute `python -m defi_lsa d3 --event euler_2023-03-13` on the full E1 dataset.
  - Verify unknown flow share and complete the manual transaction validation log (`docs/manual_tx_audit_euler.md`).

### E3 — Hourly Dataset Freeze (Implemented, Pending Live Run)
- **Implemented:**
  - Hourly panel aggregation and dataset freezing implemented in [`src/defi_lsa/d3_hourly.py`](../src/defi_lsa/d3_hourly.py) and covered by `tests/test_d3_hourly.py`.
- **Remaining:**
  - Produce frozen `dataset_euler_v1.parquet`, `dataset_manifest.json` (with SHA-256 checksums), and `docs/data_dictionary.md` from the live E2 outputs.

### E4 — Descriptive & Statistical Analysis (Not Started)
- Implement RQ1 (naive vs. classified flow estimation and misclassification ratio) and RQ2 (baseline vs. first-24h post-exploit User Net Outflow with Mann-Whitney U, Cliff's Delta, median, and IQR) plus thesis figures.

### E5 — No-Look-Ahead Alert Replay (Not Started)
- Implement RQ3 causal rule-based alert replay against the fixed 7-day pre-exploit baseline, compute detection delay, alert lag vs. [`configs/alert_benchmarks.json`](../configs/alert_benchmarks.json), false alert rate, sensitivity analysis, and `docs/alert_replay_assumptions.md`.

### E6 — Kyber Conditional Validation (Deferred / P1)
- Held as conditional validation (`kyberswap_elastic_2023-11-22`, Ethereum-only) until Euler E1–E5 pass.

### E7 — Final Submission Package (Not Started)
- Assemble end-to-end reproduction script, `docs/lecturer_feedback_traceability.md`, thesis results synthesis, figures/tables, and defense slides summary.
