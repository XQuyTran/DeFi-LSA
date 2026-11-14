Updated Plan for the Final 2 Weeks
Mode: Implementation-ready

Decision: Freeze D2 feature development. Focus on producing a defensible research dataset and thesis results.

Current status indicates that:

D1 Registry is complete.
E2–E5 core collection infrastructure is effectively complete.
E6 artifact-derived audit exists and produces D2 audit reports.
Euler and Kyber smoke collections have successfully generated logs, transactions, receipts, checkpoints, ABI coverage reports, and D2 audit outputs.
Curve remains non-executable because incident-leg verification is incomplete.

Given the remaining schedule, the primary goal is no longer platform hardening; it is delivery of a research-quality dataset and thesis evidence package.

1. Project Objective (Revised)

Build a reproducible dataset and analysis pipeline capable of answering:

RQ1: How do DeFi security incidents affect user withdrawals and liquidity?
RQ2: How much observed liquidity loss is attributable to attacker drains versus user reaction?
RQ3: How does public information relate temporally to user capital flight?

The project will prioritize:

Euler Finance as the primary case.
KyberSwap Elastic (Ethereum-only scope) as the secondary case.
Curve Finance Vyper Incident becomes an optional extension if registry completion is achieved on time.
2. Scope Freeze
Included
Event 1

Euler Finance

Collection window:
T-14 days → T+7 days


Primary dataset.

Event 2

KyberSwap Elastic

Ethereum only


Secondary dataset.

Deferred
Event 3

Curve Finance Vyper Incident

Remain:

Conditional GO


until all incident legs are verified.

3. Revised Phase Structure
Phase A
Complete D2 Operational Closure

Phase B
D3 Event Decoding & Classification

Phase C
D4 Flow & Liquidity Reconstruction

Phase D
D5 Dataset Freeze

Phase E
Research Analysis & Thesis

Phase A — D2 Operational Closure
Goal

Produce at least one complete event dataset.

Remaining Tasks
A1

Euler Full Collection

Owner:

Data Engineer


Actions:

python -m defi_lsa collect \
  --event euler \
  --stage all \
  --source auto \
  --resume


Output:

raw logs
transactions
receipts
ABI
audit


Acceptance:

D2 audit = GO
or approved CONDITIONAL_GO

A2

Artifact Validation

Verify:

receipts exist

transactions exist

logs exist

ABI coverage report exists

source manifests exist


Acceptance:

No hidden failed ranges

A3

Resume Verification

Run collection twice.

Acceptance:

Second run does not recollect
completed ranges

A4

Kyber Full Collection

Same acceptance as Euler.

Ethereum-only scope.

Phase B — D3 Event Decoding & Classification
Goal

Transform raw blockchain records into research events.

D3.1 Decode Events

Implement:

decode_event_logs()
decode_function_input()


Output:

decoded_events.parquet


Acceptance:

100% exploit transactions decoded

D3.2 Transaction Classification

Labels:

deposit
withdrawal
swap
flash_loan
exploit
recovery
unknown


Output:

classified_transactions.parquet


Acceptance:

Unknown flow ≤ 5%

D3.3 Actor Classification

Roles:

attacker
whitehat
protocol
user
unknown


Acceptance:

All exploit paths classified

Phase C — D4 Flow & Liquidity Reconstruction
Goal

Create research variables.

D4.1 UserNetOutflow

Formula:

Withdrawals - Deposits
excluding attacker actors


Output:

user_net_outflow_hourly.parquet

D4.2 Attacker Flow

Output:

attacker_flow_hourly.parquet

D4.3 Liquidity Series

Because CoinGecko remains disabled in runtime configuration and audit currently accepts this as a documented conditional status, liquidity should initially be expressed in token units rather than USD-adjusted liquidity.

Required:

WETH balances
USDC balances
WBTC balances
...


Optional:

Chainlink prices
DEX-derived prices


if time permits.

D4.4 Hourly Panel

Output:

hourly_panel.parquet


Columns:

hour_utc
user_net_outflow
attacker_flow
token_balance
forum_count
news_count

Phase D — D5 Dataset Freeze
Goal

Produce defendable research datasets.

D5.1 Quality Audit

Checks:

duplicate logs = 0

missing exploit receipts = 0

unknown_flow ≤ 5%

D5.2 Dataset Freeze

Outputs:

dataset_euler_v1.parquet

dataset_kyber_v1.parquet


Plus:

dataset_manifest.json

data_dictionary.md

D5.3 Data Readiness Gate

Required:

GO
or approved CONDITIONAL_GO


for frozen datasets.

Phase E — Research Analysis
Goal

Produce thesis-ready evidence.

E1

Descriptive Event Analysis

For:

24h
72h
7d


Compute:

deposit volume

withdrawal volume

cumulative net outflow

attacker drain

recovery flow

E2

Baseline Comparison

Minimum:

Before vs After


Optional:

OLS Event Dummy


if time allows.

E3

Thesis Figures

Produce:

Hourly User Outflow
Cumulative Outflow
Attacker vs User Flow
Liquidity Trend
Event Timeline

All charts must be generated from frozen datasets.

Two-Week Schedule
Days	Objective	Exit Condition1–2	Euler full D2	Audit GO
3–4	D3 Euler	Unknown ≤5%
5	D4 Euler	Hourly panel complete
6	D5 Euler	Dataset frozen
7–8	Kyber D2	Audit GO/Conditional GO
9–10	D3 Kyber	Classification complete
11	Baseline analysis	Tables generated
12	Figures	Thesis charts complete
13	Writing	Results section complete
14	Rebuild + package	All artifacts reproducible
De-scoped Items

The following are no longer on the critical path:

Additional D2 hardening

More AWS enhancements

CoinGecko integration

Generic multi-source pricing

Curve full implementation

BSTS

VAR

Advanced counterfactual models

Extended robustness suite

Definition of Done

The project is considered complete when:

 Euler dataset frozen
 Kyber dataset frozen or documented Conditional GO
 D3 classification complete
 D4 hourly panel complete
 D5 quality audit passed
 Figures generated automatically
 Results reproducible from frozen artifacts
 Thesis package prepared
Final Recommendation

For the remaining two weeks:

Stop expanding D2.

Finish Euler.

Finish Kyber.

Complete D3 → D4 → D5.

Write the thesis.


This provides the highest probability of delivering a defendable MSc project within the remaining schedule while leveraging the D2 infrastructure that has already been built and validated through smoke collection.