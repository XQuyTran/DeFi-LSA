# Real Data Collection Enablement Epics

## Purpose
Close the remaining gaps between the current D2 component library and a runnable, end-to-end raw-data collection workflow for Euler Finance, Curve Vyper, and Ethereum-only KyberSwap Elastic.

## E1. Collection Registry Completion
**Objective:** Make every event executable without manual address, token, query, or time-window entry.

### Tasks
- E1.1 Add `collection_start_utc`, `collection_end_utc`, `start_block`, and `end_block` to each event.
- E1.2 Complete Euler exploit transaction and asset-leg enumeration.
- E1.3 Create Curve pool-level incident legs for CRV/ETH, pETH/ETH, msETH/ETH, and alETH/ETH, including exact transaction hashes, blocks, actors, and roles.
- E1.4 Complete Ethereum-only KyberSwap affected-pool and exploit/front-run transaction enumeration.
- E1.5 Add `configs/tokens.json` with token address, decimals, CoinGecko ID, and fallback price source.
- E1.6 Add `configs/public_sources.json` with forum URLs, topic IDs or search queries, official feed URLs, GDELT aliases, keywords, allowed domains, and collection windows.
- E1.7 Validate and freeze registry version.

### Acceptance criteria
- No executable event has an unresolved collection window.
- Every required token has address, decimals, and price-source identity.
- Every registered exploit transaction belongs to an incident leg.
- Curve is not marked executable until all four pool legs are verified.
- Registry manifest includes Git commit and SHA-256 hashes.

## E2. Source Configuration and Credential Wiring
**Objective:** Provide validated, secret-free source configuration for local and Kaggle execution.

### Tasks
- E2.1 Add `configs/sources.json` using checked official base URLs.
- E2.2 Load `ETH_RPC_URL`, `ETHERSCAN_API_KEY`, `COINGECKO_API_KEY`, and optional GitHub credentials exclusively from environment variables/Kaggle Secrets.
- E2.3 Add true connectivity probes for RPC, Etherscan, CoinGecko, GDELT, forums, and AWS S3.
- E2.4 Add source-priority rules by artifact type.
- E2.5 Redact all credentials from logs, errors, manifests, and notebook outputs.

### Acceptance criteria
- `connectivity` performs a real request, not configuration-only validation.
- Required sources return `reachable`, `authentication_error`, or an explicit failure.
- No secret appears in committed code or generated reports.

## E3. Executable Collection Orchestrator
**Objective:** Connect the implemented collectors and adapters to the CLI.

### Tasks
- E3.1 Implement `CollectionContext` and canonical artifact paths.
- E3.2 Wire `collect --stage logs` to adaptive chunked collection and checkpoints.
- E3.3 Wire transaction discovery, transaction retrieval, and receipt retrieval.
- E3.4 Wire ABI acquisition and cache.
- E3.5 Wire CoinGecko price collection from token registry.
- E3.6 Wire Discourse, protocol feed, and GDELT collection from public-source registry.
- E3.7 Add `collect --stage all` with dependency ordering.
- E3.8 Make `--resume`, `--dry-run`, and versioned `--force` behavior operational.

### Acceptance criteria
- `python -m defi_lsa collect --event euler --stage logs --source rpc` writes actual raw and normalized log artifacts.
- `--resume` does not re-query completed ranges.
- `--stage all` invokes each configured collector and writes a final run summary.
- Unrecoverable errors produce a non-zero process exit code.

## E4. Concrete AWS Public Blockchain Adapter
**Objective:** Replace the injected-query stub with a real reader for the public Ethereum Parquet dataset.

### Tasks
- E4.1 Implement anonymous S3 access to `s3://aws-public-blockchain/v1.0/eth/`.
- E4.2 Support blocks, transactions, logs, token transfers, traces, and contracts date partitions.
- E4.3 Push down date, block, transaction, and scoped-address filters.
- E4.4 Normalize AWS records into existing schemas without losing source identity.
- E4.5 Add RPC fallback for receipts and verification.
- E4.6 Add source-conflict reports.

### Acceptance criteria
- A known date partition can be listed and read without AWS credentials.
- A known exploit log has the same canonical identity as the RPC record.
- Source conflicts are reported and never silently overwritten.

## E5. ABI and Proxy Metadata Hardening
**Objective:** Ensure D3 can decode collected events from verified and cached metadata.

### Tasks
- E5.1 Move Etherscan requests to API V2 and include `chainid=1`.
- E5.2 Apply shared retry, throttling, provenance, and credential redaction.
- E5.3 Persist immutable raw Etherscan responses and normalized ABI files.
- E5.4 Add ABI cache validation.
- E5.5 Resolve proxy implementations and implementation ABIs.
- E5.6 Add local protocol-repository ABI fallback.

### Acceptance criteria
- Required ABI coverage is 100%, or the event returns `CONDITIONAL_GO/NO_GO`.
- Cached ABI checksum and source URL are recorded.
- Proxy contracts have implementation addresses and appropriate ABI evidence.

## E6. Real D2 Audit and Gate Integration
**Objective:** Replace placeholder audit inputs with measurements from collected artifacts.

### Tasks
- E6.1 Load actual checkpoints, JSONL/Parquet files, ABI directories, and price reports.
- E6.2 Evaluate registered transaction and receipt coverage.
- E6.3 Evaluate completed, failed, and pending ranges.
- E6.4 Evaluate duplicate identities and source-manifest completeness.
- E6.5 Evaluate token-level price and public-source status.
- E6.6 Produce JSON and Markdown gate reports.
- E6.7 Block D3 when D2 returns `NO_GO`.

### Acceptance criteria
- Audit can be rerun without collection.
- Corrective actions identify exact missing ranges, transactions, ABIs, or tokens.
- Gate status is derived only from actual artifacts.

## E7. Packaging, Dependencies, and Kaggle Runtime
**Objective:** Make installation reproducible in a clean Kaggle notebook.

### Tasks
- E7.1 Add dependency groups for test, Parquet, and AWS access.
- E7.2 Add console entry point or maintain `python -m defi_lsa` consistently.
- E7.3 Add a Kaggle notebook that clones/pulls the GitHub repository, loads Kaggle Secrets, installs dependencies, writes runtime-only source configuration, runs tests, probes sources, performs smoke collection, then launches event collection.
- E7.4 Persist outputs under `/kaggle/working/defi-lsa-output` and optionally publish them as a Kaggle Dataset outside the collector.
- E7.5 Add disk-space and internet checks.

### Acceptance criteria
- A fresh Kaggle session can install the repository and run fixture tests.
- Secrets are never printed.
- Smoke collection returns real records for a small block range.
- Full collection can resume after notebook restart when prior artifacts are attached as a Kaggle Dataset or otherwise restored.

## E8. End-to-End Live Smoke and Event Runs
**Objective:** Demonstrate that the workflow collects real data before committing to full windows.

### Tasks
- E8.1 Run one-block and 100-block RPC smoke tests for Euler and Kyber.
- E8.2 Run one verified Curve pool/transaction smoke test after registry completion.
- E8.3 Collect one token price window per event.
- E8.4 Collect one public forum topic and one GDELT query per event.
- E8.5 Run D2 audit on smoke artifacts.
- E8.6 Run full event windows only after smoke gate passes.

### Acceptance criteria
- Smoke artifacts contain non-synthetic records and valid source checksums.
- Registered exploit transactions and receipts are present.
- No hidden failed range exists.
- Full event collection starts only after smoke status is `GO` or an approved `CONDITIONAL_GO`.

## Recommended execution order
1. E1 Registry Completion
2. E2 Source Configuration
3. E7 Packaging foundation
4. E3 CLI Orchestration
5. E5 ABI Hardening
6. E4 AWS Adapter
7. E6 Real Audit
8. E8 Live Smoke and Full Runs

## Definition of Done
Real-data collection is enabled when the Kaggle notebook can clone the GitHub repository, load secrets, install dependencies, perform real connectivity checks, collect raw and normalized on-chain logs/transactions/receipts/ABIs/prices/public metadata, resume interrupted ranges, generate source manifests, and produce a real D2 gate report for each executable event.
