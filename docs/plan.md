# D2-A01–A18 Collection Hardening Plan

## Problem and approach

The current D2 implementation has basic RPC, ABI, price-row, and public-information persistence, but it still has several production-readiness gaps:

- `fetch_logs()` sends one entire block window in a single `eth_getLogs` request.
- Existing collectors deduplicate records but do not persist progress or completed work units.
- Transaction discovery is based only on top-level `from`/`to` addresses and misses router/multicall/proxy-mediated activity.
- RPC and HTTP errors are not classified into retryable and permanent categories.
- Price and public-information functions only persist supplied rows; they do not implement source adapters.
- Source manifests derive retrieval time from file modification time and omit request/status/range/scope metadata.
- JSONL appends are not crash-safe, and normalized/raw storage contracts are not separated.
- There is no complete D2 coverage audit or command-line collection/resume/audit workflow.

Implement D2 as a source-preserving, resumable pipeline. Keep immutable source-shaped responses under `data/raw/source/`, write normalized JSONL records under `data/raw/normalized/`, and defer normalized Parquet conversion to A16. All collectors share identifier validation, request policy, checkpointing, provenance, structured errors, and deterministic fixture tests.

## Scope and decisions

- Cover the complete D2-A01–A18 backlog.
- Adopt the `data/raw/source/` and `data/raw/normalized/` split. Source responses are immutable; normalized records reference their source artifact checksum.
- Keep Ethereum Phase 1 scope and existing registry-derived `ContractScope` boundaries.
- Keep Dune out of the critical path. AWS, Ethereum JSON-RPC, Etherscan, CoinGecko, public forum/protocol endpoints, and GDELT remain configurable sources.
- Do not interpolate or force prices in D2. Missing/unsupported tokens produce explicit coverage gaps or conditional status.
- Use transfer/source observations only; no silent fallback, fabricated data, or swallowed permanent errors.
- Checkpoints are invalid when event, collector, requested range, or contract scope hash changes.
- Raw artifacts are append-only/immutable by version; `--force` must create an explicit new version rather than overwrite prior raw data.
- Every unrecoverable failure is recorded with event, collector, source, range, retry count, and machine-readable error taxonomy.

## Workstreams and planned changes

### A11 — Identifier validation and normalization

- Add `normalize_address()`, `validate_address()`, `normalize_tx_hash()`, `validate_tx_hash()`, `parse_rpc_quantity()`, and `normalize_utc_timestamp()`.
- Reject malformed identifiers and naive timestamps before persistence.
- Preserve optional original checksummed values separately while using lowercase canonical lookup keys.
- Replace ad hoc hash/address normalization in all current collectors and registry-derived scopes.

### A04 — Shared request policy

- Add `TransientSourceError`, `RateLimitError`, `AuthenticationError`, `InvalidRequestError`, `IncompleteResponseError`, and `PermanentSourceError`.
- Add `classify_source_error()`, bounded exponential backoff with jitter, `Retry-After` handling, configurable attempts, and rate limiting.
- Apply one policy to JSON-RPC, Etherscan, CoinGecko, forum, protocol, GDELT, and AWS adapters.
- Redact credentials from URLs, parameters, exception messages, logs, and manifests.
- Emit machine-readable exhausted-retry records without retrying authentication or malformed-request failures indefinitely.

### A02 — Persistent checkpoints

- Create `CheckpointStore` with `load_checkpoint()`, atomic `save_checkpoint_atomic()`, `mark_range_completed()`, `mark_range_failed()`, `get_pending_ranges()`, and `validate_checkpoint_scope()`.
- Store event ID, collector, scope hash, requested range, completed ranges, failed ranges, timestamp, adapter version, and failure details.
- Use temporary-file write, flush/fsync where applicable, and atomic replacement.
- Integrate checkpoints into block, transaction, receipt, and log collectors.
- Ensure resumed jobs do not query verified completed ranges; failed ranges remain failed until explicitly retried.

### A01 — Adaptive chunked log collection

- Add `fetch_logs_chunked()` with configurable initial/minimum/maximum chunk sizes.
- Query only the current chunk, persist successful logs immediately, mark the range completed, then continue.
- Shrink chunks after timeout, response-limit, range-limit, or provider errors; grow after successful low-volume responses within configured bounds.
- Stop at minimum chunk size on persistent failure and record the irrecoverable range.
- Store normalized logs at `data/raw/normalized/logs/{event_id}.jsonl`.
- Write checkpoint at `data/checkpoints/{event_id}/logs.json` and range report at `reports/{event_id}/log_range_report.json`.
- Canonical log key is `(chain_id, tx_hash, log_index)` and must remain duplicate-free across retries/resumes.

### A03 — Scope-aware transaction discovery

- Add `discover_scoped_transaction_hashes()` using scoped logs as the primary source.
- Add registered exploit/recovery/evidence transaction hashes from incident-leg configuration.
- Add optional direct top-level calls to scoped addresses even if no logs are emitted.
- Add `fetch_transactions_by_hash()` and `collect_scoped_transactions()` to retrieve transactions and receipts after hash discovery.
- Emit inclusion reasons: `direct_call`, `scoped_log`, and `registry_anchor`.
- Write `data/raw/normalized/transaction_index/{event_id}.jsonl` and `data/raw/normalized/transactions/{event_id}.jsonl`.
- Require every scoped log to resolve to a transaction and receipt; require every registered exploit transaction to be present.

### A05 — CoinGecko price adapter

- Add `CoinGeckoAdapter.fetch_market_chart_range()` with source-response persistence, range handling, pagination/interval behavior, UTC normalization, and request provenance.
- Emit normalized fields: event ID, token address, CoinGecko ID, source timestamp, hour UTC, USD price, source, and retrieval timestamp.
- Collect the configured `T-14` through `T+7` research window plus buffer.
- Write source responses under `data/raw/source/coingecko/` and normalized records under `data/raw/normalized/prices/coingecko/`.
- Generate per-token coverage reports, duplicate checks, and maximum consecutive-gap metrics.
- Preserve returned stablecoin values; do not force them to 1 USD.

### A06 — Public-information adapters

- Add a Discourse adapter using public JSON endpoints first, with pagination, topic/post normalization, edited timestamps, canonical URLs, and inaccessible-content error records.
- Add protocol announcement/feed metadata collection restricted to registry-configured official domains and rules; store metadata/permitted excerpts only.
- Add GDELT query and normalization using registry-defined event aliases, keywords, time windows, canonical URLs, domains, languages, and deduplication rules.
- Write source responses separately from normalized forum, announcement, and news records.
- Ensure full copyrighted article text is never stored.

### A07 — D2 collection audit

- Add `audit_block_coverage()`, `audit_registered_transaction_coverage()`, `audit_receipt_coverage()`, `audit_log_range_coverage()`, `audit_abi_coverage()`, `audit_price_coverage()`, and `audit_public_source_coverage()`.
- Add `build_d2_gate_report()` producing JSON and Markdown reports.
- Report requested/collected/missing blocks, registered and missing exploit transactions, missing receipts, duplicate logs, ABI percentage, per-token price coverage/gaps, public-source status, failed ranges, checkpoint state, and corrective actions.
- Return `GO`, `CONDITIONAL_GO`, or `NO_GO`; D3 must refuse to start on `NO_GO`.
- Make audits rerunnable without recollecting data.

### A10 — Provenance and source manifest semantics

- Replace modification-time-derived retrieval provenance with request-time capture.
- Expand records with source name, adapter version, method, URL, redacted parameter hash, requested/completed timestamps, HTTP status, response/artifact checksums, artifact path, record count, block range, event ID, and scope hash.
- Keep manifests deterministic for fixed inputs apart from explicitly runtime-generated fields.
- Include checkpoint and failed-range references in collection audit output.

### A13 — Source configuration contracts

- Add a validated configuration file for RPC, Etherscan, CoinGecko, GDELT, AWS, forum/protocol endpoints, timeout, attempts, rate limits, and log chunk bounds.
- Resolve secrets only through environment variables and validate required variables at command startup.
- Distinguish unavailable optional sources as explicit conditional status rather than silently disabling them.

### A14 — D2 CLI

- Add:
  - `python -m defi_lsa connectivity --event <event>`
  - `python -m defi_lsa collect --event <event> --source rpc`
  - `python -m defi_lsa collect --event <event> --stage logs --resume`
  - `python -m defi_lsa audit --event <event> --stage d2`
- Add unique run IDs, structured run summaries, dry-run scope/request output, resume validation, non-zero unrecoverable failure exits, and explicit versioning for force behavior.
- Preserve existing registry and source-manifest commands.

### A08 — AWS public blockchain adapter

- Add partition discovery and filtered Ethereum block/transaction/log retrieval.
- Normalize AWS records into the same contracts as RPC while preserving source identity.
- Support source selection and configured primary/fallback order.
- Produce source-conflict reports instead of overwriting conflicting records.

### A09 — Raw/normalized separation

- Move current persistence helpers toward immutable source artifacts plus normalized records with source SHA-256 references.
- Add normalization version independently from adapter version.
- Ensure normalization changes can be rerun from source artifacts without refetching.

### A12 — Crash-safe JSONL persistence

- Replace direct append-only writes with verified batch persistence.
- Validate existing JSONL lines on reopen, detect malformed trailing records, quarantine corruption explicitly, and preserve valid prior rows.
- Flush/fsync and atomically commit temporary batches where appropriate.
- Add interruption/resume tests verifying readable artifacts and stable counts.

### A15 — Cross-source reconciliation

- Add event-level samples comparing RPC, Etherscan, and AWS records.
- Compare transaction hash, block number, receipt status, and log identities.
- Produce a reconciliation report for differences; never silently choose an authoritative source.

### A16 — Normalized Parquet conversion (P1, moved earlier)

- Add explicit schemas and JSONL-to-Parquet conversion after normalized D2 collection.
- Partition by event ID, source, and block date.
- Preserve integer quantities exactly and verify row-count/duplicate invariants.
- Make D3 consume normalized Parquet rather than reparsing source JSON.
- Implement the parsing and schema layer before source-specific adapters so every
  collector has a fixed normalized output contract and can be tested against
  deterministic local fixtures.

### A17 — Collection observability

- Emit structured metrics: requests, failures, rate limits, records received/written/skipped, current block, completed percentage, bytes written, retries, and final status.
- Redact secrets and include event/source/collector/range on every error.
- Always write a final run summary, including failed runs.

### A18 — Deterministic fixture integration tests

- Add fixtures for direct calls, router-mediated calls, exploit transactions, multi-log receipts, duplicates, rate limits, incomplete prices, and forum pagination.
- Ensure CI performs no live API requests.
- Verify deterministic counts/checksums and expected D2 gate status.
- Cover success/failure paths for every P0 adapter and resume/checkpoint behavior.

## Execution order and dependencies

1. A11 identifiers.
2. A09 raw/normalized storage contracts and A12 crash-safe persistence.
3. **A16 Parquet parsing/conversion (P1):** establish schemas, parsing,
   partitioning, integer preservation, and local fixture verification before
   live/source adapters.
4. A04 request/error policy.
5. A02 persistent checkpoints.
6. A01 adaptive chunked logs.
7. A03 scope-aware transaction/receipt discovery.
8. A05 CoinGecko and A06 public-information adapters.
9. A10 provenance semantics and A13 source configuration.
10. A07 coverage audit and A14 CLI orchestration.
11. A08 AWS adapter.
12. A15 cross-source reconciliation and A17 observability.
13. A18 deterministic end-to-end fixture suite and final D2 gate verification.

## Completion criteria

D2 is complete when all registered event scopes can run the configured connectivity/collection flow; all requested block/log ranges are marked completed or failed; no failed range is hidden; registered exploit transactions and receipts are present; router-mediated transactions are retained; required ABIs and price/public-source statuses are explicit; source manifests contain request-time provenance; raw artifacts are immutable and resumable; canonical duplicates are zero; the D2 audit returns `GO` or an explicitly justified `CONDITIONAL_GO`; and the deterministic fixture suite passes without live API calls or credential leakage.
