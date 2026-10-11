# DeFi-LSA
Công nghệ Blockchain (IS6105.11.CH)

## Data-readiness pipeline

The initial implementation is registry-first. It validates the candidate event list,
derives contract-centric collection scopes, and records registry input checksums.

Run the registry validation from the repository root:

```text
python -m defi_lsa registry
```

The command writes `configs/events.json`, `configs/contract_scopes.json`, and
`configs/registry_manifest.json`. The implementation deliberately fails on malformed
addresses, hashes, dates, duplicate event IDs, or empty contract scopes.

The event build interface is reserved for the subsequent D2-D5 collector and freeze
stages:

```text
python -m defi_lsa build --event euler
python -m defi_lsa build --event curve
python -m defi_lsa build --event kyber
```

D2 collectors are contract-scoped and write append-only JSONL raw artifacts. They
are resumable: an existing record key is skipped rather than duplicated. The
available interfaces are `fetch_blocks`, `fetch_transactions`, `fetch_receipts`,
`fetch_logs`, `fetch_abi`, `fetch_hourly_prices`, and
`fetch_public_information` in
[collectors.py](D:/Quy%20Tran/Documents/masters/Blockchain/project/DeFi-LSA/src/defi_lsa/collectors.py).
Use `source-manifest` after collection to record artifact checksums:

```text
python -m defi_lsa source-manifest --output data/raw/source_manifest.json `
  --artifact "rpc=https://rpc.example/=data/raw/blocks.jsonl"
```

The RPC collectors fail explicitly on missing blocks, receipts, logs, or RPC
errors. ABI collection similarly fails on unavailable or malformed ABI responses.
Prices and public-information rows require explicit timestamps and identity fields;
the collector does not interpolate prices, classify transactions, or silently
drop malformed rows.

KyberSwap is Ethereum-only for Phase 1. Curve requires pool- and actor-level
enumeration before its registry can be frozen. No API credentials or paid services
are committed to the repository; source adapters will read credentials from the
environment when implemented.
