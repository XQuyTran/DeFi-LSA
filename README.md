# DeFi-LSA
Công nghệ Blockchain (IS6105.11.CH)

## Runtime and smoke collection

Use the workspace virtual environment on Windows:

```powershell
.venv\Scripts\python.exe -m pip install -e ".[dev,parquet,aws]"
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe -m defi_lsa --help
```

Smoke runs accept paired `--start-block` and `--end-block` overrides. They are
recorded in checkpoints and D2 reports without changing the frozen registry:

```powershell
.venv\Scripts\python.exe -m defi_lsa collect --event euler --stage all `
  --source auto --start-block 16818024 --end-block 16818024 `
  --output reports\smoke\euler_one_block --resume
.venv\Scripts\python.exe -m defi_lsa audit --event euler `
  --output reports\smoke\euler_one_block --strict
```

Use separate output roots for one-block, 100-block, and registry-driven full
runs. A valid restored root containing `data`, `checkpoints`, or `reports` is
reused; collection preflight also checks free disk space and writability.

The Kaggle notebook in `src/DeFi_LSA_D2_Kaggle_Collection.ipynb` loads
credentials from Kaggle Secrets, installs the package, performs runtime and
source checks, runs isolated Euler/Kyber smoke roots, and leaves full runs
disabled until strict smoke audits pass. Credentials are never written to the
runtime configuration or reports.

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
