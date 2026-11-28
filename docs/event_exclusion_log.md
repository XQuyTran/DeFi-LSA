# Event Exclusion Log

## Frozen scope

- **Euler Finance (`euler_2023-03-13`)** is the mandatory primary case.
- **KyberSwap Elastic (`kyberswap_elastic_2023-11-22`)** is a conditional Ethereum-only validation case.
- **Curve Finance Vyper reentrancy (`curve_vyper_2023-07-30`)** and the EVT_002, EVT_004, and EVT_008 candidates remain excluded from the thesis result variables.

## Exclusion rationale

Curve spans multiple pools and multiple actors, and the incident cannot be represented by one verified atomic transaction and pool accounting boundary. Pool, actor, and derivative-token identities require more evidence resolution than the frozen delivery plan permits.

The EVT_002, EVT_004, and EVT_008 candidates do not provide a verified single-contract accounting boundary or the incident/flow evidence required for the mandatory Euler methodology. They are therefore not used in RQ1-RQ3.

Exclusion does not assert that these incidents are technically less important. It contains the dataset and prevents heterogeneous architectures from weakening the Euler reconstruction and alert-replay conclusions.
