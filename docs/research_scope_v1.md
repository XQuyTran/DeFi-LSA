# Research Scope v1

## Mandatory primary case

Euler Finance is the primary incident case for RQ1-RQ3. The frozen collection window is March 6, 2023 08:56:35 UTC through March 16, 2023 08:56:35 UTC. The exploit transaction is fixed at block 16,818,024 and timestamp March 13, 2023 08:56:35 UTC.

## Affected asset set

The mandatory asset set is WETH, DAI, USDC, WBTC, and wstETH. Collection depth is sufficient for E1 when all exploit transactions and affected Euler vault or pool flows required for reconstruction are available, even if unrelated protocol activity is incomplete.

## Research questions

- **RQ1:** How does flow-leg classification alter liquidity-loss estimates compared with a naive pool-drain estimate?
- **RQ2:** How does first-24-hour post-exploit user capital net outflow differ from the fixed 7-day pre-exploit baseline?
- **RQ3:** How does a no-look-ahead rule-based replay trigger relative to the exploit and public threat-intelligence alerts?

## Scope gates

E0 freezes the event, block window, asset set, evidence links, and alert benchmarks. E1 requires a strict D2 audit of the Euler window; DefiLlama supplies the fixed USD price anchor immediately before the exploit, while full-window hourly price coverage remains conditional.

KyberSwap Elastic is conditional Ethereum-only validation and is not included unless Epic E6 is activated.
