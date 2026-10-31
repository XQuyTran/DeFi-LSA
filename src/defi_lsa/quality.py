"""Quality gates shared by D3-D5 stages."""



from dataclasses import dataclass
from typing import Iterable, Mapping


@dataclass(frozen=True)
class UnknownFlowAudit:
    total_flow: float
    unknown_flow: float
    unknown_share: float
    passed: bool
    threshold: float


def audit_unknown_flows(
    flows: Iterable[Mapping[str, object]],
    *,
    amount_key: str = "amount",
    classification_key: str = "classification",
    threshold: float = 0.05,
) -> UnknownFlowAudit:
    """Enforce the G2 unknown-flow threshold before D4 calculations."""
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be between 0 and 1")
    total = 0.0
    unknown = 0.0
    for flow in flows:
        try:
            amount = abs(float(flow[amount_key]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid flow amount: {flow!r}") from exc
        total += amount
        if str(flow.get(classification_key, "")).strip().lower() == "unknown":
            unknown += amount
    share = unknown / total if total else 0.0
    return UnknownFlowAudit(
        total_flow=total,
        unknown_flow=unknown,
        unknown_share=share,
        passed=share <= threshold,
        threshold=threshold,
    )
