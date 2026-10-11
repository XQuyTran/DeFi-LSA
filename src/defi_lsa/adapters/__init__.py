"""External data source adapters for D2 collection (A05, A06).

Exported adapters:
- :class:`CoinGeckoAdapter`: Historical token price collection and coverage audit.
- :class:`DiscourseAdapter`: Public forum topic/post metadata collection.
- :class:`GDELTAdapter`: News and media article metadata query.
"""

from __future__ import annotations

from .coingecko import CoinGeckoAdapter, PriceCoverageReport, calculate_price_coverage
from .discourse import DiscourseAdapter
from .gdelt import GDELTAdapter
from .protocol import ProtocolAnnouncementAdapter

__all__ = [
    "CoinGeckoAdapter",
    "DiscourseAdapter",
    "GDELTAdapter",
    "ProtocolAnnouncementAdapter",
    "PriceCoverageReport",
    "calculate_price_coverage",
]
