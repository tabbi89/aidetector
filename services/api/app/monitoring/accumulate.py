"""One day's aggregates, folded event by event so a day never lives in memory."""

from __future__ import annotations

from collections.abc import Iterable

from app.monitoring.analysis import BucketAccumulator
from app.monitoring.bots import BotAccumulator
from app.monitoring.clients import ClientAccumulator
from app.monitoring.detectors import RouteAccumulator
from app.monitoring.waf import NormalizedWafEvent


class DayAccumulator:
    """Route metrics, client buckets, bot traffic and TLS clients for one day.

    Memory tracks distinct routes, clients and identifiers, not request volume,
    which is what lets a production WAF day be collected in one pass.
    """

    def __init__(self) -> None:
        self.routes = RouteAccumulator()
        self.buckets = BucketAccumulator()
        self.bots = BotAccumulator()
        self.clients = ClientAccumulator()

    def add(self, event: NormalizedWafEvent) -> None:
        self.routes.add(event)
        self.buckets.add(event)
        self.bots.add(event)
        self.clients.add(event)

    @property
    def event_count(self) -> int:
        return self.buckets.events

    def metrics(self) -> dict:
        """The value-free payload persisted as ``MonitoringRun.metrics``."""
        return {
            "routes": {route: m.as_dict() for route, m in self.routes.result().items()},
            **self.buckets.result(),
            "bots": self.bots.result(),
            "clients": self.clients.result(),
        }


def day_metrics(events: Iterable[NormalizedWafEvent]) -> dict:
    day = DayAccumulator()
    for event in events:
        day.add(event)
    return day.metrics()
