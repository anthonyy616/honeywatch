"""Local GeoIP enrichment (GeoLite2 City + ASN).

Never performs a remote lookup. Missing databases degrade to ``None``
fields after a single warning.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class GeoResult:
    """Immutable enrichment outcome for one IP address."""

    country: str | None = None
    city: str | None = None
    asn: int | None = None
    as_org: str | None = None

    def apply(self, event: Any) -> None:
        event.geo_country = self.country
        event.geo_city = self.city
        event.asn = self.asn
        event.as_org = self.as_org


def classify_address(ip: str) -> tuple[str, str | None]:
    """Classify an address without any database lookup.

    Returns:
        ``(category, country_code)`` where category is one of
        ``public``, ``private``, ``loopback``, ``reserved``, ``documentation``.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid", None
    if addr.is_loopback:
        return "loopback", "LO"
    # Link-local, multicast, unspecified and documentation ranges are all
    # reported as ``is_private`` by ``ipaddress``, so they must be checked
    # before the generic private branch.
    if addr.is_link_local:
        return "reserved", "LL"
    if addr.is_multicast:
        return "reserved", "MC"
    if addr.is_unspecified:
        return "reserved", "UN"
    if addr.version == 4 and any(addr in net for net in _DOCUMENTATION_V4):
        return "documentation", "DOC"
    if addr.version == 6 and any(addr in net for net in _DOCUMENTATION_V6):
        return "documentation", "DOC"
    if addr.is_private:
        return "private", "LAN"
    return "public", None


_DOCUMENTATION_V4 = [
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
_DOCUMENTATION_V6 = [ipaddress.ip_network("2001:db8::/32")]


class GeoEnricher:
    """Wraps optional GeoLite2 readers with LRU caching."""

    def __init__(
        self,
        city_db: str | Path | None = None,
        asn_db: str | Path | None = None,
        *,
        cache_size: int = 4096,
    ) -> None:
        self.city_db_path = Path(city_db) if city_db else None
        self.asn_db_path = Path(asn_db) if asn_db else None
        self._city_reader: Any = None
        self._asn_reader: Any = None
        self._warned = False
        self._load()

    def _load(self) -> None:
        if self.city_db_path and self.city_db_path.is_file():
            try:
                import geoip2.database

                self._city_reader = geoip2.database.Reader(str(self.city_db_path))
            except Exception as exc:
                logger.warning("GeoIP city database unusable (%s); continuing without it", exc)
        if self.asn_db_path and self.asn_db_path.is_file():
            try:
                import geoip2.database

                self._asn_reader = geoip2.database.Reader(str(self.asn_db_path))
            except Exception as exc:
                logger.warning("GeoIP ASN database unusable (%s); continuing without it", exc)

    @property
    def available(self) -> bool:
        return self._city_reader is not None or self._asn_reader is not None

    def close(self) -> None:
        for reader in (self._city_reader, self._asn_reader):
            if reader is not None:
                try:
                    reader.close()
                except Exception:  # pragma: no cover - defensive
                    pass
        self._city_reader = None
        self._asn_reader = None

    # ---- lookups -------------------------------------------------------

    def lookup(self, ip: str) -> GeoResult:
        """Look up one address. Results are cached per address."""
        category, code = classify_address(ip)
        if category != "public":
            if not self.available and not self._warned:
                self._warned = True
                logger.info(
                    "GeoIP database not configured; non-public addresses resolve locally"
                )
            country = None if category == "invalid" else code
            return GeoResult(country=country)
        if not self.available:
            if not self._warned:
                self._warned = True
                logger.warning(
                    "GeoIP database missing or unreadable; enrichment limited to address classification"
                )
            return GeoResult()
        return self._cached_lookup(ip)

    @lru_cache(maxsize=4096)  # noqa: B019 - instance lifetime is the daemon lifetime
    def _cached_lookup(self, ip: str) -> GeoResult:
        country = city = None
        asn = as_org = None
        if self._city_reader is not None:
            try:
                resp = self._city_reader.city(ip)
                country = resp.country.iso_code or None
                city = resp.city.name or None
            except Exception:
                country = city = None
        if self._asn_reader is not None:
            try:
                resp = self._asn_reader.asn(ip)
                asn = resp.autonomous_system_number or None
                as_org = resp.autonomous_system_organization or None
            except Exception:
                asn = as_org = None
        return GeoResult(country=country, city=city, asn=asn, as_org=as_org)

    def cache_info(self) -> Any:
        """Expose LRU statistics for tests/diagnostics."""
        return self._cached_lookup.cache_info()

    def clear_cache(self) -> None:
        self._cached_lookup.cache_clear()


def enrich_event(enricher: GeoEnricher, event: Any) -> None:
    """Apply GeoIP enrichment to one event, mutating geo fields only."""
    try:
        enricher.lookup(event.src_ip).apply(event)
    except Exception:  # pragma: no cover - enrichment must never break collection
        logger.debug("geo lookup failed for %s", event.src_ip, exc_info=True)


class Enricher:
    """Alias kept for readability at pipeline call sites."""

    def __init__(self, geo: GeoEnricher | None = None) -> None:
        self.geo = geo or GeoEnricher()

    def __call__(self, event: Any) -> None:
        enrich_event(self.geo, event)

    def close(self) -> None:
        self.geo.close()