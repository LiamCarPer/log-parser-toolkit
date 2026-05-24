"""
IOC (Indicator of Compromise) Extraction Engine.

Scans parsed log records for network and file-system indicators of compromise:
  - IPv4 addresses
  - IPv6 addresses
  - Domains (common TLDs)
  - URLs (http/https)
  - File hashes (MD5 · SHA-1 · SHA-256)
  - Email addresses

Acts as a middleware in the ``api.parse_stream()`` pipeline: every record is
passed through unchanged while IOCs are silently accumulated in internal state.
After the pipeline completes, call ``write_report(path)`` to serialise the
collected IOCs to a JSON file.
"""

import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

# Strict IPv4 – avoids matching version strings like "1.2.3.4.5"
_IPV4 = re.compile(
    r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"
)

# Compressed and full-form IPv6
_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|\d\d?)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|\d\d?)){3}"
)

# URLs – greedily capture until whitespace/quote/angle-bracket
_URL = re.compile(r"https?://[^\s<>\"'`\]{}|\\^]+", re.IGNORECASE)

# Domains – require a known TLD; deliberately conservative to keep FP rate low
_DOMAIN_TLDS = (
    "com|net|org|io|co|uk|de|ru|cn|info|biz|edu|gov|mil|int|xyz|top|"
    "club|online|site|tech|app|dev|cloud|ai|security|bank|shop|store|"
    "link|click|download|zip|mov"
)
_DOMAIN = re.compile(
    rf"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)"
    rf"+(?:{_DOMAIN_TLDS})\b",
    re.IGNORECASE,
)

# Hashes – length is the discriminator; order matters (longest first)
_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_SHA1   = re.compile(r"\b[0-9a-fA-F]{40}\b")
_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")

# Email
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# ---------------------------------------------------------------------------
# Private/reserved IPv4 ranges – excluded from the public-IP bucket
# ---------------------------------------------------------------------------
_PRIVATE_PREFIXES = (
    "10.", "127.", "169.254.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "0.", "255.",
)

# Fields scanned for every log record type
_SCAN_FIELDS = frozenset({
    # Linux syslog
    "message",
    # Web access logs
    "request", "referer", "user_agent",
    # Windows event logs
    "Message",
    # Shared
    "hostname",
})

# Fields that may carry hashes (restrict to avoid false positives in hex IDs)
_HASH_FIELDS = frozenset({"message", "Message", "request"})


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _PRIVATE_PREFIXES)


class IOCExtractor:
    """
    Middleware that extracts Indicators of Compromise from log records.

    Usage
    -----
    Instantiate and add to the middleware stack. After the pipeline loop,
    call ``write_report(path)`` to persist the collected IOCs.

    Example
    -------
    .. code-block:: python

        extractor = IOCExtractor()
        stream = parse_stream(rows, middleware_stack=[..., extractor])
        for row in stream:
            ...
        extractor.write_report("iocs.json")
    """

    def __init__(self) -> None:
        self._records_analyzed: int = 0

        # Collected IOC sets
        self._ipv4_public:  Set[str] = set()
        self._ipv4_private: Set[str] = set()
        self._ipv6:         Set[str] = set()
        self._domains:      Set[str] = set()
        self._urls:         Set[str] = set()
        self._sha256:       Set[str] = set()
        self._sha1:         Set[str] = set()
        self._md5:          Set[str] = set()
        self._emails:       Set[str] = set()

    # ------------------------------------------------------------------ #
    # Middleware interface                                                  #
    # ------------------------------------------------------------------ #

    def analyze(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Scan *log* for IOCs and return it unchanged.

        Records with a parse error are skipped so as not to corrupt the
        extraction statistics.
        """
        if log.get("error"):
            return log

        self._records_analyzed += 1

        # Always collect the structured 'ip' field if present (most reliable)
        raw_ip = log.get("ip")
        if raw_ip and isinstance(raw_ip, str):
            self._collect_ip(raw_ip)

        # Scan free-text fields
        for field in _SCAN_FIELDS:
            value = log.get(field)
            if value and isinstance(value, str):
                self._extract_all(value, include_hashes=(field in _HASH_FIELDS))

        return log

    # ------------------------------------------------------------------ #
    # Extraction helpers                                                   #
    # ------------------------------------------------------------------ #

    def _collect_ip(self, ip: str) -> None:
        ip = ip.strip()
        if _is_private_ip(ip):
            self._ipv4_private.add(ip)
        else:
            self._ipv4_public.add(ip)

    def _extract_all(self, text: str, *, include_hashes: bool = False) -> None:
        # URLs first so domain regex doesn't re-match the host part
        for url in _URL.findall(text):
            self._urls.add(url)

        # IPs
        for ip in _IPV4.findall(text):
            self._collect_ip(ip)
        for ip in _IPV6.findall(text):
            self._ipv6.add(ip)

        # Domains (skip if already captured as part of a URL)
        url_bodies = " ".join(self._urls)
        for domain in _DOMAIN.findall(text):
            if domain not in url_bodies:
                self._domains.add(domain.lower())

        # Emails
        for email in _EMAIL.findall(text):
            self._emails.add(email.lower())

        # Hashes (only in message-like fields to suppress false positives)
        if include_hashes:
            sha256_hits = set(_SHA256.findall(text))
            sha1_hits   = set(_SHA1.findall(text)) - sha256_hits
            md5_hits    = set(_MD5.findall(text)) - sha256_hits - sha1_hits
            self._sha256.update(sha256_hits)
            self._sha1.update(sha1_hits)
            self._md5.update(md5_hits)

    # ------------------------------------------------------------------ #
    # Report generation                                                    #
    # ------------------------------------------------------------------ #

    def get_report(self) -> Dict[str, Any]:
        """Return the IOC extraction report as a JSON-serialisable dict."""
        total_iocs = (
            len(self._ipv4_public) + len(self._ipv4_private)
            + len(self._ipv6) + len(self._domains) + len(self._urls)
            + len(self._sha256) + len(self._sha1) + len(self._md5)
            + len(self._emails)
        )
        return {
            "extraction_timestamp": datetime.now(timezone.utc).isoformat(),
            "records_analyzed": self._records_analyzed,
            "summary": {
                "total_unique_iocs": total_iocs,
                "ipv4_public_count": len(self._ipv4_public),
                "ipv4_private_count": len(self._ipv4_private),
                "ipv6_count": len(self._ipv6),
                "domain_count": len(self._domains),
                "url_count": len(self._urls),
                "hash_count": len(self._sha256) + len(self._sha1) + len(self._md5),
                "email_count": len(self._emails),
            },
            "indicators": {
                "ipv4_public":  sorted(self._ipv4_public),
                "ipv4_private": sorted(self._ipv4_private),
                "ipv6":         sorted(self._ipv6),
                "domains":      sorted(self._domains),
                "urls":         sorted(self._urls),
                "hashes": {
                    "sha256": sorted(self._sha256),
                    "sha1":   sorted(self._sha1),
                    "md5":    sorted(self._md5),
                },
                "emails": sorted(self._emails),
            },
        }

    def write_report(self, output_path: str) -> None:
        """Serialise the collected IOCs to *output_path* as formatted JSON."""
        report = self.get_report()
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        total = report["summary"]["total_unique_iocs"]
        logger.info(
            "IOC report written to %s  (%d unique indicators from %d records)",
            output_path,
            total,
            self._records_analyzed,
        )

    # ------------------------------------------------------------------ #
    # Dunder helpers                                                       #
    # ------------------------------------------------------------------ #

    def __repr__(self) -> str:
        return (
            f"IOCExtractor(records_analyzed={self._records_analyzed}, "
            f"ipv4={len(self._ipv4_public) + len(self._ipv4_private)}, "
            f"urls={len(self._urls)}, domains={len(self._domains)})"
        )
