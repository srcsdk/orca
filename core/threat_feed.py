#!/usr/bin/env python3
"""threat intelligence feed aggregation"""

import json
import time
import hashlib
from collections import defaultdict


class ThreatFeed:
    """aggregate and manage threat intelligence data."""

    def __init__(self):
        self.indicators = {}
        self.feeds = []
        self.stats = defaultdict(int)

    def add_feed(self, name, feed_type, url=None):
        """register a threat feed source."""
        self.feeds.append({
            "name": name,
            "type": feed_type,
            "url": url,
            "last_update": 0,
            "indicator_count": 0,
        })

    def add_indicator(self, ioc_type, value, source, severity="MED",
                      tags=None):
        """add an indicator of compromise."""
        ioc_id = hashlib.md5(
            f"{ioc_type}:{value}".encode()
        ).hexdigest()[:12]
        if ioc_id in self.indicators:
            self.indicators[ioc_id]["sources"].add(source)
            self.indicators[ioc_id]["last_seen"] = time.time()
            return ioc_id
        self.indicators[ioc_id] = {
            "id": ioc_id,
            "type": ioc_type,
            "value": value,
            "severity": severity,
            "sources": {source},
            "tags": tags or [],
            "first_seen": time.time(),
            "last_seen": time.time(),
            "active": True,
        }
        self.stats[ioc_type] += 1
        return ioc_id

    def check(self, value):
        """check if a value matches any indicator."""
        for ioc in self.indicators.values():
            if not ioc["active"]:
                continue
            if ioc["value"] == value:
                return ioc
        return None

    def check_ip(self, ip):
        """check ip against threat feeds."""
        return self.check(ip)

    def check_domain(self, domain):
        """check domain against threat feeds."""
        return self.check(domain)

    def check_hash(self, file_hash):
        """check file hash against threat feeds."""
        return self.check(file_hash)

    def get_by_type(self, ioc_type):
        """get all indicators of a specific type."""
        return [
            ioc for ioc in self.indicators.values()
            if ioc["type"] == ioc_type and ioc["active"]
        ]

    def expire(self, max_age_days=30):
        """expire old indicators."""
        cutoff = time.time() - max_age_days * 86400
        expired = 0
        for ioc in self.indicators.values():
            if ioc["last_seen"] < cutoff and ioc["active"]:
                ioc["active"] = False
                expired += 1
        return expired

    def export_stix(self):
        """export indicators in simplified stix format."""
        objects = []
        for ioc in self.indicators.values():
            if not ioc["active"]:
                continue
            obj = {
                "type": "indicator",
                "id": f"indicator--{ioc['id']}",
                "pattern_type": "stix",
                "indicator_type": ioc["type"],
                "value": ioc["value"],
                "severity": ioc["severity"],
            }
            objects.append(obj)
        return {"type": "bundle", "objects": objects}

    def summary(self):
        """get feed summary."""
        active = sum(1 for i in self.indicators.values() if i["active"])
        return {
            "total_indicators": len(self.indicators),
            "active": active,
            "feeds": len(self.feeds),
            "by_type": dict(self.stats),
        }


if __name__ == "__main__":
    feed = ThreatFeed()
    feed.add_feed("abuse_ch", "ip_blocklist")
    feed.add_indicator("ip", "192.168.1.100", "abuse_ch", severity="HIGH")
    feed.add_indicator("domain", "evil.example.com", "custom", severity="CRIT")
    result = feed.check_ip("192.168.1.100")
    print(f"check result: {'found' if result else 'clean'}")
    print(f"summary: {feed.summary()}")
