#!/usr/bin/env python3
"""nvd api client for cve lookups"""

import json
import platform
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT = 6


def _api_request(params):
    """make a request to the nvd api using urllib"""
    query = urllib.parse.urlencode(params)
    url = f"{NVD_API}?{query}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "nvd-lookup/1.0")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"nvd api error: {e}", file=sys.stderr)
        return None


def search_cves(keyword, max_results=10):
    """search nvd for cves by keyword"""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    data = _api_request(params)
    if data:
        return parse_cve_response(data)
    return []


def search_by_cpe(cpe_name, max_results=20):
    """search nvd for cves affecting a specific product"""
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": max_results,
    }
    data = _api_request(params)
    if data:
        return parse_cve_response(data)
    return []


def get_cve(cve_id):
    """get details for a specific cve"""
    params = {"cveId": cve_id}
    data = _api_request(params)
    if data:
        results = parse_cve_response(data)
        return results[0] if results else None
    return None


def parse_cve_response(data):
    """parse nvd api response into simplified format"""
    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln["cve"]
        cve_id = cve["id"]

        desc = ""
        for d in cve.get("descriptions", []):
            if d["lang"] == "en":
                desc = d["value"]
                break

        score = 0
        severity = "unknown"
        metrics = cve.get("metrics", {})

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss = metrics[version][0]["cvssData"]
                score = cvss.get("baseScore", 0)
                severity = cvss.get("baseSeverity", "unknown").lower()
                break

        affected = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        affected.append(match["criteria"])

        results.append({
            "cve": cve_id,
            "description": desc[:200],
            "score": score,
            "severity": severity,
            "published": cve.get("published", ""),
            "affected": affected[:5],
        })

    return results


def build_cpe(product, version=None, vendor=None):
    """build a cpe 2.3 string for nvd queries"""
    v = vendor or "*"
    ver = version or "*"
    return f"cpe:2.3:a:{v}:{product}:{ver}:*:*:*:*:*:*:*"


def lookup_product(product, version=None):
    """search for vulnerabilities affecting a product"""
    if version:
        cpe = build_cpe(product, version)
        results = search_by_cpe(cpe)
        if results:
            return results

    query = f"{product} {version}" if version else product
    return search_cves(query)


def _default_search():
    """search for recent critical cves on the current platform"""
    os_name = platform.system().lower()
    keyword_map = {
        "linux": "linux kernel",
        "windows": "microsoft windows",
        "darwin": "apple macos",
    }
    keyword = keyword_map.get(os_name, "remote code execution")
    print(f"[nvd] searching recent critical cves for: {keyword}")
    print(f"[nvd] platform: {platform.system()} {platform.release()}")
    print()
    results = search_cves(keyword, max_results=10)
    if not results:
        print("[nvd] no results (api may be rate-limited, retry in a few seconds)")
        return
    critical = filter_by_severity(results, "critical")
    high = filter_by_severity(results, "high")
    display = critical if critical else high if high else results
    display = sort_by_severity(display)
    print(f"{len(display)} relevant cves found:")
    for r in display:
        sev = r["severity"].upper()
        print(f"  [{sev}] {r['cve']} (CVSS {r['score']})")
        print(f"    {r['description'][:100]}")


SEVERITY_LEVELS = ["critical", "high", "medium", "low", "unknown"]


def filter_by_severity(results, min_severity="low"):
    """filter cve results by minimum severity level.

    severity order: critical > high > medium > low > unknown.
    returns only results at or above the specified threshold.
    """
    if min_severity not in SEVERITY_LEVELS:
        return results

    threshold = SEVERITY_LEVELS.index(min_severity)
    filtered = []
    for r in results:
        sev = r.get("severity", "unknown").lower()
        if sev in SEVERITY_LEVELS:
            idx = SEVERITY_LEVELS.index(sev)
            if idx <= threshold:
                filtered.append(r)
        else:
            filtered.append(r)
    return filtered


def filter_by_score(results, min_score=0.0):
    """filter cve results by minimum cvss score"""
    return [r for r in results if r.get("score", 0) >= min_score]


def sort_by_severity(results):
    """sort results by severity (critical first) then by score"""
    def sort_key(r):
        sev = r.get("severity", "unknown").lower()
        idx = SEVERITY_LEVELS.index(sev) if sev in SEVERITY_LEVELS else 99
        return (idx, -r.get("score", 0))
    return sorted(results, key=sort_key)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        _default_search()
        sys.exit(0)

    if sys.argv[1] == "--cve":
        cve_id = sys.argv[2]
        result = get_cve(cve_id)
        if result:
            print(f"\n{result['cve']} (CVSS {result['score']} - {result['severity']})")
            print(f"  {result['description']}")
            if result["affected"]:
                print(f"  affected: {', '.join(result['affected'][:3])}")
    else:
        product = sys.argv[1]
        version = sys.argv[2] if len(sys.argv) > 2 else None
        results = lookup_product(product, version)
        print(f"\n{len(results)} cves found for {product} {version or ''}")
        for r in results:
            sev = r["severity"].upper()
            print(f"  [{sev}] {r['cve']} (CVSS {r['score']})")
            print(f"    {r['description'][:80]}")
