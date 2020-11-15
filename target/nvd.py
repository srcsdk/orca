#!/usr/bin/env python3
"""nvd api client for cve lookups"""

import json
import time
import sys

try:
    import requests
except ImportError:
    print("pip install requests", file=sys.stderr)
    sys.exit(1)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_LIMIT = 6  # seconds between requests (no api key)


def search_cves(keyword, max_results=10):
    """search nvd for cves by keyword"""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    try:
        resp = requests.get(NVD_API, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return parse_cve_response(data)
    except requests.RequestException as e:
        print(f"nvd api error: {e}", file=sys.stderr)
        return []


def search_by_cpe(cpe_name, max_results=20):
    """search nvd for cves affecting a specific product"""
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": max_results,
    }
    try:
        resp = requests.get(NVD_API, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return parse_cve_response(data)
    except requests.RequestException as e:
        print(f"nvd api error: {e}", file=sys.stderr)
        return []


def get_cve(cve_id):
    """get details for a specific cve"""
    params = {"cveId": cve_id}
    try:
        resp = requests.get(NVD_API, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        results = parse_cve_response(data)
        return results[0] if results else None
    except requests.RequestException as e:
        print(f"nvd api error: {e}", file=sys.stderr)
        return None


def parse_cve_response(data):
    """parse nvd api response into simplified format"""
    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln["cve"]
        cve_id = cve["id"]

        # get description
        desc = ""
        for d in cve.get("descriptions", []):
            if d["lang"] == "en":
                desc = d["value"]
                break

        # get cvss score
        score = 0
        severity = "unknown"
        metrics = cve.get("metrics", {})

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss = metrics[version][0]["cvssData"]
                score = cvss.get("baseScore", 0)
                severity = cvss.get("baseSeverity", "unknown").lower()
                break

        # get affected products (cpe)
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
    # cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
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

    # fall back to keyword search
    query = f"{product} {version}" if version else product
    return search_cves(query)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python nvd.py <product> [version]")
        print("       python nvd.py --cve CVE-2021-44228")
        sys.exit(1)

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
