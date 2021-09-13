#!/usr/bin/env python3
"""smoke test runner for module health checks"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def run_smoke_tests(base_dir=None):
    """run smoke tests: import each module and check basics."""
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(__file__))
    from orca.loader import discover_modules, load_module
    modules = discover_modules(base_dir)
    results = {"passed": 0, "failed": 0, "errors": []}
    for name in modules:
        try:
            mod = load_module(name, base_dir)
            if mod is None:
                results["failed"] += 1
                results["errors"].append(f"{name}: failed to load")
            else:
                results["passed"] += 1
        except Exception as e:
            results["failed"] += 1
            results["errors"].append(f"{name}: {e}")
    return results


def format_results(results):
    """format smoke test results."""
    total = results["passed"] + results["failed"]
    lines = [
        f"smoke tests: {results['passed']}/{total} passed",
    ]
    for err in results["errors"]:
        lines.append(f"  FAIL: {err}")
    return "\n".join(lines)


if __name__ == "__main__":
    start = time.time()
    results = run_smoke_tests()
    elapsed = time.time() - start
    print(format_results(results))
    print(f"completed in {elapsed:.2f}s")
    sys.exit(1 if results["failed"] > 0 else 0)
