#!/usr/bin/env python3
"""smoke test runner for module health checks"""

import sys
import os
import time
import importlib.util

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

SKIP_ERRORS = (
    "No module named",
    "cannot open shared object",
    "DLL load failed",
)


def try_load(filepath):
    """attempt to load a module, returning (module, error_str)."""
    name = os.path.basename(filepath)[:-3]
    spec = importlib.util.spec_from_file_location(name, filepath)
    if spec is None or spec.loader is None:
        return None, "no spec"
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        return mod, None
    except Exception as e:
        return None, str(e)


def run_smoke_tests(base_dir=None):
    """run smoke tests: import each module and check basics."""
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(__file__))
    cybersec_dir = os.path.join(base_dir, "cybersec")
    if not os.path.isdir(cybersec_dir):
        return {"passed": 0, "failed": 0, "skipped": 0, "errors": []}
    results = {"passed": 0, "failed": 0, "skipped": 0, "errors": []}
    for filename in sorted(os.listdir(cybersec_dir)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue
        name = filename[:-3]
        filepath = os.path.join(cybersec_dir, filename)
        mod, err = try_load(filepath)
        if mod is not None:
            results["passed"] += 1
        elif err and any(s in err for s in SKIP_ERRORS):
            results["skipped"] += 1
        else:
            results["failed"] += 1
            results["errors"].append(f"{name}: {err}")
    return results


def format_results(results):
    """format smoke test results."""
    total = results["passed"] + results["failed"] + results["skipped"]
    lines = [
        f"smoke tests: {results['passed']}/{total} passed, "
        f"{results['skipped']} skipped",
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
