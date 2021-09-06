#!/usr/bin/env python3
"""module health check with status reporting"""

import time
from orca.loader import discover_modules, load_module, module_info


def check_module(name, base_dir=None):
    """check if a module loads and has expected attributes."""
    start = time.time()
    module = load_module(name, base_dir)
    load_time = time.time() - start
    if module is None:
        return {"name": name, "status": "failed", "error": "could not load"}
    info = module_info(module)
    return {
        "name": name,
        "status": "healthy",
        "version": info["version"],
        "load_time": round(load_time, 3),
    }


def check_all(base_dir=None):
    """run health checks on all discovered modules."""
    modules = discover_modules(base_dir)
    results = []
    for name in modules:
        result = check_module(name, base_dir)
        results.append(result)
    healthy = sum(1 for r in results if r["status"] == "healthy")
    return {
        "total": len(results),
        "healthy": healthy,
        "failed": len(results) - healthy,
        "modules": results,
    }


def format_health(results):
    """format health check results for display."""
    lines = [f"module health: {results['healthy']}/{results['total']} healthy"]
    for mod in results["modules"]:
        status = "ok" if mod["status"] == "healthy" else "FAIL"
        lines.append(f"  [{status}] {mod['name']}")
    return "\n".join(lines)


if __name__ == "__main__":
    results = check_all()
    print(format_health(results))
