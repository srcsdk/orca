#!/usr/bin/env python3
"""unified module loader for dynamic script discovery"""

import importlib
import os


def discover_modules(base_dir=None):
    """scan directory for python modules and return their names."""
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(__file__))
    cybersec_dir = os.path.join(base_dir, "cybersec")
    if not os.path.isdir(cybersec_dir):
        return []
    modules = []
    for filename in sorted(os.listdir(cybersec_dir)):
        if filename.endswith(".py") and not filename.startswith("_"):
            name = filename[:-3]
            modules.append(name)
    return modules


def load_module(name, base_dir=None):
    """dynamically load a cybersec module by name."""
    if base_dir is None:
        base_dir = os.path.dirname(os.path.dirname(__file__))
    cybersec_dir = os.path.join(base_dir, "cybersec")
    filepath = os.path.join(cybersec_dir, f"{name}.py")
    if not os.path.exists(filepath):
        return None
    spec = importlib.util.spec_from_file_location(name, filepath)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def load_all(base_dir=None):
    """load all discovered modules."""
    names = discover_modules(base_dir)
    loaded = {}
    for name in names:
        mod = load_module(name, base_dir)
        if mod is not None:
            loaded[name] = mod
    return loaded


def module_info(module):
    """extract metadata from a loaded module."""
    return {
        "name": getattr(module, "__name__", "unknown"),
        "version": getattr(module, "__version__", "0.0.0"),
        "doc": (module.__doc__ or "").strip().split("\n")[0],
        "file": getattr(module, "__file__", ""),
    }


if __name__ == "__main__":
    modules = discover_modules()
    print(f"discovered {len(modules)} modules:")
    for name in modules:
        print(f"  {name}")
