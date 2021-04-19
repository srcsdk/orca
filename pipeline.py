#!/usr/bin/env python3
"""pipeline engine for chaining orcasec module execution"""

import importlib
import os
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from models import ScanResult


MODULE_DIR = os.path.dirname(os.path.abspath(__file__))

SKIP_FILES = {
    "__init__.py", "setup.py", "config.py", "utils.py", "models.py",
    "output.py", "pipeline.py", "cli.py", "gui.py",
}


def discover_modules(path=None):
    """scan directory for orcasec modules (python files with main())"""
    path = path or MODULE_DIR
    modules = {}
    for filename in sorted(os.listdir(path)):
        if not filename.endswith(".py") or filename in SKIP_FILES:
            continue
        name = filename[:-3]
        filepath = os.path.join(path, filename)
        description = _extract_docstring(filepath)
        modules[name] = {
            "name": name,
            "file": filepath,
            "description": description,
        }
    return modules


def _extract_docstring(filepath):
    """extract module docstring from file"""
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith('"""') or line.startswith("'''"):
                    quote = line[:3]
                    doc = line[3:]
                    if doc.endswith(quote):
                        return doc[:-3]
                    return doc
                break
    except IOError:
        pass
    return ""


def load_module(name, path=None):
    """dynamically import a module by name"""
    path = path or MODULE_DIR
    if path not in sys.path:
        sys.path.insert(0, path)
    try:
        if name in sys.modules:
            return importlib.reload(sys.modules[name])
        return importlib.import_module(name)
    except ImportError as e:
        raise ImportError(f"failed to load module '{name}': {e}")


@dataclass
class PipelineStage:
    """single stage in an execution pipeline"""
    name: str
    module_name: str
    function: str = "main"
    args: dict = field(default_factory=dict)
    timeout: float = 300
    required: bool = True

    def execute(self, context=None):
        """run this stage, returning result dict"""
        mod = load_module(self.module_name)
        func = getattr(mod, self.function, None)
        if func is None:
            raise AttributeError(f"module '{self.module_name}' has no function '{self.function}'")
        start = time.time()
        try:
            result = func(**self.args) if self.args else func()
            return {
                "stage": self.name,
                "module": self.module_name,
                "status": "success",
                "duration": time.time() - start,
                "result": result,
            }
        except Exception as e:
            return {
                "stage": self.name,
                "module": self.module_name,
                "status": "error",
                "duration": time.time() - start,
                "error": str(e),
                "traceback": traceback.format_exc(),
            }


class Pipeline:
    """chain of pipeline stages for sequential or parallel execution"""

    def __init__(self, name="default"):
        self.name = name
        self.stages = []
        self.results = []
        self.start_time = 0
        self.end_time = 0

    def add_stage(self, name, module_name, function="main", args=None,
                  timeout=300, required=True):
        """add a stage to the pipeline"""
        stage = PipelineStage(
            name=name,
            module_name=module_name,
            function=function,
            args=args or {},
            timeout=timeout,
            required=required,
        )
        self.stages.append(stage)
        return self

    def run(self, context=None):
        """execute all stages sequentially"""
        self.start_time = time.time()
        self.results = []
        for stage in self.stages:
            result = stage.execute(context)
            self.results.append(result)
            if result["status"] == "error" and stage.required:
                print(f"pipeline stopped: required stage '{stage.name}' failed",
                      file=sys.stderr)
                break
            if context is not None and result.get("result"):
                context[stage.name] = result["result"]
        self.end_time = time.time()
        return self.results

    def run_parallel(self, max_workers=4):
        """execute all stages in parallel"""
        self.start_time = time.time()
        self.results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(stage.execute): stage for stage in self.stages}
            for future in as_completed(futures):
                stage = futures[future]
                try:
                    result = future.result(timeout=stage.timeout)
                except Exception as e:
                    result = {
                        "stage": stage.name,
                        "module": stage.module_name,
                        "status": "error",
                        "error": str(e),
                    }
                self.results.append(result)
        self.end_time = time.time()
        return self.results

    def summary(self):
        """return execution summary"""
        total = len(self.results)
        success = sum(1 for r in self.results if r.get("status") == "success")
        failed = total - success
        duration = self.end_time - self.start_time if self.end_time else 0
        lines = [
            f"pipeline: {self.name}",
            f"stages: {total} ({success} passed, {failed} failed)",
            f"duration: {duration:.1f}s",
            "",
        ]
        for r in self.results:
            status = r.get("status", "unknown")
            name = r.get("stage", "?")
            dur = r.get("duration", 0)
            err = f" - {r.get('error', '')}" if status == "error" else ""
            lines.append(f"  [{status}] {name} ({dur:.1f}s){err}")
        return "\n".join(lines)

    def to_dict(self):
        return {
            "name": self.name,
            "stages": [{"name": s.name, "module": s.module_name,
                         "function": s.function, "args": s.args}
                        for s in self.stages],
            "results": self.results,
            "duration": self.end_time - self.start_time if self.end_time else 0,
        }


def build_pipeline(stage_specs):
    """build a pipeline from a list of stage spec dicts"""
    pipe = Pipeline(name="custom")
    for spec in stage_specs:
        pipe.add_stage(
            name=spec.get("name", spec.get("module", "unnamed")),
            module_name=spec["module"],
            function=spec.get("function", "main"),
            args=spec.get("args", {}),
            timeout=spec.get("timeout", 300),
            required=spec.get("required", True),
        )
    return pipe


def main():
    """show available modules and run a demo pipeline"""
    modules = discover_modules()
    print(f"discovered {len(modules)} modules:\n")
    for name, info in modules.items():
        desc = info["description"] or "(no description)"
        print(f"  {name:20s} {desc}")


if __name__ == "__main__":
    main()
