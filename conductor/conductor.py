#!/usr/bin/env python3
"""security orchestration engine with playbook system"""

import argparse
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path


try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class ModuleRegistry:
    """registry of available security modules"""

    def __init__(self, base_path=None):
        self.base_path = Path(base_path) if base_path else Path(__file__).parent.parent
        self.modules = {}
        self._discover()

    def _discover(self):
        """discover available modules"""
        if not self.base_path.is_dir():
            return

        for entry in self.base_path.iterdir():
            if not entry.is_dir():
                continue
            py_file = entry / f"{entry.name}.py"
            sh_file = entry / f"{entry.name}.sh"
            if py_file.exists() or sh_file.exists():
                self.modules[entry.name] = {
                    "path": str(entry),
                    "python": str(py_file) if py_file.exists() else None,
                    "bash": str(sh_file) if sh_file.exists() else None,
                }

    def get_module(self, name):
        return self.modules.get(name)

    def list_modules(self):
        return list(self.modules.keys())


class PlaybookStep:
    def __init__(self, name, module, args=None, on_fail="continue",
                 condition=None, timeout=300):
        self.name = name
        self.module = module
        self.args = args or []
        self.on_fail = on_fail
        self.condition = condition
        self.timeout = timeout
        self.result = None
        self.status = "pending"
        self.output = ""
        self.start_time = None
        self.end_time = None

    def to_dict(self):
        return {
            "name": self.name,
            "module": self.module,
            "status": self.status,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": (self.end_time - self.start_time).total_seconds()
                if self.start_time and self.end_time else None,
            "output_lines": len(self.output.splitlines()),
        }


class Playbook:
    def __init__(self, name, description="", steps=None, variables=None):
        self.name = name
        self.description = description
        self.steps = steps or []
        self.variables = variables or {}
        self.results = []
        self.start_time = None
        self.end_time = None

    @classmethod
    def from_yaml(cls, filepath):
        """load playbook from yaml file"""
        if not HAS_YAML:
            print("[error] pyyaml required for yaml playbooks: pip install pyyaml")
            sys.exit(1)

        with open(filepath) as f:
            data = yaml.safe_load(f)

        steps = []
        for step_data in data.get("steps", []):
            step = PlaybookStep(
                name=step_data.get("name", "unnamed"),
                module=step_data["module"],
                args=step_data.get("args", []),
                on_fail=step_data.get("on_fail", "continue"),
                condition=step_data.get("condition"),
                timeout=step_data.get("timeout", 300),
            )
            steps.append(step)

        return cls(
            name=data.get("name", Path(filepath).stem),
            description=data.get("description", ""),
            steps=steps,
            variables=data.get("variables", {}),
        )

    @classmethod
    def from_dict(cls, data):
        """load playbook from dictionary"""
        steps = []
        for step_data in data.get("steps", []):
            step = PlaybookStep(
                name=step_data.get("name", "unnamed"),
                module=step_data["module"],
                args=step_data.get("args", []),
                on_fail=step_data.get("on_fail", "continue"),
                condition=step_data.get("condition"),
                timeout=step_data.get("timeout", 300),
            )
            steps.append(step)

        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            steps=steps,
            variables=data.get("variables", {}),
        )

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "status": "completed" if self.end_time else "running",
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "steps": [s.to_dict() for s in self.steps],
        }


class Orchestrator:
    def __init__(self, base_path=None, dry_run=False):
        self.registry = ModuleRegistry(base_path)
        self.dry_run = dry_run
        self.log_entries = []
        self.alert_handlers = []

    def log(self, level, message):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
        }
        self.log_entries.append(entry)
        prefix = {"info": "[*]", "warn": "[!]", "error": "[x]", "success": "[+]"}
        print(f"{prefix.get(level, '[-]')} {message}")

    def register_alert_handler(self, handler):
        """register a callback for alerts"""
        self.alert_handlers.append(handler)

    def _resolve_args(self, args, variables):
        """substitute variables in step arguments"""
        resolved = []
        for arg in args:
            if isinstance(arg, str):
                for key, val in variables.items():
                    arg = arg.replace(f"${{{key}}}", str(val))
                    arg = arg.replace(f"${key}", str(val))
            resolved.append(arg)
        return resolved

    def _check_condition(self, condition, previous_results):
        """evaluate step condition"""
        if condition is None:
            return True

        if condition.startswith("prev_success"):
            if previous_results:
                return previous_results[-1].status == "success"
            return True

        if condition.startswith("prev_fail"):
            if previous_results:
                return previous_results[-1].status == "failed"
            return False

        return True

    def execute_step(self, step, variables):
        """execute a single playbook step"""
        module_info = self.registry.get_module(step.module)
        if not module_info:
            self.log("error", f"module not found: {step.module}")
            step.status = "failed"
            step.output = f"module not found: {step.module}"
            return step

        script = module_info["python"] or module_info["bash"]
        if not script:
            self.log("error", f"no executable found for {step.module}")
            step.status = "failed"
            return step

        args = self._resolve_args(step.args, variables)

        if script.endswith(".py"):
            cmd = [sys.executable, script] + args
        else:
            cmd = ["bash", script] + args

        self.log("info", f"executing: {step.name} ({step.module})")

        if self.dry_run:
            self.log("info", f"  [dry-run] would run: {' '.join(cmd)}")
            step.status = "skipped"
            step.start_time = datetime.now()
            step.end_time = datetime.now()
            return step

        step.start_time = datetime.now()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=step.timeout,
            )
            step.output = result.stdout + result.stderr
            step.result = result.returncode

            if result.returncode == 0:
                step.status = "success"
                self.log("success", f"  {step.name} completed")
            else:
                step.status = "failed"
                self.log("warn", f"  {step.name} failed (exit {result.returncode})")
        except subprocess.TimeoutExpired:
            step.status = "timeout"
            self.log("error", f"  {step.name} timed out after {step.timeout}s")
        except Exception as e:
            step.status = "error"
            step.output = str(e)
            self.log("error", f"  {step.name} error: {e}")

        step.end_time = datetime.now()
        return step

    def run_playbook(self, playbook):
        """execute a full playbook"""
        self.log("info", f"starting playbook: {playbook.name}")
        playbook.start_time = datetime.now()

        variables = dict(playbook.variables)
        variables["timestamp"] = datetime.now().strftime("%Y%m%d_%H%M%S")

        completed_steps = []
        for step in playbook.steps:
            if not self._check_condition(step.condition, completed_steps):
                self.log("info", f"  skipping {step.name} (condition not met)")
                step.status = "skipped"
                completed_steps.append(step)
                continue

            self.execute_step(step, variables)
            completed_steps.append(step)

            if step.status == "failed" and step.on_fail == "abort":
                self.log("error", f"aborting playbook: {step.name} failed")
                break

        playbook.end_time = datetime.now()

        success = sum(1 for s in playbook.steps if s.status == "success")
        failed = sum(1 for s in playbook.steps if s.status == "failed")
        total = len(playbook.steps)

        self.log("info",
                 f"playbook complete: {success}/{total} succeeded, {failed} failed")

        return playbook


BUILTIN_PLAYBOOKS = {
    "recon": {
        "name": "reconnaissance",
        "description": "network discovery and enumeration",
        "steps": [
            {"name": "network scan", "module": "netscan", "args": ["-s", "${target}"]},
            {"name": "port scan", "module": "target", "args": ["-t", "${target}"]},
            {"name": "dns enum", "module": "zone", "args": ["-d", "${domain}"]},
        ],
        "variables": {"target": "192.168.1.0/24", "domain": "example.com"},
    },
    "incident_response": {
        "name": "incident response",
        "description": "evidence collection and initial containment",
        "steps": [
            {"name": "collect evidence", "module": "res", "args": ["-m", "all"]},
            {"name": "check processes", "module": "tapped",
             "args": ["-m", "suspicious"], "on_fail": "continue"},
            {"name": "network audit", "module": "flow", "args": ["-m", "connections"]},
            {"name": "check integrity", "module": "patch", "args": ["-m", "verify"]},
        ],
    },
    "hardening": {
        "name": "hardening audit",
        "description": "server hardening verification",
        "steps": [
            {"name": "cis benchmarks", "module": "prodsec", "args": ["-m", "all"]},
            {"name": "tls audit", "module": "downseek",
             "args": ["-t", "${target}"], "condition": "prev_success"},
            {"name": "container audit", "module": "containok",
             "args": ["-m", "all"], "on_fail": "continue"},
        ],
        "variables": {"target": "localhost"},
    },
}


def main():
    parser = argparse.ArgumentParser(description="security orchestration engine")
    sub = parser.add_subparsers(dest="command", help="command")

    run_parser = sub.add_parser("run", help="run a playbook")
    run_parser.add_argument("playbook", help="playbook file or builtin name")
    run_parser.add_argument("--var", action="append", help="variable (key=value)")
    run_parser.add_argument("--dry-run", action="store_true", help="dry run mode")
    run_parser.add_argument("--base", help="base path for modules")
    run_parser.add_argument("--json", action="store_true", help="json output")

    list_parser = sub.add_parser("list", help="list modules or playbooks")
    list_parser.add_argument("what", choices=["modules", "playbooks"], help="what to list")
    list_parser.add_argument("--base", help="base path for modules")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    base_path = args.base if hasattr(args, "base") and args.base else None

    if args.command == "list":
        if args.what == "modules":
            registry = ModuleRegistry(base_path)
            modules = registry.list_modules()
            print(f"available modules ({len(modules)}):")
            for name in sorted(modules):
                info = registry.get_module(name)
                has_py = "py" if info["python"] else "  "
                has_sh = "sh" if info["bash"] else "  "
                print(f"  {name:15s} [{has_py}] [{has_sh}]")
        else:
            print(f"builtin playbooks ({len(BUILTIN_PLAYBOOKS)}):")
            for name, pb in BUILTIN_PLAYBOOKS.items():
                print(f"  {name:20s} - {pb.get('description', '')}")
        return

    if args.command == "run":
        orchestrator = Orchestrator(
            base_path=base_path,
            dry_run=args.dry_run,
        )

        # load playbook
        if args.playbook in BUILTIN_PLAYBOOKS:
            playbook = Playbook.from_dict(BUILTIN_PLAYBOOKS[args.playbook])
        elif Path(args.playbook).exists():
            ext = Path(args.playbook).suffix
            if ext in (".yml", ".yaml"):
                playbook = Playbook.from_yaml(args.playbook)
            elif ext == ".json":
                with open(args.playbook) as f:
                    playbook = Playbook.from_dict(json.load(f))
            else:
                print(f"[error] unknown playbook format: {ext}")
                sys.exit(1)
        else:
            print(f"[error] playbook not found: {args.playbook}")
            print(f"builtin playbooks: {', '.join(BUILTIN_PLAYBOOKS.keys())}")
            sys.exit(1)

        # apply variable overrides
        if args.var:
            for v in args.var:
                if "=" in v:
                    key, val = v.split("=", 1)
                    playbook.variables[key] = val

        result = orchestrator.run_playbook(playbook)

        if hasattr(args, "json") and args.json:
            print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
