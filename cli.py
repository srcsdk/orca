#!/usr/bin/env python3
"""unified command line interface for orcasec platform"""

import argparse
import json
import sys
import os

from config import load_config, save_config, ensure_dirs
from models import ScanResult
from output import format_result
from pipeline import discover_modules, load_module, Pipeline, build_pipeline
from utils import setup_logging, colorize, is_admin


def get_module_descriptions():
    """map of modules to their categories for help display"""
    return {
        "recon": {
            "description": "reconnaissance and information gathering",
            "modules": ["discovery", "netscan", "rec", "zone", "spider"],
        },
        "scan": {
            "description": "vulnerability and security scanning",
            "modules": ["target", "gnore", "containok", "patch", "prodsec", "downseek"],
        },
        "monitor": {
            "description": "monitoring and detection",
            "modules": ["detect", "watch", "flow", "icu", "tapped", "dnsguard", "weewoo"],
        },
        "defense": {
            "description": "defense and response",
            "modules": ["denied", "10fthigher", "logma", "supertect", "conductor",
                         "tropy", "res"],
        },
        "adversary": {
            "description": "adversary simulation and testing",
            "modules": ["poison", "over", "vaded", "sike", "probaduce"],
        },
    }


def cmd_list(args, config):
    """list available modules"""
    modules = discover_modules()
    categories = get_module_descriptions()
    if args.category:
        cat = categories.get(args.category)
        if not cat:
            print(f"unknown category: {args.category}")
            print(f"available: {', '.join(categories.keys())}")
            return 1
        print(colorize(f"{args.category}: {cat['description']}", "cyan"))
        print()
        for name in cat["modules"]:
            info = modules.get(name, {})
            desc = info.get("description", "(not installed)")
            enabled = config.get("modules", {}).get(name, {}).get("enabled", True)
            status = colorize("*", "green") if enabled else colorize("-", "red")
            print(f"  {status} {name:20s} {desc}")
        return 0
    print(colorize("orcasec modules", "bold"))
    print()
    for cat_name, cat_info in categories.items():
        print(colorize(f"  [{cat_name}] {cat_info['description']}", "cyan"))
        for name in cat_info["modules"]:
            info = modules.get(name, {})
            desc = info.get("description", "(not installed)")
            print(f"    {name:20s} {desc}")
        print()
    print(f"total: {len(modules)} modules")
    return 0


def cmd_run(args, config):
    """run a specific module"""
    module_name = args.module
    modules = discover_modules()
    if module_name not in modules:
        print(f"unknown module: {module_name}")
        print(f"available: {', '.join(sorted(modules.keys()))}")
        return 1
    try:
        mod = load_module(module_name)
        if hasattr(mod, "main"):
            sys.argv = [module_name] + (args.module_args or [])
            mod.main()
        else:
            print(f"module '{module_name}' has no main() function")
            return 1
    except Exception as e:
        print(f"error running {module_name}: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_scan(args, config):
    """run discovery + netscan + target pipeline"""
    target = args.target
    fmt = args.format or config.get("output_format", "table")
    pipe = Pipeline(name="scan")
    pipe.add_stage("discovery", "discovery", args={"target": target} if target else {})
    pipe.add_stage("netscan", "netscan", required=False)
    pipe.add_stage("target", "target", required=False)
    print(f"running scan pipeline against {target or 'local network'}...")
    results = pipe.run()
    print(pipe.summary())
    return 0


def cmd_recon(args, config):
    """run recon modules"""
    target = args.target
    pipe = Pipeline(name="recon")
    pipe.add_stage("discovery", "discovery")
    pipe.add_stage("rec", "rec", required=False)
    pipe.add_stage("zone", "zone", required=False)
    print(f"running recon pipeline against {target or 'local network'}...")
    results = pipe.run()
    print(pipe.summary())
    return 0


def cmd_monitor(args, config):
    """run monitoring modules"""
    pipe = Pipeline(name="monitor")
    if args.module:
        pipe.add_stage(args.module, args.module)
    else:
        for mod in ["detect", "watch", "flow"]:
            pipe.add_stage(mod, mod, required=False)
    print("starting monitors...")
    results = pipe.run()
    print(pipe.summary())
    return 0


def cmd_pipeline(args, config):
    """run a custom pipeline from json file"""
    if not args.file:
        saved = config.get("pipelines", {})
        if saved:
            print(colorize("saved pipelines:", "cyan"))
            for name, spec in saved.items():
                stages = len(spec.get("stages", []))
                print(f"  {name:20s} ({stages} stages)")
        else:
            print("no saved pipelines. create one with --file pipeline.json")
        return 0
    try:
        with open(args.file, "r") as f:
            spec = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"error loading pipeline: {e}", file=sys.stderr)
        return 1
    stages = spec.get("stages", [])
    if not stages:
        print("pipeline has no stages")
        return 1
    pipe = build_pipeline(stages)
    pipe.name = spec.get("name", os.path.basename(args.file))
    if args.parallel:
        results = pipe.run_parallel(max_workers=args.workers)
    else:
        results = pipe.run()
    print(pipe.summary())
    if args.output:
        with open(args.output, "w") as f:
            json.dump(pipe.to_dict(), f, indent=2, default=str)
        print(f"\nresults saved to {args.output}")
    return 0


def cmd_config(args, config):
    """show or modify configuration"""
    if args.set:
        key, value = args.set.split("=", 1)
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
        parts = key.split(".")
        target = config
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
        path = save_config(config)
        print(f"set {key} = {value}")
        print(f"saved to {path}")
        return 0
    if args.key:
        parts = args.key.split(".")
        value = config
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = None
                break
        print(json.dumps(value, indent=2) if isinstance(value, (dict, list)) else str(value))
        return 0
    print(json.dumps(config, indent=2))
    return 0


def build_parser():
    """build the argument parser"""
    parser = argparse.ArgumentParser(
        prog="orcasec",
        description="unified security toolkit",
    )
    parser.add_argument("-f", "--format", choices=["table", "json", "csv", "html"],
                        help="output format")
    parser.add_argument("-o", "--output", help="output file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    sub = parser.add_subparsers(dest="command")

    list_p = sub.add_parser("list", help="list available modules")
    list_p.add_argument("category", nargs="?", help="filter by category")

    run_p = sub.add_parser("run", help="run a specific module")
    run_p.add_argument("module", help="module name")
    run_p.add_argument("module_args", nargs=argparse.REMAINDER, help="module arguments")

    scan_p = sub.add_parser("scan", help="run scan pipeline")
    scan_p.add_argument("target", nargs="?", help="target network or host")
    scan_p.add_argument("--format", dest="format", default=None)

    recon_p = sub.add_parser("recon", help="run recon pipeline")
    recon_p.add_argument("target", nargs="?", help="target network or host")

    mon_p = sub.add_parser("monitor", help="run monitoring modules")
    mon_p.add_argument("module", nargs="?", help="specific monitor module")

    pipe_p = sub.add_parser("pipeline", help="run custom pipeline")
    pipe_p.add_argument("file", nargs="?", help="pipeline json file")
    pipe_p.add_argument("--parallel", action="store_true", help="run stages in parallel")
    pipe_p.add_argument("--workers", type=int, default=4, help="parallel workers")
    pipe_p.add_argument("-o", "--output", help="save results to file")

    cfg_p = sub.add_parser("config", help="show or set configuration")
    cfg_p.add_argument("key", nargs="?", help="config key to display")
    cfg_p.add_argument("--set", help="set a config value (key=value)")

    return parser


def main():
    """entry point"""
    ensure_dirs()
    config = load_config()
    parser = build_parser()
    args = parser.parse_args()
    level = "debug" if args.verbose else config.get("log_level", "info")
    setup_logging(level=level)
    commands = {
        "list": cmd_list,
        "run": cmd_run,
        "scan": cmd_scan,
        "recon": cmd_recon,
        "monitor": cmd_monitor,
        "pipeline": cmd_pipeline,
        "config": cmd_config,
    }
    if not args.command:
        cmd_list(argparse.Namespace(category=None), config)
        return 0
    handler = commands.get(args.command)
    if handler:
        return handler(args, config)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
