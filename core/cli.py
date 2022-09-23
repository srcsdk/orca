#!/usr/bin/env python3
"""unified cli for orca security platform"""

import sys
import argparse


def build_parser():
    """build argument parser for orca cli."""
    parser = argparse.ArgumentParser(
        prog="orca",
        description="orca security platform",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan = subparsers.add_parser("scan", help="run security scan")
    scan.add_argument("--target", required=True, help="target ip or network")
    scan.add_argument("--type", default="quick",
                      choices=["quick", "full", "web", "vuln"],
                      help="scan type")
    scan.add_argument("--output", help="output file path")

    # start command
    start = subparsers.add_parser("start", help="start orca services")
    start.add_argument("--profile", default="personal",
                       help="deployment profile")
    start.add_argument("--modules", help="comma-separated module list")

    # status command
    subparsers.add_parser("status", help="show service status")

    # alerts command
    alerts = subparsers.add_parser("alerts", help="view alerts")
    alerts.add_argument("--severity", choices=["INFO", "LOW", "MED", "HIGH", "CRIT"])
    alerts.add_argument("--limit", type=int, default=20)

    # modules command
    modules = subparsers.add_parser("modules", help="manage modules")
    modules.add_argument("action", choices=["list", "enable", "disable", "status"])
    modules.add_argument("--name", help="module name")

    # report command
    report = subparsers.add_parser("report", help="generate report")
    report.add_argument("--format", default="json",
                        choices=["json", "html", "text"])
    report.add_argument("--output", help="output file path")
    report.add_argument("--since", default="24h", help="time window")

    # dashboard command
    subparsers.add_parser("dashboard", help="launch web dashboard")

    return parser


def handle_scan(args):
    """handle scan command."""
    print(f"scanning {args.target} ({args.type} scan)")
    return 0


def handle_start(args):
    """handle start command."""
    if args.modules:
        modules = args.modules.split(",")
        print(f"starting modules: {', '.join(modules)}")
    else:
        print(f"starting with profile: {args.profile}")
    return 0


def handle_status(args):
    """handle status command."""
    print("orca status: running")
    return 0


def handle_alerts(args):
    """handle alerts command."""
    print(f"showing alerts (severity>={args.severity or 'all'}, "
          f"limit={args.limit})")
    return 0


def handle_modules(args):
    """handle modules command."""
    print(f"modules {args.action}")
    return 0


def handle_report(args):
    """handle report command."""
    print(f"generating {args.format} report (since {args.since})")
    return 0


HANDLERS = {
    "scan": handle_scan,
    "start": handle_start,
    "status": handle_status,
    "alerts": handle_alerts,
    "modules": handle_modules,
    "report": handle_report,
}


def main(argv=None):
    """main cli entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    handler = HANDLERS.get(args.command)
    if handler:
        return handler(args)
    print(f"unknown command: {args.command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
