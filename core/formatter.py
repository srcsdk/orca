#!/usr/bin/env python3
"""output formatter for scan results"""

import json


def format_text(results, title="scan results"):
    """format results as plain text report."""
    lines = [title, "=" * len(title), ""]
    for module_name, data in results.items():
        lines.append(f"[{module_name}]")
        if isinstance(data, dict):
            for key, value in data.items():
                lines.append(f"  {key}: {value}")
        elif isinstance(data, list):
            for item in data:
                lines.append(f"  - {item}")
        else:
            lines.append(f"  {data}")
        lines.append("")
    return "\n".join(lines)


def format_json(results, indent=2):
    """format results as json string."""
    return json.dumps(results, indent=indent, default=str)


def format_csv(results):
    """format flat results as csv lines."""
    lines = []
    for module_name, data in results.items():
        if isinstance(data, dict):
            for key, value in data.items():
                lines.append(f"{module_name},{key},{value}")
        elif isinstance(data, list):
            for i, item in enumerate(data):
                lines.append(f"{module_name},{i},{item}")
    return "\n".join(lines)


def severity_color(level):
    """return ansi color code for severity level."""
    colors = {
        "critical": "\033[91m",
        "high": "\033[93m",
        "medium": "\033[33m",
        "low": "\033[92m",
        "info": "\033[94m",
    }
    reset = "\033[0m"
    color = colors.get(level.lower(), "")
    return f"{color}{level.upper()}{reset}"


def summary_line(results):
    """generate one-line summary of scan results."""
    total_items = sum(
        len(v) if isinstance(v, (list, dict)) else 1
        for v in results.values()
    )
    return f"{len(results)} modules, {total_items} findings"


if __name__ == "__main__":
    sample = {
        "port_scan": {"open_ports": 3, "status": "complete"},
        "wifi_scan": ["network1", "network2"],
    }
    print(format_text(sample))
    print(summary_line(sample))
