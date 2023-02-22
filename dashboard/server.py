#!/usr/bin/env python3
"""flask web server for orca security dashboard and installer"""

import json
import os
import sys

from flask import Flask, jsonify, render_template, send_from_directory

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)


def _get_platform_info():
    """detect platform for installer page."""
    from core.installer import detect_platform
    return detect_platform()


def _get_dashboard_data():
    """compile dashboard data."""
    from dashboard.routes import format_dashboard_data
    return format_dashboard_data()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/install")
def install_page():
    info = _get_platform_info()
    return render_template("install.html", platform=info)


@app.route("/api/status")
def api_status():
    data = _get_dashboard_data()
    return jsonify(data)


@app.route("/api/platform")
def api_platform():
    info = _get_platform_info()
    return jsonify(info)


@app.route("/api/modules")
def api_modules():
    from dashboard.routes import get_module_status
    modules = get_module_status()
    return jsonify(modules)


@app.route("/api/scans")
def api_scans():
    from dashboard.routes import get_scan_results
    results = get_scan_results()
    return jsonify(results)


def main():
    port = int(os.environ.get("ORCA_PORT", 8443))
    debug = os.environ.get("ORCA_DEBUG", "0") == "1"
    print(f"orca dashboard at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)


if __name__ == "__main__":
    main()
