#!/usr/bin/env python3
"""shared utilities for orcasec platform"""

import ctypes
import logging
import os
import platform
import socket
import sys


PLATFORM = platform.system().lower()

COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "reset": "\033[0m",
    "bold": "\033[1m",
}

SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "green",
}


def _supports_color():
    """check if terminal supports ansi colors"""
    if PLATFORM == "windows":
        return os.environ.get("ANSICON") or "WT_SESSION" in os.environ
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def colorize(text, color):
    """wrap text in ansi color codes if supported"""
    if not _supports_color() or color not in COLORS:
        return text
    return f"{COLORS[color]}{text}{COLORS['reset']}"


class ColorFormatter(logging.Formatter):
    """log formatter with colored severity levels"""

    level_colors = {
        logging.DEBUG: "cyan",
        logging.INFO: "green",
        logging.WARNING: "yellow",
        logging.ERROR: "red",
        logging.CRITICAL: "magenta",
    }

    def format(self, record):
        msg = super().format(record)
        color = self.level_colors.get(record.levelno, "reset")
        level = colorize(record.levelname.ljust(8), color)
        return msg.replace(record.levelname, level, 1)


def setup_logging(name="orcasec", level="info", log_file=None):
    """configure logging with colored console and optional file output"""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    console = logging.StreamHandler()
    console.setFormatter(ColorFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s",
                                        datefmt="%H:%M:%S"))
    logger.addHandler(console)
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(fh)
    return logger


def is_admin():
    """check if running with elevated privileges"""
    if PLATFORM == "windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def get_default_interface():
    """get the default network interface name"""
    try:
        if PLATFORM == "linux":
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if fields[1] == "00000000":
                        return fields[0]
        elif PLATFORM == "darwin":
            import subprocess
            result = subprocess.run(["route", "-n", "get", "default"],
                                    capture_output=True, text=True, timeout=5)
            for line in result.stdout.split("\n"):
                if "interface:" in line:
                    return line.split(":")[1].strip()
    except (IOError, OSError, IndexError):
        pass
    return None


def format_table(headers, rows, pad=2):
    """format data as an aligned text table"""
    if not rows:
        return ""
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    sep = " " * pad
    lines = []
    header_line = sep.join(str(h).ljust(widths[i]) for i, h in enumerate(headers))
    lines.append(colorize(header_line, "bold"))
    lines.append(sep.join("-" * w for w in widths))
    for row in rows:
        cells = [str(row[i]).ljust(widths[i]) if i < len(row) else " " * widths[i]
                 for i in range(len(headers))]
        lines.append(sep.join(cells))
    return "\n".join(lines)


def main():
    """show system info"""
    print(f"platform:  {PLATFORM}")
    print(f"admin:     {is_admin()}")
    print(f"interface: {get_default_interface()}")
    logger = setup_logging()
    logger.info("utils loaded successfully")


if __name__ == "__main__":
    main()


def calculate_subnet(ip, prefix=24):
    """calculate network address and broadcast for a given ip and prefix"""
    import ipaddress
    try:
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return {
            "network": str(network.network_address),
            "broadcast": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "hosts": network.num_addresses - 2,
            "cidr": str(network),
        }
    except ValueError:
        return None


class ConnectionPool:
    """simple connection pool for reusing tcp connections"""

    def __init__(self, max_size=20):
        self.max_size = max_size
        self.pool = {}

    def get(self, host, port, timeout=5):
        """get or create a connection"""
        key = (host, port)
        if key in self.pool:
            sock = self.pool[key]
            try:
                sock.getpeername()
                return sock
            except OSError:
                del self.pool[key]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if len(self.pool) < self.max_size:
            self.pool[key] = sock
        return sock

    def close_all(self):
        """close all pooled connections"""
        for sock in self.pool.values():
            try:
                sock.close()
            except OSError:
                pass
        self.pool.clear()
