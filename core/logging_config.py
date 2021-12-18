#!/usr/bin/env python3
"""unified logging with per-module log levels"""

import logging
import os
import sys


LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
DEFAULT_FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"
DEFAULT_LEVEL = logging.INFO


def setup_logging(log_dir=None, level=None, log_file="orca.log"):
    """configure unified logging for all orca modules."""
    if log_dir is None:
        log_dir = LOG_DIR
    if level is None:
        level = DEFAULT_LEVEL
    os.makedirs(log_dir, exist_ok=True)
    root = logging.getLogger("orca")
    root.setLevel(level)
    if not root.handlers:
        console = logging.StreamHandler(sys.stderr)
        console.setLevel(logging.WARNING)
        console.setFormatter(logging.Formatter(DEFAULT_FORMAT))
        root.addHandler(console)
        filepath = os.path.join(log_dir, log_file)
        file_handler = logging.FileHandler(filepath)
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(DEFAULT_FORMAT))
        root.addHandler(file_handler)
    return root


def get_logger(module_name):
    """get a logger for a specific module."""
    return logging.getLogger(f"orca.{module_name}")


def set_module_level(module_name, level):
    """set log level for a specific module."""
    logger = logging.getLogger(f"orca.{module_name}")
    logger.setLevel(level)


if __name__ == "__main__":
    setup_logging(level=logging.DEBUG)
    logger = get_logger("test")
    logger.debug("debug message")
    logger.info("info message")
    logger.warning("warning message")
    print("logging configured")
