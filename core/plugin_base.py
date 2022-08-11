#!/usr/bin/env python3
"""plugin base class for orca modules"""

from abc import ABC, abstractmethod


class OrcaPlugin(ABC):
    """base class for all orca security modules."""

    name = "unnamed"
    version = "0.0.1"
    team = "blue"
    category = "uncategorized"
    description = ""
    dependencies = []

    def __init__(self, bus=None, config=None):
        self.bus = bus
        self.config = config or {}
        self._running = False

    @abstractmethod
    def run(self, **kwargs):
        """execute a one-shot task."""
        pass

    def start(self):
        """begin continuous operation."""
        self._running = True
        self._emit_status("started")

    def stop(self):
        """graceful shutdown."""
        self._running = False
        self._emit_status("stopped")

    def is_running(self):
        """check if module is active."""
        return self._running

    def emit_alert(self, severity, title, detail, attck_id=None):
        """publish a standardized alert event."""
        if not self.bus:
            return
        self.bus.publish("alert.new", {
            "module": self.name,
            "severity": severity,
            "title": title,
            "detail": detail,
            "attck": attck_id,
            "team": self.team,
        })

    def _emit_status(self, status):
        """publish module status event."""
        if not self.bus:
            return
        self.bus.publish(f"system.module_{status}", {
            "module": self.name,
            "version": self.version,
        })

    def get_info(self):
        """return module metadata."""
        return {
            "name": self.name,
            "version": self.version,
            "team": self.team,
            "category": self.category,
            "description": self.description,
            "running": self._running,
        }


class PluginRegistry:
    """registry for discovering and managing plugins."""

    def __init__(self):
        self._plugins = {}

    def register(self, plugin_class):
        """register a plugin class."""
        self._plugins[plugin_class.name] = plugin_class

    def get(self, name):
        """get plugin class by name."""
        return self._plugins.get(name)

    def list_plugins(self, team=None, category=None):
        """list registered plugins with optional filters."""
        result = []
        for name, cls in self._plugins.items():
            if team and cls.team != team:
                continue
            if category and cls.category != category:
                continue
            result.append({
                "name": name,
                "version": cls.version,
                "team": cls.team,
                "category": cls.category,
            })
        return result

    def instantiate(self, name, bus=None, config=None):
        """create plugin instance by name."""
        cls = self._plugins.get(name)
        if not cls:
            return None
        return cls(bus=bus, config=config)


if __name__ == "__main__":
    registry = PluginRegistry()
    print(f"registered plugins: {len(registry.list_plugins())}")
