#!/usr/bin/env python3
"""event bus for inter-module communication"""

import json
import time
import threading
from collections import defaultdict


class EventBus:
    """central event bus for module communication via pub/sub."""

    def __init__(self):
        self._handlers = defaultdict(list)
        self._lock = threading.Lock()
        self._history = []
        self._max_history = 1000

    def publish(self, topic, data):
        """publish an event to all subscribers matching topic prefix."""
        event = {
            "topic": topic,
            "timestamp": time.time(),
            "data": data,
        }
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]
            matched = []
            for prefix, handlers in self._handlers.items():
                if topic.startswith(prefix):
                    matched.extend(handlers)
        for handler in matched:
            try:
                handler(event)
            except Exception as e:
                self._log_error(topic, e)

    def subscribe(self, topic_prefix, handler):
        """subscribe to events matching a topic prefix."""
        with self._lock:
            self._handlers[topic_prefix].append(handler)

    def unsubscribe(self, topic_prefix, handler):
        """remove a handler from a topic."""
        with self._lock:
            if topic_prefix in self._handlers:
                self._handlers[topic_prefix] = [
                    h for h in self._handlers[topic_prefix]
                    if h != handler
                ]

    def get_history(self, topic_prefix=None, limit=50):
        """get recent events, optionally filtered by topic."""
        with self._lock:
            if topic_prefix:
                filtered = [
                    e for e in self._history
                    if e["topic"].startswith(topic_prefix)
                ]
                return filtered[-limit:]
            return self._history[-limit:]

    def clear_history(self):
        """clear event history."""
        with self._lock:
            self._history.clear()

    def subscriber_count(self, topic_prefix=None):
        """count active subscribers."""
        with self._lock:
            if topic_prefix:
                return len(self._handlers.get(topic_prefix, []))
            return sum(len(h) for h in self._handlers.values())

    def _log_error(self, topic, error):
        """log handler errors without crashing the bus."""
        self.publish("system.error", {
            "source": "event_bus",
            "topic": topic,
            "error": str(error),
        })

    def export_history(self):
        """export history as json string."""
        with self._lock:
            return json.dumps(self._history, indent=2)


if __name__ == "__main__":
    bus = EventBus()
    received = []

    def handler(event):
        received.append(event)

    bus.subscribe("scan.", handler)
    bus.publish("scan.host_discovered", {"ip": "192.168.1.1"})
    bus.publish("scan.port_open", {"port": 22, "service": "ssh"})
    bus.publish("alert.new", {"severity": "HIGH"})
    print(f"received {len(received)} events (expected 2)")
    print(f"total history: {len(bus.get_history())}")
