#!/usr/bin/env python3
"""module registry with dependency ordering"""

from collections import defaultdict


class ModuleRegistry:
    """registry for tracking loaded modules and their dependencies."""

    def __init__(self):
        self.modules = {}
        self.dependencies = defaultdict(set)
        self.dependents = defaultdict(set)

    def register(self, name, module, deps=None):
        """register a module with its dependencies."""
        self.modules[name] = module
        if deps:
            for dep in deps:
                self.dependencies[name].add(dep)
                self.dependents[dep].add(name)

    def unregister(self, name):
        """remove a module from the registry."""
        self.modules.pop(name, None)
        for dep in self.dependencies.pop(name, set()):
            self.dependents[dep].discard(name)

    def get(self, name):
        """get a registered module by name."""
        return self.modules.get(name)

    def is_registered(self, name):
        """check if a module is registered."""
        return name in self.modules

    def resolve_order(self):
        """topological sort of modules by dependencies."""
        visited = set()
        order = []
        temp = set()

        def visit(name):
            if name in temp:
                return
            if name in visited:
                return
            temp.add(name)
            for dep in self.dependencies.get(name, set()):
                if dep in self.modules:
                    visit(dep)
            temp.discard(name)
            visited.add(name)
            order.append(name)

        for name in self.modules:
            if name not in visited:
                visit(name)
        return order

    def list_modules(self):
        """list all registered module names."""
        return list(self.modules.keys())

    def check_deps(self, name):
        """check if all dependencies for a module are met."""
        missing = []
        for dep in self.dependencies.get(name, set()):
            if dep not in self.modules:
                missing.append(dep)
        return missing


registry = ModuleRegistry()


if __name__ == "__main__":
    reg = ModuleRegistry()
    reg.register("netscan", None, deps=[])
    reg.register("vuln", None, deps=["netscan"])
    reg.register("report", None, deps=["vuln", "netscan"])
    order = reg.resolve_order()
    print(f"load order: {order}")
