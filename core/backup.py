#!/usr/bin/env python3
"""file and configuration backup management"""

import os
import shutil
import json
import time


class BackupManager:
    """manage backups of files and configurations."""

    def __init__(self, backup_dir=None):
        if backup_dir is None:
            backup_dir = os.path.join(
                os.path.expanduser("~"), ".orca", "backups"
            )
        self.backup_dir = backup_dir
        os.makedirs(backup_dir, exist_ok=True)
        self.manifest = self._load_manifest()

    def backup_file(self, filepath, tag=""):
        """backup a single file."""
        if not os.path.isfile(filepath):
            return None
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        name = os.path.basename(filepath)
        dest_name = f"{name}.{timestamp}"
        if tag:
            dest_name = f"{name}.{tag}.{timestamp}"
        dest = os.path.join(self.backup_dir, dest_name)
        shutil.copy2(filepath, dest)
        entry = {
            "original": filepath,
            "backup": dest,
            "timestamp": timestamp,
            "tag": tag,
            "size": os.path.getsize(filepath),
        }
        self.manifest.append(entry)
        self._save_manifest()
        return entry

    def backup_directory(self, directory, tag=""):
        """backup an entire directory."""
        if not os.path.isdir(directory):
            return None
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        name = os.path.basename(directory)
        dest_name = f"{name}_{timestamp}"
        if tag:
            dest_name = f"{name}_{tag}_{timestamp}"
        dest = os.path.join(self.backup_dir, dest_name)
        shutil.copytree(directory, dest)
        entry = {
            "original": directory,
            "backup": dest,
            "timestamp": timestamp,
            "tag": tag,
            "type": "directory",
        }
        self.manifest.append(entry)
        self._save_manifest()
        return entry

    def list_backups(self, filepath=None):
        """list backups, optionally filtered by original path."""
        if filepath:
            return [
                e for e in self.manifest
                if e["original"] == filepath
            ]
        return list(self.manifest)

    def restore(self, backup_path, dest=None):
        """restore a backup to original or specified location."""
        for entry in self.manifest:
            if entry["backup"] == backup_path:
                target = dest or entry["original"]
                if os.path.isdir(backup_path):
                    if os.path.exists(target):
                        shutil.rmtree(target)
                    shutil.copytree(backup_path, target)
                else:
                    shutil.copy2(backup_path, target)
                return target
        return None

    def cleanup(self, max_age_days=30):
        """remove backups older than max_age_days."""
        cutoff = time.time() - (max_age_days * 86400)
        kept = []
        for entry in self.manifest:
            path = entry["backup"]
            if os.path.exists(path):
                mtime = os.path.getmtime(path)
                if mtime < cutoff:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                else:
                    kept.append(entry)
            else:
                pass
        self.manifest = kept
        self._save_manifest()

    def _load_manifest(self):
        path = os.path.join(self.backup_dir, "manifest.json")
        if os.path.isfile(path):
            with open(path) as f:
                return json.load(f)
        return []

    def _save_manifest(self):
        path = os.path.join(self.backup_dir, "manifest.json")
        with open(path, "w") as f:
            json.dump(self.manifest, f, indent=2)


if __name__ == "__main__":
    bm = BackupManager("/tmp/orca_backups")
    test_file = "/tmp/orca_test.txt"
    with open(test_file, "w") as f:
        f.write("important config data")
    entry = bm.backup_file(test_file, tag="test")
    print(f"backed up: {entry['backup']}")
    backups = bm.list_backups()
    print(f"total backups: {len(backups)}")
