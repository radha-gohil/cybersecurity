"""Read-only Windows Run/RunOnce registry telemetry for SENTINEL-X.

This collector reports *observed changes*, not maliciousness or process identity.
It never modifies registry values and never creates detection/response records.
"""
from __future__ import annotations

import time
from typing import Dict, Optional

import winreg

from endpoint.agent.telemetry_manager import shared_telemetry_manager
from endpoint.utils.logger import get_logger

logger = get_logger(__name__)


class RegistryMonitor:
    def __init__(self, polling_interval: float = 5.0):
        self.polling_interval = float(polling_interval)
        if self.polling_interval <= 0:
            raise ValueError("polling_interval must be positive")
        self.running = False
        self.known_values: Dict[str, Dict] = {}
        self._baseline_ready = False
        self.telemetry = shared_telemetry_manager
        self.registry_locations = [
            {
                "root": winreg.HKEY_CURRENT_USER,
                "root_name": "HKEY_CURRENT_USER",
                "path": r"Software\Microsoft\Windows\CurrentVersion\Run",
            },
            {
                "root": winreg.HKEY_CURRENT_USER,
                "root_name": "HKEY_CURRENT_USER",
                "path": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            },
        ]

    @staticmethod
    def _is_missing_key(error: OSError) -> bool:
        return isinstance(error, FileNotFoundError) or getattr(error, "winerror", None) == 2

    @staticmethod
    def _end_of_values(error: OSError) -> bool:
        # ERROR_NO_MORE_ITEMS is the normal end of EnumValue enumeration.
        return getattr(error, "winerror", None) == 259

    def read_registry_key(self, root, root_name, path) -> Optional[dict]:
        """Read a key; None means the snapshot is unreliable.

        A missing RunOnce key is a legitimate empty key. Permission errors,
        transient I/O errors and unexpected enumeration errors are *not* empty.
        """
        values = {}
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(key, index)
                    except OSError as error:
                        if self._end_of_values(error):
                            break
                        logger.warning("Registry enumeration failed at %s\\%s: %s", root_name, path, error)
                        return None
                    full_name = f"{root_name}\\{path}\\{name}"
                    values[full_name] = {
                        "name": name,
                        "value": str(value),
                        "type": value_type,
                        "registry_path": f"{root_name}\\{path}",
                    }
                    index += 1
        except OSError as error:
            if self._is_missing_key(error):
                return {}
            logger.warning("Unable to read registry path %s\\%s: %s", root_name, path, error)
            return None
        return values

    def get_current_snapshot(self) -> Optional[dict]:
        snapshot = {}
        for location in self.registry_locations:
            values = self.read_registry_key(
                location["root"], location["root_name"], location["path"]
            )
            if values is None:
                # Never compare a partial registry snapshot to the last baseline.
                return None
            snapshot.update(values)
        return snapshot

    def build_initial_snapshot(self):
        logger.info("Building initial registry snapshot...")
        snapshot = self.get_current_snapshot()
        if snapshot is None:
            logger.warning("Registry snapshot unavailable; waiting for a complete baseline")
            return False
        self.known_values = snapshot
        self._baseline_ready = True
        logger.info("Initial registry snapshot complete. %s startup values found.", len(snapshot))
        return True

    def emit_registry_event(self, event_type: str, registry_data: dict, metadata: dict = None):
        metadata = {"collector": "RegistryMonitor", **(metadata or {})}
        # A polling snapshot does not reveal which process made the change.
        metadata["attribution_status"] = "UNKNOWN"
        event = self.telemetry.emit(
            event_type=event_type,
            source="registry_monitor",
            severity="INFO",
            registry=registry_data,
            metadata=metadata,
        )
        logger.info("%s | %s | %s", event_type.upper(), registry_data.get("registry_path"), registry_data.get("name"))
        return event

    def check_changes(self):
        current_values = self.get_current_snapshot()
        if current_values is None:
            logger.warning("Registry snapshot unavailable; preserving previous baseline")
            return False
        if not self._baseline_ready:
            # Initial observation is not a change event.
            self.known_values = current_values
            self._baseline_ready = True
            return True

        old_keys = set(self.known_values)
        current_keys = set(current_values)
        for key in sorted(current_keys - old_keys):
            self.emit_registry_event("registry_create", current_values[key])
        for key in sorted(old_keys - current_keys):
            self.emit_registry_event("registry_delete", self.known_values[key])
        for key in sorted(old_keys & current_keys):
            old_data = self.known_values[key]
            new_data = current_values[key]
            if (old_data.get("value"), old_data.get("type")) != (
                new_data.get("value"), new_data.get("type")
            ):
                self.emit_registry_event(
                    "registry_modify", new_data,
                    metadata={
                        "previous_value": old_data.get("value"),
                        "new_value": new_data.get("value"),
                        "previous_type": old_data.get("type"),
                        "new_type": new_data.get("type"),
                    },
                )
        self.known_values = current_values
        return True

    def start(self):
        logger.info("Starting SENTINEL-X Registry Monitor...")
        self.running = True
        self.build_initial_snapshot()
        try:
            while self.running:
                self.check_changes()
                time.sleep(self.polling_interval)
        except KeyboardInterrupt:
            logger.info("Registry monitor interrupted")
        finally:
            self.stop()

    def stop(self):
        self.running = False
        logger.info("SENTINEL-X Registry Monitor stopped")


if __name__ == "__main__":
    RegistryMonitor().start()
