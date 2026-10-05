"""Passive, evidence-scoped ransomware *heuristics* for SENTINEL-X.

No content is read or changed; absence of a trustworthy PID never becomes
attribution to an invented process. This does not assert malware certainty.
"""
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import PureWindowsPath
from math import isfinite
from typing import Dict, List, Optional, Tuple
import time


class RansomwareBehaviorDetector:
    def __init__(self, modification_window_seconds=20, modification_threshold=15,
                 rename_window_seconds=30, rename_threshold=8,
                 extension_window_seconds=30, extension_change_threshold=6,
                 ransomware_score_threshold=70, alert_cooldown_seconds=30):
        settings = (modification_window_seconds, modification_threshold,
                    rename_window_seconds, rename_threshold,
                    extension_window_seconds, extension_change_threshold,
                    ransomware_score_threshold, alert_cooldown_seconds)
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or
               not isfinite(v) for v in settings):
            raise ValueError("Ransomware detector settings must be finite numbers")
        if min(settings[:6]) <= 0 or not 0 < ransomware_score_threshold <= 100 or alert_cooldown_seconds < 0:
            raise ValueError("Invalid ransomware detector thresholds/windows")
        self.modification_window_seconds = modification_window_seconds
        self.modification_threshold = modification_threshold
        self.rename_window_seconds = rename_window_seconds
        self.rename_threshold = rename_threshold
        self.extension_window_seconds = extension_window_seconds
        self.extension_change_threshold = extension_change_threshold
        self.ransomware_score_threshold = ransomware_score_threshold
        self.alert_cooldown_seconds = alert_cooldown_seconds
        self.modification_history = defaultdict(deque)
        self.rename_history = defaultdict(deque)
        self.extension_history = defaultdict(deque)
        self.active_signals = defaultdict(dict)
        self.last_alert_time = {}

    def now_timestamp(self):
        return time.time()

    def iso_from_timestamp(self, timestamp):
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()

    @staticmethod
    def _trusted_pid(event):
        candidate = event.get("process_id")
        if candidate is None:
            candidate = event.get("pid")
        if isinstance(candidate, bool):
            return None
        try:
            parsed = int(candidate)
            if parsed > 0 and str(candidate).strip() == str(parsed):
                return parsed
        except (TypeError, ValueError):
            pass
        return None

    @staticmethod
    def _path(event):
        return event.get("file_path") or event.get("path") or event.get("new_path") or event.get("destination_path")

    def get_entity_key(self, event: Dict) -> Tuple:
        pid = self._trusted_pid(event)
        if pid is not None:
            # PID is the strongest available key in supplied metadata. Correlation
            # must independently verify process creation time to handle PID reuse.
            return ("pid", pid)
        path = self._path(event)
        if not isinstance(path, str) or not path.strip():
            return ("unattributed", "missing_path")
        # Unknown-PID events are scoped to a directory, never combined globally.
        return ("unattributed_directory", str(PureWindowsPath(path).parent).casefold())

    @staticmethod
    def cleanup_history(history, cutoff):
        while history and history[0][0] < cutoff:
            history.popleft()

    def should_emit_alert(self, alert_key, current_time):
        previous = self.last_alert_time.get(alert_key)
        if previous is not None and 0 <= current_time - previous < self.alert_cooldown_seconds:
            return False
        self.last_alert_time[alert_key] = current_time
        return True

    def _finding(self, kind, event, now, count, threshold, window, reason, **extra):
        reliable = self._trusted_pid(event) is not None
        # A watcher with unknown PID can surface a reviewable LOW-level signal,
        # but cannot claim a high-confidence ransomware attribution.
        severity = "MEDIUM" if reliable else "LOW"
        risk = 45 if reliable else 20
        result = {
            "engine": "ransomware_behavior", "detection_type": kind,
            "severity": severity, "risk_score": risk, "risk": risk,
            "confidence": round(min(0.65 if reliable else 0.3, count / (2 * threshold)), 4),
            "time_window_seconds": window, "reason": reason,
            "detected_at": self.iso_from_timestamp(now),
            "detection_method": "RULE_BASED_BEHAVIOR",
            "attribution_status": "PID_OBSERVED" if reliable else "UNKNOWN",
            "process_id": self._trusted_pid(event),
            "entity_scope": list(self.get_entity_key(event)),
        }
        result.update(extra)
        return result

    def _record_signal(self, event, kind, now):
        self.active_signals[self.get_entity_key(event)][kind] = now

    def detect_modification_burst(self, event, current_time):
        if str(event.get("event_type", "")).lower() not in {"file_modify", "file_modified", "file_write"}:
            return None
        path = self._path(event)
        if not isinstance(path, str) or not path.strip():
            return None
        key = self.get_entity_key(event)
        history = self.modification_history[key]
        history.append((current_time, path.casefold()))
        self.cleanup_history(history, current_time - self.modification_window_seconds)
        count = len({p for _, p in history})
        if count < self.modification_threshold:
            return None
        self._record_signal(event, "FILE_MODIFICATION_BURST", current_time)
        if not self.should_emit_alert((key, "FILE_MODIFICATION_BURST"), current_time):
            return None
        return self._finding("FILE_MODIFICATION_BURST", event, current_time, count,
                             self.modification_threshold, self.modification_window_seconds,
                             f"{count} distinct files modified within {self.modification_window_seconds} seconds",
                             unique_file_count=count)

    def detect_mass_rename(self, event, current_time):
        if str(event.get("event_type", "")).lower() not in {"file_rename", "file_renamed"}:
            return None
        old = event.get("old_path") or event.get("source_path")
        new = event.get("new_path") or event.get("destination_path")
        if not all(isinstance(x, str) and x.strip() for x in (old, new)) or old == new:
            return None
        key = self.get_entity_key(event)
        history = self.rename_history[key]
        history.append((current_time, old.casefold(), new.casefold()))
        self.cleanup_history(history, current_time - self.rename_window_seconds)
        count = len({(a, b) for _, a, b in history})
        if count < self.rename_threshold:
            return None
        self._record_signal(event, "MASS_FILE_RENAME", current_time)
        if not self.should_emit_alert((key, "MASS_FILE_RENAME"), current_time):
            return None
        return self._finding("MASS_FILE_RENAME", event, current_time, count,
                             self.rename_threshold, self.rename_window_seconds,
                             f"{count} distinct file renames within {self.rename_window_seconds} seconds",
                             rename_count=count)

    def detect_extension_change(self, event, current_time):
        if str(event.get("event_type", "")).lower() not in {"file_rename", "file_renamed"}:
            return None
        old = event.get("old_path") or event.get("source_path")
        new = event.get("new_path") or event.get("destination_path")
        if not all(isinstance(x, str) and x.strip() for x in (old, new)):
            return None
        old_ext = PureWindowsPath(old).suffix.casefold()
        new_ext = PureWindowsPath(new).suffix.casefold()
        if not old_ext or not new_ext or old_ext == new_ext:
            return None
        key = self.get_entity_key(event)
        history = self.extension_history[key]
        history.append((current_time, old.casefold(), new.casefold()))
        self.cleanup_history(history, current_time - self.extension_window_seconds)
        count = len({(a, b) for _, a, b in history})
        if count < self.extension_change_threshold:
            return None
        self._record_signal(event, "EXTENSION_CHANGE_BURST", current_time)
        if not self.should_emit_alert((key, "EXTENSION_CHANGE_BURST"), current_time):
            return None
        return self._finding("EXTENSION_CHANGE_BURST", event, current_time, count,
                             self.extension_change_threshold, self.extension_window_seconds,
                             f"{count} distinct file-extension changes within {self.extension_window_seconds} seconds",
                             extension_change_count=count)

    def build_combined_detection(self, detections, event, current_time):
        pid = self._trusted_pid(event)
        if pid is None:
            return None  # Without process attribution, no authoritative escalation.
        key = self.get_entity_key(event)
        lookback = max(self.modification_window_seconds,
                       self.rename_window_seconds, self.extension_window_seconds)
        signals = {kind for kind, ts in self.active_signals[key].items()
                   if 0 <= current_time - ts <= lookback}
        # Rename + extension-change signals are generated by the SAME file event.
        # Require independent modification evidence as corroboration.
        if "FILE_MODIFICATION_BURST" not in signals or not (
                {"MASS_FILE_RENAME", "EXTENSION_CHANGE_BURST"} & signals):
            return None
        score = 35 + (30 if "MASS_FILE_RENAME" in signals else 0) + (
            40 if "EXTENSION_CHANGE_BURST" in signals else 0)
        score = min(100, score)
        if score < self.ransomware_score_threshold:
            return None
        if not self.should_emit_alert((key, "POSSIBLE_RANSOMWARE_BEHAVIOR"), current_time):
            return None
        return {
            "engine": "ransomware_behavior",
            "detection_type": "POSSIBLE_RANSOMWARE_BEHAVIOR",
            "severity": "HIGH", "risk_score": score, "risk": score,
            "confidence": round(min(0.75, score / 100.0), 4),
            "signals": sorted(signals), "process_id": pid,
            "attribution_status": "PID_OBSERVED", "entity_scope": list(key),
            "reason": "Distinct modification and rename/extension behaviors observed for the same PID; review required",
            "detected_at": self.iso_from_timestamp(current_time),
            "detection_method": "MULTI_SIGNAL_HEURISTIC",
            "interpretation": "Heuristic behavioral alert; process identity and intent require independent verification before response.",
        }

    def analyze(self, event: Dict, current_time: Optional[float] = None) -> List[Dict]:
        if not isinstance(event, dict):
            return []
        if current_time is None:
            current_time = self.now_timestamp()
        if isinstance(current_time, bool) or not isinstance(current_time, (int, float)) or not isfinite(current_time):
            return []
        # No filename means no usable evidence for behavioral analysis.
        if not self._path(event):
            return []
        found = []
        for method in (self.detect_modification_burst, self.detect_mass_rename,
                       self.detect_extension_change):
            result = method(event, current_time)
            if result:
                found.append(result)
        combined = self.build_combined_detection(found, event, current_time)
        if combined:
            found.append(combined)
        return found
