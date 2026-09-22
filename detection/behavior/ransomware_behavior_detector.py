from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class RansomwareBehaviorDetector:
    """
    SENTINEL-X ransomware behavioral detector.

    This detector does NOT encrypt, modify, rename, or delete files.

    It only analyzes file-event metadata supplied to it.

    Current signals:

        1. FILE_MODIFICATION_BURST
        2. MASS_FILE_RENAME
        3. EXTENSION_CHANGE_BURST
        4. POSSIBLE_RANSOMWARE_BEHAVIOR

    These are heuristic behavioral detections.

    They must not be interpreted as proof that ransomware is present.
    """

    def __init__(
        self,
        modification_window_seconds: int = 20,
        modification_threshold: int = 15,

        rename_window_seconds: int = 30,
        rename_threshold: int = 8,

        extension_window_seconds: int = 30,
        extension_change_threshold: int = 6,

        ransomware_score_threshold: int = 70,

        alert_cooldown_seconds: int = 30,
    ):

        self.modification_window_seconds = (
            modification_window_seconds
        )

        self.modification_threshold = (
            modification_threshold
        )

        self.rename_window_seconds = (
            rename_window_seconds
        )

        self.rename_threshold = (
            rename_threshold
        )

        self.extension_window_seconds = (
            extension_window_seconds
        )

        self.extension_change_threshold = (
            extension_change_threshold
        )

        self.ransomware_score_threshold = (
            ransomware_score_threshold
        )

        self.alert_cooldown_seconds = (
            alert_cooldown_seconds
        )

        # --------------------------------------------------------
        # HISTORY STORES
        # --------------------------------------------------------

        self.modification_history = defaultdict(
            deque
        )

        self.rename_history = defaultdict(
            deque
        )

        self.extension_history = defaultdict(
            deque
        )

        self.last_alert_time = {}

    # ============================================================
    # TIME
    # ============================================================

    def now_timestamp(
        self,
    ) -> float:

        return datetime.now(
            timezone.utc
        ).timestamp()

    def iso_from_timestamp(
        self,
        timestamp: float,
    ) -> str:

        return datetime.fromtimestamp(
            timestamp,
            timezone.utc,
        ).isoformat()

    # ============================================================
    # PROCESS / ENTITY KEY
    # ============================================================

    def get_entity_key(
        self,
        event: Dict,
    ) -> Tuple:

        process_id = (
            event.get(
                "process_id"
            )
            or event.get(
                "pid"
            )
        )

        process_name = (
            event.get(
                "process_name"
            )
            or "unknown_process"
        )

        return (
            process_id,
            process_name,
        )

    # ============================================================
    # CLEANUP
    # ============================================================

    def cleanup_history(
        self,
        history: deque,
        cutoff: float,
    ):

        while (
            history
            and history[0][0] < cutoff
        ):

            history.popleft()

    # ============================================================
    # ALERT COOLDOWN
    # ============================================================

    def should_emit_alert(
        self,
        alert_key: Tuple,
        current_time: float,
    ) -> bool:

        previous = (
            self.last_alert_time.get(
                alert_key
            )
        )

        if previous is None:

            self.last_alert_time[
                alert_key
            ] = current_time

            return True

        if (
            current_time
            - previous
            >= self.alert_cooldown_seconds
        ):

            self.last_alert_time[
                alert_key
            ] = current_time

            return True

        return False

    # ============================================================
    # FILE MODIFICATION BURST
    # ============================================================

    def detect_modification_burst(
        self,
        event: Dict,
        current_time: float,
    ) -> Optional[Dict]:

        event_type = (
            event.get(
                "event_type",
                ""
            ).lower()
        )

        if event_type not in {
            "file_modify",
            "file_modified",
            "file_write",
        }:

            return None

        key = (
            self.get_entity_key(
                event
            )
        )

        history = (
            self.modification_history[
                key
            ]
        )

        file_path = (
            event.get(
                "file_path"
            )
            or event.get(
                "path"
            )
            or "unknown"
        )

        history.append(
            (
                current_time,
                file_path,
            )
        )

        cutoff = (
            current_time
            - self.modification_window_seconds
        )

        self.cleanup_history(
            history,
            cutoff,
        )

        unique_files = {
            path
            for _, path
            in history
        }

        count = len(
            unique_files
        )

        if (
            count
            < self.modification_threshold
        ):

            return None

        alert_key = (
            "FILE_MODIFICATION_BURST",
            *key,
        )

        if not self.should_emit_alert(
            alert_key,
            current_time,
        ):

            return None

        return {
            "engine":
                "ransomware_behavior",

            "detection_type":
                "FILE_MODIFICATION_BURST",

            "severity":
                "HIGH",

            "risk_score":
                70,

            "confidence":
                min(
                    1.0,
                    count
                    / (
                        self.modification_threshold
                        * 2
                    ),
                ),

            "unique_file_count":
                count,

            "time_window_seconds":
                self.modification_window_seconds,

            "reason":
                (
                    f"{count} distinct files were modified "
                    f"within "
                    f"{self.modification_window_seconds} seconds"
                ),

            "detected_at":
                self.iso_from_timestamp(
                    current_time
                ),

            "detection_method":
                "RULE_BASED_BEHAVIOR",
        }

    # ============================================================
    # MASS RENAME
    # ============================================================

    def detect_mass_rename(
        self,
        event: Dict,
        current_time: float,
    ) -> Optional[Dict]:

        event_type = (
            event.get(
                "event_type",
                ""
            ).lower()
        )

        if event_type not in {
            "file_rename",
            "file_renamed",
        }:

            return None

        key = (
            self.get_entity_key(
                event
            )
        )

        history = (
            self.rename_history[
                key
            ]
        )

        old_path = (
            event.get(
                "old_path"
            )
            or event.get(
                "source_path"
            )
            or event.get(
                "file_path"
            )
            or "unknown"
        )

        new_path = (
            event.get(
                "new_path"
            )
            or event.get(
                "destination_path"
            )
            or "unknown"
        )

        history.append(
            (
                current_time,
                old_path,
                new_path,
            )
        )

        cutoff = (
            current_time
            - self.rename_window_seconds
        )

        while (
            history
            and history[0][0] < cutoff
        ):

            history.popleft()

        count = len(
            history
        )

        if (
            count
            < self.rename_threshold
        ):

            return None

        alert_key = (
            "MASS_FILE_RENAME",
            *key,
        )

        if not self.should_emit_alert(
            alert_key,
            current_time,
        ):

            return None

        return {
            "engine":
                "ransomware_behavior",

            "detection_type":
                "MASS_FILE_RENAME",

            "severity":
                "HIGH",

            "risk_score":
                75,

            "confidence":
                min(
                    1.0,
                    count
                    / (
                        self.rename_threshold
                        * 2
                    ),
                ),

            "rename_count":
                count,

            "time_window_seconds":
                self.rename_window_seconds,

            "reason":
                (
                    f"{count} file renames occurred within "
                    f"{self.rename_window_seconds} seconds"
                ),

            "detected_at":
                self.iso_from_timestamp(
                    current_time
                ),

            "detection_method":
                "RULE_BASED_BEHAVIOR",
        }

    # ============================================================
    # EXTENSION CHANGE
    # ============================================================

    def detect_extension_change(
        self,
        event: Dict,
        current_time: float,
    ) -> Optional[Dict]:

        event_type = (
            event.get(
                "event_type",
                ""
            ).lower()
        )

        if event_type not in {
            "file_rename",
            "file_renamed",
        }:

            return None

        old_path = (
            event.get(
                "old_path"
            )
            or event.get(
                "source_path"
            )
        )

        new_path = (
            event.get(
                "new_path"
            )
            or event.get(
                "destination_path"
            )
        )

        if (
            not old_path
            or not new_path
        ):

            return None

        old_extension = (
            Path(
                old_path
            ).suffix.lower()
        )

        new_extension = (
            Path(
                new_path
            ).suffix.lower()
        )

        if (
            not old_extension
            or not new_extension
            or old_extension == new_extension
        ):

            return None

        key = (
            self.get_entity_key(
                event
            )
        )

        history = (
            self.extension_history[
                key
            ]
        )

        history.append(
            (
                current_time,
                old_extension,
                new_extension,
            )
        )

        cutoff = (
            current_time
            - self.extension_window_seconds
        )

        while (
            history
            and history[0][0] < cutoff
        ):

            history.popleft()

        count = len(
            history
        )

        if (
            count
            < self.extension_change_threshold
        ):

            return None

        alert_key = (
            "EXTENSION_CHANGE_BURST",
            *key,
        )

        if not self.should_emit_alert(
            alert_key,
            current_time,
        ):

            return None

        return {
            "engine":
                "ransomware_behavior",

            "detection_type":
                "EXTENSION_CHANGE_BURST",

            "severity":
                "HIGH",

            "risk_score":
                80,

            "confidence":
                min(
                    1.0,
                    count
                    / (
                        self.extension_change_threshold
                        * 2
                    ),
                ),

            "extension_change_count":
                count,

            "time_window_seconds":
                self.extension_window_seconds,

            "reason":
                (
                    f"{count} file-extension changes occurred "
                    f"within "
                    f"{self.extension_window_seconds} seconds"
                ),

            "detected_at":
                self.iso_from_timestamp(
                    current_time
                ),

            "detection_method":
                "RULE_BASED_BEHAVIOR",
        }

    # ============================================================
    # COMBINED RANSOMWARE SCORE
    # ============================================================

    def build_combined_detection(
        self,
        detections: List[Dict],
        event: Dict,
        current_time: float,
    ) -> Optional[Dict]:

        if not detections:
            return None

        signal_types = {
            item.get(
                "detection_type"
            )
            for item in detections
        }

        score = 0

        if (
            "FILE_MODIFICATION_BURST"
            in signal_types
        ):

            score += 35

        if (
            "MASS_FILE_RENAME"
            in signal_types
        ):

            score += 30

        if (
            "EXTENSION_CHANGE_BURST"
            in signal_types
        ):

            score += 40

        score = min(
            100,
            score,
        )

        if (
            score
            < self.ransomware_score_threshold
        ):

            return None

        key = (
            self.get_entity_key(
                event
            )
        )

        alert_key = (
            "POSSIBLE_RANSOMWARE_BEHAVIOR",
            *key,
        )

        if not self.should_emit_alert(
            alert_key,
            current_time,
        ):

            return None

        severity = (
            "CRITICAL"
            if score >= 90
            else "HIGH"
        )

        return {
            "engine":
                "ransomware_behavior",

            "detection_type":
                "POSSIBLE_RANSOMWARE_BEHAVIOR",

            "severity":
                severity,

            "risk_score":
                score,

            "confidence":
                round(
                    score / 100.0,
                    4,
                ),

            "signals":
                sorted(
                    signal_types
                ),

            "reason":
                (
                    "Multiple high-risk file-system behaviors "
                    "were observed together: "
                    + ", ".join(
                        sorted(
                            signal_types
                        )
                    )
                ),

            "detected_at":
                self.iso_from_timestamp(
                    current_time
                ),

            "detection_method":
                "MULTI_SIGNAL_HEURISTIC",

            "interpretation":
                (
                    "Behavior resembles ransomware-like file activity. "
                    "This is a heuristic detection and requires "
                    "corroboration before containment."
                ),
        }

    # ============================================================
    # MAIN ANALYSIS
    # ============================================================

    def analyze(
        self,
        event: Dict,
        current_time: Optional[float] = None,
    ) -> List[Dict]:

        if current_time is None:

            current_time = (
                self.now_timestamp()
            )

        detections = []

        modification = (
            self.detect_modification_burst(
                event,
                current_time,
            )
        )

        if modification:

            detections.append(
                modification
            )

        rename = (
            self.detect_mass_rename(
                event,
                current_time,
            )
        )

        if rename:

            detections.append(
                rename
            )

        extension = (
            self.detect_extension_change(
                event,
                current_time,
            )
        )

        if extension:

            detections.append(
                extension
            )

        combined = (
            self.build_combined_detection(
                detections,
                event,
                current_time,
            )
        )

        if combined:

            detections.append(
                combined
            )

        return detections