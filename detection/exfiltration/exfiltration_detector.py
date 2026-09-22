from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple


class ExfiltrationBehaviorDetector:
    """
    SENTINEL-X Data Exfiltration Behavior Detector.

    Metadata-only behavioral analysis.

    This detector DOES NOT:

        - transfer files
        - upload data
        - open network connections
        - contact remote systems
        - read confidential files

    It only analyzes supplied transfer metadata.

    Signals:

        1. LARGE_OUTBOUND_TRANSFER
        2. REPEATED_OUTBOUND_UPLOADS
        3. HIGH_VOLUME_OUTBOUND_ACTIVITY
        4. UNAPPROVED_EXTERNAL_DESTINATION
        5. POSSIBLE_DATA_EXFILTRATION
    """

    def __init__(
        self,
        transfer_window_seconds: int = 60,
        large_transfer_threshold_bytes: int = (
            50 * 1024 * 1024
        ),
        repeated_upload_threshold: int = 5,
        cumulative_transfer_threshold_bytes: int = (
            100 * 1024 * 1024
        ),
        exfiltration_score_threshold: int = 70,
    ):

        self.transfer_window_seconds = (
            transfer_window_seconds
        )

        self.large_transfer_threshold_bytes = (
            large_transfer_threshold_bytes
        )

        self.repeated_upload_threshold = (
            repeated_upload_threshold
        )

        self.cumulative_transfer_threshold_bytes = (
            cumulative_transfer_threshold_bytes
        )

        self.exfiltration_score_threshold = (
            exfiltration_score_threshold
        )

        # ========================================================
        # HISTORY
        #
        # key:
        #
        # (
        #     device_id,
        #     process_name,
        #     remote_ip
        # )
        #
        # value:
        #
        # deque[
        #     (
        #         timestamp,
        #         bytes_sent
        #     )
        # ]
        # ========================================================

        self.transfer_history = defaultdict(
            deque
        )

    # ============================================================
    # HELPERS
    # ============================================================

    def normalize_text(
        self,
        value,
    ) -> str:

        if value is None:
            return ""

        return str(
            value
        ).strip()

    def safe_int(
        self,
        value,
        default=0,
    ) -> int:

        try:

            if value is None:
                return default

            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return default

    # ============================================================
    # OUTBOUND CHECK
    # ============================================================

    def is_outbound_transfer(
        self,
        event: Dict,
    ) -> bool:

        direction = (
            self.normalize_text(
                event.get(
                    "direction"
                )
            )
            .lower()
        )

        outbound_values = {

            "outbound",
            "upload",
            "egress",
            "sent",
        }

        if direction in outbound_values:

            return True

        event_type = (
            self.normalize_text(
                event.get(
                    "event_type"
                )
            )
            .lower()
        )

        return event_type in {

            "outbound_transfer",
            "file_upload",
            "network_upload",
        }

    # ============================================================
    # ENTITY KEY
    # ============================================================

    def build_entity_key(
        self,
        event: Dict,
    ) -> Tuple[str, str, str]:

        device_id = (
            self.normalize_text(
                event.get(
                    "device_id"
                )
            )
            or "local-device"
        )

        process_name = (
            self.normalize_text(
                event.get(
                    "process_name"
                )
            )
            .lower()
            or "unknown"
        )

        remote_ip = (
            self.normalize_text(
                event.get(
                    "remote_ip"
                )
            )
            or "unknown"
        )

        return (
            device_id,
            process_name,
            remote_ip,
        )

    # ============================================================
    # HISTORY CLEANUP
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
    # DESTINATION CHECK
    # ============================================================

    def is_unapproved_external_destination(
        self,
        event: Dict,
    ) -> bool:

        destination_scope = (
            self.normalize_text(
                event.get(
                    "destination_scope"
                )
            )
            .lower()
        )

        approved_destination = (
            event.get(
                "approved_destination"
            )
        )

        return (
            destination_scope
            ==
            "external"
            and approved_destination
            is False
        )

    # ============================================================
    # DETECTION BUILDER
    # ============================================================

    def build_detection(
        self,
        detection_type: str,
        severity: str,
        risk_score: int,
        reason: str,
        event: Dict,
        transfer_count: int,
        cumulative_bytes: int,
    ) -> Dict:

        return {

            "engine":
                "exfiltration_behavior",

            "detection_type":
                detection_type,

            "severity":
                severity,

            "risk":
                risk_score,

            "risk_score":
                risk_score,

            # Heuristic score, not probability.
            "confidence":
                round(
                    risk_score
                    / 100.0,
                    4,
                ),

            "device_id":
                event.get(
                    "device_id"
                ),

            "process_name":
                event.get(
                    "process_name"
                ),

            "remote_ip":
                event.get(
                    "remote_ip"
                ),

            "remote_port":
                event.get(
                    "remote_port"
                ),

            "bytes_sent":
                self.safe_int(
                    event.get(
                        "bytes_sent"
                    )
                ),

            "transfer_count":
                transfer_count,

            "cumulative_bytes":
                cumulative_bytes,

            "time_window_seconds":
                self.transfer_window_seconds,

            "reason":
                reason,

            "detection_method":
                "RULE_BASED_EXFILTRATION_BEHAVIOR",
        }

    # ============================================================
    # MAIN ANALYSIS
    # ============================================================

    def analyze(
        self,
        event: Dict,
        current_time: Optional[float] = None,
    ) -> List[Dict]:

        detections = []

        # --------------------------------------------------------
        # Ignore inbound/non-upload activity.
        # --------------------------------------------------------

        if not self.is_outbound_transfer(
            event
        ):

            return detections

        bytes_sent = (
            self.safe_int(
                event.get(
                    "bytes_sent"
                )
            )
        )

        if bytes_sent <= 0:

            return detections

        if current_time is None:

            import time

            current_time = (
                time.time()
            )

        # ========================================================
        # HISTORY
        # ========================================================

        entity_key = (
            self.build_entity_key(
                event
            )
        )

        history = (
            self.transfer_history[
                entity_key
            ]
        )

        history.append(
            (
                current_time,
                bytes_sent,
            )
        )

        cutoff = (
            current_time
            - self.transfer_window_seconds
        )

        self.cleanup_history(
            history,
            cutoff,
        )

        transfer_count = len(
            history
        )

        cumulative_bytes = sum(

            item[
                1
            ]

            for item
            in history
        )

        # ========================================================
        # SIGNAL 1 — LARGE OUTBOUND TRANSFER
        # ========================================================

        large_transfer_active = (

            bytes_sent
            >= self.large_transfer_threshold_bytes
        )

        if large_transfer_active:

            detections.append(

                self.build_detection(

                    detection_type=
                        "LARGE_OUTBOUND_TRANSFER",

                    severity=
                        "HIGH",

                    risk_score=
                        65,

                    reason=(
                        f"Outbound transfer of "
                        f"{bytes_sent} bytes exceeded the "
                        f"configured large-transfer threshold"
                    ),

                    event=
                        event,

                    transfer_count=
                        transfer_count,

                    cumulative_bytes=
                        cumulative_bytes,
                )
            )

        # ========================================================
        # SIGNAL 2 — REPEATED OUTBOUND UPLOADS
        # ========================================================

        repeated_upload_active = (

            transfer_count
            >= self.repeated_upload_threshold
        )

        if repeated_upload_active:

            detections.append(

                self.build_detection(

                    detection_type=
                        "REPEATED_OUTBOUND_UPLOADS",

                    severity=
                        "HIGH",

                    risk_score=
                        70,

                    reason=(
                        f"{transfer_count} outbound transfers "
                        f"were observed to the same destination "
                        f"within {self.transfer_window_seconds} "
                        f"seconds"
                    ),

                    event=
                        event,

                    transfer_count=
                        transfer_count,

                    cumulative_bytes=
                        cumulative_bytes,
                )
            )

        # ========================================================
        # SIGNAL 3 — HIGH CUMULATIVE OUTBOUND VOLUME
        # ========================================================

        high_volume_active = (

            cumulative_bytes
            >=
            self.cumulative_transfer_threshold_bytes
        )

        if high_volume_active:

            detections.append(

                self.build_detection(

                    detection_type=
                        "HIGH_VOLUME_OUTBOUND_ACTIVITY",

                    severity=
                        "HIGH",

                    risk_score=
                        75,

                    reason=(
                        f"Cumulative outbound volume reached "
                        f"{cumulative_bytes} bytes within "
                        f"{self.transfer_window_seconds} seconds"
                    ),

                    event=
                        event,

                    transfer_count=
                        transfer_count,

                    cumulative_bytes=
                        cumulative_bytes,
                )
            )

        # ========================================================
        # SIGNAL 4 — UNAPPROVED EXTERNAL DESTINATION
        # ========================================================

        unapproved_destination_active = (
            self.is_unapproved_external_destination(
                event
            )
        )

        if unapproved_destination_active:

            detections.append(

                self.build_detection(

                    detection_type=
                        "UNAPPROVED_EXTERNAL_DESTINATION",

                    severity=
                        "MEDIUM",

                    risk_score=
                        55,

                    reason=(
                        "Outbound transfer targeted an "
                        "external destination explicitly marked "
                        "as unapproved"
                    ),

                    event=
                        event,

                    transfer_count=
                        transfer_count,

                    cumulative_bytes=
                        cumulative_bytes,
                )
            )

        # ========================================================
        # COMBINED EXFILTRATION SCORE
        # ========================================================

        score = 0

        signals = []

        if large_transfer_active:

            score += 30

            signals.append(
                "LARGE_OUTBOUND_TRANSFER"
            )

        if repeated_upload_active:

            score += 25

            signals.append(
                "REPEATED_OUTBOUND_UPLOADS"
            )

        if high_volume_active:

            score += 30

            signals.append(
                "HIGH_VOLUME_OUTBOUND_ACTIVITY"
            )

        if unapproved_destination_active:

            score += 25

            signals.append(
                "UNAPPROVED_EXTERNAL_DESTINATION"
            )

        score = min(
            score,
            100,
        )

        # ========================================================
        # POSSIBLE DATA EXFILTRATION
        # ========================================================

        if (
            score
            >= self.exfiltration_score_threshold
        ):

            severity = (

                "CRITICAL"

                if score >= 90

                else "HIGH"
            )

            detection = (
                self.build_detection(

                    detection_type=
                        "POSSIBLE_DATA_EXFILTRATION",

                    severity=
                        severity,

                    risk_score=
                        score,

                    reason=(
                        "Outbound activity contains multiple "
                        "data-exfiltration-like signals: "
                        + ", ".join(
                            signals
                        )
                    ),

                    event=
                        event,

                    transfer_count=
                        transfer_count,

                    cumulative_bytes=
                        cumulative_bytes,
                )
            )

            detection[
                "signals"
            ] = signals

            detection[
                "detection_method"
            ] = (
                "MULTI_SIGNAL_EXFILTRATION_HEURISTIC"
            )

            detection[
                "interpretation"
            ] = (
                "The transfer pattern resembles possible "
                "data exfiltration. This heuristic does not "
                "prove that sensitive information was stolen."
            )

            detections.append(
                detection
            )

        return detections