from collections import defaultdict, deque
from statistics import median
from typing import Dict, List, Optional


class GenericBehaviorAnomalyDetector:
    """
    SENTINEL-X Generic Behavior Anomaly Detector.

    Metadata-only anomaly detection.

    This detector DOES NOT:

        - generate network traffic
        - open connections
        - read private files
        - execute processes
        - contact external systems

    It analyzes supplied behavioral metrics such as:

        - bytes_sent
        - connection_count
        - destination_count

    Signals:

        1. UNUSUAL_TRANSFER_VOLUME
        2. UNUSUAL_CONNECTION_COUNT
        3. UNUSUAL_DESTINATION_COUNT
        4. UNKNOWN_BEHAVIOR_ANOMALY
    """

    def __init__(
        self,
        history_size: int = 30,
        min_history: int = 5,
        anomaly_z_threshold: float = 3.0,
        combined_score_threshold: int = 60,
    ):

        self.history_size = history_size
        self.min_history = min_history
        self.anomaly_z_threshold = anomaly_z_threshold
        self.combined_score_threshold = (
            combined_score_threshold
        )

        # ========================================================
        # HISTORIES
        #
        # Stored separately for each behavioral entity.
        # ========================================================

        self.history = defaultdict(
            lambda: {
                "bytes_sent": deque(
                    maxlen=self.history_size
                ),
                "connection_count": deque(
                    maxlen=self.history_size
                ),
                "destination_count": deque(
                    maxlen=self.history_size
                ),
            }
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

        return str(value).strip()

    def safe_float(
        self,
        value,
        default=0.0,
    ) -> float:

        try:
            if value is None:
                return default

            return float(value)

        except (
            TypeError,
            ValueError,
        ):
            return default

    # ============================================================
    # ENTITY KEY
    # ============================================================

    def build_entity_key(
        self,
        event: Dict,
    ) -> str:

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
            ).lower()
            or "unknown-process"
        )

        return (
            f"{device_id}::{process_name}"
        )

    # ============================================================
    # ROBUST DEVIATION SCORE
    #
    # Uses median and Median Absolute Deviation (MAD).
    #
    # More robust than mean/std when a few large outliers exist.
    # ============================================================

    def calculate_robust_z_score(
        self,
        value: float,
        historical_values,
    ) -> float:

        values = list(
            historical_values
        )

        if len(values) < self.min_history:
            return 0.0

        baseline_median = median(
            values
        )

        deviations = [
            abs(
                historical_value
                - baseline_median
            )
            for historical_value
            in values
        ]

        mad = median(
            deviations
        )

        # --------------------------------------------------------
        # Perfectly stable baseline.
        #
        # If current value is unchanged -> 0 anomaly.
        # If it changes meaningfully -> return threshold+1.
        # --------------------------------------------------------

        if mad == 0:

            if value == baseline_median:
                return 0.0

            return (
                self.anomaly_z_threshold
                + 1.0
            )

        robust_z = (
            0.6745
            * (
                value
                - baseline_median
            )
            / mad
        )

        return abs(
            robust_z
        )

    # ============================================================
    # DETECTION BUILDER
    # ============================================================

    def build_detection(
        self,
        detection_type: str,
        severity: str,
        risk_score: int,
        metric_name: str,
        metric_value: float,
        z_score: float,
        event: Dict,
        reason: str,
    ) -> Dict:

        return {

            "engine":
                "generic_behavior_anomaly",

            "detection_type":
                detection_type,

            "severity":
                severity,

            "risk":
                risk_score,

            "risk_score":
                risk_score,

            # Heuristic confidence score.
            # NOT a calibrated probability.
            "confidence":
                round(
                    risk_score
                    / 100.0,
                    4,
                ),

            "metric_name":
                metric_name,

            "metric_value":
                metric_value,

            "z_score":
                round(
                    z_score,
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

            "reason":
                reason,

            "detection_method":
                "ROBUST_BEHAVIOR_BASELINE",
        }

    # ============================================================
    # UPDATE BASELINE
    # ============================================================

    def update_history(
        self,
        entity_key: str,
        metrics: Dict,
    ):

        entity_history = (
            self.history[
                entity_key
            ]
        )

        for (
            metric_name,
            metric_value,
        ) in metrics.items():

            entity_history[
                metric_name
            ].append(
                metric_value
            )

    # ============================================================
    # ANALYZE
    # ============================================================

    def analyze(
        self,
        event: Dict,
    ) -> List[Dict]:

        detections = []

        entity_key = (
            self.build_entity_key(
                event
            )
        )

        metrics = {

            "bytes_sent":
                self.safe_float(
                    event.get(
                        "bytes_sent"
                    )
                ),

            "connection_count":
                self.safe_float(
                    event.get(
                        "connection_count"
                    )
                ),

            "destination_count":
                self.safe_float(
                    event.get(
                        "destination_count"
                    )
                ),
        }

        entity_history = (
            self.history[
                entity_key
            ]
        )

        # ========================================================
        # BASELINE NOT READY
        # ========================================================

        baseline_ready = all(

            len(
                entity_history[
                    metric_name
                ]
            )
            >= self.min_history

            for metric_name
            in metrics
        )

        if not baseline_ready:

            self.update_history(
                entity_key,
                metrics,
            )

            return detections

        # ========================================================
        # CALCULATE ROBUST Z SCORES
        # ========================================================

        z_scores = {}

        for (
            metric_name,
            metric_value,
        ) in metrics.items():

            z_scores[
                metric_name
            ] = (
                self.calculate_robust_z_score(

                    metric_value,

                    entity_history[
                        metric_name
                    ],
                )
            )

        # ========================================================
        # SIGNAL 1 — TRANSFER VOLUME
        # ========================================================

        unusual_transfer = (

            z_scores[
                "bytes_sent"
            ]
            >=
            self.anomaly_z_threshold
        )

        if unusual_transfer:

            detections.append(

                self.build_detection(

                    detection_type=
                        "UNUSUAL_TRANSFER_VOLUME",

                    severity=
                        "HIGH",

                    risk_score=
                        70,

                    metric_name=
                        "bytes_sent",

                    metric_value=
                        metrics[
                            "bytes_sent"
                        ],

                    z_score=
                        z_scores[
                            "bytes_sent"
                        ],

                    event=
                        event,

                    reason=(
                        "Outbound transfer volume "
                        "deviated strongly from the "
                        "learned behavioral baseline"
                    ),
                )
            )

        # ========================================================
        # SIGNAL 2 — CONNECTION COUNT
        # ========================================================

        unusual_connections = (

            z_scores[
                "connection_count"
            ]
            >=
            self.anomaly_z_threshold
        )

        if unusual_connections:

            detections.append(

                self.build_detection(

                    detection_type=
                        "UNUSUAL_CONNECTION_COUNT",

                    severity=
                        "HIGH",

                    risk_score=
                        65,

                    metric_name=
                        "connection_count",

                    metric_value=
                        metrics[
                            "connection_count"
                        ],

                    z_score=
                        z_scores[
                            "connection_count"
                        ],

                    event=
                        event,

                    reason=(
                        "Connection count deviated "
                        "strongly from the learned "
                        "behavioral baseline"
                    ),
                )
            )

        # ========================================================
        # SIGNAL 3 — DESTINATION COUNT
        # ========================================================

        unusual_destinations = (

            z_scores[
                "destination_count"
            ]
            >=
            self.anomaly_z_threshold
        )

        if unusual_destinations:

            detections.append(

                self.build_detection(

                    detection_type=
                        "UNUSUAL_DESTINATION_COUNT",

                    severity=
                        "HIGH",

                    risk_score=
                        65,

                    metric_name=
                        "destination_count",

                    metric_value=
                        metrics[
                            "destination_count"
                        ],

                    z_score=
                        z_scores[
                            "destination_count"
                        ],

                    event=
                        event,

                    reason=(
                        "Destination count deviated "
                        "strongly from the learned "
                        "behavioral baseline"
                    ),
                )
            )

        # ========================================================
        # COMBINED SCORE
        # ========================================================

        score = 0

        signals = []

        if unusual_transfer:

            score += 35

            signals.append(
                "UNUSUAL_TRANSFER_VOLUME"
            )

        if unusual_connections:

            score += 30

            signals.append(
                "UNUSUAL_CONNECTION_COUNT"
            )

        if unusual_destinations:

            score += 30

            signals.append(
                "UNUSUAL_DESTINATION_COUNT"
            )

        score = min(
            score,
            100,
        )

        # ========================================================
        # UNKNOWN BEHAVIOR ANOMALY
        # ========================================================

        if (
            score
            >=
            self.combined_score_threshold
        ):

            severity = (

                "CRITICAL"

                if score >= 90

                else "HIGH"
            )

            detection = {

                "engine":
                    "generic_behavior_anomaly",

                "detection_type":
                    "UNKNOWN_BEHAVIOR_ANOMALY",

                "severity":
                    severity,

                "risk":
                    score,

                "risk_score":
                    score,

                "confidence":
                    round(
                        score
                        / 100.0,
                        4,
                    ),

                "signals":
                    signals,

                "z_scores":
                    {
                        key:
                            round(
                                value,
                                4,
                            )
                        for (
                            key,
                            value,
                        )
                        in z_scores.items()
                    },

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

                "reason":
                    (
                        "Behavior deviated from the "
                        "learned baseline across multiple "
                        "independent metrics: "
                        + ", ".join(
                            signals
                        )
                    ),

                "detection_method":
                    "MULTI_METRIC_ROBUST_ANOMALY_HEURISTIC",

                "interpretation":
                    (
                        "The activity is statistically unusual "
                        "relative to this entity's recent "
                        "baseline. This does not prove malicious "
                        "behavior."
                    ),
            }

            detections.append(
                detection
            )

        # ========================================================
        # BASELINE PROTECTION
        #
        # Do not immediately learn highly anomalous samples.
        #
        # This prevents one detected anomaly from quickly
        # becoming part of the normal baseline.
        # ========================================================

        if not detections:

            self.update_history(
                entity_key,
                metrics,
            )

        return detections