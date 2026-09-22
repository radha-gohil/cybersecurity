from collections import defaultdict, deque
from datetime import datetime, timezone
from statistics import mean, pstdev
from typing import Dict, List, Optional, Tuple


class NetworkBehaviorTracker:
    """
    SENTINEL-X passive network behavior detector.

    This detector does NOT generate network traffic.

    Current detections:

        1. CONNECTION_BURST
        2. PORT_SCAN_BEHAVIOR
        3. POSSIBLE_DOS_BEHAVIOR
        4. SUSPICIOUS_BEACONING

    These are behavioral/rule-based detections.

    SUSPICIOUS_BEACONING is a heuristic signal.
    It does not prove that a process is communicating with a C2 server.
    """

    def __init__(
        self,
        connection_window_seconds: int = 10,
        connection_burst_threshold: int = 20,

        port_scan_window_seconds: int = 30,
        port_scan_threshold: int = 10,

        dos_window_seconds: int = 10,
        dos_connection_threshold: int = 30,

        beacon_min_connections: int = 5,
        beacon_history_seconds: int = 600,
        beacon_min_interval_seconds: float = 5.0,
        beacon_max_interval_seconds: float = 300.0,
        beacon_max_coefficient_variation: float = 0.15,

        alert_cooldown_seconds: int = 30,
    ):

        # ========================================================
        # CONNECTION BURST SETTINGS
        # ========================================================

        self.connection_window_seconds = (
            connection_window_seconds
        )

        self.connection_burst_threshold = (
            connection_burst_threshold
        )

        # ========================================================
        # PORT SCAN SETTINGS
        # ========================================================

        self.port_scan_window_seconds = (
            port_scan_window_seconds
        )

        self.port_scan_threshold = (
            port_scan_threshold
        )

        # ========================================================
        # POSSIBLE DOS SETTINGS
        # ========================================================

        self.dos_window_seconds = (
            dos_window_seconds
        )

        self.dos_connection_threshold = (
            dos_connection_threshold
        )

        # ========================================================
        # BEACONING SETTINGS
        # ========================================================

        self.beacon_min_connections = (
            beacon_min_connections
        )

        self.beacon_history_seconds = (
            beacon_history_seconds
        )

        self.beacon_min_interval_seconds = (
            beacon_min_interval_seconds
        )

        self.beacon_max_interval_seconds = (
            beacon_max_interval_seconds
        )

        self.beacon_max_coefficient_variation = (
            beacon_max_coefficient_variation
        )

        # ========================================================
        # ALERT COOLDOWN
        # ========================================================

        self.alert_cooldown_seconds = (
            alert_cooldown_seconds
        )

        # ========================================================
        # CONNECTION HISTORY
        #
        # key:
        #     (pid, process_name)
        #
        # value:
        #     deque[timestamp]
        # ========================================================

        self.connection_history = defaultdict(
            deque
        )

        # ========================================================
        # PORT HISTORY
        #
        # key:
        #     (pid, process_name, remote_ip)
        #
        # value:
        #     deque[(timestamp, remote_port)]
        # ========================================================

        self.port_history = defaultdict(
            deque
        )

        # ========================================================
        # TARGET CONNECTION HISTORY
        #
        # Used for possible DoS detection.
        #
        # key:
        #     (
        #         pid,
        #         process_name,
        #         remote_ip,
        #         remote_port,
        #     )
        #
        # value:
        #     deque[timestamp]
        # ========================================================

        self.target_history = defaultdict(
            deque
        )

        # ========================================================
        # BEACON HISTORY
        #
        # Same process repeatedly contacting the same destination.
        #
        # key:
        #     (
        #         pid,
        #         process_name,
        #         remote_ip,
        #         remote_port,
        #     )
        #
        # value:
        #     deque[timestamp]
        # ========================================================

        self.beacon_history = defaultdict(
            deque
        )

        # ========================================================
        # LAST ALERT TIME
        # ========================================================

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
    # HISTORY CLEANUP
    # ============================================================

    def cleanup_timestamp_history(
        self,
        history: deque,
        cutoff: float,
    ):

        while (
            history
            and history[0] < cutoff
        ):

            history.popleft()

    def cleanup_port_history(
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

        previous_time = (
            self.last_alert_time.get(
                alert_key
            )
        )

        if previous_time is None:

            self.last_alert_time[
                alert_key
            ] = current_time

            return True

        elapsed = (
            current_time
            - previous_time
        )

        if (
            elapsed
            >= self.alert_cooldown_seconds
        ):

            self.last_alert_time[
                alert_key
            ] = current_time

            return True

        return False

    # ============================================================
    # CONFIDENCE
    # ============================================================

    def calculate_confidence(
        self,
        observed: int,
        threshold: int,
    ) -> float:

        if threshold <= 0:
            return 0.0

        confidence = (
            observed
            / (
                threshold
                * 2
            )
        )

        return round(
            min(
                1.0,
                max(
                    0.0,
                    confidence,
                ),
            ),
            4,
        )

    # ============================================================
    # CONNECTION BURST
    # ============================================================

    def detect_connection_burst(
        self,
        connection: Dict,
        current_time: float,
    ) -> Optional[Dict]:

        pid = connection.get(
            "pid"
        )

        process_name = (
            connection.get(
                "process_name"
            )
            or "unknown"
        )

        key = (
            pid,
            process_name,
        )

        history = (
            self.connection_history[
                key
            ]
        )

        history.append(
            current_time
        )

        cutoff = (
            current_time
            - self.connection_window_seconds
        )

        self.cleanup_timestamp_history(
            history,
            cutoff,
        )

        connection_count = len(
            history
        )

        if (
            connection_count
            < self.connection_burst_threshold
        ):

            return None

        alert_key = (
            "CONNECTION_BURST",
            pid,
            process_name,
        )

        if not self.should_emit_alert(
            alert_key,
            current_time,
        ):

            return None

        return {
            "engine":
                "network_behavior",

            "detection_type":
                "CONNECTION_BURST",

            "severity":
                "MEDIUM",

            "risk":
                55,

            "risk_score":
                55,

            "confidence":
                self.calculate_confidence(
                    connection_count,
                    self.connection_burst_threshold,
                ),

            "reason":
                (
                    f"{connection_count} network connections "
                    f"observed from process {process_name} "
                    f"within "
                    f"{self.connection_window_seconds} seconds"
                ),

            "process_id":
                pid,

            "process_name":
                process_name,

            "remote_ip":
                connection.get(
                    "remote_ip"
                ),

            "remote_port":
                connection.get(
                    "remote_port"
                ),

            "connection_count":
                connection_count,

            "time_window_seconds":
                self.connection_window_seconds,

            "detected_at":
                self.iso_from_timestamp(
                    current_time
                ),

            "detection_method":
                "RULE_BASED_BEHAVIOR",
        }

    # ============================================================
    # PORT SCAN
    # ============================================================

    def detect_port_scan(
        self,
        connection: Dict,
        current_time: float,
    ) -> Optional[Dict]:

        pid = connection.get(
            "pid"
        )

        process_name = (
            connection.get(
                "process_name"
            )
            or "unknown"
        )

        remote_ip = connection.get(
            "remote_ip"
        )

        remote_port = connection.get(
            "remote_port"
        )

        if (
            remote_ip is None
            or remote_port is None
        ):

            return None

        key = (
            pid,
            process_name,
            remote_ip,
        )

        history = (
            self.port_history[
                key
            ]
        )

        history.append(
            (
                current_time,
                remote_port,
            )
        )

        cutoff = (
            current_time
            - self.port_scan_window_seconds
        )

        self.cleanup_port_history(
            history,
            cutoff,
        )

        unique_ports = {
            port
            for _, port
            in history
        }

        unique_port_count = len(
            unique_ports
        )

        if (
            unique_port_count
            < self.port_scan_threshold
        ):

            return None

        alert_key = (
            "PORT_SCAN_BEHAVIOR",
            pid,
            process_name,
            remote_ip,
        )

        if not self.should_emit_alert(
            alert_key,
            current_time,
        ):

            return None

        return {
            "engine":
                "network_behavior",

            "detection_type":
                "PORT_SCAN_BEHAVIOR",

            "severity":
                "HIGH",

            "risk":
                75,

            "risk_score":
                75,

            "confidence":
                self.calculate_confidence(
                    unique_port_count,
                    self.port_scan_threshold,
                ),

            "reason":
                (
                    f"{unique_port_count} unique destination ports "
                    f"were accessed on {remote_ip} within "
                    f"{self.port_scan_window_seconds} seconds"
                ),

            "process_id":
                pid,

            "process_name":
                process_name,

            "remote_ip":
                remote_ip,

            "unique_ports":
                sorted(
                    unique_ports
                ),

            "unique_port_count":
                unique_port_count,

            "time_window_seconds":
                self.port_scan_window_seconds,

            "detected_at":
                self.iso_from_timestamp(
                    current_time
                ),

            "detection_method":
                "RULE_BASED_BEHAVIOR",
        }

    # ============================================================
    # POSSIBLE DOS
    # ============================================================

    def detect_possible_dos(
        self,
        connection: Dict,
        current_time: float,
    ) -> Optional[Dict]:

        pid = connection.get(
            "pid"
        )

        process_name = (
            connection.get(
                "process_name"
            )
            or "unknown"
        )

        remote_ip = connection.get(
            "remote_ip"
        )

        remote_port = connection.get(
            "remote_port"
        )

        if remote_ip is None:
            return None

        key = (
            pid,
            process_name,
            remote_ip,
            remote_port,
        )

        history = (
            self.target_history[
                key
            ]
        )

        history.append(
            current_time
        )

        cutoff = (
            current_time
            - self.dos_window_seconds
        )

        self.cleanup_timestamp_history(
            history,
            cutoff,
        )

        connection_count = len(
            history
        )

        if (
            connection_count
            < self.dos_connection_threshold
        ):

            return None

        alert_key = (
            "POSSIBLE_DOS_BEHAVIOR",
            pid,
            process_name,
            remote_ip,
            remote_port,
        )

        if not self.should_emit_alert(
            alert_key,
            current_time,
        ):

            return None

        return {
            "engine":
                "network_behavior",

            "detection_type":
                "POSSIBLE_DOS_BEHAVIOR",

            "severity":
                "HIGH",

            "risk":
                80,

            "risk_score":
                80,

            "confidence":
                self.calculate_confidence(
                    connection_count,
                    self.dos_connection_threshold,
                ),

            "reason":
                (
                    f"{connection_count} connections targeted "
                    f"{remote_ip}:{remote_port} within "
                    f"{self.dos_window_seconds} seconds"
                ),

            "process_id":
                pid,

            "process_name":
                process_name,

            "remote_ip":
                remote_ip,

            "remote_port":
                remote_port,

            "connection_count":
                connection_count,

            "time_window_seconds":
                self.dos_window_seconds,

            "detected_at":
                self.iso_from_timestamp(
                    current_time
                ),

            "detection_method":
                "RULE_BASED_BEHAVIOR",
        }

    # ============================================================
    # SUSPICIOUS BEACONING
    # ============================================================

    def detect_suspicious_beaconing(
        self,
        connection: Dict,
        current_time: float,
    ) -> Optional[Dict]:

        pid = connection.get(
            "pid"
        )

        process_name = (
            connection.get(
                "process_name"
            )
            or "unknown"
        )

        remote_ip = connection.get(
            "remote_ip"
        )

        remote_port = connection.get(
            "remote_port"
        )

        if (
            remote_ip is None
            or remote_port is None
        ):

            return None

        key = (
            pid,
            process_name,
            remote_ip,
            remote_port,
        )

        history = (
            self.beacon_history[
                key
            ]
        )

        history.append(
            current_time
        )

        cutoff = (
            current_time
            - self.beacon_history_seconds
        )

        self.cleanup_timestamp_history(
            history,
            cutoff,
        )

        # --------------------------------------------------------
        # NEED ENOUGH CONNECTIONS
        # --------------------------------------------------------

        if (
            len(history)
            < self.beacon_min_connections
        ):

            return None

        timestamps = list(
            history
        )

        # --------------------------------------------------------
        # CALCULATE INTERVALS
        # --------------------------------------------------------

        intervals = [

            timestamps[index]
            - timestamps[index - 1]

            for index
            in range(
                1,
                len(
                    timestamps
                ),
            )
        ]

        if not intervals:
            return None

        average_interval = mean(
            intervals
        )

        # --------------------------------------------------------
        # IGNORE VERY FAST TRAFFIC
        #
        # Very fast repeated traffic is handled by burst/DoS logic.
        # --------------------------------------------------------

        if (
            average_interval
            < self.beacon_min_interval_seconds
        ):

            return None

        # --------------------------------------------------------
        # IGNORE VERY SLOW REPETITION
        # --------------------------------------------------------

        if (
            average_interval
            > self.beacon_max_interval_seconds
        ):

            return None

        # --------------------------------------------------------
        # INTERVAL VARIATION
        # --------------------------------------------------------

        if len(
            intervals
        ) > 1:

            interval_std = pstdev(
                intervals
            )

        else:

            interval_std = 0.0

        if average_interval <= 0:

            return None

        coefficient_variation = (
            interval_std
            / average_interval
        )

        # --------------------------------------------------------
        # HIGH VARIATION = NOT REGULAR ENOUGH TO LOOK LIKE BEACONING
        # --------------------------------------------------------

        if (
            coefficient_variation
            > self.beacon_max_coefficient_variation
        ):

            return None

        alert_key = (
            "SUSPICIOUS_BEACONING",
            pid,
            process_name,
            remote_ip,
            remote_port,
        )

        if not self.should_emit_alert(
            alert_key,
            current_time,
        ):

            return None

        # --------------------------------------------------------
        # BEACON CONFIDENCE
        #
        # This is a deterministic heuristic score,
        # not a calibrated probability.
        # --------------------------------------------------------

        regularity_score = (
            1.0
            - min(
                1.0,
                coefficient_variation
                / max(
                    self.beacon_max_coefficient_variation,
                    0.0001,
                ),
            )
        )

        count_score = min(
            1.0,
            len(
                history
            )
            / (
                self.beacon_min_connections
                * 2
            ),
        )

        confidence = round(
            (
                regularity_score
                * 0.7
            )
            +
            (
                count_score
                * 0.3
            ),
            4,
        )

        return {
            "engine":
                "network_behavior",

            "detection_type":
                "SUSPICIOUS_BEACONING",

            "severity":
                "HIGH",

            "risk":
                85,

            "risk_score":
                85,

            "confidence":
                confidence,

            "reason":
                (
                    f"{len(history)} connections from "
                    f"{process_name} to "
                    f"{remote_ip}:{remote_port} showed a "
                    f"regular interval of approximately "
                    f"{average_interval:.2f} seconds"
                ),

            "process_id":
                pid,

            "process_name":
                process_name,

            "remote_ip":
                remote_ip,

            "remote_port":
                remote_port,

            "connection_count":
                len(
                    history
                ),

            "average_interval_seconds":
                round(
                    average_interval,
                    4,
                ),

            "interval_std_seconds":
                round(
                    interval_std,
                    4,
                ),

            "coefficient_of_variation":
                round(
                    coefficient_variation,
                    4,
                ),

            "intervals":
                [
                    round(
                        value,
                        4,
                    )
                    for value in intervals
                ],

            "detected_at":
                self.iso_from_timestamp(
                    current_time
                ),

            "detection_method":
                "RULE_BASED_PERIODICITY_ANALYSIS",

            "interpretation":
                (
                    "Regular outbound communication pattern. "
                    "May represent legitimate polling, heartbeat "
                    "traffic, or command-and-control beaconing."
                ),
        }

    # ============================================================
    # MAIN ANALYSIS
    # ============================================================

    def analyze(
        self,
        connection: Dict,
        current_time: Optional[float] = None,
    ) -> List[Dict]:

        detections = []

        # --------------------------------------------------------
        # NORMAL RUNTIME:
        #
        # current_time=None
        #
        # TESTING:
        #
        # current_time can be supplied so synthetic timestamps
        # can be tested without waiting in real time.
        # --------------------------------------------------------

        if current_time is None:

            current_time = (
                self.now_timestamp()
            )

        # --------------------------------------------------------
        # CONNECTION BURST
        # --------------------------------------------------------

        connection_burst = (
            self.detect_connection_burst(
                connection,
                current_time,
            )
        )

        if connection_burst:

            detections.append(
                connection_burst
            )

        # --------------------------------------------------------
        # PORT SCAN
        # --------------------------------------------------------

        port_scan = (
            self.detect_port_scan(
                connection,
                current_time,
            )
        )

        if port_scan:

            detections.append(
                port_scan
            )

        # --------------------------------------------------------
        # POSSIBLE DOS
        # --------------------------------------------------------

        possible_dos = (
            self.detect_possible_dos(
                connection,
                current_time,
            )
        )

        if possible_dos:

            detections.append(
                possible_dos
            )

        # --------------------------------------------------------
        # SUSPICIOUS BEACONING
        # --------------------------------------------------------

        beaconing = (
            self.detect_suspicious_beaconing(
                connection,
                current_time,
            )
        )

        if beaconing:

            detections.append(
                beaconing
            )

        return detections