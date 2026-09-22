import time
from typing import Dict, Tuple

import psutil

from detection.network.network_behavior_tracker import (
    NetworkBehaviorTracker,
)

from endpoint.agent.telemetry_manager import (
    TelemetryManager,
)

from endpoint.storage.database import (
    save_detection,
)

from endpoint.utils.logger import (
    get_logger,
)


logger = get_logger(
    __name__
)


class NetworkMonitor:

    def __init__(
        self,
        polling_interval: float = 3.0,
    ):

        self.polling_interval = (
            polling_interval
        )

        self.running = False

        # ---------------------------------------------------------
        # KNOWN CONNECTION SNAPSHOT
        # ---------------------------------------------------------

        self.known_connections: Dict[
            Tuple,
            dict
        ] = {}

        # ---------------------------------------------------------
        # UNIFIED SENTINEL-X TELEMETRY
        # ---------------------------------------------------------

        self.telemetry = (
            TelemetryManager()
        )

        # ---------------------------------------------------------
        # NETWORK BEHAVIOR DETECTION
        # ---------------------------------------------------------

        self.behavior_tracker = (
            NetworkBehaviorTracker(

                connection_window_seconds=10,

                connection_burst_threshold=20,

                port_scan_window_seconds=30,

                port_scan_threshold=10,

                dos_window_seconds=10,

                dos_connection_threshold=30,

                alert_cooldown_seconds=30,
            )
        )

    # =============================================================
    # PROCESS NAME
    # =============================================================

    def get_process_name(
        self,
        pid,
    ):

        if pid is None:
            return None

        try:

            process = psutil.Process(
                pid
            )

            return process.name()

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):

            return None

    # =============================================================
    # NORMALIZE ADDRESS
    # =============================================================

    def normalize_address(
        self,
        address,
    ):

        if not address:

            return {
                "ip": None,
                "port": None,
            }

        try:

            return {
                "ip": address.ip,
                "port": address.port,
            }

        except AttributeError:

            try:

                return {
                    "ip": address[0],
                    "port": address[1],
                }

            except Exception:

                return {
                    "ip": None,
                    "port": None,
                }

    # =============================================================
    # CONNECTION KEY
    # =============================================================

    def make_connection_key(
        self,
        connection,
    ):

        local = (
            self.normalize_address(
                connection.laddr
            )
        )

        remote = (
            self.normalize_address(
                connection.raddr
            )
        )

        return (

            connection.pid,

            local[
                "ip"
            ],

            local[
                "port"
            ],

            remote[
                "ip"
            ],

            remote[
                "port"
            ],

            connection.type,
        )

    # =============================================================
    # CONNECTION INFORMATION
    # =============================================================

    def get_connection_info(
        self,
        connection,
    ):

        local = (
            self.normalize_address(
                connection.laddr
            )
        )

        remote = (
            self.normalize_address(
                connection.raddr
            )
        )

        process_name = (
            self.get_process_name(
                connection.pid
            )
        )

        # ---------------------------------------------------------
        # PROTOCOL
        # ---------------------------------------------------------

        if connection.type == 1:

            protocol = "TCP"

        elif connection.type == 2:

            protocol = "UDP"

        else:

            protocol = str(
                connection.type
            )

        return {

            "pid":
                connection.pid,

            "process_name":
                process_name,

            "protocol":
                protocol,

            "local_ip":
                local[
                    "ip"
                ],

            "local_port":
                local[
                    "port"
                ],

            "remote_ip":
                remote[
                    "ip"
                ],

            "remote_port":
                remote[
                    "port"
                ],

            "status":
                connection.status,
        }

    # =============================================================
    # CURRENT CONNECTIONS
    # =============================================================

    def get_current_connections(
        self,
    ):

        current_connections = {}

        try:

            connections = (
                psutil.net_connections(
                    kind="inet"
                )
            )

        except psutil.AccessDenied:

            logger.warning(
                "Access denied while reading network connections."
            )

            return current_connections

        except Exception as error:

            logger.error(
                "Failed to read network connections | %s",
                error,
            )

            return current_connections

        for connection in connections:

            # -----------------------------------------------------
            # Ignore listening sockets without a remote endpoint.
            # -----------------------------------------------------

            if not connection.raddr:
                continue

            key = (
                self.make_connection_key(
                    connection
                )
            )

            connection_info = (
                self.get_connection_info(
                    connection
                )
            )

            current_connections[
                key
            ] = connection_info

        return current_connections

    # =============================================================
    # INITIAL SNAPSHOT
    # =============================================================

    def build_initial_snapshot(
        self,
    ):

        logger.info(
            "Building initial network snapshot..."
        )

        self.known_connections = (
            self.get_current_connections()
        )

        logger.info(
            "Initial network snapshot complete. "
            "%s active connections found.",
            len(
                self.known_connections
            ),
        )

    # =============================================================
    # SEVERITY SELECTION
    # =============================================================

    def get_detection_severity(
        self,
        detections,
    ):

        severity_order = {

            "INFO":
                0,

            "LOW":
                1,

            "MEDIUM":
                2,

            "HIGH":
                3,

            "CRITICAL":
                4,
        }

        final_severity = (
            "INFO"
        )

        for detection in detections:

            detection_severity = (
                detection.get(
                    "severity",
                    "INFO",
                )
            )

            if (
                severity_order.get(
                    detection_severity,
                    0,
                )
                >
                severity_order.get(
                    final_severity,
                    0,
                )
            ):

                final_severity = (
                    detection_severity
                )

        return final_severity

    # =============================================================
    # SAVE NETWORK DETECTIONS
    # =============================================================

    def save_network_detections(
        self,
        event,
        detections,
    ):

        for detection in detections:

            try:

                save_detection(
                    event.event_id,
                    detection,
                )

                logger.warning(
                    "NETWORK DETECTION | "
                    "EventID=%s | "
                    "Type=%s | "
                    "Severity=%s | "
                    "Risk=%s | "
                    "Confidence=%s | "
                    "Reason=%s",

                    event.event_id,

                    detection.get(
                        "detection_type"
                    ),

                    detection.get(
                        "severity"
                    ),

                    detection.get(
                        "risk_score"
                    ),

                    detection.get(
                        "confidence"
                    ),

                    detection.get(
                        "reason"
                    ),
                )

            except Exception as error:

                logger.error(
                    "Failed to save network detection | "
                    "EventID=%s | "
                    "Type=%s | "
                    "%s",

                    event.event_id,

                    detection.get(
                        "detection_type"
                    ),

                    error,
                )

    # =============================================================
    # CREATE NETWORK EVENT
    # =============================================================

    def create_connection_event(
        self,
        connection_info: dict,
    ):

        # ---------------------------------------------------------
        # RUN NETWORK BEHAVIOR DETECTOR
        # ---------------------------------------------------------

        try:

            detections = (
                self.behavior_tracker.analyze(
                    connection_info
                )
            )

        except Exception as error:

            logger.error(
                "Network behavior analysis failed | %s",
                error,
            )

            detections = []

        # ---------------------------------------------------------
        # EVENT SEVERITY
        # ---------------------------------------------------------

        severity = (
            self.get_detection_severity(
                detections
            )
        )

        # ---------------------------------------------------------
        # EVENT TYPE
        # ---------------------------------------------------------

        if detections:

            event_type = (
                "network_security_detection"
            )

        else:

            event_type = (
                "network_connect"
            )

        detection_types = [

            detection.get(
                "detection_type"
            )

            for detection
            in detections
        ]

        # ---------------------------------------------------------
        # CREATE SECURITY EVENT
        #
        # TelemetryManager:
        #
        # 1. Creates SecurityEvent
        # 2. Saves raw event
        # 3. Sends event into CorrelationManager
        # ---------------------------------------------------------

        event = (
            self.telemetry.emit(

                event_type=
                    event_type,

                source=
                    "network_monitor",

                severity=
                    severity,

                network=
                    connection_info,

                metadata={

                    "collector":
                        "NetworkMonitor",

                    "behavior_analysis":
                        True,

                    "detection_count":
                        len(
                            detections
                        ),

                    "detection_types":
                        detection_types,
                },
            )
        )

        # ---------------------------------------------------------
        # SAVE DEDICATED DETECTION RECORDS
        # ---------------------------------------------------------

        if detections:

            self.save_network_detections(
                event,
                detections,
            )

        # ---------------------------------------------------------
        # LOG CONNECTION
        # ---------------------------------------------------------

        logger.info(
            "NETWORK CONNECT | "
            "%s | "
            "%s:%s -> %s:%s | "
            "%s | "
            "Severity=%s | "
            "Detections=%s",

            connection_info.get(
                "process_name"
            ),

            connection_info.get(
                "local_ip"
            ),

            connection_info.get(
                "local_port"
            ),

            connection_info.get(
                "remote_ip"
            ),

            connection_info.get(
                "remote_port"
            ),

            connection_info.get(
                "status"
            ),

            severity,

            len(
                detections
            ),
        )

        return {

            "event":
                event,

            "detections":
                detections,
        }

    # =============================================================
    # CONNECTION CHANGES
    # =============================================================

    def check_connection_changes(
        self,
    ):

        current_connections = (
            self.get_current_connections()
        )

        current_keys = set(
            current_connections.keys()
        )

        previous_keys = set(
            self.known_connections.keys()
        )

        # ---------------------------------------------------------
        # NEW CONNECTIONS
        # ---------------------------------------------------------

        new_connections = (
            current_keys
            - previous_keys
        )

        for key in new_connections:

            connection_info = (
                current_connections.get(
                    key
                )
            )

            if connection_info:

                try:

                    self.create_connection_event(
                        connection_info
                    )

                except Exception as error:

                    logger.error(
                        "Failed to process network connection | %s",
                        error,
                    )

        # ---------------------------------------------------------
        # UPDATE SNAPSHOT
        # ---------------------------------------------------------

        self.known_connections = (
            current_connections
        )

    # =============================================================
    # START
    # =============================================================

    def start(
        self,
    ):

        logger.info(
            "Starting SENTINEL-X Network Monitor..."
        )

        logger.info(
            "Network behavioral detection enabled."
        )

        logger.info(
            "Connection burst threshold: %s connections / %ss",
            self.behavior_tracker.connection_burst_threshold,
            self.behavior_tracker.connection_window_seconds,
        )

        logger.info(
            "Port scan threshold: %s ports / %ss",
            self.behavior_tracker.port_scan_threshold,
            self.behavior_tracker.port_scan_window_seconds,
        )

        logger.info(
            "Possible DoS threshold: %s connections / %ss",
            self.behavior_tracker.dos_connection_threshold,
            self.behavior_tracker.dos_window_seconds,
        )

        self.running = True

        self.build_initial_snapshot()

        try:

            while self.running:

                self.check_connection_changes()

                time.sleep(
                    self.polling_interval
                )

        except KeyboardInterrupt:

            logger.info(
                "Network monitor interrupted."
            )

        finally:

            self.stop()

    # =============================================================
    # STOP
    # =============================================================

    def stop(
        self,
    ):

        self.running = False

        logger.info(
            "SENTINEL-X Network Monitor stopped."
        )


# ================================================================
# MANUAL RUN
# ================================================================

if __name__ == "__main__":

    monitor = NetworkMonitor(
        polling_interval=3.0
    )

    monitor.start()