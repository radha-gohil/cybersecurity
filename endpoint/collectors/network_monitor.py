
import time
import socket

from typing import Dict, Tuple

import psutil

from endpoint.agent.telemetry_manager import (
    shared_telemetry_manager,
)

from endpoint.storage.database import (
    save_detection,
)

from endpoint.utils.logger import (
    get_logger,
)

from ai_detection.behavior.process_context_tracker import (
    shared_process_behavior_context,
)

from detection.network.network_behavior_tracker import (
    NetworkBehaviorTracker,
)


logger = get_logger(__name__)


# ================================================================
# SENTINEL-X NETWORK MONITOR
# ================================================================
#
# Responsibilities:
#
# 1. Collect real endpoint network connections.
# 2. Maintain stable socket identity across TCP states.
# 3. Update process behavior context.
# 4. Emit ordinary network telemetry.
# 5. Analyze real network activity.
# 6. Emit evidence-backed network alerts.
# 7. Save network detections.
#
# DETECTION MODES
#
# OFF:
#     Ordinary network monitoring only.
#
# SHADOW:
#     Analyze and log findings.
#     No network attack alerts or detection rows.
#
# EMIT:
#     Analyze activity.
#     Emit network_behavior_alert events.
#     Persist matching detections.
#
# DEFAULT: OFF
#
# Passive monitoring only.
# Does not generate network traffic.
#
# ================================================================


class NetworkMonitor:

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
        polling_interval: float = 3.0,
        network_detection_mode: str = "OFF",
    ):

        self.polling_interval = float(
            polling_interval
        )

        if self.polling_interval <= 0:
            raise ValueError(
                "polling_interval must be positive"
            )

        self.running = False

        self.known_connections: Dict[
            Tuple,
            dict,
        ] = {}

        self.telemetry = (
            shared_telemetry_manager
        )

        mode = str(
            network_detection_mode
        ).strip().upper()

        if mode not in {
            "OFF",
            "SHADOW",
            "EMIT",
        }:
            raise ValueError(
                "Invalid network_detection_mode. "
                "Use OFF, SHADOW, or EMIT."
            )

        self.network_detection_mode = mode

        # Maintain tracking history across polling cycles.

        self.network_behavior_tracker = (
            NetworkBehaviorTracker()
        )

        logger.info(
            "NetworkMonitor initialized | "
            "Polling=%.1fs | DetectionMode=%s",
            self.polling_interval,
            self.network_detection_mode,
        )

    # ============================================================
    # PROCESS NAME
    # ============================================================

    def get_process_name(
        self,
        pid,
    ):

        # Windows may return PID 0 for sockets that
        # have already lost process ownership.

        if pid is None:
            return None

        if pid == 0:
            return None

        try:

            return psutil.Process(
                pid
            ).name()

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):

            return None

    # ============================================================
    # NORMALIZE ADDRESS
    # ============================================================

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

    # ============================================================
    # STABLE CONNECTION KEY
    # ============================================================

    def make_connection_key(
        self,
        connection,
    ):
        """
        Identify an observed connection independently
        of TCP state and process attribution.

        IMPORTANT:

        Do not include connection.status.

        The same connection may transition through:

            ESTABLISHED
            CLOSE_WAIT
            LAST_ACK
            TIME_WAIT

        These transitions must not be interpreted
        as separate newly observed connections.

        Do not include PID because Windows can
        lose process ownership during teardown.

        Limitation:

        If a connection disappears between polls
        and its address/port tuple is later reused,
        snapshot polling may treat it as new.
        """

        local = self.normalize_address(
            connection.laddr
        )

        remote = self.normalize_address(
            connection.raddr
        )

        return (
            connection.type,
            local.get("ip"),
            local.get("port"),
            remote.get("ip"),
            remote.get("port"),
        )

    # ============================================================
    # CONNECTION INFORMATION
    # ============================================================

    def get_connection_info(
        self,
        connection,
    ) -> dict:

        local = self.normalize_address(
            connection.laddr
        )

        remote = self.normalize_address(
            connection.raddr
        )

        process_name = self.get_process_name(
            connection.pid
        )

        try:

            if connection.type == socket.SOCK_STREAM:
                protocol = "TCP"

            elif connection.type == socket.SOCK_DGRAM:
                protocol = "UDP"

            else:
                protocol = str(connection.type)

        except Exception:
            protocol = "UNKNOWN"

        return {
            "pid": connection.pid,
            "process_name": process_name,
            "protocol": protocol,
            "local_ip": local.get("ip"),
            "local_port": local.get("port"),
            "remote_ip": remote.get("ip"),
            "remote_port": remote.get("port"),
            "status": connection.status,
        }

    # ============================================================
    # GET CURRENT CONNECTIONS
    # ============================================================

    def get_current_connections(
        self,
    ):
        """
        Return a snapshot of visible remote connections.

        None indicates a collection failure.

        An empty dict indicates a successful snapshot
        with no qualifying remote connections.

        Distinguishing these outcomes prevents a
        temporary permissions error from clearing
        known connections.
        """

        current_connections = {}

        try:

            connections = psutil.net_connections(
                kind="inet"
            )

        except (
            psutil.AccessDenied,
            PermissionError,
        ):

            logger.warning(
                "Access denied while reading "
                "network connections."
            )

            return None

        except Exception as error:

            logger.warning(
                "Unable to read network connections | %s",
                error,
            )

            return None

        for connection in connections:

            # Skip sockets without remote endpoints.

            if not connection.raddr:
                continue

            try:

                key = self.make_connection_key(
                    connection
                )

                info = self.get_connection_info(
                    connection
                )

                current_connections[key] = info

            except Exception as error:

                logger.debug(
                    "Connection normalization failed | %s",
                    error,
                )

        return current_connections

    # ============================================================
    # INITIAL SNAPSHOT
    # ============================================================

    def build_initial_snapshot(
        self,
    ):

        logger.info(
            "Building initial network snapshot..."
        )

        snapshot = self.get_current_connections()

        if snapshot is None:

            logger.warning(
                "Initial network snapshot unavailable. "
                "Will retry on the next polling cycle."
            )

            self.known_connections = {}

            return

        self.known_connections = snapshot

        seeded = 0

        for connection_info in (
            self.known_connections.values()
        ):

            pid = connection_info.get("pid")

            # Avoid attributing unknown socket ownership
            # to the Windows idle process.

            if pid is None or pid == 0:
                continue

            try:

                shared_process_behavior_context.record_network_activity(
                    pid=attributed_pid,
                    remote_ip=connection_info.get(
                        "remote_ip"
                    ),
                )

                seeded += 1

            except Exception as error:

                logger.debug(
                    "Unable to seed network AI context | %s",
                    error,
                )

        logger.info(
            "Initial network snapshot complete | "
            "Connections=%s | ContextSeeded=%s",
            len(self.known_connections),
            seeded,
        )

    # ============================================================
    # PERSIST NETWORK DETECTION
    # ============================================================

    def persist_network_detection(
        self,
        event_id: str,
        finding: dict,
    ) -> bool:
        """
        Persist a network finding using the existing
        SENTINEL-X detection storage contract.
        """

        detection_type = str(
            finding.get(
                "detection_type",
                "UNKNOWN_NETWORK_BEHAVIOR",
            )
        )

        severity = str(
            finding.get(
                "severity",
                "MEDIUM",
            )
        ).upper()

        risk_score = finding.get(
            "risk_score",
            finding.get("risk", 0),
        )

        confidence = finding.get(
            "confidence",
            0.0,
        )

        # Preserve original finding evidence.
        # Existing database normalization selects
        # the supported persistence fields.

        detection = dict(finding)

        detection.update({
            "engine": "network_behavior",
            "detected": True,
            "detection_type": detection_type,
            "threat_type": detection_type,
            "severity": severity,
            "risk": risk_score,
            "risk_score": risk_score,
            "confidence": confidence,
            "reason": finding.get(
                "reason",
                "Observed unusual network behavior.",
            ),
        })

        try:

            save_detection(
                event_id,
                detection,
            )

            logger.info(
                "NETWORK DETECTION SAVED | "
                "EventID=%s | Type=%s | Risk=%s",
                event_id,
                detection_type,
                risk_score,
            )

            return True

        except Exception:

            logger.exception(
                "Unable to save network detection | "
                "EventID=%s | Type=%s",
                event_id,
                detection_type,
            )

            return False

    # ============================================================
    # NETWORK BEHAVIOR ANALYSIS
    # ============================================================

    def analyze_network_connection(
        self,
        connection_info: dict,
        source_event_id=None,
    ) -> list[dict]:

        # --------------------------------------------------------
        # OFF MODE
        # --------------------------------------------------------

        if self.network_detection_mode == "OFF":
            return []

        if not isinstance(
            connection_info,
            dict,
        ):
            return []

        if not connection_info.get("remote_ip"):
            return []

        # --------------------------------------------------------
        # EXCLUDE CLOSING TCP CONNECTIONS
        # --------------------------------------------------------
        #
        # State transitions must not inflate the
        # behavioral tracker's connection counts.
        #
        # These sockets remain available to ordinary
        # network telemetry.
        # --------------------------------------------------------

        status = str(
            connection_info.get("status") or ""
        ).upper()

        closing_states = {
            "TIME_WAIT",
            "CLOSE_WAIT",
            "LAST_ACK",
            "FIN_WAIT1",
            "FIN_WAIT2",
            "CLOSING",
            "CLOSED",
        }

        if status in closing_states:
            return []

        # --------------------------------------------------------
        # REQUIRE RELIABLE PROCESS ATTRIBUTION
        # --------------------------------------------------------

        pid = connection_info.get("pid")

        # Missing, zero, negative, or malformed process ownership
        # cannot support process-attributed behavioral detections.
        try:
            attributed_pid = int(pid)
        except (TypeError, ValueError, OverflowError):
            return []
        if attributed_pid <= 0 or isinstance(pid, bool):
            return []

        # --------------------------------------------------------
        # BEHAVIOR TRACKER
        # --------------------------------------------------------

        try:

            findings = (
                self.network_behavior_tracker.analyze(
                    connection=connection_info,
                )
            )

        except Exception:

            logger.exception(
                "Network behavior analysis failed | PID=%s",
                pid,
            )

            return []

        if not findings:
            return []

        for finding in findings:

            if not isinstance(finding, dict):
                continue

            detection_type = str(
                finding.get(
                    "detection_type",
                    "UNKNOWN_NETWORK_BEHAVIOR",
                )
            )

            severity = str(
                finding.get(
                    "severity",
                    "MEDIUM",
                )
            ).upper()

            if severity not in {
                "INFO",
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL",
            }:
                severity = "MEDIUM"

            logger.warning(
                "NETWORK FINDING | "
                "Mode=%s | "
                "Type=%s | "
                "PID=%s | "
                "Process=%s | "
                "Risk=%s | "
                "Reason=%s",
                self.network_detection_mode,
                detection_type,
                pid,
                connection_info.get(
                    "process_name"
                ),
                finding.get("risk_score"),
                finding.get("reason"),
            )

            # ----------------------------------------------------
            # SHADOW MODE
            # ----------------------------------------------------
            #
            # Log only.
            #
            # Do not create attack events.
            # Do not save dedicated detection rows.
            # ----------------------------------------------------

            if self.network_detection_mode != "EMIT":
                continue

            # ----------------------------------------------------
            # EMIT MODE
            # ----------------------------------------------------

            try:

                network_evidence = dict(
                    connection_info
                )

                network_evidence.update({
                    "detection_type": detection_type,
                    "detection_engine": (
                        "network_behavior"
                    ),
                })

                metadata = {
                    "collector": "NetworkMonitor",
                    "detection_engine": (
                        "network_behavior"
                    ),
                    "detection_type": detection_type,
                    "detection_method": finding.get(
                        "detection_method"
                    ),
                    "risk_score": finding.get(
                        "risk_score"
                    ),
                    "confidence": finding.get(
                        "confidence"
                    ),
                    "reason": finding.get(
                        "reason"
                    ),
                    "source_event_id": source_event_id,
                    "network_detection": dict(
                        finding
                    ),
                    "simulation_mode": False,
                }

                # The existing TelemetryManager handles
                # persistence, provenance and correlation.

                alert_event = self.telemetry.emit(
                    event_type=(
                        "network_behavior_alert"
                    ),
                    source=(
                        "network_behavior_tracker"
                    ),
                    severity=severity,
                    network=network_evidence,
                    metadata=metadata,
                )

            except Exception:

                logger.exception(
                    "Failed to emit network alert | "
                    "Type=%s | SourceEvent=%s",
                    detection_type,
                    source_event_id,
                )

                continue

            # ----------------------------------------------------
            # SAVE DETECTION
            # ----------------------------------------------------
            #
            # The detection must reference the ALERT
            # event ID rather than the original
            # informational network_connect event ID.
            # ----------------------------------------------------

            saved = self.persist_network_detection(
                event_id=alert_event.event_id,
                finding=finding,
            )

            logger.warning(
                "NETWORK ALERT | "
                "EventID=%s | "
                "Type=%s | "
                "Severity=%s | "
                "DetectionSaved=%s",
                alert_event.event_id,
                detection_type,
                severity,
                saved,
            )

        return findings

    # ============================================================
    # CREATE CONNECTION EVENT
    # ============================================================

    def create_connection_event(
        self,
        connection_info: dict,
    ):
        """
        Emit the existing informational network event
        and update the process AI context.

        Attack detection is an additional stage.
        """

        # --------------------------------------------------------
        # UPDATE PROCESS AI CONTEXT
        # --------------------------------------------------------

        context_recorded = False

        pid = connection_info.get("pid")

        try:
            attributed_pid = int(pid)
        except (TypeError, ValueError, OverflowError):
            attributed_pid = 0

        if attributed_pid > 0 and not isinstance(pid, bool):

            try:

                shared_process_behavior_context.record_network_activity(
                    pid=pid,
                    remote_ip=connection_info.get(
                        "remote_ip"
                    ),
                )

                context_recorded = True

            except Exception as error:

                logger.debug(
                    "AI network context update failed | %s",
                    error,
                )

        # --------------------------------------------------------
        # ORIGINAL NETWORK TELEMETRY
        # --------------------------------------------------------

        event = self.telemetry.emit(
            event_type="network_connect",
            source="network_monitor",
            severity="INFO",
            network=connection_info,
            metadata={
                "collector": "NetworkMonitor",
                "ai_context_recorded": (
                    context_recorded
                ),
            },
        )

        logger.info(
            "NETWORK CONNECT | "
            "PID=%s | "
            "Process=%s | "
            "%s:%s -> %s:%s | "
            "%s | "
            "EventID=%s",
            connection_info.get("pid"),
            connection_info.get("process_name"),
            connection_info.get("local_ip"),
            connection_info.get("local_port"),
            connection_info.get("remote_ip"),
            connection_info.get("remote_port"),
            connection_info.get("status"),
            event.event_id,
        )

        # --------------------------------------------------------
        # OPTIONAL ATTACK DETECTION
        # --------------------------------------------------------

        if self.network_detection_mode != "OFF":

            self.analyze_network_connection(
                connection_info=connection_info,
                source_event_id=event.event_id,
            )

        return event

    # ============================================================
    # CHECK CONNECTION CHANGES
    # ============================================================

    def check_connection_changes(
        self,
    ):
        """
        Compare stable connection identities.

        TCP state transitions will no longer create
        additional new-connection events.

        Preserve the previous snapshot if Windows
        connection enumeration fails.
        """

        current_connections = (
            self.get_current_connections()
        )

        if current_connections is None:

            logger.warning(
                "Network snapshot unavailable. "
                "Keeping previous connection state."
            )

            return

        current_keys = set(
            current_connections.keys()
        )

        previous_keys = set(
            self.known_connections.keys()
        )

        new_connections = (
            current_keys - previous_keys
        )

        # Keep a deterministic processing order.
        # Avoid sorting heterogeneous tuple elements
        # that may include None.

        for key in new_connections:

            connection_info = (
                current_connections.get(key)
            )

            if connection_info:

                self.create_connection_event(
                    connection_info
                )

        self.known_connections = (
            current_connections
        )

    # ============================================================
    # START
    # ============================================================

    def start(
        self,
    ):

        logger.info(
            "Starting SENTINEL-X Network Monitor..."
        )

        logger.info(
            "Polling interval: %.1f seconds",
            self.polling_interval,
        )

        logger.info(
            "Detection mode: %s",
            self.network_detection_mode,
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

    # ============================================================
    # STOP
    # ============================================================

    def stop(
        self,
    ):

        self.running = False

        logger.info(
            "SENTINEL-X Network Monitor stopped."
        )


# ================================================================
# MANUAL EXECUTION
# ================================================================

if __name__ == "__main__":

    monitor = NetworkMonitor(
        polling_interval=3.0,
        network_detection_mode="OFF",
    )

    monitor.start()
