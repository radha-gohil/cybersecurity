import time

from typing import (
    Dict,
    Tuple,
)

import psutil


from endpoint.agent.telemetry_manager import (
    shared_telemetry_manager,
)

from endpoint.utils.logger import (
    get_logger,
)


from ai_detection.behavior.process_context_tracker import (
    shared_process_behavior_context,
)


logger = get_logger(__name__)


class NetworkMonitor:

    def __init__(
        self,
        polling_interval: float = 3.0,
    ):

        self.polling_interval = (
            polling_interval
        )

        self.running = False

        self.known_connections: Dict[
            Tuple,
            dict,
        ] = {}

        self.telemetry = (
            shared_telemetry_manager
        )


    # ============================================================
    # GET PROCESS NAME
    # ============================================================

    def get_process_name(
        self,
        pid,
    ):

        if pid is None:

            return None

        try:

            process = (
                psutil.Process(
                    pid
                )
            )

            return (
                process.name()
            )

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

                "ip":
                    None,

                "port":
                    None,
            }

        try:

            return {

                "ip":
                    address.ip,

                "port":
                    address.port,
            }

        except AttributeError:

            try:

                return {

                    "ip":
                        address[0],

                    "port":
                        address[1],
                }

            except Exception:

                return {

                    "ip":
                        None,

                    "port":
                        None,
                }


    # ============================================================
    # CONNECTION KEY
    # ============================================================

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

            local.get(
                "ip"
            ),

            local.get(
                "port"
            ),

            remote.get(
                "ip"
            ),

            remote.get(
                "port"
            ),

            connection.status,
        )


    # ============================================================
    # CONNECTION INFORMATION
    # ============================================================

    def get_connection_info(
        self,
        connection,
    ) -> dict:

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

        # --------------------------------------------------------
        # PROTOCOL
        # --------------------------------------------------------

        try:

            if connection.type == 1:

                protocol = "TCP"

            elif connection.type == 2:

                protocol = "UDP"

            else:

                protocol = str(
                    connection.type
                )

        except Exception:

            protocol = "UNKNOWN"

        return {

            "pid":
                connection.pid,

            "process_name":
                process_name,

            "protocol":
                protocol,

            "local_ip":
                local.get(
                    "ip"
                ),

            "local_port":
                local.get(
                    "port"
                ),

            "remote_ip":
                remote.get(
                    "ip"
                ),

            "remote_port":
                remote.get(
                    "port"
                ),

            "status":
                connection.status,
        }


    # ============================================================
    # GET CURRENT CONNECTIONS
    # ============================================================

    def get_current_connections(
        self,
    ) -> dict:

        current_connections = {}

        try:

            connections = (
                psutil.net_connections(
                    kind="inet"
                )
            )

        except (
            psutil.AccessDenied,
            PermissionError,
        ):

            logger.warning(
                "Access denied while reading network connections."
            )

            return current_connections

        except Exception as error:

            logger.warning(
                "Unable to read network connections | %s",
                error,
            )

            return current_connections

        for connection in connections:

            # ----------------------------------------------------
            # IGNORE LISTENING SOCKETS / NO REMOTE ENDPOINT
            # ----------------------------------------------------

            if not connection.raddr:

                continue

            try:

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

            except Exception as error:

                logger.debug(
                    "Unable to normalize network connection | %s",
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

        self.known_connections = (
            self.get_current_connections()
        )

        # --------------------------------------------------------
        # SEED AI CONTEXT
        #
        # Existing network connections are useful behavioral
        # context even though they do not generate new telemetry
        # events during initialization.
        # --------------------------------------------------------

        seeded = 0

        for connection_info in (
            self.known_connections.values()
        ):

            pid = (
                connection_info.get(
                    "pid"
                )
            )

            if pid is None:

                continue

            try:

                shared_process_behavior_context.record_network_activity(

                    pid=pid,

                    remote_ip=(
                        connection_info.get(
                            "remote_ip"
                        )
                    ),
                )

                seeded += 1

            except Exception as error:

                logger.debug(
                    "Unable to seed AI network context | %s",
                    error,
                )

        logger.info(
            "Initial network snapshot complete. %s active connections found.",
            len(
                self.known_connections
            ),
        )

        logger.info(
            "AI network behavior context seeded with %s connections.",
            seeded,
        )


    # ============================================================
    # CREATE NETWORK CONNECTION EVENT
    # ============================================================

    def create_connection_event(
        self,
        connection_info: dict,
    ):

        # --------------------------------------------------------
        # UPDATE AI BEHAVIOR CONTEXT
        # --------------------------------------------------------

        try:

            shared_process_behavior_context.record_network_activity(

                pid=(
                    connection_info.get(
                        "pid"
                    )
                ),

                remote_ip=(
                    connection_info.get(
                        "remote_ip"
                    )
                ),
            )

        except Exception as error:

            # ----------------------------------------------------
            # AI CONTEXT FAILURE MUST NEVER STOP NETWORK MONITORING
            # ----------------------------------------------------

            logger.debug(
                "Unable to update AI network context | %s",
                error,
            )

        # --------------------------------------------------------
        # SECURITY EVENT
        # --------------------------------------------------------

        event = (
            self.telemetry.emit(

                event_type=
                    "network_connect",

                source=
                    "network_monitor",

                severity=
                    "INFO",

                network=
                    connection_info,

                metadata={

                    "collector":
                        "NetworkMonitor",

                    "ai_context_recorded":
                        True,
                },
            )
        )

        # --------------------------------------------------------
        # LOG
        # --------------------------------------------------------

        logger.info(

            "NETWORK CONNECT | "
            "PID=%s | "
            "Process=%s | "
            "%s:%s -> %s:%s | "
            "%s | "
            "EventID=%s",

            connection_info.get(
                "pid"
            ),

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

            event.event_id,
        )


    # ============================================================
    # CHECK CONNECTION CHANGES
    # ============================================================

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

        # --------------------------------------------------------
        # NEW CONNECTIONS
        # --------------------------------------------------------

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

                self.create_connection_event(
                    connection_info
                )

        # --------------------------------------------------------
        # UPDATE SNAPSHOT
        # --------------------------------------------------------

        self.known_connections = (
            current_connections
        )


    # ============================================================
    # START NETWORK MONITOR
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
# MANUAL RUN
# ================================================================

if __name__ == "__main__":

    monitor = NetworkMonitor(
        polling_interval=3.0
    )

    monitor.start()