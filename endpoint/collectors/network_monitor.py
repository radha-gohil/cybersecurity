import time
from typing import Dict, Tuple

import psutil

from endpoint.agent.telemetry_manager import TelemetryManager
from endpoint.utils.logger import get_logger


logger = get_logger(__name__)


class NetworkMonitor:

    def __init__(
        self,
        polling_interval: float = 3.0,
    ):

        self.polling_interval = polling_interval

        self.running = False

        self.known_connections: Dict[
            Tuple,
            dict
        ] = {}

        # Unified telemetry manager
        self.telemetry = TelemetryManager()


    # ============================================================
    # GET PROCESS NAME FROM PID
    # ============================================================

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


    # ============================================================
    # NORMALIZE NETWORK ADDRESS
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
    # CREATE CONNECTION KEY
    # ============================================================

    def make_connection_key(
        self,
        connection,
    ):

        local = self.normalize_address(
            connection.laddr
        )

        remote = self.normalize_address(
            connection.raddr
        )

        return (
            connection.pid,
            local["ip"],
            local["port"],
            remote["ip"],
            remote["port"],
            connection.type,
        )


    # ============================================================
    # GET CONNECTION INFORMATION
    # ============================================================

    def get_connection_info(
        self,
        connection,
    ):

        local = self.normalize_address(
            connection.laddr
        )

        remote = self.normalize_address(
            connection.raddr
        )

        process_name = (
            self.get_process_name(
                connection.pid
            )
        )


        # --------------------------------------------------------
        # PROTOCOL
        # --------------------------------------------------------

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
                local["ip"],

            "local_port":
                local["port"],

            "remote_ip":
                remote["ip"],

            "remote_port":
                remote["port"],

            "status":
                connection.status,
        }


    # ============================================================
    # GET CURRENT CONNECTIONS
    # ============================================================

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


        for connection in connections:

            # Ignore listening sockets with no remote endpoint
            # for this first prototype.
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


        logger.info(
            "Initial network snapshot complete. %s active connections found.",
            len(
                self.known_connections
            ),
        )


    # ============================================================
    # CREATE NETWORK CONNECT EVENT
    # ============================================================

    def create_connection_event(
        self,
        connection_info: dict,
    ):

        self.telemetry.emit(

            event_type="network_connect",

            source="network_monitor",

            severity="INFO",

            network=connection_info,

            metadata={
                "collector":
                    "NetworkMonitor"
            },
        )


        logger.info(
            "NETWORK CONNECT | %s | %s:%s -> %s:%s | %s",
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
    # STOP NETWORK MONITOR
    # ============================================================

    def stop(
        self,
    ):

        self.running = False

        logger.info(
            "SENTINEL-X Network Monitor stopped."
        )


# ============================================================
# MANUAL TEST
# ============================================================

if __name__ == "__main__":

    monitor = NetworkMonitor(
        polling_interval=3.0
    )

    monitor.start()