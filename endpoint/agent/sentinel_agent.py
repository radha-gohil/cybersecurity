import threading
import time

from endpoint.collectors.process_monitor import (
    ProcessMonitor,
)

from endpoint.collectors.file_monitor import (
    FileMonitor,
)

from endpoint.collectors.network_monitor import (
    NetworkMonitor,
)

from endpoint.collectors.registry_monitor import (
    RegistryMonitor,
)

from endpoint.utils.logger import (
    get_logger,
)


logger = get_logger(__name__)


class SentinelAgent:

    def __init__(self):

        # ========================================================
        # COLLECTORS
        # ========================================================

        self.process_monitor = (
            ProcessMonitor(
                poll_interval=2.0,
            )
        )

        self.file_monitor = (
            FileMonitor()
        )

        self.network_monitor = (
            NetworkMonitor()
        )

        self.registry_monitor = (
            RegistryMonitor()
        )


        # ========================================================
        # THREAD STORAGE
        # ========================================================

        self.threads = []

        self.running = False


    # ============================================================
    # SAFE COLLECTOR RUNNER
    # ============================================================

    def run_collector(
        self,
        collector_name: str,
        collector,
    ):

        logger.info(
            "Starting collector thread | %s",
            collector_name,
        )


        try:

            collector.start()


        except Exception as error:

            logger.exception(
                "Collector failed | %s | %s",
                collector_name,
                error,
            )


        finally:

            logger.info(
                "Collector thread stopped | %s",
                collector_name,
            )


    # ============================================================
    # CREATE THREAD
    # ============================================================

    def create_thread(
        self,
        collector_name: str,
        collector,
    ):

        thread = threading.Thread(

            target=self.run_collector,

            args=(
                collector_name,
                collector,
            ),

            name=collector_name,

            daemon=True,
        )


        self.threads.append(
            thread
        )


        return thread


    # ============================================================
    # START ALL COLLECTORS
    # ============================================================

    def start_collectors(
        self,
    ):

        self.create_thread(
            "ProcessMonitor",
            self.process_monitor,
        )

        self.create_thread(
            "FileMonitor",
            self.file_monitor,
        )

        self.create_thread(
            "NetworkMonitor",
            self.network_monitor,
        )

        self.create_thread(
            "RegistryMonitor",
            self.registry_monitor,
        )


        for thread in self.threads:

            thread.start()


    # ============================================================
    # PRINT AGENT STATUS
    # ============================================================

    def print_status(
        self,
    ):

        logger.info(
            "=" * 70
        )

        logger.info(
            "SENTINEL-X ENDPOINT AGENT"
        )

        logger.info(
            "=" * 70
        )

        logger.info(
            "Process monitoring : ENABLED"
        )

        logger.info(
            "File monitoring    : ENABLED"
        )

        logger.info(
            "Network monitoring : ENABLED"
        )

        logger.info(
            "Registry monitoring: ENABLED"
        )

        logger.info(
            "Event correlation  : ENABLED"
        )

        logger.info(
            "Incident creation  : ENABLED"
        )

        logger.info(
            "=" * 70
        )


    # ============================================================
    # START SENTINEL-X
    # ============================================================

    def start(
        self,
    ):

        if self.running:

            logger.warning(
                "SENTINEL-X Agent is already running."
            )

            return


        logger.info(
            "Starting SENTINEL-X Endpoint Agent..."
        )


        self.running = True


        self.print_status()


        # --------------------------------------------------------
        # START COLLECTORS
        # --------------------------------------------------------

        self.start_collectors()


        logger.info(
            "All SENTINEL-X collectors started."
        )


        logger.info(
            "Press CTRL+C to stop SENTINEL-X."
        )


        try:

            while self.running:

                time.sleep(
                    1
                )


        except KeyboardInterrupt:

            logger.info(
                "Shutdown requested."
            )


        finally:

            self.stop()


    # ============================================================
    # SAFE STOP HELPER
    # ============================================================

    def stop_collector(
        self,
        collector_name: str,
        collector,
    ):

        try:

            stop_method = getattr(
                collector,
                "stop",
                None,
            )


            if callable(
                stop_method
            ):

                stop_method()


                logger.info(
                    "Collector stopped | %s",
                    collector_name,
                )


        except Exception as error:

            logger.warning(
                "Unable to stop collector cleanly | "
                "%s | %s",

                collector_name,

                error,
            )


    # ============================================================
    # STOP SENTINEL-X
    # ============================================================

    def stop(
        self,
    ):

        if not self.running:

            return


        logger.info(
            "Stopping SENTINEL-X Endpoint Agent..."
        )


        self.running = False


        # --------------------------------------------------------
        # STOP EACH COLLECTOR
        # --------------------------------------------------------

        self.stop_collector(
            "ProcessMonitor",
            self.process_monitor,
        )

        self.stop_collector(
            "FileMonitor",
            self.file_monitor,
        )

        self.stop_collector(
            "NetworkMonitor",
            self.network_monitor,
        )

        self.stop_collector(
            "RegistryMonitor",
            self.registry_monitor,
        )


        # --------------------------------------------------------
        # WAIT BRIEFLY FOR THREADS
        # --------------------------------------------------------

        for thread in self.threads:

            if thread.is_alive():

                thread.join(
                    timeout=5
                )


        logger.info(
            "=" * 70
        )

        logger.info(
            "SENTINEL-X Endpoint Agent stopped."
        )

        logger.info(
            "=" * 70
        )


# ================================================================
# MANUAL RUN
# ================================================================

if __name__ == "__main__":

    agent = SentinelAgent()

    agent.start()