import threading
import time

from config import (
    IS_VALIDATION_MODE,
)


# ================================================================
# SENTINEL-X PROCESS SECURITY RUNTIME
#
# Fusion v3 is now the PRIMARY process-level decision engine.
#
# Runtime:
#
#   Rule Detector
#       +
#   Statistical Detector
#       +
#   Isolation Forest
#       +
#   Autoencoder
#       +
#   Temporal Transformer v2
#       ↓
#   Fusion v3 PRIMARY
#
# Fusion v2 is still retained internally as:
#
#       rollback / reference engine
#
# ================================================================

from endpoint.collectors.graph_ai_process_monitor import (
    GraphAIProcessMonitor,
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

from endpoint.collectors.windows_auth_collector import (
    WindowsAuthCollector,
)

from endpoint.runtime.collector_heartbeat import (
    initialize_heartbeat_table,
    update_collector_heartbeat,
    mark_collector_offline,
)

from endpoint.utils.logger import (
    get_logger,
)


logger = get_logger(
    __name__
)


# ================================================================
# SENTINEL-X ENDPOINT AGENT
# ================================================================


class SentinelAgent:

    HEARTBEAT_INTERVAL_SECONDS = 5.0


    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
    ):

        # ========================================================
        # PROCESS SECURITY MONITOR
        #
        # Primary runtime:
        #
        #       Fusion V3
        #
        # Supporting engines:
        #
        #       Rules
        #       Statistical anomaly detection
        #       Isolation Forest
        #       Autoencoder
        #       Temporal Transformer v2
        #
        # Rollback:
        #
        #       Fusion V2
        # ========================================================

        self.process_monitor = (
            GraphAIProcessMonitor(
                poll_interval=2.0,
            )
        )


        # ========================================================
        # FILE MONITOR
        # ========================================================

        self.file_monitor = (
            FileMonitor(
                malware_detection_enabled=False,
                ransomware_detection_mode="SHADOW",
                file_detection_mode="SHADOW",
            )
        )


        # ========================================================
        # NETWORK MONITOR
        # ========================================================

        self.network_monitor = (
            NetworkMonitor(
                polling_interval=3.0,
                network_detection_mode="SHADOW",
            )
        )


        # ========================================================
        # REGISTRY MONITOR
        # ========================================================

        self.registry_monitor = (
            RegistryMonitor(
                registry_detection_mode="SHADOW",
            )
        )


        # ========================================================
        # WINDOWS AUTHENTICATION COLLECTOR
        # ========================================================

        self.auth_monitor = (
            WindowsAuthCollector(
                poll_interval=5.0,
                max_events_per_poll=50,
                auth_detection_mode="SHADOW",
            )
        )


        # ========================================================
        # COLLECTOR REGISTRY
        # ========================================================

        self.collectors = {

            "process":
                self.process_monitor,

            "file":
                self.file_monitor,

            "network":
                self.network_monitor,

            "registry":
                self.registry_monitor,

            "auth":
                self.auth_monitor,
        }

        logger.info(
            "SentinelAgent runtime mode | Validation=%s | "
            "CollectorPolicy=%s",
            IS_VALIDATION_MODE,
            (
                "LIVE_MONITOR_ONLY"
                if IS_VALIDATION_MODE
                else "FULL_PIPELINE"
            ),
        )


        # ========================================================
        # THREAD STORAGE
        # ========================================================

        self.threads = []


        self.collector_threads = {}


        self.heartbeat_thread = None


        self.running = False


        # ========================================================
        # HEARTBEAT DATABASE
        # ========================================================

        initialize_heartbeat_table()


        # ========================================================
        # VERIFY SECURITY RUNTIME
        #
        # Fail immediately if the wrong:
        #
        #       Fusion version
        #       Temporal model
        #       Temporal calibration
        #       Feature schema
        #
        # is loaded.
        # ========================================================

        if IS_VALIDATION_MODE:

            logger.info(
                "HYBRID VALIDATION: strict process security "
                "runtime verification is skipped for the live-only "
                "collector path."
            )

            logger.info(
                "Real process activity will be collected for "
                "Live Monitor only; ProcessMonitor validation guards "
                "prevent the real endpoint from entering the "
                "detection/AI/fusion pipeline."
            )

        else:

            self.verify_process_security_runtime()


    # ============================================================
    # VERIFY PROCESS SECURITY RUNTIME
    # ============================================================

    def verify_process_security_runtime(
        self,
    ):

        status = (
            self.process_monitor
            .get_primary_fusion_status()
        )


        if not isinstance(
            status,
            dict,
        ):

            raise RuntimeError(

                "Primary Fusion runtime returned "
                "an invalid status."
            )


        # ========================================================
        # PRIMARY ENGINE
        # ========================================================

        primary_engine = (
            status.get(
                "primary_engine"
            )
        )


        if (

            primary_engine

            != "process_threat_fusion_v3"

        ):

            raise RuntimeError(

                "Expected Fusion v3 as primary engine. "
                f"Received: {primary_engine}"
            )


        # ========================================================
        # PRIMARY VERSION
        # ========================================================

        primary_version = (
            status.get(
                "primary_version"
            )
        )


        if (

            primary_version

            != "v3"

        ):

            raise RuntimeError(

                "Expected Fusion version v3. "
                f"Received: {primary_version}"
            )


        # ========================================================
        # OPERATING MODE
        # ========================================================

        operating_mode = (
            status.get(
                "operating_mode"
            )
        )


        if (

            operating_mode

            != "PRODUCTION_PRIMARY"

        ):

            raise RuntimeError(

                "Expected Fusion v3 mode "
                "PRODUCTION_PRIMARY. "
                f"Received: {operating_mode}"
            )


        # ========================================================
        # PRIMARY PROMOTION
        # ========================================================

        if not status.get(
            "promoted_to_primary",
            False,
        ):

            raise RuntimeError(

                "Fusion v3 has not been promoted "
                "to primary."
            )


        # ========================================================
        # FALLBACK ENGINE
        # ========================================================

        fallback_engine = (
            status.get(
                "fallback_engine"
            )
        )


        if (

            fallback_engine

            != "process_threat_fusion_v2"

        ):

            raise RuntimeError(

                "Expected Fusion v2 rollback engine. "
                f"Received: {fallback_engine}"
            )


        if not status.get(
            "fallback_available",
            False,
        ):

            raise RuntimeError(

                "Fusion v2 rollback engine "
                "is not available."
            )


        # ========================================================
        # TEMPORAL RUNTIME
        # ========================================================

        temporal_runtime = (
            status.get(
                "temporal_runtime"
            )

            or {}
        )


        predictor = (
            temporal_runtime.get(
                "predictor"
            )

            or {}
        )


        # ========================================================
        # TEMPORAL AVAILABLE
        # ========================================================

        if not predictor.get(
            "available",
            False,
        ):

            raise RuntimeError(

                "Temporal Predictor v2 unavailable. "
                f"Load error: "
                f"{predictor.get('load_error')}"
            )


        # ========================================================
        # TRANSFORMER VERSION
        # ========================================================

        if (

            predictor.get(
                "model_version"
            )

            != "v2"

        ):

            raise RuntimeError(

                "Expected Temporal Transformer v2. "
                f"Received: "
                f"{predictor.get('model_version')}"
            )


        # ========================================================
        # PREDICTOR VERSION
        # ========================================================

        if (

            predictor.get(
                "predictor_version"
            )

            != "v2"

        ):

            raise RuntimeError(

                "Expected Temporal Predictor v2. "
                f"Received: "
                f"{predictor.get('predictor_version')}"
            )


        # ========================================================
        # CALIBRATION VERSION
        # ========================================================

        if (

            predictor.get(
                "calibration_version"
            )

            != "v2"

        ):

            raise RuntimeError(

                "Expected Temporal Calibration v2. "
                f"Received: "
                f"{predictor.get('calibration_version')}"
            )


        # ========================================================
        # SEQUENCE LENGTH
        # ========================================================

        if (

            int(
                predictor.get(
                    "sequence_length",
                    -1,
                )
            )

            != 8

        ):

            raise RuntimeError(

                "Expected Temporal sequence "
                "length 8. "
                f"Received: "
                f"{predictor.get('sequence_length')}"
            )


        # ========================================================
        # FEATURE COUNT
        # ========================================================

        if (

            int(
                predictor.get(
                    "feature_count",
                    -1,
                )
            )

            != 26

        ):

            raise RuntimeError(

                "Expected corrected Temporal "
                "feature count 26. "
                f"Received: "
                f"{predictor.get('feature_count')}"
            )


        # ========================================================
        # REPRESENTATION DIMENSION
        # ========================================================

        representation_dimension = (
            predictor.get(
                "representation_dimension"
            )
        )


        if (

            representation_dimension

            is not None

            and

            int(
                representation_dimension
            )

            != 64

        ):

            raise RuntimeError(

                "Expected Temporal representation "
                "dimension 64. "
                f"Received: "
                f"{representation_dimension}"
            )


        # ========================================================
        # NON-STATIONARY FEATURE REMOVED
        # ========================================================

        if (

            predictor.get(
                "removed_feature"
            )

            != "process_age_seconds"

        ):

            raise RuntimeError(

                "Temporal runtime does not report "
                "process_age_seconds as removed."
            )


        # ========================================================
        # BRIDGE
        # ========================================================

        bridge_version = (
            status.get(
                "bridge_version"
            )
        )


        if bridge_version is None:

            raise RuntimeError(

                "Fusion v3 Evidence Bridge "
                "version unavailable."
            )


        # ========================================================
        # SUCCESS LOG
        # ========================================================

        logger.info(

            "SENTINEL-X SECURITY RUNTIME VERIFIED | "
            "Primary=%s | "
            "Version=%s | "
            "Mode=%s | "
            "Fallback=%s | "
            "Bridge=%s | "
            "TemporalModel=%s | "
            "Predictor=%s | "
            "Calibration=%s | "
            "Sequence=%s | "
            "Features=%s | "
            "Embedding=%s | "
            "RemovedFeature=%s",

            primary_engine,

            primary_version,

            operating_mode,

            fallback_engine,

            bridge_version,

            predictor.get(
                "model_version"
            ),

            predictor.get(
                "predictor_version"
            ),

            predictor.get(
                "calibration_version"
            ),

            predictor.get(
                "sequence_length"
            ),

            predictor.get(
                "feature_count"
            ),

            predictor.get(
                "representation_dimension"
            ),

            predictor.get(
                "removed_feature"
            ),
        )


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


        # ========================================================
        # MARK ACTIVE
        # ========================================================

        update_collector_heartbeat(

            collector_name=
                collector_name,

            status=
                "ACTIVE",

            thread_alive=
                True,
        )


        try:

            # ====================================================
            # RUN COLLECTOR
            # ====================================================

            collector.start()


        except Exception as error:

            # ====================================================
            # COLLECTOR FAILURE
            # ====================================================

            logger.exception(

                "Collector failed | %s | %s",

                collector_name,

                error,
            )


            mark_collector_offline(

                collector_name=
                    collector_name,

                error=
                    str(
                        error
                    ),
            )


        finally:

            # ====================================================
            # COLLECTOR STOPPED
            # ====================================================

            mark_collector_offline(

                collector_name=
                    collector_name
            )


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

        thread = (
            threading.Thread(

                target=
                    self.run_collector,

                args=(
                    collector_name,
                    collector,
                ),

                name=
                    (
                        f"{collector_name.title()}"
                        "Monitor"
                    ),

                daemon=
                    True,
            )
        )


        self.threads.append(
            thread
        )


        self.collector_threads[
            collector_name
        ] = thread


        return thread


    # ============================================================
    # START COLLECTORS
    # ============================================================

    def start_collectors(
        self,
    ):

        # ========================================================
        # CREATE THREADS
        # ========================================================

        for (
            collector_name,
            collector,
        ) in self.collectors.items():

            self.create_thread(

                collector_name,

                collector,
            )


        # ========================================================
        # START THREADS
        # ========================================================

        for thread in self.threads:

            thread.start()


    # ============================================================
    # HEARTBEAT LOOP
    # ============================================================

    def heartbeat_loop(
        self,
    ):

        logger.info(

            "Collector heartbeat thread started | "
            "interval=%ss",

            self.HEARTBEAT_INTERVAL_SECONDS,
        )


        while self.running:

            for (
                collector_name,
                thread,
            ) in self.collector_threads.items():

                is_alive = (
                    thread.is_alive()
                )


                if is_alive:

                    update_collector_heartbeat(

                        collector_name=
                            collector_name,

                        status=
                            "ACTIVE",

                        thread_alive=
                            True,
                    )


                else:

                    mark_collector_offline(

                        collector_name=
                            collector_name,

                        error=
                            (
                                "Collector thread "
                                "is not running."
                            ),
                    )


            time.sleep(
                self.HEARTBEAT_INTERVAL_SECONDS
            )


        logger.info(

            "Collector heartbeat thread stopped."
        )


    # ============================================================
    # START HEARTBEAT
    # ============================================================

    def start_heartbeat(
        self,
    ):

        self.heartbeat_thread = (
            threading.Thread(

                target=
                    self.heartbeat_loop,

                name=
                    "CollectorHeartbeat",

                daemon=
                    True,
            )
        )


        self.heartbeat_thread.start()


    # ============================================================
    # PRINT SYSTEM STATUS
    # ============================================================

    def print_status(
        self,
    ):

        status = (
            self.process_monitor
            .get_primary_fusion_status()
        )


        temporal_runtime = (
            status.get(
                "temporal_runtime",
                {}
            )
        )


        predictor = (
            temporal_runtime.get(
                "predictor",
                {}
            )
        )


        logger.info(
            "=" * 78
        )


        logger.info(

            "SENTINEL-X ENDPOINT AGENT"
        )


        logger.info(
            "=" * 78
        )


        # ========================================================
        # COLLECTORS
        # ========================================================

        logger.info(

            "Process monitoring       : ENABLED"
        )


        logger.info(

            "File monitoring          : ENABLED"
        )


        logger.info(

            "Network monitoring       : ENABLED"
        )


        logger.info(

            "Registry monitoring      : ENABLED"
        )


        logger.info(

            "Authentication monitoring: ENABLED (READ-ONLY / SHADOW)"
        )


        # ========================================================
        # PROCESS DETECTION ENGINES
        # ========================================================

        logger.info(

            "Rule detection           : ENABLED"
        )


        logger.info(

            "Statistical detection    : ENABLED"
        )


        logger.info(

            "Isolation Forest         : ENABLED"
        )


        logger.info(

            "Autoencoder              : ENABLED"
        )


        # ========================================================
        # TEMPORAL AI
        # ========================================================

        logger.info(

            "Temporal Transformer     : %s",

            predictor.get(
                "model_version"
            ),
        )


        logger.info(

            "Temporal Predictor       : %s",

            predictor.get(
                "predictor_version"
            ),
        )


        logger.info(

            "Temporal Calibration     : %s",

            predictor.get(
                "calibration_version"
            ),
        )


        logger.info(

            "Temporal Sequence        : %s",

            predictor.get(
                "sequence_length"
            ),
        )


        logger.info(

            "Temporal Features        : %s",

            predictor.get(
                "feature_count"
            ),
        )


        logger.info(

            "Temporal Embedding       : %s",

            predictor.get(
                "representation_dimension"
            ),
        )


        logger.info(

            "Temporal Removed Feature : %s",

            predictor.get(
                "removed_feature"
            ),
        )


        # ========================================================
        # FUSION
        # ========================================================

        logger.info(

            "Fusion v3                : PRIMARY"
        )


        logger.info(

            "Fusion v3 Mode           : %s",

            status.get(
                "operating_mode"
            ),
        )


        logger.info(

            "Fusion v2                : ROLLBACK / REFERENCE"
        )


        logger.info(

            "Evidence Bridge          : %s",

            status.get(
                "bridge_version"
            ),
        )


        # ========================================================
        # SOC / INCIDENT PIPELINE
        # ========================================================

        logger.info(

            "Event correlation        : ENABLED"
        )


        logger.info(

            "Incident creation        : ENABLED"
        )


        logger.info(

            "Collector heartbeat      : ENABLED"
        )


        logger.info(
            "=" * 78
        )


    # ============================================================
    # START AGENT
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


        # ========================================================
        # ENABLE RUNNING FLAG
        # ========================================================

        self.running = True


        # ========================================================
        # PRINT RUNTIME CONFIGURATION
        # ========================================================

        self.print_status()


        # ========================================================
        # START COLLECTORS
        # ========================================================

        self.start_collectors()


        # ========================================================
        # START HEARTBEAT
        # ========================================================

        self.start_heartbeat()


        logger.info(

            "All SENTINEL-X collectors started."
        )


        logger.warning(

            "Fusion v3 is now the PRIMARY "
            "process threat decision engine."
        )


        logger.info(

            "Fusion v2 remains available "
            "as rollback/reference."
        )


        logger.info(

            "Press CTRL+C to stop SENTINEL-X."
        )


        # ========================================================
        # KEEP AGENT RUNNING
        # ========================================================

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
    # STOP ONE COLLECTOR
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

                "Unable to stop collector "
                "cleanly | %s | %s",

                collector_name,

                error,
            )


        finally:

            mark_collector_offline(

                collector_name=
                    collector_name
            )


    # ============================================================
    # STOP AGENT
    # ============================================================

    def stop(
        self,
    ):

        if not self.running:

            return


        logger.info(

            "Stopping SENTINEL-X Endpoint Agent..."
        )


        # ========================================================
        # SIGNAL AGENT STOP
        # ========================================================

        self.running = False


        # ========================================================
        # STOP COLLECTORS
        # ========================================================

        for (
            collector_name,
            collector,
        ) in self.collectors.items():

            self.stop_collector(

                collector_name,

                collector,
            )


        # ========================================================
        # JOIN COLLECTOR THREADS
        # ========================================================

        for thread in self.threads:

            if thread.is_alive():

                thread.join(
                    timeout=5
                )


        # ========================================================
        # JOIN HEARTBEAT
        # ========================================================

        if (

            self.heartbeat_thread
            is not None

            and

            self.heartbeat_thread.is_alive()

        ):

            self.heartbeat_thread.join(
                timeout=6
            )


        logger.info(
            "=" * 78
        )


        logger.info(

            "SENTINEL-X Endpoint Agent stopped."
        )


        logger.info(
            "=" * 78
        )


# ================================================================
# APPLICATION ENTRY POINT
# ================================================================

if __name__ == "__main__":

    agent = (
        SentinelAgent()
    )


    agent.start()