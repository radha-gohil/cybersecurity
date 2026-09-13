import time

import psutil

from detection.behavior.process_behavior_detector import (
    ProcessBehaviorDetector,
)

from detection.anomaly.process_anomaly_detector import (
    ProcessAnomalyDetector,
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


logger = get_logger(__name__)


class ProcessMonitor:

    def __init__(
        self,
        poll_interval: float = 2.0,
    ):

        self.poll_interval = poll_interval

        self.running = False

        self.telemetry = (
            TelemetryManager()
        )

        self.behavior_detector = (
            ProcessBehaviorDetector()
        )

        self.anomaly_detector = (
            ProcessAnomalyDetector(
                history_size=30,
                minimum_history=5,
                z_threshold=2.5,
            )
        )

        self.previous_processes = {}


    # ============================================================
    # SAFE PROCESS INFORMATION
    # ============================================================

    def get_process_info(
        self,
        process,
    ) -> dict:

        try:

            info = process.as_dict(
                attrs=[
                    "pid",
                    "ppid",
                    "name",
                    "exe",
                    "cmdline",
                    "username",
                    "create_time",
                    "memory_percent",
                    "num_threads",
                ]
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):

            return {}


        # --------------------------------------------------------
        # COMMAND LINE
        # --------------------------------------------------------

        cmdline = (
            info.get(
                "cmdline"
            )
            or []
        )

        if isinstance(
            cmdline,
            list,
        ):

            command_line = " ".join(
                str(value)
                for value in cmdline
            )

        else:

            command_line = str(
                cmdline
            )


        # --------------------------------------------------------
        # CPU USAGE
        # --------------------------------------------------------

        try:

            cpu_percent = (
                process.cpu_percent(
                    interval=None
                )
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):

            cpu_percent = 0.0


        # --------------------------------------------------------
        # PARENT PROCESS
        # --------------------------------------------------------

        parent_name = None

        parent_pid = (
            info.get(
                "ppid"
            )
        )


        if parent_pid:

            try:

                parent_process = (
                    psutil.Process(
                        parent_pid
                    )
                )

                parent_name = (
                    parent_process.name()
                )

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):

                parent_name = None


        return {

            "pid":
                info.get(
                    "pid"
                ),

            "ppid":
                info.get(
                    "ppid"
                ),

            "name":
                info.get(
                    "name"
                ),

            "exe":
                info.get(
                    "exe"
                ),

            "cmdline":
                command_line,

            "username":
                info.get(
                    "username"
                ),

            "create_time":
                info.get(
                    "create_time"
                ),

            "parent_name":
                parent_name,

            "cpu_percent":
                cpu_percent,

            "memory_percent":
                info.get(
                    "memory_percent"
                )
                or 0.0,

            "num_threads":
                info.get(
                    "num_threads"
                )
                or 0,
        }


    # ============================================================
    # PROCESS SNAPSHOT
    # ============================================================

    def get_process_snapshot(
        self,
    ) -> dict:

        snapshot = {}


        for process in (
            psutil.process_iter()
        ):

            process_info = (
                self.get_process_info(
                    process
                )
            )


            if not process_info:

                continue


            pid = (
                process_info.get(
                    "pid"
                )
            )


            if pid is None:

                continue


            snapshot[
                pid
            ] = process_info


        return snapshot


    # ============================================================
    # SCORE TO SEVERITY
    # ============================================================

    def score_to_severity(
        self,
        score: int,
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 35:
            return "MEDIUM"

        if score >= 15:
            return "LOW"

        return "INFO"


    # ============================================================
    # COMBINED PROCESS THREAT SCORE
    # ============================================================

    def calculate_combined_score(
        self,
        behavior_result: dict,
        anomaly_result: dict,
    ) -> int:

        behavior_score = (
            behavior_result.get(
                "behavior_score",
                0,
            )
        )

        anomaly_score = (
            anomaly_result.get(
                "anomaly_score",
                0,
            )
        )


        # --------------------------------------------------------
        # Fusion strategy
        #
        # Main detector score receives full weight.
        # Secondary detector provides additional supporting score.
        # --------------------------------------------------------

        primary_score = max(
            behavior_score,
            anomaly_score,
        )

        secondary_score = min(
            behavior_score,
            anomaly_score,
        )


        combined_score = (
            primary_score
            + (
                secondary_score
                * 0.25
            )
        )


        return min(
            int(
                round(
                    combined_score
                )
            ),
            100,
        )


    # ============================================================
    # SAVE PROCESS DETECTION
    # ============================================================

    def save_process_detection(
        self,
        event,
        process_info: dict,
        behavior_result: dict,
        anomaly_result: dict,
        combined_score: int,
        severity: str,
    ):

        behavior_suspicious = (
            behavior_result.get(
                "suspicious",
                False,
            )
        )

        anomaly_suspicious = (
            anomaly_result.get(
                "anomalous",
                False,
            )
        )


        if not (
            behavior_suspicious
            or anomaly_suspicious
            or combined_score >= 35
        ):

            return


        detection = {

            "engine":
                "process_behavior_anomaly",

            "detection_type":
                "process_threat",

            "risk":
                combined_score,

            "risk_score":
                combined_score,

            "severity":
                severity,

            "pid":
                process_info.get(
                    "pid"
                ),

            "process_name":
                process_info.get(
                    "name"
                ),

            "process_path":
                process_info.get(
                    "exe"
                ),

            "parent_name":
                process_info.get(
                    "parent_name"
                ),

            "command_line":
                process_info.get(
                    "cmdline"
                ),

            "behavior_score":
                behavior_result.get(
                    "behavior_score",
                    0,
                ),

            "anomaly_score":
                anomaly_result.get(
                    "anomaly_score",
                    0,
                ),

            "behavior_suspicious":
                behavior_suspicious,

            "anomaly_suspicious":
                anomaly_suspicious,

            "behavior_indicators":
                behavior_result.get(
                    "indicators",
                    [],
                ),

            "anomaly_indicators":
                anomaly_result.get(
                    "indicators",
                    [],
                ),

            "behavior_reasons":
                behavior_result.get(
                    "reasons",
                    [],
                ),

            "anomaly_reasons":
                anomaly_result.get(
                    "reasons",
                    [],
                ),
        }


        try:

            save_detection(
                event.event_id,
                detection,
            )


            logger.info(
                "Process threat detection saved | "
                "EventID=%s | "
                "Process=%s | "
                "Behavior=%s | "
                "Anomaly=%s | "
                "Combined=%s | "
                "Severity=%s",

                event.event_id,

                process_info.get(
                    "name"
                ),

                behavior_result.get(
                    "behavior_score",
                    0,
                ),

                anomaly_result.get(
                    "anomaly_score",
                    0,
                ),

                combined_score,

                severity,
            )


        except Exception as error:

            logger.error(
                "Failed to save process threat detection | "
                "EventID=%s | %s",

                event.event_id,

                error,
            )


    # ============================================================
    # HANDLE PROCESS START
    # ============================================================

    def handle_process_start(
        self,
        process_info: dict,
    ):

        # --------------------------------------------------------
        # BEHAVIOR ANALYSIS
        # --------------------------------------------------------

        behavior_result = (
            self.behavior_detector.analyze(
                process_info
            )
        )


        # --------------------------------------------------------
        # ANOMALY ANALYSIS
        # --------------------------------------------------------

        anomaly_result = (
            self.anomaly_detector.analyze(
                process_info
            )
        )


        # --------------------------------------------------------
        # COMBINED THREAT SCORE
        # --------------------------------------------------------

        combined_score = (
            self.calculate_combined_score(
                behavior_result,
                anomaly_result,
            )
        )


        severity = (
            self.score_to_severity(
                combined_score
            )
        )


        suspicious = (
            behavior_result.get(
                "suspicious",
                False,
            )
            or
            anomaly_result.get(
                "anomalous",
                False,
            )
            or
            combined_score >= 35
        )


        # --------------------------------------------------------
        # PROCESS TELEMETRY
        # --------------------------------------------------------

        process_data = dict(
            process_info
        )


        process_data.update(
            {

                # ----------------------------------------------
                # BEHAVIOR
                # ----------------------------------------------

                "behavior_score":
                    behavior_result.get(
                        "behavior_score",
                        0,
                    ),

                "behavior_suspicious":
                    behavior_result.get(
                        "suspicious",
                        False,
                    ),

                "behavior_indicators":
                    behavior_result.get(
                        "indicators",
                        [],
                    ),

                "behavior_reasons":
                    behavior_result.get(
                        "reasons",
                        [],
                    ),


                # ----------------------------------------------
                # ANOMALY
                # ----------------------------------------------

                "anomaly_score":
                    anomaly_result.get(
                        "anomaly_score",
                        0,
                    ),

                "anomaly_suspicious":
                    anomaly_result.get(
                        "anomalous",
                        False,
                    ),

                "anomaly_indicators":
                    anomaly_result.get(
                        "indicators",
                        [],
                    ),

                "anomaly_reasons":
                    anomaly_result.get(
                        "reasons",
                        [],
                    ),

                "cpu_z_score":
                    anomaly_result.get(
                        "cpu_z_score",
                        0,
                    ),

                "memory_z_score":
                    anomaly_result.get(
                        "memory_z_score",
                        0,
                    ),

                "thread_z_score":
                    anomaly_result.get(
                        "thread_z_score",
                        0,
                    ),


                # ----------------------------------------------
                # FUSION
                # ----------------------------------------------

                "combined_threat_score":
                    combined_score,

                "suspicious":
                    suspicious,

                "threat_severity":
                    severity,
            }
        )


        # --------------------------------------------------------
        # METADATA
        # --------------------------------------------------------

        metadata = {

            "collector":
                "ProcessMonitor",

            "behavior_analysis":
                True,

            "anomaly_analysis":
                True,

            "behavior_score":
                behavior_result.get(
                    "behavior_score",
                    0,
                ),

            "anomaly_score":
                anomaly_result.get(
                    "anomaly_score",
                    0,
                ),

            "combined_threat_score":
                combined_score,

            "suspicious":
                suspicious,
        }


        # --------------------------------------------------------
        # TELEMETRY EVENT
        # --------------------------------------------------------

        event = (
            self.telemetry.emit(

                event_type="process_start",

                source="process_monitor",

                severity=severity,

                process=process_data,

                metadata=metadata,
            )
        )


        # --------------------------------------------------------
        # DEDICATED DETECTION
        # --------------------------------------------------------

        self.save_process_detection(

            event=event,

            process_info=process_info,

            behavior_result=behavior_result,

            anomaly_result=anomaly_result,

            combined_score=combined_score,

            severity=severity,
        )


        # --------------------------------------------------------
        # LOG
        # --------------------------------------------------------

        logger.info(
            "PROCESS_START | "
            "PID=%s | "
            "Process=%s | "
            "Parent=%s | "
            "Behavior=%s | "
            "Anomaly=%s | "
            "Combined=%s | "
            "Suspicious=%s | "
            "Severity=%s | "
            "EventID=%s",

            process_info.get(
                "pid"
            ),

            process_info.get(
                "name"
            ),

            process_info.get(
                "parent_name"
            ),

            behavior_result.get(
                "behavior_score",
                0,
            ),

            anomaly_result.get(
                "anomaly_score",
                0,
            ),

            combined_score,

            suspicious,

            severity,

            event.event_id,
        )


    # ============================================================
    # HANDLE PROCESS STOP
    # ============================================================

    def handle_process_stop(
        self,
        process_info: dict,
    ):

        event = (
            self.telemetry.emit(

                event_type="process_stop",

                source="process_monitor",

                severity="INFO",

                process=process_info,

                metadata={
                    "collector":
                        "ProcessMonitor",
                },
            )
        )


        logger.info(
            "PROCESS_STOP | "
            "PID=%s | "
            "Process=%s | "
            "EventID=%s",

            process_info.get(
                "pid"
            ),

            process_info.get(
                "name"
            ),

            event.event_id,
        )


    # ============================================================
    # INITIALIZE BASELINE
    # ============================================================

    def initialize(
        self,
    ):

        logger.info(
            "Building initial process baseline..."
        )


        self.previous_processes = (
            self.get_process_snapshot()
        )


        # --------------------------------------------------------
        # Seed anomaly detector with current normal processes.
        # This does NOT create security events.
        # --------------------------------------------------------

        for process_info in (
            self.previous_processes.values()
        ):

            try:

                self.anomaly_detector.analyze(
                    process_info
                )

            except Exception as error:

                logger.debug(
                    "Unable to seed anomaly baseline: %s",
                    error,
                )


        logger.info(
            "Initial process baseline contains %s processes.",
            len(
                self.previous_processes
            ),
        )


    # ============================================================
    # CHECK PROCESS CHANGES
    # ============================================================

    def check_processes(
        self,
    ):

        current_processes = (
            self.get_process_snapshot()
        )


        previous_pids = set(
            self.previous_processes.keys()
        )

        current_pids = set(
            current_processes.keys()
        )


        # --------------------------------------------------------
        # PROCESS START
        # --------------------------------------------------------

        started_pids = (
            current_pids
            - previous_pids
        )


        for pid in started_pids:

            process_info = (
                current_processes.get(
                    pid
                )
            )

            if process_info:

                self.handle_process_start(
                    process_info
                )


        # --------------------------------------------------------
        # PROCESS STOP
        # --------------------------------------------------------

        stopped_pids = (
            previous_pids
            - current_pids
        )


        for pid in stopped_pids:

            process_info = (
                self.previous_processes.get(
                    pid
                )
            )

            if process_info:

                self.handle_process_stop(
                    process_info
                )


        self.previous_processes = (
            current_processes
        )


    # ============================================================
    # START MONITOR
    # ============================================================

    def start(
        self,
    ):

        logger.info(
            "Starting SENTINEL-X Process Monitor..."
        )


        logger.info(
            "Polling interval: %.1f seconds",
            self.poll_interval,
        )


        self.initialize()

        self.running = True


        try:

            while self.running:

                self.check_processes()

                time.sleep(
                    self.poll_interval
                )


        except KeyboardInterrupt:

            logger.info(
                "Process monitor interrupted."
            )


        finally:

            self.stop()


    # ============================================================
    # STOP MONITOR
    # ============================================================

    def stop(
        self,
    ):

        self.running = False

        logger.info(
            "SENTINEL-X Process Monitor stopped."
        )


# ============================================================
# MANUAL RUN
# ============================================================

if __name__ == "__main__":

    monitor = ProcessMonitor(
        poll_interval=2.0,
    )

    monitor.start()