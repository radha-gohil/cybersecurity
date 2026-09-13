import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from config import FILE_MONITOR_PATH

from detection.malware.static_file_analyzer import StaticFileAnalyzer
from detection.malware.malware_predictor import MalwarePredictor

from endpoint.agent.telemetry_manager import TelemetryManager
from endpoint.storage.database import save_detection
from endpoint.utils.logger import get_logger


logger = get_logger(__name__)


class SentinelFileEventHandler(FileSystemEventHandler):

    def __init__(self):

        super().__init__()

        self.telemetry = TelemetryManager()

        self.static_analyzer = StaticFileAnalyzer()

        self.malware_predictor = MalwarePredictor()

        # Stores recently scanned SHA-256 values.
        #
        # Structure:
        # {
        #     "sha256_hash": last_scan_time
        # }
        self.recent_detections = {}

        # Duplicate detections for the same unchanged file
        # will be ignored during this window.
        self.deduplication_window = 5


    # ============================================================
    # GET BASIC FILE INFORMATION
    # ============================================================

    def get_file_info(
        self,
        file_path: str,
    ) -> dict:

        path = Path(
            file_path
        )

        file_info = {
            "name": path.name,
            "path": str(path),
            "extension": path.suffix.lower(),
            "size": None,
            "exists": path.exists(),
        }

        try:

            if (
                path.exists()
                and path.is_file()
            ):

                file_info["size"] = (
                    path.stat().st_size
                )

        except (
            PermissionError,
            OSError,
        ):

            pass

        return file_info


    # ============================================================
    # STATIC FILE ANALYSIS
    # ============================================================

    def analyze_file(
        self,
        file_path: str,
    ) -> dict:

        try:

            return (
                self.static_analyzer.analyze(
                    file_path
                )
            )

        except Exception as error:

            logger.warning(
                "Static analysis failed for %s | %s",
                file_path,
                error,
            )

            return {}


    # ============================================================
    # ML MALWARE PREDICTION
    # ============================================================

    def predict_malware(
        self,
        file_path: str,
    ) -> dict:

        try:

            return (
                self.malware_predictor.predict(
                    file_path
                )
            )

        except Exception as error:

            logger.warning(
                "Malware prediction failed for %s | %s",
                file_path,
                error,
            )

            return {}


    # ============================================================
    # FINAL SEVERITY
    # ============================================================

    def get_final_severity(
        self,
        static_analysis: dict,
        ml_prediction: dict,
    ) -> str:

        severity_order = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        static_severity = (
            static_analysis.get(
                "severity",
                "INFO",
            )
            if static_analysis
            else "INFO"
        )

        ml_severity = (
            ml_prediction.get(
                "severity",
                "INFO",
            )
            if (
                ml_prediction
                and ml_prediction.get(
                    "valid"
                )
            )
            else "INFO"
        )

        return max(
            [
                static_severity,
                ml_severity,
            ],
            key=lambda value:
                severity_order.get(
                    value,
                    0,
                ),
        )


    # ============================================================
    # CALCULATE DETECTION RISK
    # ============================================================

    def get_detection_risk(
        self,
        malware_probability,
    ) -> int:

        if malware_probability is None:
            return 0

        if malware_probability >= 0.90:
            return 100

        if malware_probability >= 0.75:
            return 80

        if malware_probability >= 0.50:
            return 60

        if malware_probability >= 0.25:
            return 40

        if malware_probability >= 0.10:
            return 20

        return 5


    # ============================================================
    # CHECK DUPLICATE DETECTION
    # ============================================================

    def is_duplicate_detection(
        self,
        sha256: str,
    ) -> bool:

        if not sha256:
            return False

        current_time = time.time()

        last_detection_time = (
            self.recent_detections.get(
                sha256
            )
        )

        if last_detection_time is not None:

            time_difference = (
                current_time
                - last_detection_time
            )

            if (
                time_difference
                < self.deduplication_window
            ):

                return True

        self.recent_detections[
            sha256
        ] = current_time

        return False


    # ============================================================
    # CLEAN OLD CACHE RECORDS
    # ============================================================

    def cleanup_detection_cache(
        self,
    ):

        current_time = time.time()

        expired_hashes = []

        for (
            sha256,
            timestamp,
        ) in self.recent_detections.items():

            if (
                current_time
                - timestamp
                > 60
            ):

                expired_hashes.append(
                    sha256
                )

        for sha256 in expired_hashes:

            self.recent_detections.pop(
                sha256,
                None,
            )


    # ============================================================
    # SAVE FILE EVENT
    # ============================================================

    def save_file_event(
        self,
        event_type: str,
        file_path: str,
        extra_metadata: dict = None,
    ):

        # --------------------------------------------------------
        # BASIC FILE INFO
        # --------------------------------------------------------

        file_info = (
            self.get_file_info(
                file_path
            )
        )


        # --------------------------------------------------------
        # ANALYSIS RESULTS
        # --------------------------------------------------------

        static_analysis = {}

        ml_prediction = {}


        # --------------------------------------------------------
        # RUN ANALYSIS
        # --------------------------------------------------------

        if (
            event_type
            in {
                "file_create",
                "file_modify",
                "file_rename",
            }
            and file_info.get(
                "exists"
            )
        ):

            static_analysis = (
                self.analyze_file(
                    file_path
                )
            )


            # ----------------------------------------------------
            # RUN ML ONLY FOR PE FILE
            # ----------------------------------------------------

            if (
                static_analysis
                and static_analysis.get(
                    "is_pe"
                )
            ):

                ml_prediction = (
                    self.predict_malware(
                        file_path
                    )
                )


        # --------------------------------------------------------
        # STATIC RESULTS
        # --------------------------------------------------------

        if static_analysis:

            file_info.update(
                {
                    "md5":
                        static_analysis.get(
                            "md5"
                        ),

                    "sha1":
                        static_analysis.get(
                            "sha1"
                        ),

                    "sha256":
                        static_analysis.get(
                            "sha256"
                        ),

                    "entropy":
                        static_analysis.get(
                            "entropy"
                        ),

                    "is_pe":
                        static_analysis.get(
                            "is_pe"
                        ),

                    "static_risk_score":
                        static_analysis.get(
                            "risk_score"
                        ),

                    "static_severity":
                        static_analysis.get(
                            "severity"
                        ),

                    "static_reasons":
                        static_analysis.get(
                            "reasons"
                        ),
                }
            )


        # --------------------------------------------------------
        # ML RESULTS
        # --------------------------------------------------------

        if (
            ml_prediction
            and ml_prediction.get(
                "valid"
            )
        ):

            file_info.update(
                {
                    "ml_prediction":
                        ml_prediction.get(
                            "prediction"
                        ),

                    "malware_probability":
                        ml_prediction.get(
                            "malware_probability"
                        ),

                    "benign_probability":
                        ml_prediction.get(
                            "benign_probability"
                        ),

                    "ml_confidence":
                        ml_prediction.get(
                            "confidence"
                        ),

                    "ml_severity":
                        ml_prediction.get(
                            "severity"
                        ),
                }
            )


        # --------------------------------------------------------
        # METADATA
        # --------------------------------------------------------

        metadata = {
            "collector":
                "FileMonitor",
        }


        if static_analysis:

            metadata.update(
                {
                    "static_analysis":
                        True,

                    "static_risk_score":
                        static_analysis.get(
                            "risk_score",
                            0,
                        ),

                    "static_severity":
                        static_analysis.get(
                            "severity",
                            "INFO",
                        ),
                }
            )


        if (
            ml_prediction
            and ml_prediction.get(
                "valid"
            )
        ):

            metadata.update(
                {
                    "ml_analysis":
                        True,

                    "ml_prediction":
                        ml_prediction.get(
                            "prediction"
                        ),

                    "malware_probability":
                        ml_prediction.get(
                            "malware_probability"
                        ),

                    "benign_probability":
                        ml_prediction.get(
                            "benign_probability"
                        ),

                    "ml_confidence":
                        ml_prediction.get(
                            "confidence"
                        ),

                    "ml_severity":
                        ml_prediction.get(
                            "severity"
                        ),
                }
            )


        if extra_metadata:

            metadata.update(
                extra_metadata
            )


        # --------------------------------------------------------
        # FINAL SEVERITY
        # --------------------------------------------------------

        severity = (
            self.get_final_severity(
                static_analysis,
                ml_prediction,
            )
        )


        # --------------------------------------------------------
        # SAVE TELEMETRY EVENT
        # --------------------------------------------------------

        event = (
            self.telemetry.emit(

                event_type=event_type,

                source="file_monitor",

                severity=severity,

                file=file_info,

                metadata=metadata,
            )
        )


        # --------------------------------------------------------
        # SAVE DEDICATED MALWARE DETECTION
        # --------------------------------------------------------

        if (
            ml_prediction
            and ml_prediction.get(
                "valid"
            )
        ):

            sha256 = (
                static_analysis.get(
                    "sha256"
                )
                if static_analysis
                else None
            )

            malware_probability = (
                ml_prediction.get(
                    "malware_probability"
                )
            )


            # ----------------------------------------------------
            # DEDUPLICATION
            # ----------------------------------------------------

            duplicate = (
                self.is_duplicate_detection(
                    sha256
                )
            )


            if duplicate:

                logger.info(
                    "Duplicate malware detection skipped | "
                    "SHA256=%s | File=%s",

                    sha256,

                    file_path,
                )

            else:

                risk = (
                    self.get_detection_risk(
                        malware_probability
                    )
                )

                detection = {

                    "engine":
                        "malware_ml",

                    "detection_type":
                        "malware",

                    "prediction":
                        ml_prediction.get(
                            "prediction"
                        ),

                    "malware_probability":
                        malware_probability,

                    "benign_probability":
                        ml_prediction.get(
                            "benign_probability"
                        ),

                    "confidence":
                        ml_prediction.get(
                            "confidence"
                        ),

                    "risk":
                        risk,

                    "risk_score":
                        risk,

                    "severity":
                        ml_prediction.get(
                            "severity"
                        ),

                    "file_path":
                        file_path,

                    "sha256":
                        sha256,
                }


                try:

                    save_detection(
                        event.event_id,
                        detection,
                    )

                    logger.info(
                        "Malware detection saved | "
                        "EventID=%s | "
                        "Engine=%s | "
                        "Prediction=%s | "
                        "Probability=%.4f | "
                        "Risk=%s",

                        event.event_id,

                        detection.get(
                            "engine"
                        ),

                        ml_prediction.get(
                            "prediction"
                        ),

                        malware_probability
                        if malware_probability
                        is not None
                        else 0,

                        risk,
                    )

                except Exception as error:

                    logger.error(
                        "Failed to save malware detection | "
                        "EventID=%s | %s",

                        event.event_id,

                        error,
                    )


        # --------------------------------------------------------
        # CLEAN OLD DEDUPLICATION RECORDS
        # --------------------------------------------------------

        self.cleanup_detection_cache()


        # --------------------------------------------------------
        # EVENT LOG
        # --------------------------------------------------------

        static_risk = (
            static_analysis.get(
                "risk_score",
                0,
            )
            if static_analysis
            else 0
        )


        malware_probability = (
            ml_prediction.get(
                "malware_probability"
            )
            if (
                ml_prediction
                and ml_prediction.get(
                    "valid"
                )
            )
            else None
        )


        logger.info(
            "%s | %s | "
            "StaticRisk=%s | "
            "MalwareProbability=%s | "
            "Severity=%s | "
            "EventID=%s",

            event_type.upper(),

            file_path,

            static_risk,

            (
                f"{malware_probability:.4f}"
                if malware_probability
                is not None
                else "N/A"
            ),

            severity,

            event.event_id,
        )


    # ============================================================
    # FILE CREATED
    # ============================================================

    def on_created(
        self,
        event,
    ):

        if event.is_directory:
            return

        self.save_file_event(
            event_type="file_create",
            file_path=event.src_path,
        )


    # ============================================================
    # FILE MODIFIED
    # ============================================================

    def on_modified(
        self,
        event,
    ):

        if event.is_directory:
            return

        self.save_file_event(
            event_type="file_modify",
            file_path=event.src_path,
        )


    # ============================================================
    # FILE DELETED
    # ============================================================

    def on_deleted(
        self,
        event,
    ):

        if event.is_directory:
            return

        self.save_file_event(
            event_type="file_delete",
            file_path=event.src_path,
        )


    # ============================================================
    # FILE RENAMED / MOVED
    # ============================================================

    def on_moved(
        self,
        event,
    ):

        if event.is_directory:
            return

        self.save_file_event(

            event_type="file_rename",

            file_path=event.dest_path,

            extra_metadata={
                "source_path":
                    event.src_path,

                "destination_path":
                    event.dest_path,
            },
        )


# ============================================================
# FILE MONITOR
# ============================================================

class FileMonitor:

    def __init__(
        self,
        watch_path=None,
    ):

        if watch_path is None:

            watch_path = (
                FILE_MONITOR_PATH
            )

        self.watch_path = Path(
            watch_path
        )

        self.observer = Observer()

        self.running = False


    # ============================================================
    # START
    # ============================================================

    def start(
        self,
    ):

        self.watch_path.mkdir(
            parents=True,
            exist_ok=True,
        )

        logger.info(
            "Starting SENTINEL-X File Monitor..."
        )

        logger.info(
            "Watching directory: %s",
            self.watch_path,
        )

        event_handler = (
            SentinelFileEventHandler()
        )

        self.observer.schedule(
            event_handler,
            str(
                self.watch_path
            ),
            recursive=True,
        )

        self.observer.start()

        self.running = True

        try:

            while self.running:

                time.sleep(
                    1
                )

        except KeyboardInterrupt:

            logger.info(
                "File monitor interrupted."
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

        if self.observer.is_alive():

            self.observer.stop()

            self.observer.join()

        logger.info(
            "SENTINEL-X File Monitor stopped."
        )


# ============================================================
# MANUAL RUN
# ============================================================

if __name__ == "__main__":

    monitor = FileMonitor()

    monitor.start()