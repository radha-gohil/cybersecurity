import math
import time
import psutil

from detection.behavior.process_behavior_detector import (

    ProcessBehaviorDetector,

)

from config import (
    IS_VALIDATION_MODE,
)

from endpoint.agent.telemetry_manager import (

    shared_telemetry_manager,

)



from detection.anomaly.process_anomaly_detector import (

    ProcessAnomalyDetector,

)









from endpoint.storage.database import (

    save_detection,

)



from endpoint.utils.logger import (

    get_logger,

)





from ai_detection.behavior.process_feature_extractor import (

    ProcessFeatureExtractor,

)



from ai_detection.behavior.behavior_feature_store import (

    BehaviorFeatureStore,

)



from ai_detection.behavior.behavior_model_result_store import (

    BehaviorModelResultStore,

)



from ai_detection.behavior.process_context_tracker import (

    shared_process_behavior_context,

)



from ai_detection.behavior.process_feature_schema import (

    PROCESS_FEATURE_SCHEMA_VERSION,

)



from ai_detection.behavior.process_isolation_forest_predictor import (

    ProcessIsolationForestPredictor,

)



from ai_detection.behavior.process_autoencoder_predictor import (

    ProcessAutoencoderPredictor,

)



from ai_detection.behavior.process_threat_fusion_v2 import (

    ProcessThreatFusionV2,

)





logger = get_logger(__name__)





class ProcessMonitor:



    def __init__(

        self,

        poll_interval: float = 2.0,

    ):



        self.poll_interval = (

            poll_interval

        )



        self.running = False





        # ========================================================

        # TELEMETRY

        # ========================================================



        self.telemetry = (

            shared_telemetry_manager

        )





        # ========================================================

        # SECURITY ENGINES

        # ========================================================



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





        # ========================================================

        # FEATURE PIPELINE

        # ========================================================



        self.ai_feature_extractor = (

            ProcessFeatureExtractor()

        )





        self.ai_feature_store = (

            BehaviorFeatureStore()

        )





        # ========================================================

        # MULTI-MODEL RESULT STORE

        # ========================================================



        self.ai_result_store = (

            BehaviorModelResultStore()

        )





        # ========================================================

        # AI MODEL 1

        # ISOLATION FOREST

        # ========================================================



        self.isolation_forest_predictor = (

            ProcessIsolationForestPredictor(

                auto_load=True

            )

        )





        # ========================================================

        # AI MODEL 2

        # AUTOENCODER V2

        # ========================================================



        self.autoencoder_predictor = (

            ProcessAutoencoderPredictor(

                auto_load=True

            )

        )





        # ========================================================

        # THREAT FUSION V2

        #

        # Rules

        # +

        # Statistical anomaly

        # +

        # Isolation Forest + Autoencoder consensus

        # ========================================================



        self.fusion_engine = (

            ProcessThreatFusionV2()

        )





        # ========================================================

        # PROCESS STATE

        # ========================================================



        self.previous_processes = {}





        # ========================================================

        # PERIODIC AI INFERENCE

        # ========================================================



        self.ai_feature_sample_interval = (

            15.0

        )





        self.last_ai_feature_sample = {}





        # ========================================================

        # FUSION ALERT COOLDOWN

        # ========================================================



        self.fusion_alert_cooldown_seconds = (

            120.0

        )





        self.last_fusion_alert_time = {}





    # ============================================================

    # PROCESS INFORMATION

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





        # ========================================================

        # COMMAND LINE

        # ========================================================



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



                str(

                    value

                )



                for value

                in cmdline

            )



        else:



            command_line = str(

                cmdline

            )





        # ========================================================

        # CPU

        # ========================================================



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





        # ========================================================

        # MEMORY

        # ========================================================



        try:



            memory_info = (

                process.memory_info()

            )





            rss_mb = (



                memory_info.rss



                / (

                    1024.0

                    * 1024.0

                )

            )



        except (

            psutil.NoSuchProcess,

            psutil.AccessDenied,

            AttributeError,

        ):



            rss_mb = 0.0





        # ========================================================

        # WINDOWS HANDLE COUNT

        # ========================================================



        try:



            num_handles_method = getattr(



                process,



                "num_handles",



                None,

            )





            if callable(

                num_handles_method

            ):



                num_handles = (

                    num_handles_method()

                )



            else:



                num_handles = 0



        except (

            psutil.NoSuchProcess,

            psutil.AccessDenied,

            AttributeError,

        ):



            num_handles = 0





        # ========================================================

        # PARENT PROCESS

        # ========================================================



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

                (

                    info.get(

                        "memory_percent"

                    )

                    or 0.0

                ),



            "rss_mb":

                rss_mb,



            "num_threads":

                (

                    info.get(

                        "num_threads"

                    )

                    or 0

                ),



            "num_handles":

                num_handles,

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

    # STORE MODEL RESULT

    # ============================================================



    def save_model_result(



        self,



        feature_record_id,



        model_family: str,



        result: dict | None,



        raw_metric_name: str | None = None,



        raw_metric_value=None,



    ):



        if feature_record_id is None:



            return None





        if not result:



            return None





        if not result.get(

            "available",

            False,

        ):



            return None





        if result.get(

            "prediction_failed",

            False,

        ):



            return None





        try:



            result_id = (



                self.ai_result_store.save_result(



                    feature_record_id=

                        feature_record_id,



                    model_family=

                        model_family,



                    result=

                        result,



                    raw_metric_name=

                        raw_metric_name,



                    raw_metric_value=

                        raw_metric_value,

                )

            )





            return result_id





        except Exception as error:



            logger.warning(



                "Unable to persist AI model result | "

                "FeatureRecord=%s | "

                "Model=%s | "

                "Error=%s",



                feature_record_id,



                model_family,



                error,

            )





            return None





    # ============================================================

    # FEATURE EXTRACTION + MULTI-MODEL AI

    # ============================================================



    def collect_ai_behavior_features(



        self,



        process_info: dict,



        context: dict | None = None,



    ) -> dict:



        result = {



            "record_id":

                None,



            "feature_record":

                None,



            "isolation_forest":

                None,



            "autoencoder":

                None,



            "model_result_ids":

                {},

        }





        if not process_info:



            return result



        # ====================================================

        # WINDOWS PID 0 — MODEL ELIGIBILITY

        # ====================================================

        #

        # Windows System Idle Process is not an ordinary

        # executable process.

        #

        # Its creation time, CPU accounting, executable path

        # and associated features differ substantially from

        # normal processes used for model training.

        #

        # Do not store ordinary executable-model features

        # or generate IF/AE predictions for PID 0.

        #

        # Other endpoint telemetry remains unaffected.

        # ====================================================



        pid = process_info.get("pid")



        if pid is not None and str(pid).strip() == "0":



            logger.debug(

                "PROCESS AI INFERENCE SKIPPED | "

                "PID=0 | "

                "Reason=Special Windows idle process"

            )



            return result

        # ========================================================
        # AI INPUT VALIDITY: CREATION TIMESTAMP
        # ========================================================
        # Some Windows kernel processes (including PID 4) expose
        # create_time=0.0. Treating this as Unix epoch time makes
        # the process appear decades old, invalidating the normal
        # executable model's process-age feature. Keep rule and
        # statistical monitoring active; skip only IF/AE inference.
        # Do not fabricate a creation time or overwrite evidence.

        create_time = process_info.get("create_time")
        try:
            creation_epoch = float(create_time)
        except (TypeError, ValueError, OverflowError):
            creation_epoch = float("nan")

        if (
            not math.isfinite(creation_epoch)
            or creation_epoch <= 0.0
            or creation_epoch > time.time() + 60.0
        ):
            result["skip_reason"] = "INVALID_PROCESS_CREATE_TIME"
            logger.debug(
                "PROCESS AI INFERENCE SKIPPED | PID=%s | "
                "Process=%s | Reason=%s | create_time=%r",
                pid,
                process_info.get("name"),
                result["skip_reason"],
                create_time,
            )
            return result



        try:



            # ====================================================

            # EXTRACT FEATURE VECTOR

            # ====================================================



            feature_record = (



                self.ai_feature_extractor.extract(



                    process_data=

                        process_info,



                    context=(

                        context

                        or {}

                    ),

                )

            )





            result[

                "feature_record"

            ] = feature_record





            # ====================================================

            # STORE FEATURE VECTOR ONCE

            # ====================================================



            record_id = (



                self.ai_feature_store

                .save_process_features(

                    feature_record

                )

            )





            result[

                "record_id"

            ] = record_id





            # ====================================================

            # ISOLATION FOREST

            # ====================================================



            isolation_result = (



                self.isolation_forest_predictor.predict(



                    record=

                        feature_record,



                    record_id=

                        record_id,

                )

            )





            result[

                "isolation_forest"

            ] = isolation_result





            isolation_result_id = (



                self.save_model_result(



                    feature_record_id=

                        record_id,



                    model_family=

                        "isolation_forest",



                    result=

                        isolation_result,



                    raw_metric_name=

                        "decision_score",



                    raw_metric_value=

                        (

                            isolation_result.get(

                                "decision_score"

                            )



                            if isolation_result



                            else None

                        ),

                )

            )





            if isolation_result_id is not None:



                result[

                    "model_result_ids"

                ][

                    "isolation_forest"

                ] = isolation_result_id





            # ====================================================

            # AUTOENCODER V2

            # ====================================================



            autoencoder_result = (



                self.autoencoder_predictor.predict(

                    feature_record

                )

            )





            result[

                "autoencoder"

            ] = autoencoder_result





            autoencoder_result_id = (



                self.save_model_result(



                    feature_record_id=

                        record_id,



                    model_family=

                        "autoencoder",



                    result=

                        autoencoder_result,



                    raw_metric_name=

                        "reconstruction_error",



                    raw_metric_value=

                        (

                            autoencoder_result.get(

                                "reconstruction_error"

                            )



                            if autoencoder_result



                            else None

                        ),

                )

            )





            if autoencoder_result_id is not None:



                result[

                    "model_result_ids"

                ][

                    "autoencoder"

                ] = autoencoder_result_id





            logger.debug(



                "PROCESS MULTI-AI | "

                "Record=%s | "

                "PID=%s | "

                "Process=%s | "

                "IF=%s/%s | "

                "AE=%s/%s",



                record_id,



                process_info.get(

                    "pid"

                ),



                process_info.get(

                    "name"

                ),



                (

                    isolation_result.get(

                        "anomaly_confidence"

                    )



                    if isolation_result



                    else None

                ),



                (

                    isolation_result.get(

                        "anomaly_label"

                    )



                    if isolation_result



                    else None

                ),



                (

                    autoencoder_result.get(

                        "anomaly_confidence"

                    )



                    if autoencoder_result



                    else None

                ),



                (

                    autoencoder_result.get(

                        "anomaly_label"

                    )



                    if autoencoder_result



                    else None

                ),

            )





            return result





        except Exception as error:



            logger.warning(



                "Multi-model process AI failed | "

                "PID=%s | "

                "Process=%s | "

                "Error=%s",



                process_info.get(

                    "pid"

                ),



                process_info.get(

                    "name"

                ),



                error,

            )





            result[

                "error"

            ] = str(

                error

            )





            return result





    # ============================================================

    # FUSION V2

    # ============================================================



    def calculate_fusion(



        self,



        behavior_result: dict,



        anomaly_result: dict,



        isolation_result: dict | None,



        autoencoder_result: dict | None,



    ) -> dict:



        return (



            self.fusion_engine.fuse(



                behavior_result=

                    behavior_result,



                anomaly_result=

                    anomaly_result,



                isolation_result=

                    isolation_result,



                autoencoder_result=

                    autoencoder_result,

            )

        )




    # ============================================================
    # CLASSIFY PROCESS THREAT
    # ============================================================

    # ============================================================
    # CLASSIFY PROCESS THREAT
    # ============================================================

    def classify_process_threat(
        self,
        process_info: dict,
    ) -> str:

        if not isinstance(
            process_info,
            dict,
        ):

            process_info = {}


        # ========================================================
        # PROCESS NAME
        # ========================================================

        raw_name = str(

            process_info.get(
                "name"
            )

            or process_info.get(
                "process_name"
            )

            or process_info.get(
                "exe"
            )

            or ""
        ).strip().lower()


        raw_name = (
            raw_name.replace(
                "/",
                "\\",
            )
        )


        process_name = (
            raw_name.rsplit(
                "\\",
                1,
            )[-1]
        )


        # ========================================================
        # PARENT NAME
        # ========================================================

        raw_parent = str(

            process_info.get(
                "parent_name"
            )

            or process_info.get(
                "parent_process"
            )

            or ""
        ).strip().lower()


        raw_parent = (
            raw_parent.replace(
                "/",
                "\\",
            )
        )


        parent_name = (
            raw_parent.rsplit(
                "\\",
                1,
            )[-1]
        )


        # ========================================================
        # COMMAND LINE
        # ========================================================

        raw_command = (

            process_info.get(
                "cmdline"
            )

            or process_info.get(
                "command_line"
            )

            or ""
        )


        if isinstance(
            raw_command,
            (
                list,
                tuple,
            ),
        ):

            command_line = " ".join(

                str(value)

                for value
                in raw_command

            ).lower()

        else:

            command_line = str(
                raw_command
            ).lower()


        # ========================================================
        # COMMON FLAGS
        # ========================================================

        has_url = any(

            marker
            in command_line

            for marker
            in (
                "http://",
                "https://",
            )
        )


        encoded = any(

            marker
            in command_line

            for marker
            in (
                "-encodedcommand",
                "-encoded-command",
                "-enc ",
                "frombase64string",
            )
        )


        hidden = any(

            marker
            in command_line

            for marker
            in (
                "-windowstyle hidden",
                "-window hidden",
                "-w hidden",
            )
        )


        download = any(

            marker
            in command_line

            for marker
            in (
                "downloadstring",
                "invoke-webrequest",
                "invoke-restmethod",
                "start-bitstransfer",
            )
        )


        execute = any(

            marker
            in command_line

            for marker
            in (
                "invoke-expression",
                "iex ",
                "iex(",
            )
        )


        document_parent = (

            parent_name
            in {
                "winword.exe",
                "excel.exe",
                "powerpnt.exe",
                "outlook.exe",
            }
        )


        powershell = (

            process_name
            in {
                "powershell.exe",
                "powershell",
                "pwsh.exe",
                "pwsh",
            }
        )


        # ========================================================
        # DOCUMENT → PROCESS CHAINS
        # ========================================================

        if (
            document_parent

            and

            process_name
            == "cmd.exe"

            and

            encoded
        ):

            return (
                "DOCUMENT_TO_CMD"
            )


        if (
            document_parent

            and

            powershell

            and

            encoded
        ):

            return (
                "DOCUMENT_TO_POWERSHELL"
            )


        if (
            document_parent

            and

            process_name
            == "wscript.exe"

            and

            has_url
        ):

            return (
                "DOCUMENT_TO_WSCRIPT"
            )


        if (
            document_parent

            and

            process_name
            == "cscript.exe"

            and

            has_url
        ):

            return (
                "DOCUMENT_TO_CSCRIPT"
            )


        if (
            document_parent

            and

            process_name
            == "mshta.exe"

            and

            has_url
        ):

            return (
                "DOCUMENT_TO_MSHTA"
            )


        # ========================================================
        # CERTUTIL
        # ========================================================

        if (
            process_name
            == "certutil.exe"

            and

            has_url

            and

            "-urlcache"
            in command_line
        ):

            return (
                "CERTUTIL_DOWNLOAD"
            )


        # ========================================================
        # BITSADMIN
        # ========================================================

        if (
            process_name
            == "bitsadmin.exe"

            and

            has_url

            and

            "/transfer"
            in command_line
        ):

            return (
                "BITSADMIN_TRANSFER"
            )


        # ========================================================
        # RUNDLL32
        # ========================================================

        if (
            process_name
            == "rundll32.exe"

            and

            any(

                marker
                in command_line

                for marker
                in (
                    "javascript:",
                    "vbscript:",
                    "mshtml,runhtmlapplication",
                )
            )
        ):

            return (
                "RUNDLL32_SCRIPT_EXECUTION"
            )


        # ========================================================
        # REGSVR32
        # ========================================================

        if (
            process_name
            == "regsvr32.exe"

            and

            has_url

            and

            "/i:"
            in command_line

            and

            "scrobj.dll"
            in command_line
        ):

            return (
                "REGSVR32_REMOTE_SCRIPTLET"
            )


        # ========================================================
        # REMOTE SCRIPT ENGINES
        # ========================================================

        if (
            process_name
            == "mshta.exe"

            and

            has_url
        ):

            return (
                "MSHTA_REMOTE_PAYLOAD"
            )


        if (
            process_name
            == "wscript.exe"

            and

            has_url
        ):

            return (
                "WSCRIPT_REMOTE_SCRIPT"
            )


        if (
            process_name
            == "cscript.exe"

            and

            has_url
        ):

            return (
                "CSCRIPT_REMOTE_SCRIPT"
            )


        # ========================================================
        # POWERSHELL
        # ========================================================

        if (
            powershell

            and

            download

            and

            execute
        ):

            return (
                "POWERSHELL_DOWNLOAD_EXECUTION"
            )


        if (
            powershell

            and

            encoded

            and

            hidden
        ):

            return (
                "HIDDEN_ENCODED_POWERSHELL"
            )


        if (
            powershell

            and

            encoded
        ):

            return (
                "ENCODED_POWERSHELL"
            )


        if (
            powershell

            and

            hidden
        ):

            return (
                "HIDDEN_POWERSHELL"
            )


        # ========================================================
        # DOCUMENT PARENT WITHOUT EXTRA INDICATOR
        # ========================================================

        if (
            document_parent

            and

            process_name
            == "cmd.exe"
        ):

            return (
                "DOCUMENT_TO_CMD"
            )


        if (
            document_parent

            and

            process_name
            == "wscript.exe"
        ):

            return (
                "DOCUMENT_TO_WSCRIPT"
            )


        if (
            document_parent

            and

            process_name
            == "cscript.exe"
        ):

            return (
                "DOCUMENT_TO_CSCRIPT"
            )


        if (
            document_parent

            and

            process_name
            == "mshta.exe"
        ):

            return (
                "DOCUMENT_TO_MSHTA"
            )


        # ========================================================
        # CMD → ENCODED POWERSHELL
        # ========================================================

        if (
            process_name
            == "cmd.exe"

            and

            encoded
        ):

            return (
                "CMD_TO_ENCODED_POWERSHELL"
            )


        return (
            "SUSPICIOUS_PROCESS_BEHAVIOR"
        )
    # ============================================================
    # SAVE FINAL FUSION DETECTION

    # ============================================================



    def save_fusion_detection(
        self,
        event,
        process_info: dict,
        fusion_result: dict,
        feature_record_id: int | None,
    ) -> None:


        if not fusion_result.get(

            "suspicious",

            False,
        ):

            return

        primary_engine = (

            fusion_result.get(
                "primary_engine"
            )

            or fusion_result.get(
                "fusion_name"
            )

            or "process_threat_fusion_v3"
        )


        threat_type = (
            self.classify_process_threat(
                process_info
            )
        )
        ai_consensus = (



            fusion_result.get(

                "ai_consensus"

            )



            or {}

        )





        detection = {



            # ====================================================

            # DETECTION IDENTITY

            # ====================================================



            "engine":
                primary_engine,

            "detected":
                True,

            "threat_type":
                threat_type,

            "detection_type":
                threat_type,



            "risk":

                int(

                    round(



                        fusion_result.get(

                            "fusion_score",

                            0,

                        )

                    )

                ),



            "risk_score":

                int(

                    round(



                        fusion_result.get(

                            "fusion_score",

                            0,

                        )

                    )

                ),



            "severity":

                fusion_result.get(

                    "severity",

                    "INFO",

                ),





            # ====================================================

            # PROCESS

            # ====================================================



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





            # ====================================================

            # SECURITY CATEGORIES

            # ====================================================



            "rule_score":

                fusion_result.get(

                    "rule_score"

                ),



            "statistical_score":

                fusion_result.get(

                    "statistical_score"

                ),



            "behavioral_ai_consensus_score":

                fusion_result.get(

                    "ai_consensus_score"

                ),





            # ====================================================

            # INDIVIDUAL AI MODELS

            # ====================================================



            "isolation_forest_score":

                ai_consensus.get(

                    "isolation_forest_score"

                ),



            "autoencoder_score":

                ai_consensus.get(

                    "autoencoder_score"

                ),



            "ai_average_score":

                ai_consensus.get(

                    "average_score"

                ),



            "ai_agreement":

                ai_consensus.get(

                    "agreement"

                ),



            "ai_agreement_difference":

                ai_consensus.get(

                    "agreement_difference"

                ),



            "ai_disagreement":

                ai_consensus.get(

                    "disagreement"

                ),



            "ai_both_active":

                ai_consensus.get(

                    "both_active"

                ),



            "ai_both_strong":

                ai_consensus.get(

                    "both_strong"

                ),



            "ai_confidence":

                ai_consensus.get(

                    "confidence"

                ),



            "ai_consensus_label":

                ai_consensus.get(

                    "consensus_label"

                ),





            # ====================================================

            # FINAL FUSION

            # ====================================================



            "fusion_score":

                fusion_result.get(

                    "fusion_score"

                ),



            "evidence_confidence":

                fusion_result.get(

                    "evidence_confidence"

                ),



            "active_signal_count":

                fusion_result.get(

                    "active_signal_count"

                ),



            "strong_signal_count":

                fusion_result.get(

                    "strong_signal_count"

                ),



            "active_signals":

                fusion_result.get(

                    "active_signals"

                ),



            "strong_signals":

                fusion_result.get(

                    "strong_signals"

                ),



            "critical_allowed":

                fusion_result.get(

                    "critical_allowed"

                ),



            "ai_disagreement_penalty":

                fusion_result.get(

                    "ai_disagreement_penalty"

                ),



            "ai_internal_bonus":

                fusion_result.get(

                    "ai_internal_bonus"

                ),



            "agreement_bonus":

                fusion_result.get(

                    "agreement_bonus"

                ),



            "strong_bonus":

                fusion_result.get(

                    "strong_bonus"

                ),



            "reasons":

                fusion_result.get(

                    "reasons",

                    [],

                ),





            # ====================================================

            # EVIDENCE

            # ====================================================



            "behavior_indicators":

                fusion_result.get(

                    "behavior_indicators",

                    [],

                ),



            "statistical_indicators":

                fusion_result.get(

                    "statistical_indicators",

                    [],

                ),



            "feature_record_id":

                feature_record_id,

        }





        try:



            save_detection(



                event.event_id,



                detection,

            )





            logger.info(



                "PROCESS FUSION DETECTION | "

                "PID=%s | "

                "Process=%s | "

                "Rule=%s | "

                "Stat=%s | "

                "IF=%s | "

                "AE=%s | "

                "AIConsensus=%s | "

                "Fusion=%s | "

                "Severity=%s",



                process_info.get(

                    "pid"

                ),



                process_info.get(

                    "name"

                ),



                fusion_result.get(

                    "rule_score"

                ),



                fusion_result.get(

                    "statistical_score"

                ),



                ai_consensus.get(

                    "isolation_forest_score"

                ),



                ai_consensus.get(

                    "autoencoder_score"

                ),



                fusion_result.get(

                    "ai_consensus_score"

                ),



                fusion_result.get(

                    "fusion_score"

                ),



                fusion_result.get(

                    "severity"

                ),

            )





        except Exception as error:



            logger.error(



                "Unable to save Fusion v2 detection | "

                "EventID=%s | "

                "Error=%s",



                event.event_id,



                error,

            )





    # ============================================================

    # ALERT COOLDOWN

    # ============================================================



    def fusion_alert_allowed(

        self,

        pid,

    ) -> bool:



        if pid is None:



            return True





        last_alert = (



            self.last_fusion_alert_time.get(

                pid

            )

        )





        if last_alert is None:



            return True





        return (



            time.time()

            - last_alert



            >= self.fusion_alert_cooldown_seconds

        )





    # ============================================================

    # PERIODIC FUSION ALERT

    # ============================================================



    def emit_periodic_fusion_alert(



        self,



        process_info: dict,



        fusion_result: dict,



        isolation_result: dict | None,



        autoencoder_result: dict | None,



        feature_record_id: int | None,



        context: dict,



    ) -> None:





        if not fusion_result.get(

            "should_alert",

            False,

        ):



            return





        # ========================================================

        # WINDOWS SYSTEM IDLE PROCESS SAFEGUARD

        # ========================================================

        #

        # PID 0 represents the Windows System Idle Process.

        #

        # It does not have the same process characteristics

        # as an ordinary executable.

        #

        # Anomaly scores for PID 0 must not independently

        # generate process-fusion security alerts.

        #

        # This safeguard affects alert emission only.

        # Existing process telemetry, feature collection,

        # and model evaluation are preserved.

        # ========================================================



        pid = process_info.get("pid")



        if pid is not None and str(pid).strip() == "0":



            logger.debug(

                "FUSION ALERT SUPPRESSED | "

                "PID=0 | "

                "Process=System Idle Process | "

                "Score=%s | "

                "Reason=Special Windows process",

                fusion_result.get("fusion_score"),

            )



            return



        # ========================================================

        # EXISTING ALERT COOLDOWN

        # ========================================================



        if not self.fusion_alert_allowed(pid):

            return





        ai_consensus = (



            fusion_result.get(

                "ai_consensus"

            )



            or {}

        )





        process_data = dict(

            process_info

        )





        process_data.update(

            {



                # ----------------------------------------------

                # FINAL FUSION

                # ----------------------------------------------



                "fusion_version":

                    "v2",



                "fusion_score":

                    fusion_result.get(

                        "fusion_score"

                    ),



                "fusion_severity":

                    fusion_result.get(

                        "severity"

                    ),



                "fusion_confidence":

                    fusion_result.get(

                        "evidence_confidence"

                    ),



                "fusion_reasons":

                    fusion_result.get(

                        "reasons",

                        [],

                    ),





                # ----------------------------------------------

                # AI CONSENSUS

                # ----------------------------------------------



                "ai_consensus_score":

                    fusion_result.get(

                        "ai_consensus_score"

                    ),



                "ai_consensus":

                    ai_consensus,





                # ----------------------------------------------

                # RAW MODEL RESULTS

                # ----------------------------------------------



                "isolation_forest":

                    isolation_result,



                "autoencoder":

                    autoencoder_result,





                # ----------------------------------------------

                # FEATURE DATA

                # ----------------------------------------------



                "ai_feature_record_id":

                    feature_record_id,



                "ai_behavior_context":

                    context,

            }

        )





        event = (



            self.telemetry.emit(



                event_type=

                    "process_fusion_detection",



                source=

                    "process_threat_fusion_v2",



                severity=

                    fusion_result.get(

                        "severity",

                        "HIGH",

                    ),



                process=

                    process_data,



                metadata={



                    "collector":

                        "ProcessMonitor",



                    "fusion_version":

                        "v2",



                    "rule_score":

                        fusion_result.get(

                            "rule_score"

                        ),



                    "statistical_score":

                        fusion_result.get(

                            "statistical_score"

                        ),



                    "isolation_forest_score":

                        ai_consensus.get(

                            "isolation_forest_score"

                        ),



                    "autoencoder_score":

                        ai_consensus.get(

                            "autoencoder_score"

                        ),



                    "ai_consensus_score":

                        fusion_result.get(

                            "ai_consensus_score"

                        ),



                    "ai_agreement":

                        ai_consensus.get(

                            "agreement"

                        ),



                    "ai_disagreement":

                        ai_consensus.get(

                            "disagreement"

                        ),



                    "fusion_score":

                        fusion_result.get(

                            "fusion_score"

                        ),



                    "evidence_confidence":

                        fusion_result.get(

                            "evidence_confidence"

                        ),



                    "critical_allowed":

                        fusion_result.get(

                            "critical_allowed"

                        ),



                    "feature_record_id":

                        feature_record_id,

                },

            )

        )





        self.save_fusion_detection(



            event=

                event,



            process_info=

                process_info,



            fusion_result=

                fusion_result,



            feature_record_id=

                feature_record_id,

        )





        if pid is not None:



            self.last_fusion_alert_time[

                pid

            ] = time.time()





        logger.warning(



            "LIVE FUSION V2 ALERT | "

            "PID=%s | "

            "Process=%s | "

            "IF=%s | "

            "AE=%s | "

            "AIConsensus=%s | "

            "Agreement=%s | "

            "Fusion=%s | "

            "Severity=%s",



            pid,



            process_info.get(

                "name"

            ),



            ai_consensus.get(

                "isolation_forest_score"

            ),



            ai_consensus.get(

                "autoencoder_score"

            ),



            fusion_result.get(

                "ai_consensus_score"

            ),



            ai_consensus.get(

                "agreement"

            ),



            fusion_result.get(

                "fusion_score"

            ),



            fusion_result.get(

                "severity"

            ),

        )





    # ============================================================

    # PROCESS START

    # ============================================================



    def handle_process_start(



        self,



        process_info: dict,
 
    ):


        # ========================================================
        # VALIDATION MODE — LIVE TELEMETRY ONLY
        #
        # Real endpoint processes must remain visible in
        # Live Monitor, but they must NOT run through:
        #
        #   Rules
        #   Statistical detector
        #   Isolation Forest
        #   Autoencoder
        #   Temporal Transformer
        #   Fusion
        #
        # Controlled synthetic scenarios will exercise those
        # engines separately.
        # ========================================================

        if IS_VALIDATION_MODE:

            event = (
                self.telemetry.emit(

                    event_type=
                        "process_start",

                    source=
                        "process_monitor",

                    severity=
                        "INFO",

                    process=
                        dict(
                            process_info
                        ),

                    metadata={

                        "collector":
                            "ProcessMonitor",

                        "runtime_path":
                            "LIVE_ONLY",

                        "detection_pipeline":
                            "DISABLED_DURING_VALIDATION",
                    },
                )
            )


            logger.info(

                "PROCESS_START LIVE_ONLY | "
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


            return event
        # ========================================================

        # RULE DETECTOR

        # ========================================================



        behavior_result = (



            self.behavior_detector.analyze(

                process_info

            )

        )





        # ========================================================

        # STATISTICAL DETECTOR

        # ========================================================



        anomaly_result = (



            self.anomaly_detector.analyze(

                process_info

            )

        )





        pid = (

            process_info.get(

                "pid"

            )

        )





        ppid = (

            process_info.get(

                "ppid"

            )

        )





        # ========================================================

        # BEHAVIORAL CONTEXT

        # ========================================================



        try:



            shared_process_behavior_context.record_process_activity(

                pid

            )





            shared_process_behavior_context.record_child_process(

                ppid

            )





            context = (



                shared_process_behavior_context

                .get_context(

                    pid

                )

            )



        except Exception:



            context = {}





        # ========================================================

        # RUN BOTH AI MODELS

        # ========================================================



        ai_result = (



            self.collect_ai_behavior_features(



                process_info=

                    process_info,



                context=

                    context,

            )

        )





        feature_record_id = (

            ai_result.get(

                "record_id"

            )

        )





        isolation_result = (

            ai_result.get(

                "isolation_forest"

            )

        )





        autoencoder_result = (

            ai_result.get(

                "autoencoder"

            )

        )





        # ========================================================

        # FUSION V2

        # ========================================================



        fusion_result = (



            self.calculate_fusion(



                behavior_result=

                    behavior_result,



                anomaly_result=

                    anomaly_result,



                isolation_result=

                    isolation_result,



                autoencoder_result=

                    autoencoder_result,

            )

        )





        ai_consensus = (



            fusion_result.get(

                "ai_consensus"

            )



            or {}

        )





        # ========================================================

        # EVENT DATA

        # ========================================================



        process_data = dict(

            process_info

        )





        process_data.update(

            {



                # ----------------------------------------------

                # RULE ENGINE

                # ----------------------------------------------



                "behavior_score":

                    fusion_result.get(

                        "rule_score"

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

                # STATISTICAL ENGINE

                # ----------------------------------------------



                "statistical_score":

                    fusion_result.get(

                        "statistical_score"

                    ),



                "statistical_indicators":

                    anomaly_result.get(

                        "indicators",

                        [],

                    ),



                "statistical_reasons":

                    anomaly_result.get(

                        "reasons",

                        [],

                    ),





                # ----------------------------------------------

                # FEATURE RECORD

                # ----------------------------------------------



                "ai_feature_record_id":

                    feature_record_id,



                "ai_feature_schema":

                    PROCESS_FEATURE_SCHEMA_VERSION,



                "model_result_ids":

                    ai_result.get(

                        "model_result_ids",

                        {},

                    ),





                # ----------------------------------------------

                # RAW AI RESULTS

                # ----------------------------------------------



                "isolation_forest":

                    isolation_result,



                "autoencoder":

                    autoencoder_result,





                # ----------------------------------------------

                # DUAL AI

                # ----------------------------------------------



                "ai_consensus":

                    ai_consensus,



                "ai_consensus_score":

                    fusion_result.get(

                        "ai_consensus_score"

                    ),



                "ai_agreement":

                    ai_consensus.get(

                        "agreement"

                    ),



                "ai_disagreement":

                    ai_consensus.get(

                        "disagreement"

                    ),





                # ----------------------------------------------

                # FINAL FUSION

                # ----------------------------------------------



                "fusion_version":

                    "v2",



                "fusion_score":

                    fusion_result.get(

                        "fusion_score"

                    ),



                "fusion_severity":

                    fusion_result.get(

                        "severity"

                    ),



                "fusion_suspicious":

                    fusion_result.get(

                        "suspicious"

                    ),



                "fusion_confidence":

                    fusion_result.get(

                        "evidence_confidence"

                    ),



                "critical_allowed":

                    fusion_result.get(

                        "critical_allowed"

                    ),



                "fusion_reasons":

                    fusion_result.get(

                        "reasons",

                        [],

                    ),

            }

        )





        # ========================================================

        # PROCESS START EVENT

        # ========================================================



        event = (



            self.telemetry.emit(



                event_type=

                    "process_start",



                source=

                    "process_monitor",



                severity=

                    fusion_result.get(

                        "severity",

                        "INFO",

                    ),



                process=

                    process_data,



                metadata={



                    "collector":

                        "ProcessMonitor",



                    "fusion_version":

                        "v2",



                    "rule_score":

                        fusion_result.get(

                            "rule_score"

                        ),



                    "statistical_score":

                        fusion_result.get(

                            "statistical_score"

                        ),



                    "isolation_forest_score":

                        ai_consensus.get(

                            "isolation_forest_score"

                        ),



                    "autoencoder_score":

                        ai_consensus.get(

                            "autoencoder_score"

                        ),



                    "ai_consensus_score":

                        fusion_result.get(

                            "ai_consensus_score"

                        ),



                    "ai_agreement":

                        ai_consensus.get(

                            "agreement"

                        ),



                    "ai_disagreement":

                        ai_consensus.get(

                            "disagreement"

                        ),



                    "fusion_score":

                        fusion_result.get(

                            "fusion_score"

                        ),



                    "evidence_confidence":

                        fusion_result.get(

                            "evidence_confidence"

                        ),



                    "critical_allowed":

                        fusion_result.get(

                            "critical_allowed"

                        ),



                    "feature_record_id":

                        feature_record_id,

                },

            )

        )





        # ========================================================

        # STORE FINAL DETECTION

        # ========================================================



        self.save_fusion_detection(



            event=

                event,



            process_info=

                process_info,



            fusion_result=

                fusion_result,



            feature_record_id=

                feature_record_id,

        )





        logger.info(



            "PROCESS_START V2 | "

            "PID=%s | "

            "Process=%s | "

            "Rule=%s | "

            "Stat=%s | "

            "IF=%s | "

            "AE=%s | "

            "AIConsensus=%s | "

            "Agreement=%s | "

            "Fusion=%s | "

            "Severity=%s",



            pid,



            process_info.get(

                "name"

            ),



            fusion_result.get(

                "rule_score"

            ),



            fusion_result.get(

                "statistical_score"

            ),



            ai_consensus.get(

                "isolation_forest_score"

            ),



            ai_consensus.get(

                "autoencoder_score"

            ),



            fusion_result.get(

                "ai_consensus_score"

            ),



            ai_consensus.get(

                "agreement"

            ),



            fusion_result.get(

                "fusion_score"

            ),



            fusion_result.get(

                "severity"

            ),

        )





    # ============================================================

    # PROCESS STOP

    # ============================================================



    def handle_process_stop(



        self,



        process_info: dict,



    ):





        event = (



            self.telemetry.emit(



                event_type=

                    "process_stop",



                source=

                    "process_monitor",



                severity=

                    "INFO",



                process=

                    process_info,



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

    # PERIODIC LIVE INTELLIGENCE

    # ============================================================



    def sample_process_intelligence(
        self,
        current_processes: dict,
    ) -> None:
        # ========================================================
        # VALIDATION MODE
        #
        # Periodic model inference belongs to controlled synthetic
        # validation, not the real endpoint while validation mode
        # is active.
        # ========================================================

        if IS_VALIDATION_MODE:

            return
        now = time.time()

        for (

            pid,

            process_info,

        ) in current_processes.items():





            last_sample = (



                self.last_ai_feature_sample.get(

                    pid,

                    0.0,

                )

            )





            if (



                now

                - last_sample



                < self.ai_feature_sample_interval



            ):



                continue





            try:



                # =================================================

                # UPDATE CONTEXT

                # =================================================



                shared_process_behavior_context.record_process_activity(

                    pid

                )





                context = (



                    shared_process_behavior_context

                    .get_context(

                        pid

                    )

                )





                # =================================================

                # RULES

                # =================================================



                behavior_result = (



                    self.behavior_detector.analyze(

                        process_info

                    )

                )





                # =================================================

                # STATISTICAL

                # =================================================



                anomaly_result = (



                    self.anomaly_detector.analyze(

                        process_info

                    )

                )





                # =================================================

                # DUAL AI

                # =================================================



                ai_result = (



                    self.collect_ai_behavior_features(



                        process_info=

                            process_info,



                        context=

                            context,

                    )

                )





                record_id = (

                    ai_result.get(

                        "record_id"

                    )

                )





                isolation_result = (

                    ai_result.get(

                        "isolation_forest"

                    )

                )





                autoencoder_result = (

                    ai_result.get(

                        "autoencoder"

                    )

                )





                # =================================================

                # FUSION V2

                # =================================================



                fusion_result = (



                    self.calculate_fusion(



                        behavior_result=

                            behavior_result,



                        anomaly_result=

                            anomaly_result,



                        isolation_result=

                            isolation_result,



                        autoencoder_result=

                            autoencoder_result,

                    )

                )





                # =================================================

                # ALERT IF REQUIRED

                # =================================================



                self.emit_periodic_fusion_alert(



                    process_info=

                        process_info,



                    fusion_result=

                        fusion_result,



                    isolation_result=

                        isolation_result,



                    autoencoder_result=

                        autoencoder_result,



                    feature_record_id=

                        record_id,



                    context=

                        context,

                )





                # Record each attempted sample, including ineligible
                # observations. Otherwise PID 0/PID 4 are reprocessed
                # on every 2-second poll rather than every 15 seconds.
                # Start/stop telemetry and rule detection are unchanged.
                self.last_ai_feature_sample[pid] = now





            except Exception as error:



                logger.debug(



                    "Periodic Fusion v2 inference failed | "

                    "PID=%s | "

                    "Error=%s",



                    pid,



                    error,

                )





    # ============================================================

    # INITIALIZATION

    # ============================================================



    def initialize(

        self,

    ):
        
        logger.info(

            "Building initial process baseline..."

        )

        # ========================================================
        # VALIDATION MODE
        #
        # Establish only the PID snapshot necessary to detect
        # future process starts/stops.
        #
        # Do NOT:
        #
        #   seed statistical history
        #   extract AI features
        #   run IF / AE
        #   run Temporal AI
        #   run Fusion
        #
        # on the real endpoint.
        # ========================================================

        if IS_VALIDATION_MODE:

            self.previous_processes = (
                self.get_process_snapshot()
            )


            self.last_ai_feature_sample.clear()


            logger.warning(
                "Process detector validation isolation ACTIVE | "
                "Live processes=%s | "
                "Rules=OFF | "
                "Statistical=OFF | "
                "IF=OFF | "
                "AE=OFF | "
                "Temporal=OFF | "
                "Fusion=OFF",

                len(
                    self.previous_processes
                ),
            )


            return
        # ========================================================

        # ISOLATION FOREST STATUS

        # ========================================================



        isolation_status = (



            self.isolation_forest_predictor

            .get_status()

        )





        logger.info(



            "Isolation Forest | "

            "Available=%s | "

            "Version=%s | "

            "Features=%s",



            isolation_status.get(

                "available"

            ),



            isolation_status.get(

                "model_version"

            ),



            isolation_status.get(

                "feature_count"

            ),

        )





        # ========================================================

        # AUTOENCODER STATUS

        # ========================================================



        autoencoder_status = (



            self.autoencoder_predictor

            .get_status()

        )





        logger.info(



            "Autoencoder | "

            "Available=%s | "

            "Version=%s | "

            "Activation=%s | "

            "Embedding=%s",



            autoencoder_status.get(

                "available"

            ),



            autoencoder_status.get(

                "model_version"

            ),



            autoencoder_status.get(

                "hidden_activation"

            ),



            autoencoder_status.get(

                "bottleneck_dimension"

            ),

        )





        # ========================================================

        # FUSION STATUS

        # ========================================================



        logger.info(



            "Process Threat Fusion | "

            "Version=v2 | "

            "Dual-AI consensus ENABLED"

        )





        # ========================================================

        # CURRENT PROCESSES

        # ========================================================



        self.previous_processes = (

            self.get_process_snapshot()

        )





        stored_records = 0





        for process_info in (

            self.previous_processes.values()

        ):



            try:



                # ------------------------------------------------

                # Initialize statistical history

                # ------------------------------------------------



                self.anomaly_detector.analyze(

                    process_info

                )





                pid = (

                    process_info.get(

                        "pid"

                    )

                )





                ppid = (

                    process_info.get(

                        "ppid"

                    )

                )





                # ------------------------------------------------

                # Context

                # ------------------------------------------------



                shared_process_behavior_context.record_process_activity(

                    pid

                )





                shared_process_behavior_context.record_child_process(

                    ppid

                )





                context = (



                    shared_process_behavior_context

                    .get_context(

                        pid

                    )

                )





                # ------------------------------------------------

                # Store features + both AI model results.

                #

                # Important:

                # Initialization does NOT emit security alerts.

                # ------------------------------------------------



                ai_result = (



                    self.collect_ai_behavior_features(



                        process_info=

                            process_info,



                        context=

                            context,

                    )

                )





                record_id = (

                    ai_result.get(

                        "record_id"

                    )

                )





                if record_id is not None:



                    stored_records += 1





                    self.last_ai_feature_sample[

                        pid

                    ] = time.time()





            except Exception as error:



                logger.debug(



                    "Unable to initialize process AI | "

                    "Error=%s",



                    error,

                )





        logger.info(



            "Initial process baseline contains %s processes.",



            len(

                self.previous_processes

            ),

        )





        logger.info(



            "Dual-AI behavior records initialized: %s",



            stored_records,

        )





        logger.info(



            "LIVE PROCESS INTELLIGENCE:"

        )





        logger.info(



            "Rules + Statistical + "

            "IsolationForest + AutoencoderV2 + FusionV2"

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





        # ========================================================

        # PERIODIC INTELLIGENCE

        # ========================================================



        self.sample_process_intelligence(

            current_processes

        )





        previous_pids = set(

            self.previous_processes.keys()

        )





        current_pids = set(

            current_processes.keys()

        )





        # ========================================================

        # STARTED

        # ========================================================



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





                self.last_ai_feature_sample[

                    pid

                ] = time.time()





        # ========================================================

        # STOPPED

        # ========================================================



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





            shared_process_behavior_context.remove_process(

                pid

            )





            self.last_ai_feature_sample.pop(

                pid,

                None,

            )





            self.last_fusion_alert_time.pop(

                pid,

                None,

            )





        self.previous_processes = (

            current_processes

        )





    # ============================================================

    # START

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





        logger.info(



            "Dual-AI inference interval: %.1f seconds",



            self.ai_feature_sample_interval,

        )





        logger.info(



            "Fusion alert cooldown: %.1f seconds",



            self.fusion_alert_cooldown_seconds,

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

    # STOP

    # ============================================================



    def stop(

        self,

    ):



        self.running = False





        logger.info(



            "SENTINEL-X Process Monitor stopped."

        )





# ================================================================

# MANUAL RUN

# ================================================================



if __name__ == "__main__":



    monitor = (

        ProcessMonitor(

            poll_interval=2.0

        )

    )

    monitor.start()