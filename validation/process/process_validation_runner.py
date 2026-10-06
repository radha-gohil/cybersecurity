from __future__ import annotations

import json
import sqlite3
import time

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
# HELPERS
# ================================================================

def compact_result(
    result,
    keys,
):

    if not isinstance(
        result,
        dict,
    ):
        return None

    return {

        key:
            result.get(
                key
            )

        for key in keys
    }


def database_count(
    table_name: str,
) -> int:

    connection = sqlite3.connect(
        ACTIVE_SOC_DATABASE_PATH
    )

    try:

        return int(
            connection.execute(
                f"""
                SELECT COUNT(*)
                FROM {table_name}
                """
            ).fetchone()[0]
        )

    finally:

        connection.close()


def event_detection_count(
    event_id: str,
) -> int:

    connection = sqlite3.connect(
        ACTIVE_SOC_DATABASE_PATH
    )

    try:

        return int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM detections
                WHERE event_id = ?
                """,
                (
                    event_id,
                ),
            ).fetchone()[0]
        )

    finally:

        connection.close()


def run_p1_03():
    
    if not IS_VALIDATION_MODE:

        raise RuntimeError(
            "P1 validation requires "
            "SENTINEL_RUNTIME_MODE=VALIDATION."
        )


    print(
        "=" * 78
    )

    print(
        "SENTINEL-X PROCESS VALIDATION"
    )

    print(
        "P1-02 — BENIGN POWERSHELL / GET-SERVICE"
    )

    print(
        "=" * 78
    )


    # ============================================================
    # PRIMARY PROCESS ENGINE
    #
    # Deliberately use FusionV3PrimaryProcessMonitor rather than
    # GraphAIProcessMonitor.
    #
    # Graph AI is currently SHADOW evidence and does not influence
    # the authoritative Fusion-v3 decision.
    # ============================================================

    monitor = (
        FusionV3PrimaryProcessMonitor(
            poll_interval=2.0
        )
    )


    # ============================================================
    # SYNTHETIC PROCESS
    # ============================================================

    process_create_time = (
        time.time()
        - 5.0
    )

    process_info = {

        "pid":
            991103,

        "ppid":
            991100,

        "name":
            "powershell.exe",

        "exe":
            (
                r"C:\Windows\System32"
                r"\WindowsPowerShell\v1.0"
                r"\powershell.exe"
            ),

        "cmdline":
            (
                'powershell.exe '
                '-NoLogo '
                '-NoProfile '
                '-Command "'
                'Invoke-WebRequest '
                'https://example.com/file.txt '
                '-OutFile C:\\Temp\\file.txt'
                '"'
            ),

        "username":
            "sentinel-validation",

        "create_time":
            time.time() - 5.0,

        "parent_name":
            "explorer.exe",

        "cpu_percent":
            0.6,

        "memory_percent":
            0.2,

        "rss_mb":
            47.0,

        "num_threads":
            8,

        "num_handles":
            125,
    }

    # ============================================================
    # LIVE COUNTER BEFORE
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
    # 1. RULE ENGINE
    # ============================================================

    rule_result = (
        monitor.behavior_detector
        .analyze(
            process_info
        )
    )


    # ============================================================
    # 2. STATISTICAL ENGINE
    # ============================================================

    statistical_result = (
        monitor.anomaly_detector
        .analyze(
            process_info
        )
    )


    # ============================================================
    # 3. PROCESS CONTEXT
    # ============================================================

    shared_process_behavior_context \
        .record_process_activity(
            process_info[
                "pid"
            ]
        )


    shared_process_behavior_context \
        .record_child_process(
            process_info[
                "ppid"
            ]
        )


    context = (
        shared_process_behavior_context
        .get_context(
            process_info[
                "pid"
            ]
        )
    )


    # ============================================================
    # 4. IF + AE + TEMPORAL V2
    #
    # This also prepares the Fusion-v3 evidence-bridge package.
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
    )


    autoencoder_result = (
        ai_result.get(
            "autoencoder"
        )
    )


    temporal_wrapper = (
        ai_result.get(
            "temporal"
        )

        or {}
    )


    # ============================================================
    # 5. AUTHORITATIVE FUSION V3
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


    # ============================================================
    # 6. BUILD PROCESS EVENT PAYLOAD
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

            "ai_feature_record_id":
                feature_record_id,

            "isolation_forest":
                isolation_result,

            "autoencoder":
                autoencoder_result,

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
    # 7. PERSIST AS SYNTHETIC VALIDATION EVENT
    #
    # This MUST NOT increase Live Monitor counters.
    # ============================================================

    event = (
        shared_telemetry_manager
        .emit_validation(

            scenario_id=
                "P1-03",

            validation_run_id=
                "POWERSHELL-VALIDATION-V1",

            event_type=
                "process_start",

            source=
                "process_validation_runner",

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

                "scenario_name":
                    "PowerShell Invoke-WebRequest Download",

                "expected_detection":
                    False,

                "expected_threat":
                    "SUSPICIOUS_ACTIVITY_LOW",

                "expected_rule_score":
                    30,
            },
        )
    )


    # ============================================================
    # 8. USE REAL DETECTION PERSISTENCE
    #
    # If Fusion says benign, save_fusion_detection() returns
    # without inserting a detection.
    #
    # If Fusion falsely says suspicious, the bad detection is
    # intentionally persisted so we can inspect it.
    # ============================================================

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


    # ============================================================
    # LIVE COUNTER AFTER
    # ============================================================

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


    # ============================================================
    # STORED DETECTION COUNT
    # ============================================================

    stored_detections = (
        event_detection_count(
            event.event_id
        )
    )


    # ============================================================
    # REPORT
    # ============================================================

    print(
        "\n[1] INPUT"
    )

    print(
        json.dumps(
            process_info,
            indent=2,
        )
    )


    print(
        "\n[2] RULE ENGINE"
    )

    print(
        json.dumps(
            rule_result,
            indent=2,
            default=str,
        )
    )


    print(
        "\n[3] STATISTICAL ENGINE"
    )

    print(
        json.dumps(
            statistical_result,
            indent=2,
            default=str,
        )
    )


    print(
        "\n[4] ISOLATION FOREST"
    )

    print(
        json.dumps(
            compact_result(
                isolation_result,
                [
                    "available",
                    "model_name",
                    "model_version",
                    "decision_score",
                    "anomaly_confidence",
                    "anomaly_label",
                    "severity",
                    "should_alert",
                    "candidate_alert",
                ],
            ),
            indent=2,
            default=str,
        )
    )


    print(
        "\n[5] AUTOENCODER"
    )

    print(
        json.dumps(
            compact_result(
                autoencoder_result,
                [
                    "available",
                    "model_name",
                    "model_version",
                    "reconstruction_error",
                    "anomaly_confidence",
                    "anomaly_label",
                    "severity",
                    "should_alert",
                    "candidate_alert",
                ],
            ),
            indent=2,
            default=str,
        )
    )


    print(
        "\n[6] TEMPORAL"
    )

    print(
        json.dumps(
            compact_result(
                temporal_wrapper,
                [
                    "available",
                    "state",
                    "buffer_size",
                    "sequence_length",
                    "temporal_result_id",
                    "temporal_alert_emitted",
                ],
            ),
            indent=2,
            default=str,
        )
    )


    print(
        "\n[7] FUSION V3 PRIMARY"
    )

    print(
        json.dumps(
            compact_result(
                fusion_result,
                [
                    "primary_engine",
                    "fusion_version",
                    "operating_mode",
                    "fusion_score",
                    "severity",
                    "suspicious",
                    "should_alert",
                    "evidence_confidence",
                    "rule_score",
                    "statistical_score",
                    "ai_consensus_score",
                    "temporal_ai_score",
                    "active_signal_count",
                    "strong_signal_count",
                    "active_signals",
                    "strong_signals",
                    "reasons",
                    "promoted_to_primary",
                    "fallback_reason",
                ],
            ),
            indent=2,
            default=str,
        )
    )


    print(
        "\n[8] PERSISTENCE"
    )

    print(
        "Event ID:",
        event.event_id
    )

    print(
        "Event data source:",
        event.metadata.get(
            "data_source"
        )
    )

    print(
        "Stored detections for event:",
        stored_detections
    )

    print(
        "Live counter before:",
        live_before
    )

    print(
        "Live counter after:",
        live_after
    )


    print(
        "\n[9] PROCESS AI TABLE COUNTS"
    )

    for table in [

        "events",

        "detections",

        "process_behavior_features",

        "behavior_model_results",

        "process_temporal_results",

        "process_fusion_v3_results",

    ]:

        try:

            print(
                f"{table:<32}",
                database_count(
                    table
                )
            )

        except sqlite3.OperationalError:

            print(
                f"{table:<32}",
                "TABLE_NOT_PRESENT"
            )


    # ============================================================
    # EXPECTED-vs-ACTUAL
    # ============================================================

    rule_pass = (

        rule_result.get(
            "behavior_score"
        )
        == 30

        and

        not rule_result.get(
            "suspicious",
            False,
        )
    )


    statistical_pass = (

        statistical_result.get(
            "anomaly_score"
        )
        == 0

        and

        not statistical_result.get(
            "anomalous",
            False,
        )
    )


    fusion_pass = (

        not fusion_result.get(
            "should_alert",
            False,
        )

        and

        float(
            fusion_result.get(
                "fusion_score",
                0.0,
            )
            or 0.0
        )
        < 60.0
    )


    persistence_pass = (
        stored_detections
        == 0
    )


    live_isolation_pass = (
        live_after
        == live_before
    )


    overall_pass = all(
        [
            rule_pass,
            statistical_pass,
            fusion_pass,
            persistence_pass,
            live_isolation_pass,
        ]
    )


    print(
        "\n" + "=" * 78
    )

    print(
        "P1-03 EXPECTED vs ACTUAL"
    )

    print(
        "=" * 78
    )

    print(
        "RULE BENIGN:",
        "PASS"
        if rule_pass
        else "FAIL"
    )

    print(
        "STATISTICAL BENIGN:",
        "PASS"
        if statistical_pass
        else "FAIL"
    )

    print(
        "FUSION NO ALERT:",
        "PASS"
        if fusion_pass
        else "FAIL"
    )

    print(
        "NO DETECTION STORED:",
        "PASS"
        if persistence_pass
        else "FAIL"
    )

    print(
        "SYNTHETIC NOT IN LIVE COUNTER:",
        "PASS"
        if live_isolation_pass
        else "FAIL"
    )

    print(
        "-" * 78
    )

    print(
        "P1-03 FINAL:",
        "PASS"
        if overall_pass
        else "FAIL"
    )

    print(
        "=" * 78
    )


    return {

        "scenario_id":
            "P1-03",

        "passed":
            overall_pass,

        "rule":
            rule_result,

        "statistical":
            statistical_result,

        "isolation_forest":
            isolation_result,

        "autoencoder":
            autoencoder_result,

        "temporal":
            temporal_wrapper,

        "fusion":
            fusion_result,

        "event_id":
            event.event_id,

        "stored_detection_count":
            stored_detections,
    }

if __name__ == "__main__":

    run_p1_03()