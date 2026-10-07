from __future__ import annotations
import json
import sqlite3

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path


from config import (
    ACTIVE_SOC_DATABASE_PATH,
    DATA_SOURCE_VALIDATION,
    IS_VALIDATION_MODE,
    VALIDATION_DATABASE_PATH,
)

from endpoint.models.security_event import (
    SecurityEvent,
)

from endpoint.storage.database import (
    initialize_database,
    save_event,
    save_detection,
)

from detection.fusion.incident_store import (
    IncidentStore,
)

from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)

from ai_detection.behavior.process_threat_fusion_v3 import (
    ProcessThreatFusionV3,
)
# ================================================================
# CONSTANTS
# ================================================================

PREFIX = "SYNTH-"

DEVICE_ID = (
    "sentinelx-validation-device"
)

HOSTNAME = (
    "sentinelx-validation-host"
)

SOURCE = (
    "synthetic_validation_demo"
)


# ================================================================
# BASIC HELPERS
# ================================================================

def now_iso():

    return (
        datetime.now(
            timezone.utc
        ).isoformat()
    )


def validation_guard():

    if not IS_VALIDATION_MODE:

        raise RuntimeError(
            "Synthetic demo seed is allowed only "
            "when SENTINEL_RUNTIME_MODE=VALIDATION."
        )


    active = Path(
        ACTIVE_SOC_DATABASE_PATH
    ).resolve()


    expected = Path(
        VALIDATION_DATABASE_PATH
    ).resolve()


    if active != expected:

        raise RuntimeError(
            (
                "Active database is not "
                "sentinel_validation.db.\n"
                f"ACTIVE={active}\n"
                f"EXPECTED={expected}"
            )
        )


# ================================================================
# REMOVE ONLY OUR PREVIOUS SYNTHETIC DEMO DATA
# ================================================================

# ================================================================
# RESET DEDICATED VALIDATION DATABASE
# ================================================================

def reset_validation_database():

    """
    Recreate the dedicated SENTINEL-X validation database
    from a completely clean state.

    IMPORTANT:
    This function is protected by validation_guard().

    It MUST NEVER operate on the live endpoint database.

    Why we reset the whole validation DB:
    - removes previous SYNTH-* records
    - removes PHASE7-E2E validation records
    - removes PowerShell validation-suite records
    - removes old correlated incidents
    - removes previous SOC workflow state
    - removes old tickets/actions/evidence

    This guarantees deterministic Phase-7 product validation.
    """

    # ------------------------------------------------------------
    # SAFETY CHECK
    # ------------------------------------------------------------

    validation_guard()

    database_path = Path(
        ACTIVE_SOC_DATABASE_PATH
    ).resolve()

    expected_path = Path(
        VALIDATION_DATABASE_PATH
    ).resolve()

    if database_path != expected_path:

        raise RuntimeError(
            "Refusing to reset database because the active "
            "database is not the dedicated validation database."
        )

    # ------------------------------------------------------------
    # SQLITE FILES
    # ------------------------------------------------------------

    database_files = [

        database_path,

        Path(
            str(database_path) + "-wal"
        ),

        Path(
            str(database_path) + "-shm"
        ),

        Path(
            str(database_path) + "-journal"
        ),
    ]

    print()

    print(
        "=" * 92
    )

    print(
        "RESETTING SENTINEL-X VALIDATION DATABASE"
    )

    print(
        "=" * 92
    )

    print(
        "Database:",
        database_path,
    )

    # ------------------------------------------------------------
    # DELETE VALIDATION DATABASE + SQLITE SIDECARS
    # ------------------------------------------------------------

    for file_path in database_files:

        if not file_path.exists():

            continue

        try:

            file_path.unlink()

            print(
                "Removed:",
                file_path.name,
            )

        except PermissionError as error:

            raise RuntimeError(
                "\nUnable to reset the validation database.\n\n"
                "The database appears to be in use.\n"
                "Stop the FastAPI backend before running the "
                "synthetic seeder, then try again.\n\n"
                f"Locked file: {file_path}"
            ) from error

        except OSError as error:

            raise RuntimeError(
                "Unable to remove validation database file: "
                f"{file_path}\n"
                f"Reason: {error}"
            ) from error

    print(
        "Validation database reset complete."
    )

    print(
        "=" * 92
    )

    print()
    
# ================================================================
# SAVE ONE SYNTHETIC EVENT
# ================================================================

def add_event(
    *,
    event_id,
    event_type,
    category,
    severity="INFO",
    process=None,
    file=None,
    network=None,
    registry=None,
    metadata=None,
    detection=None,
):

    event_metadata = {

        "event_category":
            category,

        "data_source":
            DATA_SOURCE_VALIDATION,

        "synthetic":
            True,

        "synthetic_validation":
            True,

        "synthetic_demo":
            True,

        "simulation_mode":
            True,

        "device_id":
            DEVICE_ID,

        "hostname":
            HOSTNAME,

        "dataset":
            "FULL_SYNTHETIC_VALIDATION",
    }


    if isinstance(
        metadata,
        dict,
    ):

        event_metadata.update(
            metadata
        )


    event = SecurityEvent(

        event_id=
            event_id,

        event_type=
            event_type,

        source=
            SOURCE,

        device_id=
            DEVICE_ID,

        severity=
            severity,

        process=
            process or {},

        file=
            file or {},

        network=
            network or {},

        registry=
            registry or {},

        metadata=
            event_metadata,
    )


    save_event(
        event
    )


    if isinstance(
        detection,
        dict,
    ):

        save_detection(

            event_id=
                event.event_id,

            detection=
                detection,
        )


    return (
        event.to_dict()
    )


# ================================================================
# DETECTION HELPERS
# ================================================================

def benign_detection(
    engine,
    threat_type,
):

    return {

        "engine":
            engine,

        "detected":
            False,

        "threat_type":
            threat_type,

        "confidence":
            0.99,

        "risk_score":
            0,

        "severity":
            "INFO",

        "reason":
            [
                "Synthetic benign validation case."
            ],
    }


def threat_detection(
    engine,
    threat_type,
    risk,
    severity,
    reason,
):

    return {

        "engine":
            engine,

        "detected":
            True,

        "threat_type":
            threat_type,

        "confidence":
            0.91,

        "risk_score":
            risk,

        "severity":
            severity,

        "reason":
            [
                reason,
                "Synthetic validation metadata only.",
            ],
    }


# ================================================================
# RAW TELEMETRY + DETECTION MATRIX
# ================================================================

def seed_telemetry_matrix():

    rows = []


    # ============================================================
    # PROCESS — BENIGN
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-PROC-BENIGN",

            event_type=
                "process_start",

            category=
                "PROCESS",

            severity=
                "INFO",

            process={
                "pid":
                    4100,

                "name":
                    "notepad.exe",

                "exe":
                    (
                        r"C:\Windows"
                        r"\System32\notepad.exe"
                    ),

                "parent_name":
                    "explorer.exe",
            },

            detection=
                benign_detection(
                    "process_behavior",
                    "BENIGN_PROCESS_ACTIVITY",
                ),
        )
    )


    # ============================================================
    # PROCESS — SUSPICIOUS POWERSHELL
    # ============================================================

    # ============================================================
    # DERIVE POWERSHELL FUSION USING THE REAL CURRENT V3 ENGINE
    #
    # IMPORTANT:
    # The underlying detector/model outputs remain deterministic
    # synthetic validation evidence.
    #
    # But the final Fusion-v3 score, severity, corroboration state,
    # evidence confidence and reasons are calculated by the same
    # ProcessThreatFusionV3 policy used by the runtime.
    #
    # This prevents the product-validation fixture from drifting
    # away from the actual detector policy.
    # ============================================================

    powershell_fusion_engine = (
        ProcessThreatFusionV3()
    )

    powershell_fusion_result = (
        powershell_fusion_engine.calculate(

            rule_result={
                "available":
                    True,

                "score":
                    86,
            },

            statistical_result={
                "available":
                    True,

                "score":
                    18,
            },

            isolation_result={
                "available":
                    True,

                "anomaly_confidence":
                    29.06,
            },

            autoencoder_result={
                "available":
                    True,

                "anomaly_confidence":
                    27.5,
            },

            temporal_result={
                "available":
                    True,

                "score":
                    91,
            },
        )
    )

    powershell_behavioral_consensus = (
        powershell_fusion_result.get(
            "behavioral_ai_consensus"
        )
        or {}
    )
    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-PROC-POWERSHELL",

            event_type=
                "process_fusion_detection",

            category=
                "PROCESS",

            severity=
                powershell_fusion_result.get(
                    "severity",
                    "INFO",
                ),

            process={

                # ------------------------------------------------
                # PROCESS IDENTITY
                # ------------------------------------------------

                "pid":
                    4201,

                "ppid":
                    4190,
                
                "create_time":
                    1791302400.0,

                "name":
                    "powershell.exe",

                "exe":
                    (
                        r"C:\Windows\System32"
                        r"\WindowsPowerShell\v1.0"
                        r"\powershell.exe"
                    ),

                "parent_name":
                    "winword.exe",

                "parent_process_name":
                    "winword.exe",

                "command_line":
                    (
                        "powershell.exe "
                        "-WindowStyle Hidden "
                        "-EncodedCommand "
                        "SYNTHETIC_VALIDATION_ONLY"
                    ),

                # ------------------------------------------------
                # BASIC PROCESS TELEMETRY
                # ------------------------------------------------

                "cpu_percent":
                    1.8,

                "memory_percent":
                    0.4,

                "rss_mb":
                    52.4,

                "num_threads":
                    9,

                "num_handles":
                    132,

                # ------------------------------------------------
                # RULE / BEHAVIORAL LAYER
                # ------------------------------------------------

                "behavior_score":
                    86,

                "rule_score":
                    86,

                "statistical_score":
                    18,

                "behavior_indicators": [
                    "script_interpreter",
                    "encoded_command_pattern",
                    "hidden_window_pattern",
                    "unusual_parent_process",
                ],

                "behavior_reasons": [
                    (
                        "PowerShell was launched by "
                        "a document-processing application."
                    ),
                    (
                        "The synthetic command contains "
                        "encoded-command behavior."
                    ),
                    (
                        "Hidden PowerShell execution "
                        "behavior is represented."
                    ),
                ],

                # ------------------------------------------------
                # ISOLATION FOREST
                #
                # Deliberately NORMAL.
                # A single anomaly detector is not enough to
                # represent the full threat story.
                # ------------------------------------------------

                "isolation_forest": {

                    "available":
                        True,

                    "model_name":
                        "sentinelx_process_isolation_forest",

                    "model_version":
                        "v1",

                    "schema_version":
                        "process_behavior_v1",

                    "feature_count":
                        19,

                    "decision_score":
                        0.0442,

                    "raw_score":
                        -0.4558,

                    "model_prediction":
                        1,

                    "model_outlier":
                        False,

                    "anomaly_confidence":
                        29.06,

                    "anomaly_label":
                        "NORMAL",

                    "severity":
                        "INFO",

                    "should_alert":
                        False,

                    "feature_deviations": [

                        {
                            "feature":
                                "is_script_interpreter",

                            "value":
                                1,

                            "baseline_mean":
                                0.0281,

                            "baseline_std":
                                0.1653,

                            "deviation_std":
                                5.8789,
                        },

                        {
                            "feature":
                                "command_arg_count",

                            "value":
                                8,

                            "baseline_mean":
                                4.2561,

                            "baseline_std":
                                7.9446,

                            "deviation_std":
                                0.471,
                        },

                        {
                            "feature":
                                "num_handles",

                            "value":
                                132,

                            "baseline_mean":
                                464.0356,

                            "baseline_std":
                                579.8446,

                            "deviation_std":
                                0.5726,
                        },
                    ],

                    "pid":
                        4201,

                    "process_name":
                        "powershell.exe",

                    "parent_process_name":
                        "winword.exe",

                    "executable_path":
                        (
                            r"C:\Windows\System32"
                            r"\WindowsPowerShell\v1.0"
                            r"\powershell.exe"
                        ),

                    "synthetic":
                        True,
                },

                # ------------------------------------------------
                # AUTOENCODER
                #
                # Also deliberately mostly normal.
                # ------------------------------------------------

                "autoencoder": {

                    "available":
                        True,

                    "model_name":
                        "sentinelx_process_autoencoder",

                    "model_version":
                        "v2",

                    "hidden_activation":
                        "tanh",

                    "schema_version":
                        "process_behavior_v1",

                    "feature_count":
                        19,

                    "reconstruction_error":
                        0.0314,

                    "reconstruction_region":
                        "NORMAL_BASELINE",

                    "anomaly_confidence":
                        27.5,

                    "anomaly_label":
                        "NORMAL",

                    "severity":
                        "INFO",

                    "candidate_alert":
                        False,

                    "embedding_dimension":
                        4,

                    "behavior_embedding": [
                        0.94,
                        0.71,
                        0.91,
                        0.42,
                    ],

                    "feature_reconstruction_errors": [

                        {
                            "feature":
                                "command_line_length",

                            "actual_value":
                                91,

                            "reconstructed_value":
                                58.4,

                            "scaled_squared_error":
                                0.083,

                            "absolute_original_difference":
                                32.6,
                        },

                        {
                            "feature":
                                "num_handles",

                            "actual_value":
                                132,

                            "reconstructed_value":
                                410.2,

                            "scaled_squared_error":
                                0.24,

                            "absolute_original_difference":
                                278.2,
                        },
                    ],

                    "pid":
                        4201,

                    "process_name":
                        "powershell.exe",

                    "parent_process_name":
                        "winword.exe",

                    "executable_path":
                        (
                            r"C:\Windows\System32"
                            r"\WindowsPowerShell\v1.0"
                            r"\powershell.exe"
                        ),

                    "synthetic":
                        True,
                },

                # ------------------------------------------------
                # TEMPORAL AI
                #
                # Strong sequential signal.
                # ------------------------------------------------

                "temporal_ai": {

                    "state":
                        "TEMPORAL_INFERENCE_COMPLETE",

                    "available":
                        True,

                    "model_name":
                        "sentinelx_temporal_process_model",

                    "model_version":
                        "v1",

                    "depth":
                        8,

                    "score":
                        91,

                    "temporal_score":
                        91,

                    "severity":
                        "HIGH",

                    "label":
                        "HIGH_ANOMALY",

                    "should_alert":
                        True,

                    "synthetic":
                        True,

                    "reason": (
                        "Synthetic sequential behavior "
                        "matches a suspicious PowerShell "
                        "execution pattern."
                    ),
                },

                # ------------------------------------------------
                # FUSION V3
                #
                # Derived from the current real Fusion-v3 policy.
                # ------------------------------------------------

                "fusion_version":
                    powershell_fusion_result.get(
                        "fusion_version",
                        "v3",
                    ),

                "fusion_score":
                    powershell_fusion_result.get(
                        "fusion_score"
                    ),

                "fusion_severity":
                    powershell_fusion_result.get(
                        "severity"
                    ),

                # ------------------------------------------------
                # Product-level recorded confidence.
                #
                # This remains explicitly non-calibrated in the
                # canonical contract.
                # ------------------------------------------------

                "fusion_confidence":
                    0.91,

                # Actual categorical confidence from Fusion-v3.
                "fusion_evidence_confidence":
                    powershell_fusion_result.get(
                        "evidence_confidence"
                    ),

                "fusion_reasons":
                    list(
                        powershell_fusion_result.get(
                            "reasons",
                            [],
                        )
                    ),

                "critical_allowed":
                    powershell_fusion_result.get(
                        "critical_allowed"
                    ),

                "active_signal_count":
                    powershell_fusion_result.get(
                        "active_signal_count"
                    ),

                "strong_signal_count":
                    powershell_fusion_result.get(
                        "strong_signal_count"
                    ),

                "active_categories":
                    list(
                        powershell_fusion_result.get(
                            "active_categories",
                            [],
                        )
                    ),

                "strong_categories":
                    list(
                        powershell_fusion_result.get(
                            "strong_categories",
                            [],
                        )
                    ),

                # ------------------------------------------------
                # AI CONSENSUS / DISAGREEMENT CONTEXT
                # ------------------------------------------------

                "ai_consensus_score":
                    powershell_behavioral_consensus.get(
                        "consensus_score"
                    ),

                "ai_consensus":
                    powershell_behavioral_consensus.get(
                        "consensus_label"
                    ),

                "ai_behavior_context": {

                    "agreement": [
                        "rules",
                        "temporal_ai",
                    ],

                    "disagreement": (
                        [
                            "behavioral_ai_consensus"
                        ]
                        if powershell_fusion_result.get(
                            "ai_temporal_disagreement"
                        )
                        else []
                    ),

                    "behavioral_ai_consensus":
                        powershell_behavioral_consensus,

                    "temporal_disagreement":
                        bool(
                            powershell_fusion_result.get(
                                "ai_temporal_disagreement",
                                False,
                            )
                        ),

                    "interpretation": (
                        "Rules and temporal evidence are "
                        "suspicious while the point-in-time "
                        "Isolation Forest and Autoencoder "
                        "consensus remains closer to baseline."
                    ),

                    "synthetic":
                        True,
                },
            },

            # ====================================================
            # EVENT / MODEL METADATA
            # ====================================================

            metadata={

                "rule_score":
                    86,

                "statistical_score":
                    18,

                "isolation_forest_score":
                    29.06,

                "autoencoder_score":
                    27.5,

                "temporal_score":
                    91,

                "ai_consensus_score":
                    powershell_behavioral_consensus.get(
                        "consensus_score"
                    ),

                "fusion_score":
                    powershell_fusion_result.get(
                        "fusion_score"
                    ),

                "ai_agreement": [
                    "rules",
                    "temporal_ai",
                ],

                "ai_disagreement": [
                    "isolation_forest",
                    "autoencoder",
                ],

                "evidence_confidence":
                    powershell_fusion_result.get(
                        "evidence_confidence"
                    ),

                "recorded_detection_confidence":
                    0.91,

                "critical_allowed":
                    powershell_fusion_result.get(
                        "critical_allowed"
                    ),

                "active_signal_count":
                    powershell_fusion_result.get(
                        "active_signal_count"
                    ),

                "strong_signal_count":
                    powershell_fusion_result.get(
                        "strong_signal_count"
                    ),

                "fusion_modifiers":
                    powershell_fusion_result.get(
                        "modifiers",
                        {},
                    ),

                "feature_record_id":
                    "SYNTH-FEAT-PROC-POWERSHELL-001",

                "synthetic_model_evidence":
                    True,

                "model_evidence_source":
                    "DETERMINISTIC_VALIDATION_FIXTURE",
            },

            # ====================================================
            # DETECTION
            # ====================================================

            detection={

                "engine":
                    "process_threat_fusion_v3",

                "detected":
                    True,

                "threat_type":
                    "POWERSHELL_SUSPICIOUS_BEHAVIOR",

                "confidence":
                    0.91,

                "risk_score":
                    powershell_fusion_result.get(
                        "fusion_score"
                    ),

                "severity":
                    powershell_fusion_result.get(
                        "severity",
                        "INFO",
                    ),

                "reason": (
                    list(
                        powershell_fusion_result.get(
                            "reasons",
                            [],
                        )
                    )
                    +
                    [
                        (
                            "Synthetic validation evidence only."
                        )
                    ]
                ),
            },
        )
    )
    # ============================================================
    # PROCESS — LOLBIN STYLE
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-PROC-LOLBIN",

            event_type=
                "process_fusion_detection",

            category=
                "PROCESS",

            severity=
                "HIGH",

            process={
                "pid":
                    4202,

                "name":
                    "rundll32.exe",

                "exe":
                    (
                        r"C:\Windows"
                        r"\System32\rundll32.exe"
                    ),

                "command_line":
                    "SYNTHETIC_LOLBIN_PATTERN_ONLY",
            },

            detection=
                threat_detection(
                    "process_behavior",
                    "LOLBIN_SUSPICIOUS_EXECUTION",
                    76,
                    "HIGH",
                    "Suspicious LOLBin-style execution metadata.",
                ),
        )
    )


    # ============================================================
    # FILE — BENIGN
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-FILE-BENIGN",

            event_type=
                "file_modify",

            category=
                "FILE",

            severity=
                "INFO",

            file={
                "name":
                    "notes.txt",

                "path":
                    r"C:\Users\Public\notes.txt",

                "extension":
                    ".txt",
            },

            detection=
                benign_detection(
                    "file_behavior",
                    "BENIGN_FILE_ACTIVITY",
                ),
        )
    )


    # ============================================================
    # FILE — SUSPICIOUS EXECUTABLE
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-FILE-EXECUTABLE",

            event_type=
                "file_create",

            category=
                "FILE",

            severity=
                "HIGH",

            file={
                "name":
                    "validation_payload.exe",

                "path":
                    (
                        r"C:\Users\Public"
                        r"\validation_payload.exe"
                    ),

                "extension":
                    ".exe",

                "sha256":
                    "SYNTHETIC_FILE_SHA256_001",
            },

            detection=
                threat_detection(
                    "file_behavior",
                    "SUSPICIOUS_EXECUTABLE_CREATION",
                    74,
                    "HIGH",
                    "Executable creation in synthetic validation path.",
                ),
        )
    )


    # ============================================================
    # FILE — MALWARE CLASSIFICATION
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-FILE-MALWARE",

            event_type=
                "file_security_detection",

            category=
                "FILE",

            severity=
                "CRITICAL",

            file={
                "name":
                    "validation_sample.exe",

                "path":
                    (
                        r"C:\SentinelXValidation"
                        r"\validation_sample.exe"
                    ),

                "sha256":
                    "SYNTHETIC_MALWARE_SHA256",
            },

            detection=
                threat_detection(
                    "ember_malware_classifier",
                    "MALWARE_STATIC_CLASSIFICATION",
                    94,
                    "CRITICAL",
                    (
                        "Synthetic static malware "
                        "classification case."
                    ),
                ),
        )
    )


    # ============================================================
    # FILE — RANSOMWARE
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-FILE-RANSOMWARE",

            event_type=
                "file_security_detection",

            category=
                "FILE",

            severity=
                "CRITICAL",

            file={
                "name":
                    "validation_document.locked",

                "path":
                    (
                        r"C:\SentinelXValidation"
                        r"\validation_document.locked"
                    ),
            },

            metadata={
                "rename_burst":
                    42,

                "extension_change":
                    True,
            },

            detection=
                threat_detection(
                    "ransomware_behavior",
                    "RANSOMWARE_BEHAVIOR",
                    96,
                    "CRITICAL",
                    (
                        "Synthetic rapid file-change "
                        "pattern resembles ransomware."
                    ),
                ),
        )
    )


    # ============================================================
    # NETWORK — BENIGN HTTPS
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-NET-BENIGN",

            event_type=
                "network_connect",

            category=
                "NETWORK",

            severity=
                "INFO",

            network={
                "pid":
                    4300,

                "process_name":
                    "chrome.exe",

                "local_ip":
                    "192.0.2.10",

                "local_port":
                    52000,

                "remote_ip":
                    "198.51.100.10",

                "remote_port":
                    443,

                "protocol":
                    "TCP",
            },

            detection=
                benign_detection(
                    "network_behavior",
                    "BENIGN_NETWORK_ACTIVITY",
                ),
        )
    )


    # ============================================================
    # NETWORK — BEACONING
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-NET-BEACON",

            event_type=
                "network_security_detection",

            category=
                "NETWORK",

            severity=
                "HIGH",

            network={
                "pid":
                    4301,

                "process_name":
                    "validation_beacon.exe",

                "remote_ip":
                    "203.0.113.200",

                "remote_port":
                    443,

                "protocol":
                    "TCP",

                "interval_seconds":
                    10,
            },

            detection=
                threat_detection(
                    "network_behavior",
                    "SUSPICIOUS_BEACONING",
                    85,
                    "HIGH",
                    (
                        "Synthetic periodic connection "
                        "pattern detected."
                    ),
                ),
        )
    )


    # ============================================================
    # NETWORK — PORT SCAN
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-NET-SCAN",

            event_type=
                "network_security_detection",

            category=
                "NETWORK",

            severity=
                "HIGH",

            network={
                "pid":
                    4302,

                "remote_ip":
                    "198.51.100.55",

                "scanned_port_count":
                    48,

                "protocol":
                    "TCP",
            },

            detection=
                threat_detection(
                    "network_behavior",
                    "PORT_SCAN_ACTIVITY",
                    82,
                    "HIGH",
                    "Synthetic multi-port scan pattern.",
                ),
        )
    )


    # ============================================================
    # NETWORK — EXFILTRATION-LIKE
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-NET-EXFIL",

            event_type=
                "network_security_detection",

            category=
                "NETWORK",

            severity=
                "CRITICAL",

            network={
                "pid":
                    4303,

                "remote_ip":
                    "203.0.113.77",

                "remote_port":
                    443,

                "bytes_sent":
                    250000000,

                "protocol":
                    "TCP",
            },

            detection=
                threat_detection(
                    "network_behavior",
                    "POSSIBLE_DATA_EXFILTRATION",
                    93,
                    "CRITICAL",
                    "Synthetic unusually large outbound transfer.",
                ),
        )
    )


    # ============================================================
    # NETWORK — DDoS-LIKE BURST
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-NET-DDOS",

            event_type=
                "network_security_detection",

            category=
                "NETWORK",

            severity=
                "HIGH",

            network={
                "pid":
                    4304,

                "connection_rate":
                    900,

                "unique_remote_count":
                    120,
            },

            detection=
                threat_detection(
                    "network_behavior",
                    "HIGH_RATE_NETWORK_BURST",
                    86,
                    "HIGH",
                    "Synthetic high-rate network burst.",
                ),
        )
    )


    # ============================================================
    # REGISTRY — BENIGN
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-REG-BENIGN",

            event_type=
                "registry_modify",

            category=
                "REGISTRY",

            severity=
                "INFO",

            registry={
                "key":
                    (
                        r"HKCU\Software"
                        r"\SentinelXValidation"
                    ),

                "value_name":
                    "Theme",

                "value_data":
                    "Dark",
            },

            detection=
                benign_detection(
                    "registry_behavior",
                    "BENIGN_REGISTRY_ACTIVITY",
                ),
        )
    )


    # ============================================================
    # REGISTRY — RUN KEY
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-REG-RUN",

            event_type=
                "registry_security_detection",

            category=
                "REGISTRY",

            severity=
                "HIGH",

            registry={
                "key":
                    (
                        r"HKCU\Software\Microsoft"
                        r"\Windows\CurrentVersion\Run"
                    ),

                "value_name":
                    "ValidationUpdater",

                "value_data":
                    (
                        r"C:\SentinelXValidation"
                        r"\validation_updater.exe"
                    ),
            },

            detection=
                threat_detection(
                    "registry_behavior",
                    "RUN_KEY_PERSISTENCE",
                    88,
                    "HIGH",
                    "Synthetic startup persistence pattern.",
                ),
        )
    )


    # ============================================================
    # REGISTRY — SERVICE PERSISTENCE
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-REG-SERVICE",

            event_type=
                "registry_security_detection",

            category=
                "REGISTRY",

            severity=
                "HIGH",

            registry={
                "key":
                    (
                        r"HKLM\System\CurrentControlSet"
                        r"\Services\ValidationService"
                    ),

                "value_name":
                    "ImagePath",

                "value_data":
                    (
                        r"C:\SentinelXValidation"
                        r"\validation_service.exe"
                    ),
            },

            detection=
                threat_detection(
                    "registry_behavior",
                    "SERVICE_PERSISTENCE",
                    83,
                    "HIGH",
                    "Synthetic service persistence metadata.",
                ),
        )
    )


    # ============================================================
    # AUTH — SUCCESS
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-AUTH-SUCCESS",

            event_type=
                "security_auth_success",

            category=
                "SECURITY",

            severity=
                "INFO",

            network={
                "remote_ip":
                    "192.0.2.50",
            },

            metadata={
                "username":
                    "validation.user",

                "result":
                    "success",
            },

            detection=
                benign_detection(
                    "auth_behavior",
                    "NORMAL_AUTHENTICATION",
                ),
        )
    )


    # ============================================================
    # AUTH — SINGLE FAILURE
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-AUTH-FAIL",

            event_type=
                "security_auth_failure",

            category=
                "SECURITY",

            severity=
                "LOW",

            network={
                "remote_ip":
                    "192.0.2.51",
            },

            metadata={
                "username":
                    "validation.user",

                "result":
                    "failure",

                "failure_count":
                    1,
            },

            detection=
                benign_detection(
                    "auth_behavior",
                    "ISOLATED_AUTH_FAILURE",
                ),
        )
    )


    # ============================================================
    # AUTH — BRUTE FORCE
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-AUTH-BRUTE",

            event_type=
                "security_auth_detection",

            category=
                "SECURITY",

            severity=
                "HIGH",

            network={
                "remote_ip":
                    "203.0.113.44",
            },

            metadata={
                "username":
                    "validation.admin",

                "failure_count":
                    25,

                "window_seconds":
                    60,
            },

            detection=
                threat_detection(
                    "auth_behavior",
                    "AUTH_BRUTE_FORCE",
                    90,
                    "HIGH",
                    "Synthetic repeated authentication failures.",
                ),
        )
    )


    # ============================================================
    # AUTH — PRIVILEGED LOGIN
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-AUTH-PRIV",

            event_type=
                "security_auth_detection",

            category=
                "SECURITY",

            severity=
                "MEDIUM",

            network={
                "remote_ip":
                    "198.51.100.80",
            },

            metadata={
                "username":
                    "validation.admin",

                "privileged":
                    True,

                "unusual_time":
                    True,
            },

            detection=
                threat_detection(
                    "auth_behavior",
                    "UNUSUAL_PRIVILEGED_LOGIN",
                    64,
                    "MEDIUM",
                    "Synthetic unusual privileged authentication.",
                ),
        )
    )


    # ============================================================
    # SYSTEM — BENIGN
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-SYSTEM-BENIGN",

            event_type=
                "security_service_start",

            category=
                "SYSTEM",

            severity=
                "INFO",

            metadata={
                "service_name":
                    "ValidationService",

                "expected":
                    True,
            },

            detection=
                benign_detection(
                    "system_behavior",
                    "NORMAL_SYSTEM_ACTIVITY",
                ),
        )
    )


    # ============================================================
    # SYSTEM — PRIVILEGE CHANGE
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-SYSTEM-PRIV",

            event_type=
                "security_privilege_change",

            category=
                "SYSTEM",

            severity=
                "HIGH",

            metadata={
                "account":
                    "validation.user",

                "privilege":
                    "ADMINISTRATIVE",

                "unexpected":
                    True,
            },

            detection=
                threat_detection(
                    "system_behavior",
                    "UNEXPECTED_PRIVILEGE_CHANGE",
                    84,
                    "HIGH",
                    "Synthetic privilege-change scenario.",
                ),
        )
    )


    # ============================================================
    # STARTUP — BENIGN
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-STARTUP-BENIGN",

            event_type=
                "startup_entry",

            category=
                "STARTUP",

            severity=
                "INFO",

            metadata={
                "entry_name":
                    "ValidationKnownUpdater",

                "trusted":
                    True,
            },

            detection=
                benign_detection(
                    "startup_behavior",
                    "NORMAL_STARTUP_ENTRY",
                ),
        )
    )


    # ============================================================
    # STARTUP — SUSPICIOUS
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-STARTUP-THREAT",

            event_type=
                "startup_security_detection",

            category=
                "STARTUP",

            severity=
                "HIGH",

            metadata={
                "entry_name":
                    "ValidationUnknownStartup",

                "trusted":
                    False,

                "path":
                    (
                        r"C:\SentinelXValidation"
                        r"\startup_payload.exe"
                    ),
            },

            detection=
                threat_detection(
                    "startup_behavior",
                    "SUSPICIOUS_STARTUP_PERSISTENCE",
                    82,
                    "HIGH",
                    "Synthetic suspicious startup entry.",
                ),
        )
    )


    return rows


# ================================================================
# INCIDENT PERSISTENCE
# ================================================================
# ================================================================
# SAFE JSON DECODING
# ================================================================

def safe_json_value(
    value,
    default=None,
):

    if value is None:

        return default

    if isinstance(
        value,
        (
            dict,
            list,
            int,
            float,
            bool,
        ),
    ):

        return value

    if isinstance(
        value,
        str,
    ):

        text = value.strip()

        if not text:

            return default

        try:

            return json.loads(
                text
            )

        except (
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):

            return value

    return default


# ================================================================
# TIMELINE EVENT CATEGORY
# ================================================================

def infer_event_category(
    event_type,
    metadata=None,
):

    metadata = (
        metadata
        if isinstance(
            metadata,
            dict,
        )
        else {}
    )

    stored_category = str(
        metadata.get(
            "event_category",
            "",
        )
        or ""
    ).upper()

    if stored_category:

        return stored_category

    value = str(
        event_type
        or ""
    ).lower()

    if value.startswith(
        "process"
    ):

        return "PROCESS"

    if value.startswith(
        "file"
    ):

        return "FILE"

    if value.startswith(
        "network"
    ):

        return "NETWORK"

    if value.startswith(
        "registry"
    ):

        return "REGISTRY"

    if value.startswith(
        "security"
    ):

        return "SECURITY"

    if value.startswith(
        "startup"
    ):

        return "STARTUP"

    return "OTHER"


# ================================================================
# LOAD ONE EVENT FOR INCIDENT TIMELINE
# ================================================================

def load_timeline_event(
    event_id,
):

    """
    Build an incident timeline entry from the actual event and
    detection persisted by the synthetic seeder.

    This prevents incident timelines from losing the underlying
    process/file/network/registry evidence.
    """

    database_path = Path(
        ACTIVE_SOC_DATABASE_PATH
    )

    connection = sqlite3.connect(
        str(
            database_path
        )
    )

    connection.row_factory = (
        sqlite3.Row
    )

    try:

        event_row = (
            connection.execute(
                """
                SELECT
                    event_id,
                    timestamp,
                    device_id,
                    event_type,
                    severity,
                    source,
                    process_data,
                    file_data,
                    network_data,
                    registry_data,
                    metadata
                FROM events
                WHERE event_id = ?
                """,
                (
                    event_id,
                ),
            ).fetchone()
        )

        detection_row = (
            connection.execute(
                """
                SELECT
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
                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    event_id,
                ),
            ).fetchone()
        )

        # --------------------------------------------------------
        # EVENT NOT FOUND
        # --------------------------------------------------------

        if event_row is None:

            return {

                "event_id":
                    event_id,

                "event_type":
                    "unknown_event",

                "event_category":
                    "OTHER",

                "timestamp":
                    now_iso(),

                "description":
                    (
                        "Synthetic event record "
                        "was not found."
                    ),

                "synthetic":
                    True,
            }

        event = dict(
            event_row
        )

        process = safe_json_value(
            event.get(
                "process_data"
            ),
            {},
        )

        file_data = safe_json_value(
            event.get(
                "file_data"
            ),
            {},
        )

        network = safe_json_value(
            event.get(
                "network_data"
            ),
            {},
        )

        registry = safe_json_value(
            event.get(
                "registry_data"
            ),
            {},
        )

        metadata = safe_json_value(
            event.get(
                "metadata"
            ),
            {},
        )

        if not isinstance(
            process,
            dict,
        ):

            process = {}

        if not isinstance(
            file_data,
            dict,
        ):

            file_data = {}

        if not isinstance(
            network,
            dict,
        ):

            network = {}

        if not isinstance(
            registry,
            dict,
        ):

            registry = {}

        if not isinstance(
            metadata,
            dict,
        ):

            metadata = {}

        detection = {}

        if detection_row is not None:

            detection = dict(
                detection_row
            )

            detection_reason = (
                safe_json_value(
                    detection.get(
                        "reason"
                    ),
                    [],
                )
            )

            if isinstance(
                detection_reason,
                str,
            ):

                detection_reason = [
                    detection_reason
                ]

            if not isinstance(
                detection_reason,
                list,
            ):

                detection_reason = []

            detection[
                "reason"
            ] = detection_reason

        # --------------------------------------------------------
        # HUMAN-READABLE DESCRIPTION
        # --------------------------------------------------------

        threat_type = str(
            detection.get(
                "threat_type",
                "",
            )
            or ""
        )

        if threat_type:

            description = (
                threat_type
                .replace(
                    "_",
                    " ",
                )
                .title()
            )

        else:

            description = (
                str(
                    event.get(
                        "event_type"
                    )
                    or "Security event"
                )
                .replace(
                    "_",
                    " ",
                )
                .title()
            )

        # --------------------------------------------------------
        # FINAL TIMELINE ITEM
        # --------------------------------------------------------

        return {

            "event_id":
                event.get(
                    "event_id"
                ),

            "event_type":
                event.get(
                    "event_type"
                ),

            "event_category":
                infer_event_category(
                    event.get(
                        "event_type"
                    ),
                    metadata,
                ),

            "source":
                event.get(
                    "source"
                ),

            "severity":
                event.get(
                    "severity"
                ),

            "timestamp":
                event.get(
                    "timestamp"
                ),

            "device_id":
                event.get(
                    "device_id"
                ),

            "description":
                description,

            "process":
                process,

            "file":
                file_data,

            "network":
                network,

            "registry":
                registry,

            "metadata":
                metadata,

            "detection":
                {

                    "engine":
                        detection.get(
                            "engine"
                        ),

                    "detected":
                        bool(
                            detection.get(
                                "detected"
                            )
                        ),

                    "threat_type":
                        detection.get(
                            "threat_type"
                        ),

                    "confidence":
                        detection.get(
                            "confidence"
                        ),

                    "risk_score":
                        detection.get(
                            "risk_score"
                        ),

                    "severity":
                        detection.get(
                            "severity"
                        ),

                    "reason":
                        detection.get(
                            "reason",
                            [],
                        ),
                },

            "synthetic":
                True,

            "simulation_mode":
                True,
        }

    finally:

        connection.close()

def save_incident(
    store,
    *,
    incident_id,
    title,
    severity,
    score,
    categories,
    event_ids,
    requires_investigation=True,
):

    # ============================================================
    # BUILD TIMELINE FROM THE ACTUAL PERSISTED EVENTS
    # ============================================================

    timeline = [

        load_timeline_event(
            event_id
        )

        for event_id
        in event_ids
    ]

    # ============================================================
    # SORT USING STORED EVENT TIME
    # ============================================================

    timeline.sort(

        key=lambda item:
            str(
                item.get(
                    "timestamp"
                )
                or ""
            )
    )

    # ============================================================
    # INCIDENT
    # ============================================================

    incident = {

        "incident_id":
            incident_id,

        "title":
            title,

        "status":
            "DETECTED",

        "correlation_score":
            score,

        "severity":
            severity,

        "categories":
            categories,

        "event_ids":
            event_ids,

        "event_count":
            len(
                event_ids
            ),

        "timeline":
            timeline,

        "source":
            "SYNTHETIC_VALIDATION_DEMO",

        "requires_investigation":
            requires_investigation,

        "synthetic":
            True,

        "simulation_mode":
            True,

        "created_at":
            now_iso(),

        "updated_at":
            now_iso(),
    }

    store.save_incident(
        incident
    )

    return incident
# ================================================================
# INCIDENT MATRIX
# ================================================================

def seed_incidents():

    store = IncidentStore()

    incidents = []


    incident_specs = [

        (
            "SYNTH-INC-PROCESS-NETWORK",
            "[SYNTHETIC] Suspicious Process + Network Activity",
            "HIGH",
            72,
            ["PROCESS", "NETWORK"],
            [
                "SYNTH-EVT-PROC-POWERSHELL",
                "SYNTH-EVT-NET-BEACON",
            ],
        ),

        (
            "SYNTH-INC-PROCESS-FILE",
            "[SYNTHETIC] Process + Suspicious File Activity",
            "HIGH",
            80,
            ["PROCESS", "FILE"],
            [
                "SYNTH-EVT-PROC-LOLBIN",
                "SYNTH-EVT-FILE-EXECUTABLE",
            ],
        ),

        (
            "SYNTH-INC-PROCESS-REGISTRY",
            "[SYNTHETIC] Process + Registry Persistence",
            "HIGH",
            90,
            ["PROCESS", "REGISTRY"],
            [
                "SYNTH-EVT-PROC-LOLBIN",
                "SYNTH-EVT-REG-RUN",
            ],
        ),

        (
            "SYNTH-INC-FULL-CHAIN",
            "[SYNTHETIC] Multi-Stage Endpoint Attack Chain",
            "CRITICAL",
            100,
            [
                "PROCESS",
                "FILE",
                "NETWORK",
                "REGISTRY",
            ],
            [
                "SYNTH-EVT-PROC-POWERSHELL",
                "SYNTH-EVT-FILE-MALWARE",
                "SYNTH-EVT-NET-EXFIL",
                "SYNTH-EVT-REG-RUN",
            ],
        ),

        (
            "SYNTH-INC-RANSOMWARE",
            "[SYNTHETIC] Ransomware-Like File Activity",
            "CRITICAL",
            95,
            ["FILE"],
            [
                "SYNTH-EVT-FILE-RANSOMWARE",
            ],
        ),

        (
            "SYNTH-INC-MALWARE",
            "[SYNTHETIC] Static Malware Detection",
            "CRITICAL",
            94,
            ["FILE"],
            [
                "SYNTH-EVT-FILE-MALWARE",
            ],
        ),

        (
            "SYNTH-INC-AUTH",
            "[SYNTHETIC] Authentication Brute Force",
            "HIGH",
            88,
            ["SECURITY"],
            [
                "SYNTH-EVT-AUTH-BRUTE",
            ],
        ),

        (
            "SYNTH-INC-NETWORK-SCAN",
            "[SYNTHETIC] Network Scan Activity",
            "HIGH",
            82,
            ["NETWORK"],
            [
                "SYNTH-EVT-NET-SCAN",
            ],
        ),
    ]


    for spec in incident_specs:

        incidents.append(
            save_incident(

                store,

                incident_id=
                    spec[0],

                title=
                    spec[1],

                severity=
                    spec[2],

                score=
                    spec[3],

                categories=
                    spec[4],

                event_ids=
                    spec[5],
            )
        )


    return incidents


# ================================================================
# CONTROLLED SOC INTELLIGENCE
# ================================================================

def build_soc_intelligence(
    incident_id,
    *,
    risk_score,
    risk_level,
    with_response,
):

    process = {

        "pid":
            99001,

        "name":
            "validation_process.exe",

        "exe":
            (
                r"C:\SentinelXValidation"
                r"\validation_process.exe"
            ),

        "behavior_score":
            risk_score,

        "combined_threat_score":
            risk_score,

        "threat_type":
            "SYNTHETIC_VALIDATION_ONLY",
    }


    evidence = {

        "processes":
            [
                process,
            ],

        "files":
            [
                {
                    "path":
                        (
                            r"C:\SentinelXValidation"
                            r"\validation_payload.exe"
                        ),

                    "sha256":
                        "SYNTHETIC_SOC_SHA256",
                },
            ],

        "network_connections":
            [
                {
                    "pid":
                        99001,

                    "remote_ip":
                        "203.0.113.90",

                    "remote_port":
                        443,
                },
            ],

        "registry_artifacts":
            [],
    }


    recommendations = []


    if with_response:

        recommendations = [

            {
                "action":
                    "PROCESS_TERMINATION_REVIEW",

                "priority":
                    "HIGH",

                "reason":
                    (
                        "Synthetic validation response "
                        "recommendation."
                    ),

                "requires_approval":
                    True,

                "target":
                    process,
            },
        ]


    intelligence = {

        "incident_id":
            incident_id,

        "risk": {

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "requires_response":
                with_response,

            "requires_response_review":
                with_response,
        },

        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "response": {

            "response_level":
                (
                    "RESPONSE_REVIEW"
                    if with_response
                    else
                    "MONITOR_ONLY"
                ),

            "recommendation_count":
                len(
                    recommendations
                ),

            "recommendations":
                recommendations,

            "execution_allowed":
                False,

            "simulation_only":
                True,
        },

        "coordinated_analysis": {

            "evidence":
                evidence,
        },

        "source_incident": {

            "incident_id":
                incident_id,

            "device_id":
                DEVICE_ID,

            "hostname":
                HOSTNAME,

            "timeline":
                [],
        },

        "execution_enabled":
            False,

        "simulation_mode":
            True,
    }


    return (
        intelligence,
        evidence,
    )


# ================================================================
# BUILD + PERSIST ONE SOC CASE
# ================================================================

def create_demo_soc_case(
    workflow,
    incident_id,
    *,
    risk_score,
    risk_level,
    state,
):

    with_response = (
        state
        in {
            "PENDING",
            "APPROVED",
            "REJECTED",
            "VERIFIED",
        }
    )


    intelligence, evidence = (
        build_soc_intelligence(

            incident_id,

            risk_score=
                risk_score,

            risk_level=
                risk_level,

            with_response=
                with_response,
        )
    )


    case = (
        workflow
        .workflow
        .create_case(

            incident_id=
                incident_id,

            intelligence=
                intelligence,
        )
    )


    workflow.persist_case(
        case
    )


    workflow.evidence_store.save_evidence_bundle(

        incident_id=
            incident_id,

        evidence=
            evidence,

        replace_existing=
            True,
    )


    workflow.evidence_store.save_timeline(

        incident_id=
            incident_id,

        timeline=
            [
                {
                    "event_type":
                        "synthetic_validation",

                    "timestamp":
                        now_iso(),

                    "description":
                        (
                            "Synthetic SOC workflow "
                            f"state: {state}"
                        ),
                },
            ],

        replace_existing=
            True,
    )


    if state == "APPROVED":

        workflow.approve_case(

            incident_id=
                incident_id,

            analyst=
                "synthetic.validation",

            comment=
                "Synthetic validation approval.",
        )


    elif state == "REJECTED":

        workflow.reject_case(

            incident_id=
                incident_id,

            analyst=
                "synthetic.validation",

            reason=
                "Synthetic validation rejection.",
        )


    elif state == "VERIFIED":

        approval = (
            workflow.approve_case(

                incident_id=
                    incident_id,

                analyst=
                    "synthetic.validation",

                comment=
                    "Synthetic validation approval.",
            )
        )


        workflow.verify_simulated_mitigation(

            incident_id=
                incident_id,

            before_state={
                "risk_score":
                    risk_score,

                "suspicious_event_count":
                    10,

                "active_indicator_count":
                    6,

                "exposure_score":
                    80,
            },

            simulated_after_state={
                "risk_score":
                    15,

                "suspicious_event_count":
                    1,

                "active_indicator_count":
                    1,

                "exposure_score":
                    15,
            },

            response_result=
                approval,
        )


    return (
        workflow.recover_case(
            incident_id
        )
    )


# ================================================================
# SOC STATE MATRIX
# ================================================================

def seed_soc_states():

    workflow = (
        PersistentSOCWorkflow(
            simulation_mode=True
        )
    )


    store = IncidentStore()


    states = [

        (
            "SYNTH-INC-SOC-LOW",
            "[SYNTHETIC] Low-Risk Investigation",
            "LOW",
            25,
            "LOW",
        ),

        (
            "SYNTH-INC-SOC-PENDING",
            "[SYNTHETIC] Pending Analyst Approval",
            "HIGH",
            78,
            "PENDING",
        ),

        (
            "SYNTH-INC-SOC-APPROVED",
            "[SYNTHETIC] Approved Simulated Response",
            "HIGH",
            82,
            "APPROVED",
        ),

        (
            "SYNTH-INC-SOC-REJECTED",
            "[SYNTHETIC] Analyst Rejected Response",
            "HIGH",
            75,
            "REJECTED",
        ),

        (
            "SYNTH-INC-SOC-VERIFIED",
            "[SYNTHETIC] Verified Simulated Mitigation",
            "CRITICAL",
            92,
            "VERIFIED",
        ),
    ]


    output = []


    for (
        incident_id,
        title,
        severity,
        risk,
        state,
    ) in states:

        event_id = (
            f"{incident_id}-EVENT"
        )


        add_event(

            event_id=
                event_id,

            event_type=
                "process_security_detection",

            category=
                "PROCESS",

            severity=
                severity,

            process={
                "pid":
                    99001,

                "name":
                    "validation_process.exe",

                "exe":
                    (
                        r"C:\SentinelXValidation"
                        r"\validation_process.exe"
                    ),
            },

            detection=
                threat_detection(
                    "synthetic_soc_validation",
                    (
                        "SOC_"
                        + state
                        + "_CASE"
                    ),
                    risk,
                    severity,
                    (
                        "Synthetic SOC workflow "
                        f"state {state}."
                    ),
                ),
        )


        save_incident(

            store,

            incident_id=
                incident_id,

            title=
                title,

            severity=
                severity,

            score=
                max(
                    40,
                    risk,
                ),

            categories=
                [
                    "PROCESS",
                ],

            event_ids=
                [
                    event_id,
                ],
        )


        output.append(
            create_demo_soc_case(

                workflow,

                incident_id,

                risk_score=
                    risk,

                risk_level=
                    severity,

                state=
                    state,
            )
        )


    return output


# ================================================================
# SUMMARY
# ================================================================

def print_summary(
    telemetry,
    incidents,
    cases,
):

    print()

    print(
        "=" * 92
    )

    print(
        "SENTINEL-X FULL SYNTHETIC VALIDATION DATASET"
    )

    print(
        "=" * 92
    )


    print(
        "Database:",
        ACTIVE_SOC_DATABASE_PATH,
    )


    print(
        "Raw telemetry events:",
        len(
            telemetry
        ),
    )


    print(
        "Detected incidents:",
        (
            len(
                incidents
            )
            +
            len(
                cases
            )
        ),
    )


    print(
        "SOC state cases:",
        len(
            cases
        ),
    )


    print()

    print(
        "Included SOC states:"
    )

    print(
        "  LOW / NO RESPONSE"
    )

    print(
        "  PENDING APPROVAL"
    )

    print(
        "  APPROVED + SIMULATED SUCCESS"
    )

    print(
        "  REJECTED"
    )

    print(
        "  MITIGATION VERIFIED"
    )


    print()

    print(
        "No real process, file, network, registry, "
        "authentication, or response action was executed."
    )


    print(
        "=" * 92
    )


# ================================================================
# MAIN
# ================================================================

def main():
    
    # ============================================================
    # SAFETY
    # ============================================================

    validation_guard()

    # ============================================================
    # START FROM COMPLETELY CLEAN VALIDATION STATE
    # ============================================================

    reset_validation_database()

    # ============================================================
    # RECREATE ENDPOINT DATABASE SCHEMA
    # ============================================================

    initialize_database()

    # ============================================================
    # SEED PRODUCT VALIDATION TELEMETRY
    # ============================================================

    telemetry = (
        seed_telemetry_matrix()
    )

    # ============================================================
    # SEED CORRELATED SECURITY INCIDENTS
    # ============================================================

    incidents = (
        seed_incidents()
    )

    # ============================================================
    # SEED LEGACY WORKFLOW REGRESSION STATES
    #
    # Keep these internally for now.
    # Later they will become user_visible=False.
    # ============================================================

    cases = (
        seed_soc_states()
    )

    # ============================================================
    # SUMMARY
    # ============================================================

    print_summary(
        telemetry,
        incidents,
        cases,
    )


if __name__ == "__main__":

    main()