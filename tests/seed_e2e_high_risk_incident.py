import sys

from pathlib import Path


# ================================================================
# PROJECT PATH
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


if str(
    PROJECT_ROOT
) not in sys.path:

    sys.path.insert(
        0,
        str(
            PROJECT_ROOT
        ),
    )


from endpoint.agent.telemetry_manager import (
    TelemetryManager,
    shared_correlation_manager,
)


OUTPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "e2e_last_incident.txt"
)


# ================================================================
# MAIN
# ================================================================

def main():

    print()

    print(
        "=" * 80
    )

    print(
        "SENTINEL-X HIGH-RISK E2E INCIDENT SEED"
    )

    print(
        "=" * 80
    )

    print()

    print(
        "SIMULATION / METADATA ONLY"
    )

    print(
        "No real endpoint action is performed."
    )

    print()


    # ============================================================
    # SYNTHETIC ENDPOINT IDENTITY
    # ============================================================

    demo_device_id = (
        "sentinelx-e2e-device"
    )

    demo_hostname = (
        "sentinelx-e2e-host"
    )


    telemetry = (
        TelemetryManager(
            device_id=
                demo_device_id
        )
    )


    # ============================================================
    # SYNTHETIC ARTIFACTS
    # ============================================================

    demo_path = (
        r"C:\Temp\sentinelx_e2e_demo.exe"
    )

    demo_name = (
        "sentinelx_e2e_demo.exe"
    )

    demo_pid = 42420

    demo_sha256 = (
        "E2E_SYNTHETIC_SHA256_"
        "000000000000000000000000000001"
    )


    # ============================================================
    # EVENT 1 — PROCESS
    # ============================================================

    process_event = telemetry.emit(

        event_type=
            "process_start",

        source=
            "e2e_process_monitor",

        severity=
            "CRITICAL",

        process={

            "pid":
                demo_pid,

            "ppid":
                2000,

            "name":
                demo_name,

            "exe":
                demo_path,

            "cmdline":
                demo_path,

            "parent_name":
                "explorer.exe",

            "behavior_score":
                95,

            "anomaly_score":
                90,

            "combined_threat_score":
                98,

            "behavior_indicators": [

                "synthetic_suspicious_execution",

                "synthetic_behavior_anomaly",
            ],
        },

        metadata={

            "synthetic_e2e":
                True,

            "device_id":
                demo_device_id,

            "hostname":
                demo_hostname,

            "test_stage":
                "PROCESS",

            "risk_score":
                95,

            "description":
                (
                    "Synthetic high-risk "
                    "process telemetry."
                ),
        },
    )


    # ============================================================
    # EVENT 2 — FILE
    # ============================================================

    file_event = telemetry.emit(

        event_type=
            "file_modify",

        source=
            "e2e_file_monitor",

        severity=
            "CRITICAL",

        process={

            "pid":
                demo_pid,

            "name":
                demo_name,

            "exe":
                demo_path,
        },

        file={

            "name":
                demo_name,

            "path":
                demo_path,

            "extension":
                ".exe",

            "size":
                250000,

            "sha256":
                demo_sha256,

            "entropy":
                7.8,

            "is_pe":
                True,

            "static_risk_score":
                95,

            "static_severity":
                "CRITICAL",

            "ml_prediction":
                1,

            "malware_probability":
                0.98,

            "ml_confidence":
                0.98,

            "static_reasons": [

                "Synthetic executable risk signal",

                "Synthetic high entropy signal",
            ],
        },

        metadata={

            "synthetic_e2e":
                True,

            "device_id":
                demo_device_id,

            "hostname":
                demo_hostname,

            "test_stage":
                "FILE",

            "risk_score":
                95,
        },
    )


    # ============================================================
    # EVENT 3 — NETWORK
    #
    # 203.0.113.0/24 is TEST-NET-3 and is used only as
    # documentation/example metadata.
    # No real connection is made.
    # ============================================================

    network_event_1 = telemetry.emit(

        event_type=
            "network_connect",

        source=
            "e2e_network_monitor",

        severity=
            "CRITICAL",

        process={

            "pid":
                demo_pid,

            "name":
                demo_name,

            "exe":
                demo_path,
        },

        network={

            "pid":
                demo_pid,

            "process_name":
                demo_name,

            "protocol":
                "TCP",

            "local_ip":
                "192.0.2.10",

            "local_port":
                53000,

            "remote_ip":
                "203.0.113.250",

            "remote_port":
                443,

            "status":
                "ESTABLISHED",

            "behavior_score":
                95,
        },

        metadata={

            "synthetic_e2e":
                True,

            "device_id":
                demo_device_id,

            "hostname":
                demo_hostname,

            "test_stage":
                "NETWORK",

            "risk_score":
                95,

            "indicator":
                "synthetic_c2_like_activity",
        },
    )


    # ============================================================
    # EVENT 4 — REGISTRY
    # ============================================================

    registry_event = telemetry.emit(

        event_type=
            "registry_change",

        source=
            "e2e_registry_monitor",

        severity=
            "CRITICAL",

        process={

            "pid":
                demo_pid,

            "name":
                demo_name,

            "exe":
                demo_path,
        },

        registry={

            "key":
                (
                    r"HKCU\Software\Microsoft"
                    r"\Windows\CurrentVersion\Run"
                ),

            "value_name":
                "SentinelXE2EDemo",

            "value_data":
                demo_path,

            "risk_score":
                95,
        },

        metadata={

            "synthetic_e2e":
                True,

            "device_id":
                demo_device_id,

            "hostname":
                demo_hostname,

            "test_stage":
                "REGISTRY",

            "risk_score":
                95,

            "indicator":
                "synthetic_persistence",
        },
    )


    # ============================================================
    # EVENT 5 — SECOND NETWORK OBSERVATION
    # ============================================================

    network_event_2 = telemetry.emit(

        event_type=
            "network_connect",

        source=
            "e2e_network_monitor",

        severity=
            "CRITICAL",

        process={

            "pid":
                demo_pid,

            "name":
                demo_name,

            "exe":
                demo_path,
        },

        network={

            "pid":
                demo_pid,

            "process_name":
                demo_name,

            "protocol":
                "TCP",

            "local_ip":
                "192.0.2.10",

            "local_port":
                53001,

            "remote_ip":
                "203.0.113.250",

            "remote_port":
                443,

            "status":
                "ESTABLISHED",

            "behavior_score":
                98,
        },

        metadata={

            "synthetic_e2e":
                True,

            "device_id":
                demo_device_id,

            "hostname":
                demo_hostname,

            "test_stage":
                "NETWORK_REPEAT",

            "risk_score":
                98,

            "indicator":
                (
                    "synthetic_repeated_"
                    "external_activity"
                ),
        },
    )


    # ============================================================
    # EVENTS CREATED
    # ============================================================

    emitted_events = [

        process_event,

        file_event,

        network_event_1,

        registry_event,

        network_event_2,
    ]


    print(
        "SecurityEvents emitted:",
        len(
            emitted_events
        ),
    )

    print()


    for event in emitted_events:

        print(
            event.event_id,
            "|",
            event.event_type,
            "|",
            event.severity,
        )


    # ============================================================
    # CORRELATED INCIDENTS
    # ============================================================

    incidents = (
        shared_correlation_manager
        .get_incidents()
    )


    if not incidents:

        raise RuntimeError(
            (
                "No correlated incident was created. "
                "Check correlation logs above."
            )
        )


    incident = max(

        incidents,

        key=lambda item:
            item.get(
                "correlation_score",
                0,
            ),
    )


    incident_id = (
        incident.get(
            "incident_id"
        )
    )


    if not incident_id:

        raise RuntimeError(
            "Incident does not contain incident_id."
        )


    # ============================================================
    # SAVE INCIDENT ID
    # ============================================================

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    OUTPUT_FILE.write_text(
        incident_id,
        encoding="utf-8",
    )


    # ============================================================
    # SUMMARY
    # ============================================================

    print()

    print(
        "=" * 80
    )

    print(
        "CORRELATED INCIDENT"
    )

    print(
        "=" * 80
    )


    print(
        "Incident ID:",
        incident_id,
    )

    print(
        "Title:",
        incident.get(
            "title"
        ),
    )

    print(
        "Severity:",
        incident.get(
            "severity"
        ),
    )

    print(
        "Correlation Score:",
        incident.get(
            "correlation_score"
        ),
    )

    print(
        "Event Count:",
        incident.get(
            "event_count"
        ),
    )

    print(
        "Categories:",
        incident.get(
            "categories"
        ),
    )

    print(
        "Requires Investigation:",
        incident.get(
            "requires_investigation"
        ),
    )


    print(
        "Device ID:",
        demo_device_id,
    )

    print(
        "Hostname:",
        demo_hostname,
    )


    print()

    print(
        "Incident ID saved to:"
    )

    print(
        OUTPUT_FILE
    )


    print()

    print(
        "=" * 80
    )

    print(
        "E2E SEED COMPLETED"
    )

    print(
        "=" * 80
    )

    print()

    print(
        "Verified so far:"
    )

    print(
        "Synthetic telemetry metadata"
    )

    print(
        "    -> SecurityEvent"
    )

    print(
        "    -> endpoint SQLite event persistence"
    )

    print(
        "    -> CorrelationManager"
    )

    print(
        "    -> persistent detected incident"
    )

    print()

    print(
        "No process terminated."
    )

    print(
        "No file modified."
    )

    print(
        "No network connection created."
    )

    print(
        "No registry key modified."
    )

    print(
        "No endpoint isolated."
    )


if __name__ == "__main__":

    main()