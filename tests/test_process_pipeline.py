import sys
from pathlib import Path


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


# ================================================================
# IMPORTS
# ================================================================

import endpoint.collectors.process_monitor as process_monitor_module

from endpoint.collectors.process_monitor import (
    ProcessMonitor,
)

from endpoint.agent.telemetry_manager import (
    shared_correlation_manager,
)


# ================================================================
# HELPERS
# ================================================================

def separator():

    print(
        "\n"
        + "=" * 72
    )


# ================================================================
# MAIN
# ================================================================

def main():

    separator()

    print(
        "SENTINEL-X PROCESS FULL PIPELINE TEST"
    )

    separator()

    print(
        "\nNo process is started by this test."
    )

    print(
        "No PowerShell command is executed."
    )

    print(
        "Only synthetic process metadata is analyzed."
    )

    # ============================================================
    # CREATE PROCESS MONITOR
    # ============================================================

    monitor = ProcessMonitor(
        poll_interval=2.0
    )

    # ============================================================
    # CAPTURE GENERATED SECURITY EVENTS
    #
    # We still call the REAL TelemetryManager.emit(), so:
    #
    #   database storage
    #   correlation
    #   incident creation
    #
    # all continue normally.
    # ============================================================

    captured_events = []

    original_emit = (
        monitor.telemetry.emit
    )

    def capture_emit(
        *args,
        **kwargs,
    ):

        event = original_emit(
            *args,
            **kwargs,
        )

        captured_events.append(
            event
        )

        return event

    monitor.telemetry.emit = (
        capture_emit
    )

    # ============================================================
    # CAPTURE DETECTIONS
    #
    # Again, the REAL save_detection() is still called.
    # ============================================================

    captured_detections = []

    original_save_detection = (
        process_monitor_module.save_detection
    )

    def capture_save_detection(
        event_id,
        detection,
    ):

        captured_detections.append(
            {
                "event_id":
                    event_id,

                "detection":
                    dict(
                        detection
                    ),
            }
        )

        return original_save_detection(
            event_id,
            detection,
        )

    process_monitor_module.save_detection = (
        capture_save_detection
    )

    # ============================================================
    # RECORD INCIDENT STATE BEFORE TEST
    # ============================================================

    incidents_before = set(
        shared_correlation_manager
        .incidents
        .keys()
    )

    try:

        # ========================================================
        # STEP 1 — BUILD SYNTHETIC NORMAL BASELINE
        #
        # ProcessAnomalyDetector requires historical samples.
        #
        # These samples create NO telemetry events.
        # ========================================================

        print(
            "\nBuilding synthetic anomaly baseline..."
        )

        for index in range(
            5
        ):

            baseline_process = {

                "pid":
                    99123,

                "ppid":
                    90000,

                "name":
                    "powershell.exe",

                "exe":
                    (
                        "C:\\Windows\\System32\\"
                        "WindowsPowerShell\\v1.0\\"
                        "powershell.exe"
                    ),

                "cmdline":
                    "powershell.exe",

                "username":
                    "SYNTHETIC_TEST",

                "create_time":
                    1_700_000_000
                    + index,

                "parent_name":
                    "explorer.exe",

                "cpu_percent":
                    5.0,

                "memory_percent":
                    1.0,

                "num_threads":
                    5,

                "synthetic_test":
                    True,
            }

            baseline_result = (
                monitor
                .anomaly_detector
                .analyze(
                    baseline_process
                )
            )

            print(
                "Baseline",
                index + 1,
                "| Score:",
                baseline_result.get(
                    "anomaly_score"
                ),
            )

        # ========================================================
        # STEP 2 — SYNTHETIC SUSPICIOUS PROCESS METADATA
        #
        # IMPORTANT:
        #
        # This string is NOT executed.
        #
        # It exists only so ProcessBehaviorDetector can analyze
        # metadata characteristics.
        # ========================================================

        suspicious_process = {

            "pid":
                99123,

            "ppid":
                88000,

            "name":
                "powershell.exe",

            "exe":
                (
                    "C:\\Windows\\System32\\"
                    "WindowsPowerShell\\v1.0\\"
                    "powershell.exe"
                ),

            "cmdline":
                (
                    "powershell.exe "
                    "-EncodedCommand "
                    "SYNTHETIC_ONLY"
                ),

            "username":
                "SYNTHETIC_TEST",

            "create_time":
                1_700_001_000,

            "parent_name":
                "winword.exe",

            # ----------------------------------------------------
            # Synthetic resource spike
            # ----------------------------------------------------

            "cpu_percent":
                95.0,

            "memory_percent":
                60.0,

            "num_threads":
                50,

            "synthetic_test":
                True,
        }

        # ========================================================
        # STEP 3 — PREVIEW DETECTOR RESULTS
        #
        # Use separate preview detectors would alter history.
        # Therefore we directly calculate only behavior here.
        # Anomaly is validated through ProcessMonitor below.
        # ========================================================

        behavior_preview = (
            monitor
            .behavior_detector
            .analyze(
                suspicious_process
            )
        )

        print(
            "\nBehavior preview:"
        )

        print(
            "Score:",
            behavior_preview.get(
                "behavior_score"
            ),
        )

        print(
            "Suspicious:",
            behavior_preview.get(
                "suspicious"
            ),
        )

        print(
            "Indicators:",
            behavior_preview.get(
                "indicators"
            ),
        )

        # ========================================================
        # STEP 4 — SEND THROUGH REAL PROCESSMONITOR PIPELINE
        #
        # Repeat the same synthetic PID so correlation can
        # recognize related process events.
        # ========================================================

        separator()

        print(
            "FEEDING SYNTHETIC PROCESS EVENTS"
        )

        for index in range(
            5
        ):

            print(
                "\n"
                + "-" * 72
            )

            print(
                "Synthetic Process Event:",
                index + 1,
            )

            event_data = dict(
                suspicious_process
            )

            event_data[
                "create_time"
            ] = (
                1_700_001_000
                + index
            )

            monitor.handle_process_start(
                event_data
            )

        # ========================================================
        # INCIDENT STATE AFTER TEST
        # ========================================================

        incidents_after = set(
            shared_correlation_manager
            .incidents
            .keys()
        )

        new_incident_ids = (
            incidents_after
            - incidents_before
        )

        # ========================================================
        # SUMMARY
        # ========================================================

        separator()

        print(
            "PROCESS PIPELINE SUMMARY"
        )

        print(
            "\nSecurityEvents created:",
            len(
                captured_events
            ),
        )

        print(
            "Process detections stored:",
            len(
                captured_detections
            ),
        )

        print(
            "New incidents:",
            len(
                new_incident_ids
            ),
        )

        # ========================================================
        # PRINT EVENTS
        # ========================================================

        print(
            "\nEVENTS:"
        )

        for event in captured_events:

            process_data = (
                event.process
                or {}
            )

            print(
                "\nEvent ID:",
                event.event_id,
            )

            print(
                "Type:",
                event.event_type,
            )

            print(
                "Severity:",
                event.severity,
            )

            print(
                "Process:",
                process_data.get(
                    "name"
                ),
            )

            print(
                "Behavior Score:",
                process_data.get(
                    "behavior_score"
                ),
            )

            print(
                "Anomaly Score:",
                process_data.get(
                    "anomaly_score"
                ),
            )

            print(
                "Combined Score:",
                process_data.get(
                    "combined_threat_score"
                ),
            )

        # ========================================================
        # PRINT DETECTIONS
        # ========================================================

        print(
            "\nDETECTIONS:"
        )

        for item in captured_detections:

            detection = (
                item[
                    "detection"
                ]
            )

            print(
                "\n>>> PROCESS THREAT DETECTION"
            )

            print(
                "Event ID:",
                item[
                    "event_id"
                ],
            )

            print(
                "Engine:",
                detection.get(
                    "engine"
                ),
            )

            print(
                "Type:",
                detection.get(
                    "detection_type"
                ),
            )

            print(
                "Behavior Score:",
                detection.get(
                    "behavior_score"
                ),
            )

            print(
                "Anomaly Score:",
                detection.get(
                    "anomaly_score"
                ),
            )

            print(
                "Combined Risk:",
                detection.get(
                    "risk_score"
                ),
            )

            print(
                "Severity:",
                detection.get(
                    "severity"
                ),
            )

            print(
                "Behavior Indicators:",
                detection.get(
                    "behavior_indicators"
                ),
            )

            print(
                "Anomaly Indicators:",
                detection.get(
                    "anomaly_indicators"
                ),
            )

        # ========================================================
        # INCIDENTS
        # ========================================================

        if new_incident_ids:

            print(
                "\nINCIDENTS:"
            )

            for incident_id in (
                new_incident_ids
            ):

                incident = (
                    shared_correlation_manager
                    .incidents
                    .get(
                        incident_id,
                        {},
                    )
                )

                print(
                    "\nIncident ID:",
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

        # ========================================================
        # VALIDATION
        # ========================================================

        separator()

        print(
            "VALIDATION"
        )

        # --------------------------------------------------------
        # EVENTS
        # --------------------------------------------------------

        if len(
            captured_events
        ) < 5:

            raise AssertionError(
                "Expected at least 5 "
                "process SecurityEvents."
            )

        print(
            "SecurityEvent creation: PASS"
        )

        # --------------------------------------------------------
        # PROCESS EVENT TYPE
        # --------------------------------------------------------

        if not all(
            event.event_type
            ==
            "process_start"
            for event
            in captured_events
        ):

            raise AssertionError(
                "Unexpected process event type."
            )

        print(
            "ProcessMonitor integration: PASS"
        )

        # --------------------------------------------------------
        # DETECTIONS
        # --------------------------------------------------------

        if not captured_detections:

            raise AssertionError(
                "No process detections "
                "were stored."
            )

        print(
            "Detection database integration: PASS"
        )

        # --------------------------------------------------------
        # DETECTION ENGINE
        # --------------------------------------------------------

        process_detections = [

            item[
                "detection"
            ]

            for item
            in captured_detections

            if (
                item[
                    "detection"
                ].get(
                    "engine"
                )
                ==
                "process_behavior_anomaly"
            )
        ]

        if not process_detections:

            raise AssertionError(
                "process_behavior_anomaly "
                "detection not found."
            )

        print(
            "Process detection engine: PASS"
        )

        # --------------------------------------------------------
        # BEHAVIOR
        # --------------------------------------------------------

        first_detection = (
            process_detections[
                0
            ]
        )

        if (
            first_detection.get(
                "behavior_score",
                0,
            )
            < 35
        ):

            raise AssertionError(
                "Behavior detection "
                "did not trigger."
            )

        print(
            "Behavior detection: PASS"
        )

        # --------------------------------------------------------
        # ANOMALY
        # --------------------------------------------------------

        if (
            first_detection.get(
                "anomaly_score",
                0,
            )
            < 35
        ):

            raise AssertionError(
                "Anomaly detection "
                "did not trigger."
            )

        print(
            "Anomaly detection: PASS"
        )

        # --------------------------------------------------------
        # FUSION
        # --------------------------------------------------------

        if (
            first_detection.get(
                "risk_score",
                0,
            )
            < 35
        ):

            raise AssertionError(
                "Threat fusion "
                "did not trigger."
            )

        print(
            "Threat fusion: PASS"
        )

        # --------------------------------------------------------
        # INCIDENT
        # --------------------------------------------------------

        if not new_incident_ids:

            raise AssertionError(
                "No correlated process "
                "incident was created."
            )

        print(
            "Correlation: PASS"
        )

        print(
            "Incident creation: PASS"
        )

        # ========================================================
        # COMPLETE
        # ========================================================

        separator()

        print(
            "PROCESS PIPELINE TEST "
            "COMPLETED SUCCESSFULLY"
        )

        separator()

        print(
            """
Verified path:

Synthetic Process Metadata
          |
          v
ProcessBehaviorDetector
          |
          +------------------+
          |                  |
          v                  v
ProcessAnomalyDetector    Behavior Rules
          |                  |
          +--------+---------+
                   |
                   v
         Combined Threat Score
                   |
                   v
             ProcessMonitor
                   |
                   v
             SecurityEvent
                   |
                   v
              Database
                   |
                   v
        process_threat Detection
                   |
                   v
              Correlation
                   |
                   v
               Incident
"""
        )

    finally:

        # ========================================================
        # RESTORE ORIGINAL FUNCTIONS
        # ========================================================

        monitor.telemetry.emit = (
            original_emit
        )

        process_monitor_module.save_detection = (
            original_save_detection
        )


if __name__ == "__main__":

    main()