from detection.behavior.process_behavior_detector import (
    ProcessBehaviorDetector,
)

from endpoint.agent.telemetry_manager import TelemetryManager
from endpoint.storage.database import save_detection


def main():

    detector = ProcessBehaviorDetector()

    telemetry = TelemetryManager()


    # ============================================================
    # SAFE SYNTHETIC PROCESS DATA
    #
    # IMPORTANT:
    # This does NOT execute PowerShell.
    # This only creates fake metadata in Python memory
    # so we can validate the detection pipeline safely.
    # ============================================================

    synthetic_process = {

        "pid":
            99999,

        "ppid":
            88888,

        "name":
            "powershell.exe",

        "exe":
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",

        "cmdline":
            "powershell.exe -EncodedCommand TEST_DATA_ONLY",

        "username":
            "test-user",

        "parent_name":
            "winword.exe",
    }


    # ============================================================
    # RUN BEHAVIOR ANALYSIS
    # ============================================================

    behavior_result = (
        detector.analyze(
            synthetic_process
        )
    )


    print()
    print("=" * 70)
    print("SENTINEL-X BEHAVIOR DETECTION STORAGE TEST")
    print("=" * 70)

    print(
        "Process:",
        synthetic_process["name"],
    )

    print(
        "Parent:",
        synthetic_process["parent_name"],
    )

    print(
        "Behavior Score:",
        behavior_result["behavior_score"],
    )

    print(
        "Severity:",
        behavior_result["severity"],
    )

    print(
        "Suspicious:",
        behavior_result["suspicious"],
    )

    print(
        "Indicators:",
        behavior_result["indicators"],
    )

    print(
        "Reasons:",
        behavior_result["reasons"],
    )


    # ============================================================
    # EMIT SYNTHETIC TELEMETRY EVENT
    # ============================================================

    event = (
        telemetry.emit(

            event_type="process_start",

            source="behavior_test",

            severity=behavior_result.get(
                "severity",
                "INFO",
            ),

            process={
                **synthetic_process,

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
            },

            metadata={
                "collector":
                    "SyntheticBehaviorTest",

                "synthetic_test":
                    True,

                "behavior_analysis":
                    True,
            },
        )
    )


    # ============================================================
    # SAVE DETECTION ONLY IF SUSPICIOUS
    # ============================================================

    if behavior_result.get(
        "suspicious"
    ):

        risk_score = (
            behavior_result.get(
                "behavior_score",
                0,
            )
        )


        detection = {

            "engine":
                "behavior_rules",

            "detection_type":
                "process_behavior",

            "risk":
                risk_score,

            "risk_score":
                risk_score,

            "severity":
                behavior_result.get(
                    "severity",
                    "INFO",
                ),

            "pid":
                synthetic_process.get(
                    "pid"
                ),

            "process_name":
                synthetic_process.get(
                    "name"
                ),

            "process_path":
                synthetic_process.get(
                    "exe"
                ),

            "parent_name":
                synthetic_process.get(
                    "parent_name"
                ),

            "command_line":
                synthetic_process.get(
                    "cmdline"
                ),

            "suspicious":
                behavior_result.get(
                    "suspicious"
                ),

            "indicators":
                behavior_result.get(
                    "indicators",
                    [],
                ),

            "reasons":
                behavior_result.get(
                    "reasons",
                    [],
                ),

            "synthetic_test":
                True,
        }


        try:

            save_detection(
                event.event_id,
                detection,
            )

            print()
            print(
                "Behavior detection saved successfully."
            )

            print(
                "Event ID:",
                event.event_id,
            )

        except Exception as error:

            print()
            print(
                "Behavior detection save failed:"
            )

            print(
                error
            )

    else:

        print()
        print(
            "No behavior detection saved because "
            "the synthetic process was not suspicious."
        )


if __name__ == "__main__":

    main()