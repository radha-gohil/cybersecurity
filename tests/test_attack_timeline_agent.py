from agents.attack_timeline_agent import (
    AttackTimelineAgent,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X ATTACK TIMELINE RECONSTRUCTION TEST"
    )
    print("=" * 80)


    # ============================================================
    # Events intentionally NOT in chronological order
    # ============================================================

    incident = {

        "incident_id":
            "INC-TIMELINE-001",

        "timeline": [

            # ----------------------------------------------------
            # REGISTRY - LAST
            # ----------------------------------------------------

            {

                "event_id":
                    "registry-001",

                "timestamp_unix":
                    1030,

                "event_type":
                    "registry_change",

                "source":
                    "registry_monitor",

                "severity":
                    "HIGH",

                "process":
                    {},

                "file":
                    {},

                "network":
                    {},

                "registry": {

                    "key":
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                    "value_name":
                        "DemoApp",

                    "value_data":
                        r"C:\Temp\demo.exe",
                },

                "metadata":
                    {},
            },


            # ----------------------------------------------------
            # PROCESS - FIRST
            # ----------------------------------------------------

            {

                "event_id":
                    "process-001",

                "timestamp_unix":
                    1000,

                "event_type":
                    "process_start",

                "source":
                    "process_monitor",

                "severity":
                    "MEDIUM",

                "process": {

                    "pid":
                        5000,

                    "name":
                        "demo.exe",

                    "exe":
                        r"C:\Temp\demo.exe",
                },

                "file":
                    {},

                "network":
                    {},

                "registry":
                    {},

                "metadata":
                    {},
            },


            # ----------------------------------------------------
            # NETWORK - THIRD
            # ----------------------------------------------------

            {

                "event_id":
                    "network-001",

                "timestamp_unix":
                    1020,

                "event_type":
                    "network_connect",

                "source":
                    "network_monitor",

                "severity":
                    "HIGH",

                "process":
                    {},

                "file":
                    {},

                "network": {

                    "pid":
                        5000,

                    "process_name":
                        "demo.exe",

                    "protocol":
                        "TCP",

                    "remote_ip":
                        "203.0.113.60",

                    "remote_port":
                        443,

                    "status":
                        "ESTABLISHED",
                },

                "registry":
                    {},

                "metadata":
                    {},
            },


            # ----------------------------------------------------
            # FILE - SECOND
            # ----------------------------------------------------

            {

                "event_id":
                    "file-001",

                "timestamp_unix":
                    1010,

                "event_type":
                    "file_modify",

                "source":
                    "file_monitor",

                "severity":
                    "HIGH",

                "process":
                    {},

                "file": {

                    "name":
                        "demo.exe",

                    "path":
                        r"C:\Temp\demo.exe",

                    "sha256":
                        "TIMELINE_TEST_HASH",

                    "malware_probability":
                        0.88,
                },

                "network":
                    {},

                "registry":
                    {},

                "metadata":
                    {},
            },
        ],
    }


    agent = (
        AttackTimelineAgent()
    )


    result = (
        agent.reconstruct(
            incident
        )
    )


    print()
    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )

    print(
        "Agent:",
        result[
            "agent"
        ],
    )

    print(
        "Event Count:",
        result[
            "event_count"
        ],
    )

    print(
        "Attack Stages:",
        result[
            "attack_stages"
        ],
    )


    # ============================================================
    # TIMELINE
    # ============================================================

    print()
    print("=" * 80)
    print(
        "RECONSTRUCTED TIMELINE"
    )
    print("=" * 80)


    for entry in result[
        "timeline"
    ]:

        print()

        print(
            f"Sequence: {entry['sequence']}"
        )

        print(
            f"Timestamp: {entry['timestamp']}"
        )

        print(
            f"Category: {entry['category']}"
        )

        print(
            f"Event Type: {entry['event_type']}"
        )

        print(
            f"Severity: {entry['severity']}"
        )

        print(
            f"Stage: {entry['attack_stage']}"
        )

        print(
            f"Description: {entry['description']}"
        )


    # ============================================================
    # ATTACK STORY
    # ============================================================

    print()
    print("=" * 80)
    print(
        "ATTACK STORY"
    )
    print("=" * 80)


    for line in result[
        "attack_story"
    ]:

        print(
            line
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    timeline = (
        result[
            "timeline"
        ]
    )


    chronological_pass = (

        timeline[
            0
        ][
            "event_id"
        ]
        == "process-001"

        and timeline[
            1
        ][
            "event_id"
        ]
        == "file-001"

        and timeline[
            2
        ][
            "event_id"
        ]
        == "network-001"

        and timeline[
            3
        ][
            "event_id"
        ]
        == "registry-001"
    )


    execution_pass = (
        "EXECUTION"
        in result[
            "attack_stages"
        ]
    )


    network_pass = (
        "COMMAND_OR_NETWORK_ACTIVITY"
        in result[
            "attack_stages"
        ]
    )


    persistence_pass = (
        "PERSISTENCE"
        in result[
            "attack_stages"
        ]
    )


    story_pass = (
        len(
            result[
                "attack_story"
            ]
        )
        == 4
    )


    print()
    print("=" * 80)
    print(
        "FINAL TIMELINE VALIDATION"
    )
    print("=" * 80)


    print(
        "Chronological ordering:",
        "PASS"
        if chronological_pass
        else "FAIL",
    )


    print(
        "Execution stage:",
        "PASS"
        if execution_pass
        else "FAIL",
    )


    print(
        "Network stage:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Persistence stage:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Attack story generation:",
        "PASS"
        if story_pass
        else "FAIL",
    )


    overall = all(
        [
            chronological_pass,
            execution_pass,
            network_pass,
            persistence_pass,
            story_pass,
        ]
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )


    print("=" * 80)


if __name__ == "__main__":

    main()