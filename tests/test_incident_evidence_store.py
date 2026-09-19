from response.incident_evidence_store import (
    IncidentEvidenceStore,
)


TEST_INCIDENT = (
    "INC-EVIDENCE-STORE-001"
)


def main():

    print()

    print(
        "=" * 80
    )

    print(
        "SENTINEL-X INCIDENT EVIDENCE + TIMELINE STORE TEST"
    )

    print(
        "=" * 80
    )


    store = (
        IncidentEvidenceStore()
    )


    # ============================================================
    # CLEAN PREVIOUS TEST DATA
    # ============================================================

    store.clear_incident(
        TEST_INCIDENT
    )


    # ============================================================
    # SYNTHETIC EVIDENCE
    # ============================================================

    evidence = {

        "processes": [

            {
                "pid":
                    9400,

                "name":
                    "evidence-demo.exe",

                "exe":
                    r"C:\Temp\evidence-demo.exe",

                "combined_threat_score":
                    95,
            }
        ],

        "files": [

            {
                "name":
                    "evidence-demo.exe",

                "path":
                    r"C:\Temp\evidence-demo.exe",

                "sha256":
                    "EVIDENCE_TEST_SHA256",

                "malware_probability":
                    0.96,
            }
        ],

        "network_connections": [

            {
                "pid":
                    9400,

                "process_name":
                    "evidence-demo.exe",

                "remote_ip":
                    "203.0.113.251",

                "remote_port":
                    443,
            }
        ],

        "registry_artifacts": [

            {
                "key":
                    (
                        r"HKCU\Software\Microsoft"
                        r"\Windows\CurrentVersion\Run"
                    ),

                "value_name":
                    "EvidenceDemo",

                "value_data":
                    r"C:\Temp\evidence-demo.exe",
            }
        ],
    }


    # ============================================================
    # SYNTHETIC ATTACK TIMELINE
    # ============================================================

    timeline = [

        {
            "timestamp":
                "2026-09-16T10:00:00+00:00",

            "event_type":
                "PROCESS_ACTIVITY",

            "description":
                "Suspicious process observed.",

            "pid":
                9400,
        },

        {
            "timestamp":
                "2026-09-16T10:00:03+00:00",

            "event_type":
                "FILE_ACTIVITY",

            "description":
                "Suspicious file associated with process.",

            "path":
                r"C:\Temp\evidence-demo.exe",
        },

        {
            "timestamp":
                "2026-09-16T10:00:08+00:00",

            "event_type":
                "NETWORK_ACTIVITY",

            "description":
                "Process established suspicious network connection.",

            "remote_ip":
                "203.0.113.251",
        },

        {
            "timestamp":
                "2026-09-16T10:00:12+00:00",

            "event_type":
                "PERSISTENCE_ACTIVITY",

            "description":
                "Registry persistence artifact observed.",
        },
    ]


    # ============================================================
    # SAVE EVIDENCE
    # ============================================================

    evidence_result = (
        store.save_evidence_bundle(

            incident_id=
                TEST_INCIDENT,

            evidence=
                evidence,

            replace_existing=
                True,
        )
    )


    # ============================================================
    # SAVE TIMELINE
    # ============================================================

    timeline_result = (
        store.save_timeline(

            incident_id=
                TEST_INCIDENT,

            timeline=
                timeline,

            replace_existing=
                True,
        )
    )


    # ============================================================
    # RELOAD
    # ============================================================

    restored_evidence = (
        store.get_evidence_bundle(
            TEST_INCIDENT
        )
    )


    restored_timeline = (
        store.get_timeline(
            TEST_INCIDENT
        )
    )


    # ============================================================
    # DISPLAY
    # ============================================================

    print()

    print(
        "Evidence Saved:",
        evidence_result[
            "total"
        ],
    )


    print(
        "Timeline Events Saved:",
        timeline_result[
            "saved_timeline_events"
        ],
    )


    print(
        "Processes Restored:",
        len(
            restored_evidence[
                "processes"
            ]
        ),
    )


    print(
        "Files Restored:",
        len(
            restored_evidence[
                "files"
            ]
        ),
    )


    print(
        "Network Connections Restored:",
        len(
            restored_evidence[
                "network_connections"
            ]
        ),
    )


    print(
        "Registry Artifacts Restored:",
        len(
            restored_evidence[
                "registry_artifacts"
            ]
        ),
    )


    print(
        "Timeline Restored:",
        len(
            restored_timeline
        ),
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    evidence_count_pass = (
        evidence_result[
            "total"
        ]
        == 4
    )


    process_pass = (

        len(
            restored_evidence[
                "processes"
            ]
        )
        == 1

        and

        restored_evidence[
            "processes"
        ][0][
            "pid"
        ]
        == 9400
    )


    file_pass = (

        len(
            restored_evidence[
                "files"
            ]
        )
        == 1

        and

        restored_evidence[
            "files"
        ][0][
            "sha256"
        ]
        == "EVIDENCE_TEST_SHA256"
    )


    network_pass = (

        len(
            restored_evidence[
                "network_connections"
            ]
        )
        == 1

        and

        restored_evidence[
            "network_connections"
        ][0][
            "remote_ip"
        ]
        == "203.0.113.251"
    )


    registry_pass = (

        len(
            restored_evidence[
                "registry_artifacts"
            ]
        )
        == 1

        and

        restored_evidence[
            "registry_artifacts"
        ][0][
            "value_name"
        ]
        == "EvidenceDemo"
    )


    timeline_count_pass = (
        len(
            restored_timeline
        )
        == 4
    )


    timeline_order_pass = (

        restored_timeline[
            0
        ][
            "event_type"
        ]
        == "PROCESS_ACTIVITY"

        and

        restored_timeline[
            1
        ][
            "event_type"
        ]
        == "FILE_ACTIVITY"

        and

        restored_timeline[
            2
        ][
            "event_type"
        ]
        == "NETWORK_ACTIVITY"

        and

        restored_timeline[
            3
        ][
            "event_type"
        ]
        == "PERSISTENCE_ACTIVITY"
    )


    database_evidence_count_pass = (
        store.count_evidence(
            TEST_INCIDENT
        )
        == 4
    )


    database_timeline_count_pass = (
        store.count_timeline(
            TEST_INCIDENT
        )
        == 4
    )


    # ============================================================
    # FINAL
    # ============================================================

    print()

    print(
        "=" * 80
    )

    print(
        "FINAL INCIDENT EVIDENCE STORE VALIDATION"
    )

    print(
        "=" * 80
    )


    print(
        "Four evidence categories persisted:",
        "PASS"
        if evidence_count_pass
        else "FAIL",
    )


    print(
        "Process evidence restored:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "File evidence restored:",
        "PASS"
        if file_pass
        else "FAIL",
    )


    print(
        "Network evidence restored:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Registry evidence restored:",
        "PASS"
        if registry_pass
        else "FAIL",
    )


    print(
        "Attack timeline restored:",
        "PASS"
        if timeline_count_pass
        else "FAIL",
    )


    print(
        "Timeline order preserved:",
        "PASS"
        if timeline_order_pass
        else "FAIL",
    )


    print(
        "Evidence database count correct:",
        "PASS"
        if database_evidence_count_pass
        else "FAIL",
    )


    print(
        "Timeline database count correct:",
        "PASS"
        if database_timeline_count_pass
        else "FAIL",
    )


    overall = all(
        [
            evidence_count_pass,
            process_pass,
            file_pass,
            network_pass,
            registry_pass,
            timeline_count_pass,
            timeline_order_pass,
            database_evidence_count_pass,
            database_timeline_count_pass,
        ]
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )

    print(
        "=" * 80
    )


if __name__ == "__main__":

    main()