from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)

from response.incident_view_service import (
    IncidentViewService,
)


TEST_INCIDENT = (
    "INC-EVIDENCE-INTEGRATION-001"
)


def build_intelligence():

    return {

        "risk_score":
            96,

        "risk_level":
            "CRITICAL",

        "risk": {

            "risk_score":
                96,

            "risk_level":
                "CRITICAL",
        },

        "coordinated_analysis": {

            "evidence": {

                "processes": [

                    {
                        "pid":
                            9500,

                        "name":
                            "integration-demo.exe",

                        "exe":
                            r"C:\Temp\integration-demo.exe",

                        "combined_threat_score":
                            96,
                    }
                ],

                "files": [

                    {
                        "name":
                            "integration-demo.exe",

                        "path":
                            r"C:\Temp\integration-demo.exe",

                        "sha256":
                            "INTEGRATION_TEST_SHA256",

                        "malware_probability":
                            0.97,

                        "static_risk_score":
                            85,
                    }
                ],

                "network_connections": [

                    {
                        "pid":
                            9500,

                        "process_name":
                            "integration-demo.exe",

                        "remote_ip":
                            "203.0.113.252",

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
                            "IntegrationDemo",

                        "value_data":
                            r"C:\Temp\integration-demo.exe",
                    }
                ],
            },
        },

        "response": {

            "recommendations": [

                {
                    "recommendation_type":
                        "QUARANTINE_REVIEW",
                },

                {
                    "recommendation_type":
                        "PROCESS_TERMINATION_REVIEW",
                },

                {
                    "recommendation_type":
                        "NETWORK_BLOCK_REVIEW",
                },

                {
                    "recommendation_type":
                        "PERSISTENCE_REMEDIATION_REVIEW",
                },

                {
                    "recommendation_type":
                        "ENDPOINT_ISOLATION_REVIEW",
                },
            ],
        },
    }


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X PERSISTENT EVIDENCE INTEGRATION TEST"
    )
    print("=" * 80)


    workflow = (
        PersistentSOCWorkflow(
            simulation_mode=True
        )
    )


    # ============================================================
    # CLEAN EXISTING TEST INCIDENT EVIDENCE
    # ============================================================

    existing = (
        workflow.recover_case(
            TEST_INCIDENT
        )
    )


    if existing is None:

        case = (
            workflow.create_case(

                incident_id=
                    TEST_INCIDENT,

                intelligence=
                    build_intelligence(),
            )
        )

    else:

        case = existing


    # ============================================================
    # NEW WORKFLOW INSTANCE = SIMULATED RESTART
    # ============================================================

    del workflow


    workflow_2 = (
        PersistentSOCWorkflow(
            simulation_mode=True
        )
    )


    recovered = (
        workflow_2.recover_case(
            TEST_INCIDENT
        )
    )


    evidence = (
        recovered.get(
            "evidence",
            {}
        )
    )


    timeline = (
        recovered.get(
            "timeline",
            []
        )
    )


    # ============================================================
    # INCIDENT VIEW
    # ============================================================

    view_service = (
        IncidentViewService(
            workflow=workflow_2
        )
    )


    full_view = (
        view_service.get_full_incident(
            TEST_INCIDENT
        )
    )


    # ============================================================
    # DISPLAY
    # ============================================================

    print()

    print(
        "Processes:",
        len(
            evidence.get(
                "processes",
                []
            )
        ),
    )


    print(
        "Files:",
        len(
            evidence.get(
                "files",
                []
            )
        ),
    )


    print(
        "Network:",
        len(
            evidence.get(
                "network_connections",
                []
            )
        ),
    )


    print(
        "Registry:",
        len(
            evidence.get(
                "registry_artifacts",
                []
            )
        ),
    )


    print(
        "Timeline Events:",
        len(
            timeline
        ),
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    process_pass = (

        len(
            evidence.get(
                "processes",
                []
            )
        )
        == 1
    )


    file_pass = (

        len(
            evidence.get(
                "files",
                []
            )
        )
        == 1

        and

        evidence[
            "files"
        ][0][
            "sha256"
        ]
        == "INTEGRATION_TEST_SHA256"
    )


    network_pass = (

        len(
            evidence.get(
                "network_connections",
                []
            )
        )
        == 1
    )


    registry_pass = (

        len(
            evidence.get(
                "registry_artifacts",
                []
            )
        )
        == 1
    )


    timeline_pass = (
        len(
            timeline
        )
        == 4
    )


    timeline_types = [

        item.get(
            "event_type"
        )

        for item in timeline
    ]


    timeline_type_pass = all(

        event_type in timeline_types

        for event_type in [

            "PROCESS_ACTIVITY",
            "FILE_ACTIVITY",
            "NETWORK_ACTIVITY",
            "PERSISTENCE_ACTIVITY",
        ]
    )


    full_view_pass = (
        full_view
        is not None
    )


    view_evidence_pass = (

        full_view[
            "evidence"
        ][
            "raw_evidence_available"
        ]
        is True
    )


    view_timeline_pass = (

        full_view[
            "timeline"
        ][
            "event_count"
        ]
        == 4
    )


    persistence_pass = (

        full_view[
            "evidence"
        ][
            "persistent"
        ]
        is True

        and

        full_view[
            "timeline"
        ][
            "persistent"
        ]
        is True
    )


    safety_pass = (

        full_view[
            "safety"
        ][
            "real_response_executed"
        ]
        is False
    )


    # ============================================================
    # FINAL
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL PERSISTENT EVIDENCE INTEGRATION VALIDATION"
    )
    print("=" * 80)


    print(
        "Process evidence persisted:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "File evidence persisted:",
        "PASS"
        if file_pass
        else "FAIL",
    )


    print(
        "Network evidence persisted:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Registry evidence persisted:",
        "PASS"
        if registry_pass
        else "FAIL",
    )


    print(
        "Attack timeline persisted:",
        "PASS"
        if timeline_pass
        else "FAIL",
    )


    print(
        "Timeline categories correct:",
        "PASS"
        if timeline_type_pass
        else "FAIL",
    )


    print(
        "Unified incident view created:",
        "PASS"
        if full_view_pass
        else "FAIL",
    )


    print(
        "Incident view uses persistent evidence:",
        "PASS"
        if view_evidence_pass
        else "FAIL",
    )


    print(
        "Incident view uses persistent timeline:",
        "PASS"
        if view_timeline_pass
        else "FAIL",
    )


    print(
        "Persistence flags correct:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "No real response executed:",
        "PASS"
        if safety_pass
        else "FAIL",
    )


    overall = all(
        [
            process_pass,
            file_pass,
            network_pass,
            registry_pass,
            timeline_pass,
            timeline_type_pass,
            full_view_pass,
            view_evidence_pass,
            view_timeline_pass,
            persistence_pass,
            safety_pass,
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