from agents.risk_assessment_agent import (
    RiskAssessmentAgent,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X EXPLAINABLE RISK ASSESSMENT TEST"
    )
    print("=" * 80)


    # ============================================================
    # INCIDENT
    # ============================================================

    incident = {

        "incident_id":
            "INC-RISK-001",

        "severity":
            "CRITICAL",

        "correlation_score":
            90,
    }


    # ============================================================
    # INVESTIGATION
    # ============================================================

    investigation = {

        "category_counts": {

            "PROCESS":
                1,

            "FILE":
                1,

            "NETWORK":
                1,

            "REGISTRY":
                1,
        },
    }


    # ============================================================
    # ENRICHED EVIDENCE
    # ============================================================

    enriched_evidence = {

        "processes": [

            {

                "pid":
                    5000,

                "name":
                    "demo.exe",

                "behavior_score":
                    75,

                "anomaly_score":
                    65,

                "combined_threat_score":
                    90,
            },
        ],


        "files": [

            {

                "name":
                    "demo.exe",

                "path":
                    r"C:\Temp\demo.exe",

                "static_risk_score":
                    72,

                "malware_probability":
                    0.92,
            },
        ],


        "network_connections": [

            {

                "pid":
                    5000,

                "remote_ip":
                    "203.0.113.100",

                "remote_port":
                    443,
            },
        ],


        "registry_artifacts": [

            {

                "key":
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                "value_name":
                    "Demo",

                "value_data":
                    r"C:\Temp\demo.exe",
            },
        ],


        "relationships": [

            {

                "source_type":
                    "PROCESS",

                "relationship":
                    "EXECUTABLE_FILE",

                "target_type":
                    "FILE",

                "confidence":
                    100,
            },

            {

                "source_type":
                    "PROCESS",

                "relationship":
                    "CONNECTED_TO",

                "target_type":
                    "NETWORK",

                "confidence":
                    100,
            },

            {

                "source_type":
                    "REGISTRY",

                "relationship":
                    "REFERENCES",

                "target_type":
                    "FILE",

                "confidence":
                    100,
            },
        ],
    }


    # ============================================================
    # ATTACK TIMELINE
    # ============================================================

    attack_timeline = {

        "attack_stages": [

            "EXECUTION",

            "FILE_ACTIVITY",

            "COMMAND_OR_NETWORK_ACTIVITY",

            "PERSISTENCE",
        ],
    }


    # ============================================================
    # ATTACK GRAPH
    # ============================================================

    attack_graph = {

        "summary": {

            "nodes":
                4,

            "edges":
                4,
        },
    }


    agent = (
        RiskAssessmentAgent()
    )


    result = (
        agent.assess(
            incident,
            investigation,
            enriched_evidence,
            attack_timeline,
            attack_graph,
        )
    )


    # ============================================================
    # MAIN RESULT
    # ============================================================

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
        "Risk Score:",
        result[
            "risk_score"
        ],
    )

    print(
        "Risk Level:",
        result[
            "risk_level"
        ],
    )

    print(
        "Requires Response:",
        result[
            "requires_response"
        ],
    )

    print(
        "Recommended Action:",
        result[
            "recommended_action"
        ],
    )


    # ============================================================
    # COMPONENTS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "RISK COMPONENTS"
    )
    print("=" * 80)


    for key, value in result[
        "components"
    ].items():

        print()

        print(
            key
        )

        print(
            "  Value:",
            value[
                "value"
            ],
        )

        print(
            "  Points:",
            value[
                "points"
            ],
        )


    # ============================================================
    # REASONS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "EXPLAINABLE REASONS"
    )
    print("=" * 80)


    for reason in result[
        "reasons"
    ]:

        print(
            " -",
            reason
        )


    # ============================================================
    # EVIDENCE SUMMARY
    # ============================================================

    print()
    print("=" * 80)
    print(
        "EVIDENCE SUMMARY"
    )
    print("=" * 80)


    for key, value in result[
        "evidence_summary"
    ].items():

        print(
            f"{key}: {value}"
        )


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    score_pass = (
        result[
            "risk_score"
        ]
        >= 80
    )


    level_pass = (
        result[
            "risk_level"
        ]
        == "CRITICAL"
    )


    response_pass = (
        result[
            "requires_response"
        ]
        is True
    )


    malware_pass = (
        result[
            "components"
        ][
            "malware_probability"
        ][
            "points"
        ]
        > 0
    )


    behavior_pass = (
        result[
            "components"
        ][
            "behavior"
        ][
            "points"
        ]
        > 0
    )


    persistence_pass = (
        result[
            "components"
        ][
            "persistence"
        ][
            "points"
        ]
        > 0
    )


    network_pass = (
        result[
            "components"
        ][
            "network_activity"
        ][
            "points"
        ]
        > 0
    )


    correlation_pass = (
        result[
            "components"
        ][
            "correlation"
        ][
            "points"
        ]
        > 0
    )


    print()
    print("=" * 80)
    print(
        "FINAL RISK VALIDATION"
    )
    print("=" * 80)


    print(
        "High risk score:",
        "PASS"
        if score_pass
        else "FAIL",
    )


    print(
        "Critical risk level:",
        "PASS"
        if level_pass
        else "FAIL",
    )


    print(
        "Response required:",
        "PASS"
        if response_pass
        else "FAIL",
    )


    print(
        "Malware evidence contribution:",
        "PASS"
        if malware_pass
        else "FAIL",
    )


    print(
        "Behavior contribution:",
        "PASS"
        if behavior_pass
        else "FAIL",
    )


    print(
        "Persistence contribution:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Network contribution:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Correlation contribution:",
        "PASS"
        if correlation_pass
        else "FAIL",
    )


    overall = all(
        [
            score_pass,
            level_pass,
            response_pass,
            malware_pass,
            behavior_pass,
            persistence_pass,
            network_pass,
            correlation_pass,
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