from response.digital_twin_decision_integration import (
    DigitalTwinDecisionIntegration,
)

from response.digital_twin_explainability import (
    DigitalTwinExplainability,
)

from response.automatic_ticket_generator import (
    AutomaticTicketGenerator,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X AUTOMATIC SOC TICKET GENERATOR TEST"
    )
    print("=" * 80)


    # ============================================================
    # SYNTHETIC INTELLIGENCE OUTPUT
    # ============================================================

    intelligence = {

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
                            7000,

                        "name":
                            "demo.exe",

                        "exe":
                            r"C:\Temp\demo.exe",

                        "behavior_score":
                            85,

                        "anomaly_score":
                            75,

                        "combined_threat_score":
                            95,
                    },
                ],

                "files": [

                    {
                        "name":
                            "demo.exe",

                        "path":
                            r"C:\Temp\demo.exe",

                        "sha256":
                            "AUTO_TICKET_SHA256",

                        "malware_probability":
                            0.96,

                        "static_risk_score":
                            80,
                    },
                ],

                "network_connections": [

                    {
                        "pid":
                            7000,

                        "process_name":
                            "demo.exe",

                        "remote_ip":
                            "203.0.113.150",

                        "remote_port":
                            443,
                    },
                ],

                "registry_artifacts": [

                    {
                        "key":
                            (
                                r"HKCU\Software\Microsoft"
                                r"\Windows\CurrentVersion\Run"
                            ),

                        "value_name":
                            "DemoApp",

                        "value_data":
                            r"C:\Temp\demo.exe",
                    },
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


    # ============================================================
    # DIGITAL TWIN DECISION
    # ============================================================

    decision_engine = (
        DigitalTwinDecisionIntegration()
    )


    decision = (
        decision_engine.evaluate(

            incident_id=
                "INC-AUTO-TICKET-001",

            intelligence=
                intelligence,
        )
    )


    # ============================================================
    # EXPLANATION
    # ============================================================

    explainer = (
        DigitalTwinExplainability()
    )


    explanation = (
        explainer.generate(
            decision
        )
    )


    # ============================================================
    # GENERATE TICKET
    # ============================================================

    generator = (
        AutomaticTicketGenerator()
    )


    result = (
        generator.generate(

            decision_result=
                decision,

            explanation_result=
                explanation,
        )
    )


    ticket = (
        result[
            "ticket"
        ]
    )


    # ============================================================
    # PRINT
    # ============================================================

    print()
    print(
        "Ticket ID:",
        ticket[
            "ticket_id"
        ],
    )

    print(
        "Incident ID:",
        ticket[
            "incident_id"
        ],
    )

    print(
        "Priority:",
        ticket[
            "priority"
        ],
    )

    print(
        "Risk Score:",
        ticket[
            "risk_score"
        ],
    )

    print(
        "Risk Level:",
        ticket[
            "risk_level"
        ],
    )

    print(
        "Selected Plan:",
        ticket[
            "selected_plan"
        ],
    )

    print(
        "Predicted Residual Risk:",
        ticket[
            "predicted_residual_risk"
        ],
    )

    print(
        "Operational Impact:",
        ticket[
            "operational_impact"
        ],
    )

    print(
        "Approval Required:",
        ticket[
            "approval_required"
        ],
    )

    print(
        "Approval Status:",
        ticket[
            "approval_status"
        ],
    )

    print(
        "Ticket Status:",
        ticket[
            "status"
        ],
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    created_pass = (
        result[
            "ticket_created"
        ]
        is True
    )


    id_pass = (
        ticket[
            "ticket_id"
        ].startswith(
            "TKT-"
        )
    )


    priority_pass = (
        ticket[
            "priority"
        ]
        == "P1"
    )


    risk_pass = (
        ticket[
            "risk_score"
        ]
        == 96
    )


    level_pass = (
        ticket[
            "risk_level"
        ]
        == "CRITICAL"
    )


    plan_pass = (
        ticket[
            "selected_plan"
        ]
        == "Targeted Full Remediation"
    )


    residual_pass = (
        ticket[
            "predicted_residual_risk"
        ]
        == 0
    )


    impact_pass = (
        ticket[
            "operational_impact"
        ]
        == "MEDIUM"
    )


    approval_pass = (

        ticket[
            "approval_required"
        ]
        is True

        and

        ticket[
            "approval_status"
        ]
        == "PENDING"
    )


    status_pass = (
        ticket[
            "status"
        ]
        == "AWAITING_APPROVAL"
    )


    explanation_pass = (
        len(
            ticket[
                "explanation"
            ]
        )
        > 50
    )


    persisted = (
        generator.store.get_ticket(
            ticket[
                "ticket_id"
            ]
        )
    )


    persistence_pass = (
        persisted
        is not None
    )


    no_endpoint_change_pass = (
        result[
            "real_endpoint_modified"
        ]
        is False
    )


    # ============================================================
    # PRIORITY BOUNDARY TESTS
    # ============================================================

    priority_boundary_pass = all(
        [
            generator.risk_to_priority(
                100
            )
            == "P1",

            generator.risk_to_priority(
                80
            )
            == "P1",

            generator.risk_to_priority(
                79
            )
            == "P2",

            generator.risk_to_priority(
                60
            )
            == "P2",

            generator.risk_to_priority(
                59
            )
            == "P3",

            generator.risk_to_priority(
                35
            )
            == "P3",

            generator.risk_to_priority(
                34
            )
            == "P4",

            generator.risk_to_priority(
                0
            )
            == "P4",
        ]
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL AUTOMATIC TICKET VALIDATION"
    )
    print("=" * 80)


    print(
        "Ticket automatically created:",
        "PASS"
        if created_pass
        else "FAIL",
    )


    print(
        "Ticket ID generated:",
        "PASS"
        if id_pass
        else "FAIL",
    )


    print(
        "P1 priority assigned:",
        "PASS"
        if priority_pass
        else "FAIL",
    )


    print(
        "Risk score stored:",
        "PASS"
        if risk_pass
        else "FAIL",
    )


    print(
        "Risk level stored:",
        "PASS"
        if level_pass
        else "FAIL",
    )


    print(
        "Digital Twin plan stored:",
        "PASS"
        if plan_pass
        else "FAIL",
    )


    print(
        "Residual risk stored:",
        "PASS"
        if residual_pass
        else "FAIL",
    )


    print(
        "Operational impact stored:",
        "PASS"
        if impact_pass
        else "FAIL",
    )


    print(
        "Approval state generated:",
        "PASS"
        if approval_pass
        else "FAIL",
    )


    print(
        "Ticket awaiting approval:",
        "PASS"
        if status_pass
        else "FAIL",
    )


    print(
        "Explainability summary stored:",
        "PASS"
        if explanation_pass
        else "FAIL",
    )


    print(
        "Ticket persisted:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Priority boundaries correct:",
        "PASS"
        if priority_boundary_pass
        else "FAIL",
    )


    print(
        "Real endpoint unchanged:",
        "PASS"
        if no_endpoint_change_pass
        else "FAIL",
    )


    overall = all(
        [
            created_pass,
            id_pass,
            priority_pass,
            risk_pass,
            level_pass,
            plan_pass,
            residual_pass,
            impact_pass,
            approval_pass,
            status_pass,
            explanation_pass,
            persistence_pass,
            priority_boundary_pass,
            no_endpoint_change_pass,
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