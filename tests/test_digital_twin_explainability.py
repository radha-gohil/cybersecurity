from response.digital_twin_decision_integration import (
    DigitalTwinDecisionIntegration,
)

from response.digital_twin_explainability import (
    DigitalTwinExplainability,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X DIGITAL TWIN EXPLAINABILITY TEST"
    )
    print("=" * 80)


    # ============================================================
    # SAME SYNTHETIC INTELLIGENCE FORMAT USED BY DECISION TEST
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
                        "pid": 7000,
                        "name": "demo.exe",
                        "exe": r"C:\Temp\demo.exe",
                        "behavior_score": 85,
                        "anomaly_score": 75,
                        "combined_threat_score": 95,
                    }
                ],

                "files": [
                    {
                        "name": "demo.exe",
                        "path": r"C:\Temp\demo.exe",
                        "sha256": "EXPLAIN_SHA256",
                        "malware_probability": 0.96,
                        "static_risk_score": 80,
                    }
                ],

                "network_connections": [
                    {
                        "pid": 7000,
                        "process_name": "demo.exe",
                        "remote_ip": "203.0.113.120",
                        "remote_port": 443,
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
                            "DemoApp",

                        "value_data":
                            r"C:\Temp\demo.exe",
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


    # ============================================================
    # DIGITAL TWIN DECISION
    # ============================================================

    integration = (
        DigitalTwinDecisionIntegration()
    )


    decision = integration.evaluate(

        incident_id=
            "INC-DT-EXPLAIN-001",

        intelligence=
            intelligence,
    )


    # ============================================================
    # GENERATE EXPLANATION
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
    # PRINT
    # ============================================================

    print()
    print(
        "Status:",
        explanation[
            "status"
        ],
    )

    print(
        "Incident:",
        explanation[
            "incident_id"
        ],
    )


    print()
    print("=" * 80)
    print(
        "SELECTED PLAN"
    )
    print("=" * 80)


    selected = (
        explanation[
            "selected_plan"
        ]
    )


    print(
        "Plan:",
        selected[
            "plan_name"
        ],
    )

    print(
        "Plan Score:",
        selected[
            "plan_score"
        ],
    )

    print(
        "Residual Risk:",
        selected[
            "predicted_residual_risk"
        ],
    )

    print(
        "Risk Reduction %:",
        selected[
            "risk_reduction_percentage"
        ],
    )

    print(
        "Operational Impact:",
        selected[
            "operational_impact"
        ],
    )


    print()
    print("=" * 80)
    print(
        "WHY SELECTED"
    )
    print("=" * 80)


    for reason in explanation[
        "why_selected"
    ]:

        print(
            "-",
            reason,
        )


    print()
    print("=" * 80)
    print(
        "ALTERNATIVES"
    )
    print("=" * 80)


    for alternative in explanation[
        "alternative_plans"
    ]:

        print()

        print(
            "Plan:",
            alternative[
                "plan_name"
            ],
        )

        for reason in alternative[
            "reasons_not_selected"
        ]:

            print(
                "  -",
                reason,
            )


    print()
    print("=" * 80)
    print(
        "EXPLAINABILITY SUMMARY"
    )
    print("=" * 80)

    print(
        explanation[
            "summary"
        ]
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    status_pass = (
        explanation[
            "status"
        ]
        == "EXPLANATION_GENERATED"
    )


    selected_pass = (
        explanation[
            "selected_plan"
        ][
            "plan_name"
        ]
        == "Targeted Full Remediation"
    )


    reasons_pass = (
        len(
            explanation[
                "why_selected"
            ]
        )
        >= 3
    )


    alternatives_pass = (
        len(
            explanation[
                "alternative_plans"
            ]
        )
        >= 2
    )


    risk_pass = (
        explanation[
            "selected_plan"
        ][
            "predicted_residual_risk"
        ]
        < 96
    )


    approval_pass = (
        explanation[
            "requires_analyst_approval"
        ]
        is True
    )


    safe_pass = (
        explanation[
            "real_endpoint_modified"
        ]
        is False
    )


    summary_pass = (
        len(
            explanation[
                "summary"
            ]
        )
        > 50
    )


    # ============================================================
    # FINAL
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL DIGITAL TWIN EXPLAINABILITY VALIDATION"
    )
    print("=" * 80)


    print(
        "Explanation generated:",
        "PASS"
        if status_pass
        else "FAIL",
    )


    print(
        "Correct selected plan explained:",
        "PASS"
        if selected_pass
        else "FAIL",
    )


    print(
        "Selection reasons generated:",
        "PASS"
        if reasons_pass
        else "FAIL",
    )


    print(
        "Alternative plans explained:",
        "PASS"
        if alternatives_pass
        else "FAIL",
    )


    print(
        "Risk improvement explained:",
        "PASS"
        if risk_pass
        else "FAIL",
    )


    print(
        "Analyst approval preserved:",
        "PASS"
        if approval_pass
        else "FAIL",
    )


    print(
        "Human-readable summary generated:",
        "PASS"
        if summary_pass
        else "FAIL",
    )


    print(
        "Real endpoint unchanged:",
        "PASS"
        if safe_pass
        else "FAIL",
    )


    overall = all(
        [
            status_pass,
            selected_pass,
            reasons_pass,
            alternatives_pass,
            risk_pass,
            approval_pass,
            summary_pass,
            safe_pass,
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