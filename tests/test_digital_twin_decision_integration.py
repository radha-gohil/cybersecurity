import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )

from response.digital_twin_decision_integration import (
    DigitalTwinDecisionIntegration,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X DIGITAL TWIN DECISION INTEGRATION TEST"
    )
    print("=" * 80)


    # ============================================================
    # SYNTHETIC MULTI-AGENT OUTPUT
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
                            "DECISION_TWIN_SHA256",

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
                            "203.0.113.120",

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


    integration = (
        DigitalTwinDecisionIntegration()
    )


    result = (
        integration.evaluate(

            incident_id=
                "INC-DT-DECISION-001",

            intelligence=
                intelligence,
        )
    )


    # ============================================================
    # PRINT SUMMARY
    # ============================================================

    print()
    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )

    print(
        "Twin ID:",
        result[
            "twin_id"
        ],
    )

    print(
        "Initial Risk:",
        result[
            "initial_risk_score"
        ],
    )

    print(
        "Initial Level:",
        result[
            "initial_risk_level"
        ],
    )

    print(
        "Candidate Actions:",
        result[
            "candidate_action_count"
        ],
    )

    print(
        "Plans Evaluated:",
        result[
            "plans_evaluated"
        ],
    )

    print(
        "Decision:",
        result[
            "decision"
        ],
    )


    # ============================================================
    # RANKED PLANS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "DIGITAL TWIN RESPONSE PLAN RANKING"
    )
    print("=" * 80)


    for index, plan in enumerate(
        result[
            "ranked_plans"
        ],
        start=1,
    ):

        print()

        print(
            "Rank:",
            index,
        )

        print(
            "Plan:",
            plan[
                "plan_name"
            ],
        )

        print(
            "Residual Risk:",
            plan[
                "predicted_residual_risk"
            ],
        )

        print(
            "Risk Reduction %:",
            plan[
                "risk_reduction_percentage"
            ],
        )

        print(
            "Operational Impact:",
            plan[
                "operational_impact"
            ][
                "impact_level"
            ],
        )

        print(
            "Plan Score:",
            plan[
                "plan_score"
            ],
        )


    # ============================================================
    # BEST PLAN
    # ============================================================

    best = (
        result[
            "best_plan"
        ]
    )


    print()
    print("=" * 80)
    print(
        "DIGITAL TWIN SELECTED PLAN"
    )
    print("=" * 80)


    print(
        "Plan:",
        best[
            "plan_name"
        ],
    )

    print(
        "Residual Risk:",
        best[
            "predicted_residual_risk"
        ],
    )

    print(
        "Impact:",
        best[
            "operational_impact"
        ][
            "impact_level"
        ],
    )

    print(
        "Effectiveness:",
        best[
            "response_effectiveness"
        ],
    )

    print(
        "Plan Score:",
        best[
            "plan_score"
        ],
    )

    print(
        "Analyst Approval Required:",
        result[
            "requires_analyst_approval"
        ],
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    twin_pass = (
        result[
            "twin_id"
        ].startswith(
            "TWIN-"
        )
    )


    risk_pass = (
        result[
            "initial_risk_score"
        ]
        == 96
    )


    actions_pass = (
        result[
            "candidate_action_count"
        ]
        == 5
    )


    plans_pass = (
        result[
            "plans_evaluated"
        ]
        >= 3
    )


    best_pass = (
        best
        is not None
    )


    reduction_pass = (
        best[
            "predicted_residual_risk"
        ]
        < 96
    )


    ranking_pass = all(

        result[
            "ranked_plans"
        ][i][
            "plan_score"
        ]
        >=

        result[
            "ranked_plans"
        ][i + 1][
            "plan_score"
        ]

        for i in range(
            len(
                result[
                    "ranked_plans"
                ]
            )
            - 1
        )
    )


    approval_pass = (
        result[
            "requires_analyst_approval"
        ]
        is True
    )


    decision_pass = (
        result[
            "decision"
        ]
        == "ANALYST_APPROVAL_REQUIRED"
    )


    safe_pass = (
        result[
            "real_endpoint_modified"
        ]
        is False
    )


    # ============================================================
    # FINAL
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL DIGITAL TWIN DECISION VALIDATION"
    )
    print("=" * 80)


    print(
        "Digital twin created:",
        "PASS"
        if twin_pass
        else "FAIL",
    )


    print(
        "Initial risk loaded:",
        "PASS"
        if risk_pass
        else "FAIL",
    )


    print(
        "Five response candidates created:",
        "PASS"
        if actions_pass
        else "FAIL",
    )


    print(
        "Multiple plans evaluated:",
        "PASS"
        if plans_pass
        else "FAIL",
    )


    print(
        "Best plan selected:",
        "PASS"
        if best_pass
        else "FAIL",
    )


    print(
        "Selected plan reduces risk:",
        "PASS"
        if reduction_pass
        else "FAIL",
    )


    print(
        "Response plans ranked:",
        "PASS"
        if ranking_pass
        else "FAIL",
    )


    print(
        "Analyst approval required:",
        "PASS"
        if approval_pass
        else "FAIL",
    )


    print(
        "Decision correctly gated:",
        "PASS"
        if decision_pass
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
            twin_pass,
            risk_pass,
            actions_pass,
            plans_pass,
            best_pass,
            reduction_pass,
            ranking_pass,
            approval_pass,
            decision_pass,
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