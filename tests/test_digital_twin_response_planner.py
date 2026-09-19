from response.endpoint_digital_twin import (
    EndpointDigitalTwin,
)

from response.digital_twin_response_planner import (
    DigitalTwinResponsePlanner,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X DIGITAL TWIN RESPONSE PLANNER TEST"
    )
    print("=" * 80)


    # ============================================================
    # SYNTHETIC EVIDENCE
    # ============================================================

    evidence = {

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
                "sha256": "PLANNER_SHA256",
                "malware_probability": 0.96,
                "static_risk_score": 80,
            }
        ],

        "network_connections": [
            {
                "pid": 7000,
                "process_name": "demo.exe",
                "remote_ip": "203.0.113.100",
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
    }


    # ============================================================
    # CREATE SOURCE TWIN
    # ============================================================

    twin = EndpointDigitalTwin(

        incident_id=
            "INC-PLANNER-001",

        initial_risk_score=
            96,

        initial_risk_level=
            "CRITICAL",
    )


    twin.load_evidence(
        evidence
    )


    planner = (
        DigitalTwinResponsePlanner()
    )


    # ============================================================
    # RESPONSE PLANS
    # ============================================================

    plans = [

        # --------------------------------------------------------
        # PLAN A
        # --------------------------------------------------------

        {
            "plan_id":
                "PLAN-A",

            "plan_name":
                "Quarantine Only",

            "description":
                "Quarantine the suspicious file.",

            "actions": [

                {
                    "action_type":
                        "QUARANTINE_FILE",

                    "target": {
                        "path":
                            r"C:\Temp\demo.exe",

                        "sha256":
                            "PLANNER_SHA256",
                    },
                },
            ],
        },


        # --------------------------------------------------------
        # PLAN B
        # --------------------------------------------------------

        {
            "plan_id":
                "PLAN-B",

            "plan_name":
                "Process and File Containment",

            "description":
                (
                    "Terminate suspicious process "
                    "and quarantine associated file."
                ),

            "actions": [

                {
                    "action_type":
                        "TERMINATE_PROCESS",

                    "target": {
                        "pid":
                            7000,
                    },
                },

                {
                    "action_type":
                        "QUARANTINE_FILE",

                    "target": {
                        "path":
                            r"C:\Temp\demo.exe",

                        "sha256":
                            "PLANNER_SHA256",
                    },
                },
            ],
        },


        # --------------------------------------------------------
        # PLAN C
        # --------------------------------------------------------

        {
            "plan_id":
                "PLAN-C",

            "plan_name":
                "Targeted Full Remediation",

            "description":
                (
                    "Terminate process, quarantine file "
                    "and remove persistence."
                ),

            "actions": [

                {
                    "action_type":
                        "TERMINATE_PROCESS",

                    "target": {
                        "pid":
                            7000,
                    },
                },

                {
                    "action_type":
                        "QUARANTINE_FILE",

                    "target": {
                        "path":
                            r"C:\Temp\demo.exe",

                        "sha256":
                            "PLANNER_SHA256",
                    },
                },

                {
                    "action_type":
                        "REMEDIATE_PERSISTENCE",

                    "target": {

                        "key":
                            (
                                r"HKCU\Software\Microsoft"
                                r"\Windows\CurrentVersion\Run"
                            ),

                        "value_name":
                            "DemoApp",
                    },
                },
            ],
        },


        # --------------------------------------------------------
        # PLAN D
        # --------------------------------------------------------

        {
            "plan_id":
                "PLAN-D",

            "plan_name":
                "Full Endpoint Isolation",

            "description":
                (
                    "Isolate the endpoint "
                    "from non-management network access."
                ),

            "actions": [

                {
                    "action_type":
                        "ISOLATE_ENDPOINT",

                    "target": {},
                },
            ],
        },
    ]


    # ============================================================
    # COMPARE
    # ============================================================

    result = (
        planner.compare_plans(
            twin,
            plans,
        )
    )


    # ============================================================
    # PRINT RANKING
    # ============================================================

    print()
    print("=" * 80)
    print(
        "RESPONSE PLAN RANKING"
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
            f"Rank {index}"
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
            "Impact:",
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
        "SELECTED RESPONSE PLAN"
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
        "Plan Score:",
        best[
            "plan_score"
        ],
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    count_pass = (
        result[
            "plans_evaluated"
        ]
        == 4
    )


    ranking_pass = (
        len(
            result[
                "ranked_plans"
            ]
        )
        == 4
    )


    sorted_pass = all(

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


    best_exists_pass = (
        best
        is not None
    )


    residual_pass = (
        best[
            "predicted_residual_risk"
        ]
        < 96
    )


    safe_pass = all(

        plan[
            "real_endpoint_modified"
        ]
        is False

        for plan in result[
            "ranked_plans"
        ]
    )


    source_unchanged_pass = (

        twin.get_state_summary()[
            "active_processes"
        ]
        == 1

        and

        twin.get_state_summary()[
            "active_files"
        ]
        == 1

        and

        twin.get_state_summary()[
            "active_persistence_artifacts"
        ]
        == 1
    )


    # ============================================================
    # FINAL
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL RESPONSE PLANNER VALIDATION"
    )
    print("=" * 80)


    print(
        "Four plans evaluated:",
        "PASS"
        if count_pass
        else "FAIL",
    )


    print(
        "Ranking generated:",
        "PASS"
        if ranking_pass
        else "FAIL",
    )


    print(
        "Plans correctly ranked:",
        "PASS"
        if sorted_pass
        else "FAIL",
    )


    print(
        "Best plan selected:",
        "PASS"
        if best_exists_pass
        else "FAIL",
    )


    print(
        "Best plan reduces risk:",
        "PASS"
        if residual_pass
        else "FAIL",
    )


    print(
        "No real endpoint modification:",
        "PASS"
        if safe_pass
        else "FAIL",
    )


    print(
        "Original twin unchanged:",
        "PASS"
        if source_unchanged_pass
        else "FAIL",
    )


    overall = all(
        [
            count_pass,
            ranking_pass,
            sorted_pass,
            best_exists_pass,
            residual_pass,
            safe_pass,
            source_unchanged_pass,
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