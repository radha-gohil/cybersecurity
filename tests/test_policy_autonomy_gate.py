from agents.policy_autonomy_gate import (
    PolicyAutonomyGate,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X POLICY / AUTONOMY GATE TEST"
    )
    print("=" * 80)


    response_result = {

        "recommendations": [

            {

                "action":
                    "MONITOR_INCIDENT",

                "requires_approval":
                    False,
            },

            {

                "action":
                    "INVESTIGATE_INCIDENT",

                "requires_approval":
                    False,
            },

            {

                "action":
                    "QUARANTINE_REVIEW",

                "requires_approval":
                    True,
            },

            {

                "action":
                    "PROCESS_TERMINATION_REVIEW",

                "requires_approval":
                    True,
            },

            {

                "action":
                    "NETWORK_BLOCK_REVIEW",

                "requires_approval":
                    True,
            },

            {

                "action":
                    "PERSISTENCE_REMEDIATION_REVIEW",

                "requires_approval":
                    True,
            },

            {

                "action":
                    "ENDPOINT_ISOLATION_REVIEW",

                "requires_approval":
                    True,
            },
        ],
    }


    # ============================================================
    # TEST CURRENT DEVELOPMENT MODE
    # AUTONOMY LEVEL 2
    # ============================================================

    gate = (
        PolicyAutonomyGate(
            autonomy_level=2
        )
    )


    result = (
        gate.evaluate_recommendations(
            response_result
        )
    )


    print()
    print(
        "Autonomy Level:",
        result[
            "autonomy_level"
        ],
    )

    print(
        "Autonomy Mode:",
        result[
            "autonomy_mode"
        ],
    )

    print(
        "Allowed:",
        result[
            "allowed_count"
        ],
    )

    print(
        "Review / Recommendation:",
        result[
            "review_or_recommendation_count"
        ],
    )

    print(
        "Denied:",
        result[
            "denied_count"
        ],
    )


    print()
    print("=" * 80)
    print(
        "ACTION EVALUATIONS"
    )
    print("=" * 80)


    for item in result[
        "evaluations"
    ]:

        print()

        print(
            "Action:",
            item[
                "action"
            ],
        )

        print(
            "Classification:",
            item[
                "classification"
            ],
        )

        print(
            "Policy Decision:",
            item[
                "policy_decision"
            ],
        )

        print(
            "Execution Allowed:",
            item[
                "execution_allowed"
            ],
        )

        print(
            "Approval Required:",
            item[
                "approval_required"
            ],
        )

        print(
            "Reason:",
            item[
                "reason"
            ],
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    evaluation_map = {

        item[
            "action"
        ]:
            item

        for item in result[
            "evaluations"
        ]
    }


    monitor_pass = (

        evaluation_map[
            "MONITOR_INCIDENT"
        ][
            "policy_decision"
        ]
        == "ALLOW"
    )


    investigation_pass = (

        evaluation_map[
            "INVESTIGATE_INCIDENT"
        ][
            "policy_decision"
        ]
        == "ALLOW"
    )


    quarantine_pass = (

        evaluation_map[
            "QUARANTINE_REVIEW"
        ][
            "policy_decision"
        ]
        == "RECOMMEND_ONLY"

        and

        evaluation_map[
            "QUARANTINE_REVIEW"
        ][
            "execution_allowed"
        ]
        is False
    )


    process_pass = (

        evaluation_map[
            "PROCESS_TERMINATION_REVIEW"
        ][
            "execution_allowed"
        ]
        is False
    )


    network_pass = (

        evaluation_map[
            "NETWORK_BLOCK_REVIEW"
        ][
            "execution_allowed"
        ]
        is False
    )


    persistence_pass = (

        evaluation_map[
            "PERSISTENCE_REMEDIATION_REVIEW"
        ][
            "execution_allowed"
        ]
        is False
    )


    isolation_pass = (

        evaluation_map[
            "ENDPOINT_ISOLATION_REVIEW"
        ][
            "execution_allowed"
        ]
        is False
    )


    containment_disabled_pass = (

        result[
            "automatic_containment_enabled"
        ]
        is False
    )


    # ============================================================
    # LEVEL 0 TEST
    # ============================================================

    level_zero = (
        PolicyAutonomyGate(
            autonomy_level=0
        )
    )


    level_zero_result = (
        level_zero.evaluate_recommendations(
            response_result
        )
    )


    level_zero_map = {

        item[
            "action"
        ]:
            item

        for item in level_zero_result[
            "evaluations"
        ]
    }


    level_zero_pass = (

        level_zero_map[
            "MONITOR_INCIDENT"
        ][
            "policy_decision"
        ]
        == "ALLOW"

        and

        level_zero_map[
            "INVESTIGATE_INCIDENT"
        ][
            "policy_decision"
        ]
        == "DENY"
    )


    # ============================================================
    # LEVEL 4 TEST
    # ============================================================

    level_four = (
        PolicyAutonomyGate(
            autonomy_level=4
        )
    )


    level_four_result = (
        level_four.evaluate_recommendations(
            response_result
        )
    )


    level_four_map = {

        item[
            "action"
        ]:
            item

        for item in level_four_result[
            "evaluations"
        ]
    }


    level_four_pass = (

        level_four_map[
            "ENDPOINT_ISOLATION_REVIEW"
        ][
            "policy_decision"
        ]
        == "POLICY_ELIGIBLE"

        and

        level_four_map[
            "ENDPOINT_ISOLATION_REVIEW"
        ][
            "execution_allowed"
        ]
        is False
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL POLICY / AUTONOMY VALIDATION"
    )
    print("=" * 80)


    print(
        "Monitoring allowed:",
        "PASS"
        if monitor_pass
        else "FAIL",
    )


    print(
        "Investigation allowed:",
        "PASS"
        if investigation_pass
        else "FAIL",
    )


    print(
        "Quarantine remains recommendation-only:",
        "PASS"
        if quarantine_pass
        else "FAIL",
    )


    print(
        "Process termination not executed:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "Network block not executed:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Persistence remediation not executed:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Endpoint isolation not executed:",
        "PASS"
        if isolation_pass
        else "FAIL",
    )


    print(
        "Automatic containment disabled:",
        "PASS"
        if containment_disabled_pass
        else "FAIL",
    )


    print(
        "Level 0 monitor-only policy:",
        "PASS"
        if level_zero_pass
        else "FAIL",
    )


    print(
        "Level 4 policy eligibility:",
        "PASS"
        if level_four_pass
        else "FAIL",
    )


    overall = all(
        [
            monitor_pass,
            investigation_pass,
            quarantine_pass,
            process_pass,
            network_pass,
            persistence_pass,
            isolation_pass,
            containment_disabled_pass,
            level_zero_pass,
            level_four_pass,
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