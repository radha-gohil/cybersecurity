from response.recommendation_action_mapper import (
    RecommendationActionMapper,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X RECOMMENDATION -> ACTION MAPPER TEST"
    )
    print("=" * 80)


    # ============================================================
    # SYNTHETIC RESPONSE RECOMMENDATIONS
    # ============================================================

    response_result = {

        "recommendations": [

            {
                "action":
                    "MONITOR_INCIDENT",

                "priority":
                    "LOW",

                "reason":
                    "Continue monitoring incident.",

                "requires_approval":
                    False,

                "target":
                    {},
            },

            {
                "action":
                    "INVESTIGATE_INCIDENT",

                "priority":
                    "HIGH",

                "reason":
                    "Further investigation required.",

                "requires_approval":
                    False,

                "target":
                    {},
            },

            {
                "action":
                    "QUARANTINE_REVIEW",

                "priority":
                    "CRITICAL",

                "reason":
                    "High malware probability.",

                "requires_approval":
                    True,

                "target": {

                    "files": [

                        {
                            "path":
                                r"C:\Temp\demo.exe",

                            "sha256":
                                "MAPPER_SHA256",

                            "malware_probability":
                                0.96,
                        },
                    ],
                },
            },

            {
                "action":
                    "PROCESS_TERMINATION_REVIEW",

                "priority":
                    "CRITICAL",

                "reason":
                    "High process threat score.",

                "requires_approval":
                    True,

                "target": {

                    "processes": [

                        {
                            "pid":
                                9999,

                            "name":
                                "demo.exe",

                            "exe":
                                r"C:\Temp\demo.exe",

                            "threat_score":
                                95,
                        },
                    ],
                },
            },

            {
                "action":
                    "NETWORK_BLOCK_REVIEW",

                "priority":
                    "HIGH",

                "reason":
                    "Network activity associated with incident.",

                "requires_approval":
                    True,

                "target": {

                    "connections": [

                        {
                            "remote_ip":
                                "203.0.113.10",

                            "remote_port":
                                443,

                            "pid":
                                9999,

                            "process_name":
                                "demo.exe",
                        },
                    ],
                },
            },

            {
                "action":
                    "PERSISTENCE_REMEDIATION_REVIEW",

                "priority":
                    "HIGH",

                "reason":
                    "Possible persistence artifact detected.",

                "requires_approval":
                    True,

                "target": {

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

            {
                "action":
                    "ENDPOINT_ISOLATION_REVIEW",

                "priority":
                    "CRITICAL",

                "reason":
                    "Critical incident requires containment review.",

                "requires_approval":
                    True,

                "target": {},
            },
        ],
    }


    # ============================================================
    # SYNTHETIC POLICY RESULT
    # ============================================================

    policy_result = {

        "autonomy_level":
            2,

        "autonomy_mode":
            "RECOMMEND_ONLY",

        "evaluations": [

            {
                "action":
                    "MONITOR_INCIDENT",

                "policy_decision":
                    "ALLOW",
            },

            {
                "action":
                    "INVESTIGATE_INCIDENT",

                "policy_decision":
                    "ALLOW",
            },

            {
                "action":
                    "QUARANTINE_REVIEW",

                "policy_decision":
                    "RECOMMEND_ONLY",
            },

            {
                "action":
                    "PROCESS_TERMINATION_REVIEW",

                "policy_decision":
                    "RECOMMEND_ONLY",
            },

            {
                "action":
                    "NETWORK_BLOCK_REVIEW",

                "policy_decision":
                    "RECOMMEND_ONLY",
            },

            {
                "action":
                    "PERSISTENCE_REMEDIATION_REVIEW",

                "policy_decision":
                    "RECOMMEND_ONLY",
            },

            {
                "action":
                    "ENDPOINT_ISOLATION_REVIEW",

                "policy_decision":
                    "RECOMMEND_ONLY",
            },
        ],
    }


    # ============================================================
    # RUN MAPPER
    # ============================================================

    mapper = (
        RecommendationActionMapper()
    )


    result = (
        mapper.map_all(

            incident_id=
                "INC-MAPPER-001",

            response_result=
                response_result,

            policy_result=
                policy_result,

            risk_level=
                "CRITICAL",
        )
    )


    # ============================================================
    # PRINT ACTIONS
    # ============================================================

    print()
    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )

    print(
        "Action Count:",
        result[
            "action_count"
        ],
    )


    print()
    print("=" * 80)
    print(
        "GENERATED RESPONSE ACTIONS"
    )
    print("=" * 80)


    for action in result[
        "actions"
    ]:

        data = (
            action.to_dict()
        )


        print()

        print(
            "Action ID:",
            data[
                "action_id"
            ],
        )

        print(
            "Action Type:",
            data[
                "action_type"
            ],
        )

        print(
            "Policy Decision:",
            data[
                "policy_decision"
            ],
        )

        print(
            "Approval Required:",
            data[
                "approval_required"
            ],
        )

        print(
            "Approval Status:",
            data[
                "approval_status"
            ],
        )

        print(
            "Execution Status:",
            data[
                "execution_status"
            ],
        )

        print(
            "Can Execute:",
            data[
                "can_execute"
            ],
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    action_types = {

        action.action_type

        for action in result[
            "actions"
        ]
    }


    count_pass = (
        result[
            "action_count"
        ]
        == 7
    )


    monitor_pass = (
        "MONITOR_INCIDENT"
        in action_types
    )


    investigate_pass = (
        "INVESTIGATE_INCIDENT"
        in action_types
    )


    quarantine_pass = (
        "QUARANTINE_FILE"
        in action_types
    )


    terminate_pass = (
        "TERMINATE_PROCESS"
        in action_types
    )


    network_pass = (
        "BLOCK_NETWORK"
        in action_types
    )


    persistence_pass = (
        "REMEDIATE_PERSISTENCE"
        in action_types
    )


    isolation_pass = (
        "ISOLATE_ENDPOINT"
        in action_types
    )


    destructive_actions = {

        "QUARANTINE_FILE",

        "TERMINATE_PROCESS",

        "BLOCK_NETWORK",

        "REMEDIATE_PERSISTENCE",

        "ISOLATE_ENDPOINT",
    }


    approval_pass = all(

        action.approval_required
        is True

        and

        action.approval_status
        == "PENDING"

        and

        action.can_execute()
        is False

        for action in result[
            "actions"
        ]

        if action.action_type
        in destructive_actions
    )


    policy_pass = all(

        action.policy_decision
        == "RECOMMEND_ONLY"

        for action in result[
            "actions"
        ]

        if action.action_type
        in destructive_actions
    )


    print()
    print("=" * 80)
    print(
        "FINAL RECOMMENDATION -> ACTION VALIDATION"
    )
    print("=" * 80)


    print(
        "Seven actions generated:",
        "PASS"
        if count_pass
        else "FAIL",
    )


    print(
        "Monitor action:",
        "PASS"
        if monitor_pass
        else "FAIL",
    )


    print(
        "Investigation action:",
        "PASS"
        if investigate_pass
        else "FAIL",
    )


    print(
        "Quarantine action:",
        "PASS"
        if quarantine_pass
        else "FAIL",
    )


    print(
        "Process action:",
        "PASS"
        if terminate_pass
        else "FAIL",
    )


    print(
        "Network action:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Persistence action:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Isolation action:",
        "PASS"
        if isolation_pass
        else "FAIL",
    )


    print(
        "Response actions require approval:",
        "PASS"
        if approval_pass
        else "FAIL",
    )


    print(
        "Policy decision preserved:",
        "PASS"
        if policy_pass
        else "FAIL",
    )


    overall = all(
        [
            count_pass,
            monitor_pass,
            investigate_pass,
            quarantine_pass,
            terminate_pass,
            network_pass,
            persistence_pass,
            isolation_pass,
            approval_pass,
            policy_pass,
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