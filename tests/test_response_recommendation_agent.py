from agents.response_recommendation_agent import (
    ResponseRecommendationAgent,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X RESPONSE RECOMMENDATION AGENT TEST"
    )
    print("=" * 80)


    # ============================================================
    # CONSENSUS
    # ============================================================

    consensus = {

        "final_decision":
            "CONTAINMENT_RECOMMENDED",

        "consensus_confidence":
            94,

        "severity":
            "CRITICAL",
    }


    # ============================================================
    # RISK
    # ============================================================

    risk = {

        "risk_score":
            96,

        "risk_level":
            "CRITICAL",

        "requires_response":
            True,
    }


    # ============================================================
    # EVIDENCE
    # ============================================================

    evidence = {

        "processes": [

            {

                "pid":
                    9000,

                "name":
                    "demo.exe",

                "exe":
                    r"C:\Temp\demo.exe",

                "behavior_score":
                    80,

                "anomaly_score":
                    70,

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
                    "RESPONSE_TEST_SHA256",

                "malware_probability":
                    0.96,
            },
        ],


        "network_connections": [

            {

                "pid":
                    9000,

                "process_name":
                    "demo.exe",

                "remote_ip":
                    "203.0.113.220",

                "remote_port":
                    443,
            },
        ],


        "registry_artifacts": [

            {

                "key":
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                "value_name":
                    "DemoApp",

                "value_data":
                    r"C:\Temp\demo.exe",
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

            "NETWORK_ACTIVITY",

            "PERSISTENCE",
        ],
    }


    # ============================================================
    # RUN AGENT
    # ============================================================

    agent = (
        ResponseRecommendationAgent()
    )


    result = (
        agent.generate(
            consensus,
            risk,
            evidence,
            attack_timeline,
        )
    )


    # ============================================================
    # PRINT SUMMARY
    # ============================================================

    print()
    print(
        "Response Level:",
        result[
            "response_level"
        ],
    )

    print(
        "Consensus Decision:",
        result[
            "consensus_decision"
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
        "Recommendation Count:",
        result[
            "recommendation_count"
        ],
    )

    print(
        "Execution Allowed:",
        result[
            "execution_allowed"
        ],
    )


    # ============================================================
    # PRINT RECOMMENDATIONS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "RESPONSE RECOMMENDATIONS"
    )
    print("=" * 80)


    for item in result[
        "recommendations"
    ]:

        print()

        print(
            "Action:",
            item[
                "action"
            ],
        )

        print(
            "Priority:",
            item[
                "priority"
            ],
        )

        print(
            "Requires Approval:",
            item[
                "requires_approval"
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

    actions = {

        item[
            "action"
        ]

        for item in result[
            "recommendations"
        ]
    }


    monitor_pass = (
        "MONITOR_INCIDENT"
        in actions
    )


    investigation_pass = (
        "INVESTIGATE_INCIDENT"
        in actions
    )


    quarantine_pass = (
        "QUARANTINE_REVIEW"
        in actions
    )


    process_pass = (
        "PROCESS_TERMINATION_REVIEW"
        in actions
    )


    network_pass = (
        "NETWORK_BLOCK_REVIEW"
        in actions
    )


    persistence_pass = (
        "PERSISTENCE_REMEDIATION_REVIEW"
        in actions
    )


    isolation_pass = (
        "ENDPOINT_ISOLATION_REVIEW"
        in actions
    )


    execution_pass = (
        result[
            "execution_allowed"
        ]
        is False
    )


    level_pass = (
        result[
            "response_level"
        ]
        == "CONTAINMENT_REVIEW"
    )


    approval_pass = all(

        item[
            "requires_approval"
        ]

        for item in result[
            "recommendations"
        ]

        if item[
            "action"
        ]
        in {

            "QUARANTINE_REVIEW",

            "PROCESS_TERMINATION_REVIEW",

            "NETWORK_BLOCK_REVIEW",

            "PERSISTENCE_REMEDIATION_REVIEW",

            "ENDPOINT_ISOLATION_REVIEW",
        }
    )


    print()
    print("=" * 80)
    print(
        "FINAL RESPONSE RECOMMENDATION VALIDATION"
    )
    print("=" * 80)


    print(
        "Monitoring recommendation:",
        "PASS"
        if monitor_pass
        else "FAIL",
    )


    print(
        "Investigation recommendation:",
        "PASS"
        if investigation_pass
        else "FAIL",
    )


    print(
        "Quarantine review:",
        "PASS"
        if quarantine_pass
        else "FAIL",
    )


    print(
        "Process termination review:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "Network block review:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Persistence remediation review:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Endpoint isolation review:",
        "PASS"
        if isolation_pass
        else "FAIL",
    )


    print(
        "No automatic execution:",
        "PASS"
        if execution_pass
        else "FAIL",
    )


    print(
        "Containment review level:",
        "PASS"
        if level_pass
        else "FAIL",
    )


    print(
        "Destructive actions require approval:",
        "PASS"
        if approval_pass
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
            execution_pass,
            level_pass,
            approval_pass,
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