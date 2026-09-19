from agents.agent_coordinator import (
    AgentCoordinator,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X MULTI-AGENT COORDINATOR TEST"
    )
    print("=" * 80)


    incident = {

        "incident_id":
            "INC-AGENTS-001",

        "title":
            "Multi-source correlated security incident",

        "severity":
            "CRITICAL",

        "correlation_score":
            92,

        "categories": [
            "PROCESS",
            "FILE",
            "NETWORK",
            "REGISTRY",
        ],

        "timeline": [

            # ====================================================
            # PROCESS
            # ====================================================

            {

                "event_id":
                    "proc-agent-001",

                "timestamp_unix":
                    1000,

                "event_type":
                    "process_start",

                "source":
                    "process_monitor",

                "severity":
                    "HIGH",

                "process": {

                    "pid":
                        8000,

                    "ppid":
                        1000,

                    "name":
                        "demo.exe",

                    "exe":
                        r"C:\Temp\demo.exe",

                    "cmdline":
                        r"C:\Temp\demo.exe",

                    "parent_name":
                        "explorer.exe",

                    "behavior_score":
                        80,

                    "anomaly_score":
                        70,

                    "combined_threat_score":
                        95,

                    "behavior_indicators": [
                        "suspicious_execution",
                    ],
                },

                "file":
                    {},

                "network":
                    {},

                "registry":
                    {},

                "metadata":
                    {},
            },


            # ====================================================
            # FILE
            # ====================================================

            {

                "event_id":
                    "file-agent-001",

                "timestamp_unix":
                    1010,

                "event_type":
                    "file_modify",

                "source":
                    "file_monitor",

                "severity":
                    "HIGH",

                "process":
                    {},

                "file": {

                    "name":
                        "demo.exe",

                    "path":
                        r"C:\Temp\demo.exe",

                    "extension":
                        ".exe",

                    "size":
                        250000,

                    "md5":
                        "AGENT_MD5",

                    "sha1":
                        "AGENT_SHA1",

                    "sha256":
                        "AGENT_SHA256",

                    "entropy":
                        7.3,

                    "is_pe":
                        True,

                    "static_risk_score":
                        75,

                    "static_severity":
                        "HIGH",

                    "ml_prediction":
                        1,

                    "malware_probability":
                        0.96,

                    "ml_confidence":
                        0.96,

                    "static_reasons": [
                        "Executable or script file type",
                        "High entropy executable",
                    ],
                },

                "network":
                    {},

                "registry":
                    {},

                "metadata":
                    {},
            },


            # ====================================================
            # NETWORK
            # ====================================================

            {

                "event_id":
                    "network-agent-001",

                "timestamp_unix":
                    1020,

                "event_type":
                    "network_connect",

                "source":
                    "network_monitor",

                "severity":
                    "HIGH",

                "process":
                    {},

                "file":
                    {},

                "network": {

                    "pid":
                        8000,

                    "process_name":
                        "demo.exe",

                    "protocol":
                        "TCP",

                    "local_ip":
                        "192.168.1.20",

                    "local_port":
                        52000,

                    "remote_ip":
                        "203.0.113.200",

                    "remote_port":
                        443,

                    "status":
                        "ESTABLISHED",
                },

                "registry":
                    {},

                "metadata":
                    {},
            },


            # ====================================================
            # REGISTRY
            # ====================================================

            {

                "event_id":
                    "registry-agent-001",

                "timestamp_unix":
                    1030,

                "event_type":
                    "registry_change",

                "source":
                    "registry_monitor",

                "severity":
                    "HIGH",

                "process":
                    {},

                "file":
                    {},

                "network":
                    {},

                "registry": {

                    "key":
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                    "value_name":
                        "DemoApp",

                    "value_data":
                        r"C:\Temp\demo.exe",
                },

                "metadata":
                    {},
            },
        ],
    }


    coordinator = (
        AgentCoordinator()
    )


    result = (
        coordinator.coordinate(
            incident
        )
    )


    # ============================================================
    # BASIC RESULT
    # ============================================================

    print()
    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )

    print(
        "Coordinator:",
        result[
            "coordinator"
        ],
    )

    print(
        "Status:",
        result[
            "status"
        ],
    )


    # ============================================================
    # AGENT OUTPUTS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "AGENT OUTPUTS"
    )
    print("=" * 80)


    for agent_name in result[
        "agent_outputs"
    ]:

        print(
            agent_name
        )


    # ============================================================
    # DECISIONS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "AGENT DECISIONS"
    )
    print("=" * 80)


    for decision in result[
        "decisions"
    ]:

        print()

        print(
            "Agent:",
            decision[
                "agent"
            ],
        )

        print(
            "Decision:",
            decision[
                "decision"
            ],
        )

        print(
            "Confidence:",
            decision[
                "confidence"
            ],
        )

        print(
            "Reason:",
            decision[
                "reason"
            ],
        )


    # ============================================================
    # RECOMMENDATIONS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "AGENT RECOMMENDATIONS"
    )
    print("=" * 80)


    for recommendation in result[
        "recommendations"
    ]:

        print()

        print(
            recommendation
        )


    # ============================================================
    # RISK
    # ============================================================

    print()
    print("=" * 80)
    print(
        "SHARED RISK"
    )
    print("=" * 80)


    print(
        "Risk Score:",
        result[
            "risk"
        ].get(
            "risk_score"
        ),
    )

    print(
        "Risk Level:",
        result[
            "risk"
        ].get(
            "risk_level"
        ),
    )


    # ============================================================
    # ERRORS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "AGENT ERRORS"
    )
    print("=" * 80)


    if result[
        "errors"
    ]:

        for error in result[
            "errors"
        ]:

            print(
                error
            )

    else:

        print(
            "No agent errors."
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    expected_agents = [

        "TriageAgent",

        "InvestigationAgent",

        "EvidenceEnrichmentAgent",

        "AttackTimelineAgent",

        "AttackGraphAgent",

        "RiskAssessmentAgent",

        "InvestigationReportAgent",
    ]


    agents_pass = all(

        agent_name
        in result[
            "agent_outputs"
        ]

        for agent_name
        in expected_agents
    )


    triage_pass = (
        result[
            "agent_outputs"
        ][
            "TriageAgent"
        ][
            "priority"
        ]
        == "P1"
    )


    risk_pass = (
        result[
            "risk"
        ].get(
            "risk_level"
        )
        == "CRITICAL"
    )


    decisions_pass = (
        len(
            result[
                "decisions"
            ]
        )
        >= 3
    )


    recommendations_pass = (
        len(
            result[
                "recommendations"
            ]
        )
        >= 2
    )


    errors_pass = (
        len(
            result[
                "errors"
            ]
        )
        == 0
    )


    status_pass = (
        result[
            "status"
        ]
        == "COMPLETED"
    )


    report_pass = (
        "InvestigationReportAgent"
        in result[
            "agent_outputs"
        ]
        and
        "text_report"
        in result[
            "agent_outputs"
        ][
            "InvestigationReportAgent"
        ]
    )


    print()
    print("=" * 80)
    print(
        "FINAL MULTI-AGENT COORDINATOR VALIDATION"
    )
    print("=" * 80)


    print(
        "All agents executed:",
        "PASS"
        if agents_pass
        else "FAIL",
    )


    print(
        "Triage decision:",
        "PASS"
        if triage_pass
        else "FAIL",
    )


    print(
        "Shared risk:",
        "PASS"
        if risk_pass
        else "FAIL",
    )


    print(
        "Agent decisions:",
        "PASS"
        if decisions_pass
        else "FAIL",
    )


    print(
        "Agent recommendations:",
        "PASS"
        if recommendations_pass
        else "FAIL",
    )


    print(
        "No agent errors:",
        "PASS"
        if errors_pass
        else "FAIL",
    )


    print(
        "Final report:",
        "PASS"
        if report_pass
        else "FAIL",
    )


    print(
        "Coordinator status:",
        "PASS"
        if status_pass
        else "FAIL",
    )


    overall = all(
        [
            agents_pass,
            triage_pass,
            risk_pass,
            decisions_pass,
            recommendations_pass,
            errors_pass,
            report_pass,
            status_pass,
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