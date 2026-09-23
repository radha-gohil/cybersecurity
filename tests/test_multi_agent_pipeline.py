import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )

from agents.multi_agent_pipeline import (
    MultiAgentSecurityPipeline,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X FULL MULTI-AGENT INTEGRATION TEST"
    )
    print("=" * 80)


    # ============================================================
    # SYNTHETIC TEST INCIDENT
    #
    # This is metadata only.
    # No malicious command or containment action is executed.
    # ============================================================

    incident = {

        "incident_id":
            "INC-MULTI-AGENT-001",

        "title":
            "Synthetic Multi-Source Security Incident",

        "severity":
            "CRITICAL",

        "correlation_score":
            94,

        "categories": [

            "PROCESS",

            "FILE",

            "NETWORK",

            "REGISTRY",
        ],

        "timeline": [

            # ====================================================
            # PROCESS EVENT
            # ====================================================

            {

                "event_id":
                    "ma-process-001",

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
                        10000,

                    "ppid":
                        2000,

                    "name":
                        "demo.exe",

                    "exe":
                        r"C:\Temp\demo.exe",

                    "cmdline":
                        r"C:\Temp\demo.exe",

                    "parent_name":
                        "explorer.exe",

                    "behavior_score":
                        85,

                    "anomaly_score":
                        75,

                    "combined_threat_score":
                        98,

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
            # FILE EVENT
            # ====================================================

            {

                "event_id":
                    "ma-file-001",

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
                        "MULTI_AGENT_MD5",

                    "sha1":
                        "MULTI_AGENT_SHA1",

                    "sha256":
                        "MULTI_AGENT_SHA256",

                    "entropy":
                        7.4,

                    "is_pe":
                        True,

                    "static_risk_score":
                        80,

                    "static_severity":
                        "HIGH",

                    "ml_prediction":
                        1,

                    "malware_probability":
                        0.97,

                    "ml_confidence":
                        0.97,

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
            # NETWORK EVENT
            # ====================================================

            {

                "event_id":
                    "ma-network-001",

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
                        10000,

                    "process_name":
                        "demo.exe",

                    "protocol":
                        "TCP",

                    "local_ip":
                        "192.168.1.50",

                    "local_port":
                        53000,

                    "remote_ip":
                        "203.0.113.250",

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
            # REGISTRY EVENT
            # ====================================================

            {

                "event_id":
                    "ma-registry-001",

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
                        (
                            r"HKCU\Software\Microsoft"
                            r"\Windows\CurrentVersion\Run"
                        ),

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


    # ============================================================
    # CREATE PIPELINE
    #
    # Level 2 = recommendations only.
    # ============================================================

    pipeline = (
        MultiAgentSecurityPipeline(
            autonomy_level=2
        )
    )


    # ============================================================
    # PROCESS INCIDENT
    # ============================================================

    result = (
        pipeline.process_incident(
            incident
        )
    )


    # ============================================================
    # BASIC PIPELINE RESULT
    # ============================================================

    print()
    print("-" * 80)
    print(
        "PIPELINE RESULT"
    )
    print("-" * 80)


    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )


    print(
        "Status:",
        result[
            "status"
        ],
    )


    print(
        "Security State:",
        result[
            "security_state"
        ],
    )


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
        "Final Decision:",
        result[
            "final_decision"
        ],
    )


    # ============================================================
    # AGENT DECISIONS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "STANDARDIZED AGENT DECISIONS"
    )
    print("=" * 80)


    for decision in result[
        "agent_decisions"
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
            "Severity:",
            decision[
                "severity"
            ],
        )


    # ============================================================
    # CONSENSUS
    # ============================================================

    consensus = (
        result[
            "consensus"
        ]
    )


    print()
    print("=" * 80)
    print(
        "AGENT CONSENSUS"
    )
    print("=" * 80)


    print(
        "Final Decision:",
        consensus[
            "final_decision"
        ],
    )


    print(
        "Consensus Confidence:",
        consensus[
            "consensus_confidence"
        ],
    )


    print(
        "Conflict Detected:",
        consensus[
            "conflict_detected"
        ],
    )


    # ============================================================
    # RESPONSE RECOMMENDATIONS
    # ============================================================

    response = (
        result[
            "response"
        ]
    )


    print()
    print("=" * 80)
    print(
        "RESPONSE RECOMMENDATIONS"
    )
    print("=" * 80)


    for item in response[
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


    # ============================================================
    # POLICY EVALUATION
    # ============================================================

    policy = (
        result[
            "policy"
        ]
    )


    print()
    print("=" * 80)
    print(
        "POLICY / AUTONOMY EVALUATION"
    )
    print("=" * 80)


    for item in policy[
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


    # ============================================================
    # VALIDATION
    # ============================================================

    pipeline_pass = (
        result[
            "status"
        ]
        == "COMPLETED"
    )


    autonomy_pass = (

        result[
            "autonomy_level"
        ]
        == 2

        and

        result[
            "autonomy_mode"
        ]
        == "RECOMMEND_ONLY"
    )


    decisions_pass = (
        len(
            result[
                "agent_decisions"
            ]
        )
        == 3
    )


    decision_agents = {

        item[
            "agent"
        ]

        for item in result[
            "agent_decisions"
        ]
    }


    decision_agents_pass = (

        "TriageAgent"
        in decision_agents

        and

        "InvestigationAgent"
        in decision_agents

        and

        "RiskAssessmentAgent"
        in decision_agents
    )


    consensus_pass = (
        result[
            "final_decision"
        ]
        == "CONTAINMENT_RECOMMENDED"
    )


    risk_pass = (

        result[
            "risk_level"
        ]
        == "CRITICAL"

        and

        result[
            "risk_score"
        ]
        >= 80
    )


    response_actions = {

        item[
            "action"
        ]

        for item in response[
            "recommendations"
        ]
    }


    quarantine_pass = (
        "QUARANTINE_REVIEW"
        in response_actions
    )


    process_pass = (
        "PROCESS_TERMINATION_REVIEW"
        in response_actions
    )


    network_pass = (
        "NETWORK_BLOCK_REVIEW"
        in response_actions
    )


    persistence_pass = (
        "PERSISTENCE_REMEDIATION_REVIEW"
        in response_actions
    )


    isolation_pass = (
        "ENDPOINT_ISOLATION_REVIEW"
        in response_actions
    )


    policy_map = {

        item[
            "action"
        ]:
            item

        for item in policy[
            "evaluations"
        ]
    }


    policy_pass = all(

        policy_map[
            action
        ][
            "execution_allowed"
        ]
        is False

        for action in {

            "QUARANTINE_REVIEW",

            "PROCESS_TERMINATION_REVIEW",

            "NETWORK_BLOCK_REVIEW",

            "PERSISTENCE_REMEDIATION_REVIEW",

            "ENDPOINT_ISOLATION_REVIEW",
        }

        if action in policy_map
    )


    execution_pass = (
        result[
            "execution_enabled"
        ]
        is False
    )


    errors = (
        result[
            "coordinated_analysis"
        ].get(
            "errors",
            [],
        )
    )


    error_pass = (
        len(
            errors
        )
        == 0
    )


    report_output = (
        result[
            "coordinated_analysis"
        ][
            "agent_outputs"
        ].get(
            "InvestigationReportAgent",
            {},
        )
    )


    report_pass = (
        "text_report"
        in report_output
    )


    # ============================================================
    # FINAL VALIDATION OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL MULTI-AGENT INTEGRATION VALIDATION"
    )
    print("=" * 80)


    print(
        "Pipeline completed:",
        "PASS"
        if pipeline_pass
        else "FAIL",
    )


    print(
        "Autonomy level 2:",
        "PASS"
        if autonomy_pass
        else "FAIL",
    )


    print(
        "Three standardized decisions:",
        "PASS"
        if decisions_pass
        else "FAIL",
    )


    print(
        "Correct decision agents:",
        "PASS"
        if decision_agents_pass
        else "FAIL",
    )


    print(
        "Consensus decision:",
        "PASS"
        if consensus_pass
        else "FAIL",
    )


    print(
        "Critical risk assessment:",
        "PASS"
        if risk_pass
        else "FAIL",
    )


    print(
        "Quarantine recommendation:",
        "PASS"
        if quarantine_pass
        else "FAIL",
    )


    print(
        "Process review recommendation:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "Network review recommendation:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Persistence review recommendation:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Isolation review recommendation:",
        "PASS"
        if isolation_pass
        else "FAIL",
    )


    print(
        "Policy blocks active response:",
        "PASS"
        if policy_pass
        else "FAIL",
    )


    print(
        "Execution globally disabled:",
        "PASS"
        if execution_pass
        else "FAIL",
    )


    print(
        "No agent errors:",
        "PASS"
        if error_pass
        else "FAIL",
    )


    print(
        "Investigation report generated:",
        "PASS"
        if report_pass
        else "FAIL",
    )


    overall = all(
        [

            pipeline_pass,

            autonomy_pass,

            decisions_pass,

            decision_agents_pass,

            consensus_pass,

            risk_pass,

            quarantine_pass,

            process_pass,

            network_pass,

            persistence_pass,

            isolation_pass,

            policy_pass,

            execution_pass,

            error_pass,

            report_pass,
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