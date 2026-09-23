import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )

from response.unified_soc_workflow import (
    UnifiedSOCWorkflow,
)

from response.soc_ticket import (
    SOCTicket,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X UNIFIED SOC INCIDENT WORKFLOW TEST"
    )
    print("=" * 80)


    # ============================================================
    # SYNTHETIC INTELLIGENCE
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
                    }
                ],

                "files": [
                    {
                        "name":
                            "demo.exe",

                        "path":
                            r"C:\Temp\demo.exe",

                        "sha256":
                            "SOC_WORKFLOW_SHA256",

                        "malware_probability":
                            0.96,

                        "static_risk_score":
                            80,
                    }
                ],

                "network_connections": [
                    {
                        "pid":
                            7000,

                        "process_name":
                            "demo.exe",

                        "remote_ip":
                            "203.0.113.210",

                        "remote_port":
                            443,
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
    # CREATE WORKFLOW
    # ============================================================

    workflow = (
        UnifiedSOCWorkflow(
            simulation_mode=True
        )
    )


    case = (
        workflow.create_case(

            incident_id=
                "INC-SOC-WORKFLOW-001",

            intelligence=
                intelligence,
        )
    )


    print()
    print(
        "Case Status:",
        case[
            "status"
        ],
    )

    print(
        "Response Actions:",
        case[
            "response_action_count"
        ],
    )


    # ============================================================
    # RECONSTRUCT TICKET OBJECT
    # FROM GENERATED TICKET DATA
    # ============================================================

    ticket_data = (
        case[
            "ticket_data"
        ]
    )


    ticket = SOCTicket(

        ticket_id=
            ticket_data[
                "ticket_id"
            ],

        incident_id=
            ticket_data[
                "incident_id"
            ],

        title=
            ticket_data[
                "title"
            ],

        priority=
            ticket_data[
                "priority"
            ],

        risk_score=
            ticket_data[
                "risk_score"
            ],

        risk_level=
            ticket_data[
                "risk_level"
            ],

        selected_plan=
            ticket_data[
                "selected_plan"
            ],

        predicted_residual_risk=
            ticket_data[
                "predicted_residual_risk"
            ],

        operational_impact=
            ticket_data[
                "operational_impact"
            ],

        explanation=
            ticket_data[
                "explanation"
            ],

        approval_required=
            ticket_data[
                "approval_required"
            ],

        approval_status=
            ticket_data[
                "approval_status"
            ],

        assigned_analyst=
            ticket_data[
                "assigned_analyst"
            ],

        status=
            ticket_data[
                "status"
            ],

        created_at=
            ticket_data[
                "created_at"
            ],

        updated_at=
            ticket_data[
                "updated_at"
            ],
    )


    # ============================================================
    # APPROVE CASE
    # ============================================================

    approval = (
        workflow.approve_case(

            case_result=
                case,

            ticket=
                ticket,

            analyst=
                "SOCAnalyst01",

            comment=
                (
                    "Digital Twin plan reviewed "
                    "and approved for simulation."
                ),
        )
    )


    print()
    print("=" * 80)
    print(
        "APPROVAL RESULT"
    )
    print("=" * 80)


    print(
        "Workflow Success:",
        approval[
            "success"
        ],
    )

    print(
        "Ticket Status:",
        ticket.status,
    )

    print(
        "Ticket Approval:",
        ticket.approval_status,
    )

    print(
        "Approved Actions:",
        approval[
            "approved_action_count"
        ],
    )

    print(
        "Routed Actions:",
        len(
            approval[
                "routing_results"
            ]
        ),
    )

    print(
        "Real Response Executed:",
        approval[
            "real_response_executed"
        ],
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    case_pass = (
        case[
            "status"
        ]
        == "AWAITING_ANALYST_REVIEW"
    )


    action_count_pass = (
        case[
            "response_action_count"
        ]
        >= 1
    )


    ticket_pass = (
        ticket.ticket_id.startswith(
            "TKT-"
        )
    )


    priority_pass = (
        ticket.priority
        == "P1"
    )


    decision_pass = (
        case[
            "decision"
        ][
            "best_plan"
        ]
        is not None
    )


    approval_pass = (
        approval[
            "success"
        ]
        is True
    )


    ticket_approved_pass = (

        ticket.status
        == "APPROVED"

        and

        ticket.approval_status
        == "APPROVED"
    )


    action_approved_pass = all(

        action.approval_status
        == "APPROVED"

        for action in case[
            "response_actions"
        ]
    )


    ready_pass = all(

        action.execution_status
        == "READY"

        for action in case[
            "response_actions"
        ]
    )


    route_pass = (
        len(
            approval[
                "routing_results"
            ]
        )
        ==
        case[
            "response_action_count"
        ]
    )


    simulation_pass = all(

        result.get(
            "executed"
        )
        is False

        for result in approval[
            "routing_results"
        ]
    )


    no_real_response_pass = (
        approval[
            "real_response_executed"
        ]
        is False
    )


    # ============================================================
    # FINAL
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL UNIFIED SOC WORKFLOW VALIDATION"
    )
    print("=" * 80)


    print(
        "SOC case created:",
        "PASS"
        if case_pass
        else "FAIL",
    )

    print(
        "Response actions generated:",
        "PASS"
        if action_count_pass
        else "FAIL",
    )

    print(
        "Automatic ticket generated:",
        "PASS"
        if ticket_pass
        else "FAIL",
    )

    print(
        "P1 priority preserved:",
        "PASS"
        if priority_pass
        else "FAIL",
    )

    print(
        "Digital Twin decision available:",
        "PASS"
        if decision_pass
        else "FAIL",
    )

    print(
        "Analyst approval synchronized:",
        "PASS"
        if approval_pass
        else "FAIL",
    )

    print(
        "Ticket approved:",
        "PASS"
        if ticket_approved_pass
        else "FAIL",
    )

    print(
        "All ResponseActions approved:",
        "PASS"
        if action_approved_pass
        else "FAIL",
    )

    print(
        "All ResponseActions READY:",
        "PASS"
        if ready_pass
        else "FAIL",
    )

    print(
        "All actions routed:",
        "PASS"
        if route_pass
        else "FAIL",
    )

    print(
        "Response remained simulated:",
        "PASS"
        if simulation_pass
        else "FAIL",
    )

    print(
        "No real response executed:",
        "PASS"
        if no_real_response_pass
        else "FAIL",
    )


    overall = all(
        [
            case_pass,
            action_count_pass,
            ticket_pass,
            priority_pass,
            decision_pass,
            approval_pass,
            ticket_approved_pass,
            action_approved_pass,
            ready_pass,
            route_pass,
            simulation_pass,
            no_real_response_pass,
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