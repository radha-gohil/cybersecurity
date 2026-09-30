import uuid

from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


# ================================================================
# BUILD SYNTHETIC INCIDENT INTELLIGENCE
# ================================================================

def build_intelligence():

    return {

        "risk_score": 96,

        "risk_level": "CRITICAL",

        "risk": {
            "risk_score": 96,
            "risk_level": "CRITICAL",
        },

        "coordinated_analysis": {

            "evidence": {

                # ------------------------------------------------
                # PROCESS EVIDENCE
                # ------------------------------------------------
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

                # ------------------------------------------------
                # FILE EVIDENCE
                # ------------------------------------------------
                "files": [
                    {
                        "name": "demo.exe",
                        "path": r"C:\Temp\demo.exe",
                        "sha256": "FASTAPI_TEST_SHA256",
                        "malware_probability": 0.96,
                        "static_risk_score": 80,
                    }
                ],

                # ------------------------------------------------
                # NETWORK EVIDENCE
                # ------------------------------------------------
                "network_connections": [
                    {
                        "pid": 7000,
                        "process_name": "demo.exe",
                        "remote_ip": "203.0.113.220",
                        "remote_port": 443,
                    }
                ],

                # ------------------------------------------------
                # REGISTRY EVIDENCE
                # ------------------------------------------------
                "registry_artifacts": [
                    {
                        "key": (
                            r"HKCU\Software\Microsoft"
                            r"\Windows\CurrentVersion\Run"
                        ),
                        "value_name": "DemoApp",
                        "value_data": r"C:\Temp\demo.exe",
                    }
                ],
            },
        },

        # ========================================================
        # RESPONSE RECOMMENDATIONS
        # ========================================================
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


# ================================================================
# MAIN TEST
# ================================================================

def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X FASTAPI SOC BACKEND TEST"
    )
    print("=" * 80)

    # ============================================================
    # HEALTH
    # ============================================================

    health_response = (
        client.get(
            "/api/v1/health"
        )
    )

    health_data = (
        health_response.json()
    )

    # ============================================================
    # CREATE UNIQUE INCIDENT ID
    #
    # IMPORTANT:
    # Old version used:
    #
    #     INC-FASTAPI-001
    #
    # That caused HTTP 409 on repeated test runs because the SOC
    # case already existed in persistent storage.
    #
    # A unique ID now makes this integration test rerunnable.
    # ============================================================

    incident_id = (
        f"INC-FASTAPI-"
        f"{uuid.uuid4().hex[:8].upper()}"
    )

    print()
    print(
        "Generated Incident ID:",
        incident_id,
    )

    # ============================================================
    # CREATE CASE
    # ============================================================

    create_response = (
        client.post(

            "/api/v1/cases",

            json={
                "incident_id":
                    incident_id,

                "intelligence":
                    build_intelligence(),
            },
        )
    )

    create_data = (
        create_response.json()
    )

    print()
    print(
        "Create Status:",
        create_response.status_code,
    )

    # ------------------------------------------------------------
    # Stop cleanly when case creation fails.
    # ------------------------------------------------------------

    if (
        create_response.status_code
        != 200
    ):

        print(
            "Create Response:",
            create_data,
        )

        return

    # ============================================================
    # CREATED TICKET
    # ============================================================

    ticket = (
        create_data[
            "ticket"
        ]
    )

    print()
    print(
        "Incident:",
        create_data[
            "incident_id"
        ],
    )

    print(
        "Ticket:",
        ticket[
            "ticket_id"
        ],
    )

    print(
        "Priority:",
        ticket[
            "priority"
        ],
    )

    print(
        "Plan:",
        ticket[
            "selected_plan"
        ],
    )

    print(
        "Response Actions:",
        create_data[
            "response_action_count"
        ],
    )

    # ============================================================
    # GET CASE
    # ============================================================

    case_response = (
        client.get(
            f"/api/v1/cases/{incident_id}"
        )
    )

    case_data = (
        case_response.json()
    )

    # ============================================================
    # DIGITAL TWIN
    # ============================================================

    twin_response = (
        client.get(
            (
                f"/api/v1/cases/"
                f"{incident_id}/digital-twin"
            )
        )
    )

    twin_data = (
        twin_response.json()
    )

    # ============================================================
    # RESPONSE ACTIONS
    # ============================================================

    response_actions_response = (
        client.get(
            (
                f"/api/v1/cases/"
                f"{incident_id}/responses"
            )
        )
    )

    response_actions_data = (
        response_actions_response.json()
    )

    # ============================================================
    # APPROVE
    # ============================================================

    approval_response = (
        client.post(

            (
                f"/api/v1/cases/"
                f"{incident_id}/approve"
            ),

            json={
                "analyst":
                    "SOCAnalystAPI",

                "comment":
                    (
                        "Approved during "
                        "FastAPI integration test."
                    ),
            },
        )
    )

    approval_data = (
        approval_response.json()
    )

    print()
    print(
        "Approval HTTP Status:",
        approval_response.status_code,
    )

    print(
        "Approval Workflow Status:",
        approval_data.get(
            "status"
        ),
    )

    print(
        "Routed Actions:",
        approval_data.get(
            "routed_action_count"
        ),
    )

    print(
        "Real Response Executed:",
        approval_data.get(
            "real_response_executed"
        ),
    )

    # ============================================================
    # TICKET ENDPOINT
    # ============================================================

    ticket_response = (
        client.get(
            (
                "/api/v1/tickets/"
                + ticket[
                    "ticket_id"
                ]
            )
        )
    )

    stored_ticket = (
        ticket_response.json()
    )

    # ============================================================
    # DASHBOARD
    # ============================================================

    dashboard_response = (
        client.get(
            "/api/v1/dashboard/summary"
        )
    )

    dashboard_data = (
        dashboard_response.json()
    )

    # ============================================================
    # VALIDATION
    # ============================================================

    # ------------------------------------------------------------
    # HEALTH
    # ------------------------------------------------------------

    health_pass = (

        health_response.status_code
        == 200

        and

        health_data[
            "status"
        ]
        == "HEALTHY"
    )

    # ------------------------------------------------------------
    # CASE CREATION
    # ------------------------------------------------------------

    create_pass = (

        create_response.status_code
        == 200

        and

        create_data[
            "success"
        ]
        is True
    )

    # ------------------------------------------------------------
    # AUTOMATIC TICKET
    # ------------------------------------------------------------

    ticket_pass = (
        ticket[
            "ticket_id"
        ].startswith(
            "TKT-"
        )
    )

    # ------------------------------------------------------------
    # TICKET PRIORITY
    # ------------------------------------------------------------

    priority_pass = (
        ticket[
            "priority"
        ]
        == "P1"
    )

    # ------------------------------------------------------------
    # DIGITAL TWIN SELECTED PLAN
    # ------------------------------------------------------------

    plan_pass = (
        ticket[
            "selected_plan"
        ]
        == "Targeted Full Remediation"
    )

    # ------------------------------------------------------------
    # CASE RETRIEVAL
    # ------------------------------------------------------------

    case_pass = (

        case_response.status_code
        == 200

        and

        case_data[
            "incident_id"
        ]
        == incident_id
    )

    # ------------------------------------------------------------
    # DIGITAL TWIN ENDPOINT
    # ------------------------------------------------------------

    twin_pass = (

        twin_response.status_code
        == 200

        and

        twin_data[
            "decision"
        ][
            "best_plan"
        ]
        is not None
    )

    # ------------------------------------------------------------
    # RESPONSE ACTIONS ENDPOINT
    # ------------------------------------------------------------

    responses_pass = (

        response_actions_response.status_code
        == 200

        and

        response_actions_data[
            "count"
        ]
        == 4
    )

    # ------------------------------------------------------------
    # ANALYST APPROVAL
    # ------------------------------------------------------------

    approval_pass = (

        approval_response.status_code
        == 200

        and

        approval_data.get(
            "success"
        )
        is True
    )

    # ------------------------------------------------------------
    # RESPONSE MUST REMAIN SIMULATED
    # ------------------------------------------------------------

    simulated_pass = (
        approval_data.get(
            "real_response_executed"
        )
        is False
    )

    # ------------------------------------------------------------
    # APPROVED TICKET MUST PERSIST
    # ------------------------------------------------------------

    persisted_pass = (

        ticket_response.status_code
        == 200

        and

        stored_ticket[
            "approval_status"
        ]
        == "APPROVED"
    )

    # ------------------------------------------------------------
    # DASHBOARD
    # ------------------------------------------------------------

    dashboard_pass = (

        dashboard_response.status_code
        == 200

        and

        dashboard_data[
            "total_tickets"
        ]
        >= 1
    )

    # ============================================================
    # FINAL VALIDATION OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL FASTAPI SOC BACKEND VALIDATION"
    )
    print("=" * 80)

    print(
        "Health endpoint:",
        "PASS"
        if health_pass
        else "FAIL",
    )

    print(
        "SOC case API:",
        "PASS"
        if create_pass
        else "FAIL",
    )

    print(
        "Automatic ticket returned:",
        "PASS"
        if ticket_pass
        else "FAIL",
    )

    print(
        "P1 priority returned:",
        "PASS"
        if priority_pass
        else "FAIL",
    )

    print(
        "Digital Twin plan returned:",
        "PASS"
        if plan_pass
        else "FAIL",
    )

    print(
        "Case retrieval endpoint:",
        "PASS"
        if case_pass
        else "FAIL",
    )

    print(
        "Digital Twin endpoint:",
        "PASS"
        if twin_pass
        else "FAIL",
    )

    print(
        "Response actions endpoint:",
        "PASS"
        if responses_pass
        else "FAIL",
    )

    print(
        "Analyst approval endpoint:",
        "PASS"
        if approval_pass
        else "FAIL",
    )

    print(
        "Response remained simulated:",
        "PASS"
        if simulated_pass
        else "FAIL",
    )

    print(
        "Approved ticket persisted:",
        "PASS"
        if persisted_pass
        else "FAIL",
    )

    print(
        "Dashboard summary endpoint:",
        "PASS"
        if dashboard_pass
        else "FAIL",
    )

    # ============================================================
    # OVERALL
    # ============================================================

    overall = all(
        [
            health_pass,
            create_pass,
            ticket_pass,
            priority_pass,
            plan_pass,
            case_pass,
            twin_pass,
            responses_pass,
            approval_pass,
            simulated_pass,
            persisted_pass,
            dashboard_pass,
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


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    main()