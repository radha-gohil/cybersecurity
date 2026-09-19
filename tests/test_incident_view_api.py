from fastapi.testclient import (
    TestClient,
)

from api.main import (
    app,
)


client = TestClient(
    app
)


TEST_INCIDENT = (
    "INC-INCIDENT-VIEW-001"
)


# ================================================================
# SYNTHETIC INTELLIGENCE
# ================================================================

def build_intelligence():

    return {

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
                            9300,

                        "name":
                            "incident-view-demo.exe",

                        "exe":
                            (
                                r"C:\Temp"
                                r"\incident-view-demo.exe"
                            ),

                        "behavior_score":
                            90,

                        "anomaly_score":
                            82,

                        "combined_threat_score":
                            96,
                    }
                ],

                "files": [

                    {
                        "name":
                            "incident-view-demo.exe",

                        "path":
                            (
                                r"C:\Temp"
                                r"\incident-view-demo.exe"
                            ),

                        "sha256":
                            "INCIDENT_VIEW_TEST_SHA256",

                        "malware_probability":
                            0.97,

                        "static_risk_score":
                            85,
                    }
                ],

                "network_connections": [

                    {
                        "pid":
                            9300,

                        "process_name":
                            "incident-view-demo.exe",

                        "remote_ip":
                            "203.0.113.250",

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
                            "IncidentViewDemo",

                        "value_data":
                            (
                                r"C:\Temp"
                                r"\incident-view-demo.exe"
                            ),
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


# ================================================================
# ENSURE INCIDENT EXISTS
# ================================================================

def ensure_incident_exists():

    response = client.get(
        f"/api/v1/cases/{TEST_INCIDENT}"
    )


    # ------------------------------------------------------------
    # Incident already exists
    # ------------------------------------------------------------

    if response.status_code == 200:

        return True


    # ------------------------------------------------------------
    # Create incident
    # ------------------------------------------------------------

    create_response = client.post(

        "/api/v1/cases",

        json={

            "incident_id":
                TEST_INCIDENT,

            "intelligence":
                build_intelligence(),
        },
    )


    if create_response.status_code == 200:

        return True


    # ------------------------------------------------------------
    # 409 can happen if persistence already contains the case
    # ------------------------------------------------------------

    if create_response.status_code == 409:

        check_response = client.get(
            f"/api/v1/cases/{TEST_INCIDENT}"
        )

        return (
            check_response.status_code
            == 200
        )


    print(
        "Failed to create test incident:"
    )

    print(
        create_response.status_code,
        create_response.json(),
    )

    return False


# ================================================================
# MAIN TEST
# ================================================================

def main():

    print()

    print(
        "=" * 80
    )

    print(
        "SENTINEL-X UNIFIED INCIDENT DETAIL API TEST"
    )

    print(
        "=" * 80
    )


    # ============================================================
    # ENSURE DATA EXISTS
    # ============================================================

    setup_pass = (
        ensure_incident_exists()
    )


    if not setup_pass:

        print()

        print(
            "Test incident setup: FAIL"
        )

        print(
            "OVERALL: FAIL"
        )

        return


    # ============================================================
    # REQUEST FULL INCIDENT
    # ============================================================

    response = (
        client.get(
            (
                "/api/v1/incidents/"
                f"{TEST_INCIDENT}/full"
            )
        )
    )


    print()

    print(
        "HTTP Status:",
        response.status_code,
    )


    if (
        response.status_code
        != 200
    ):

        print(
            "Response:"
        )

        print(
            response.json()
        )

        print()

        print(
            "OVERALL: FAIL"
        )

        return


    data = (
        response.json()
    )


    # ============================================================
    # SECTIONS
    # ============================================================

    risk = (
        data.get(
            "risk",
            {}
        )
    )


    evidence = (
        data.get(
            "evidence",
            {}
        )
    )


    intelligence = (
        data.get(
            "intelligence",
            {}
        )
    )


    digital_twin = (
        data.get(
            "digital_twin",
            {}
        )
    )


    ticket = (
        data.get(
            "ticket",
            {}
        )
    )


    response_section = (
        data.get(
            "response",
            {}
        )
    )


    safety = (
        data.get(
            "safety",
            {}
        )
    )


    persistence = (
        data.get(
            "persistence",
            {}
        )
    )


    # ============================================================
    # DISPLAY RESULT
    # ============================================================

    print(
        "Incident:",
        data.get(
            "incident_id"
        ),
    )


    print(
        "Case Status:",
        data.get(
            "case_status"
        ),
    )


    print(
        "Recovered From Database:",
        persistence.get(
            "recovered_from_database"
        ),
    )


    print(
        "Initial Risk:",
        risk.get(
            "initial_risk_score"
        ),
    )


    print(
        "Risk Level:",
        risk.get(
            "initial_risk_level"
        ),
    )


    print(
        "Residual Risk:",
        risk.get(
            "predicted_residual_risk"
        ),
    )


    print(
        "Selected Plan:",
        digital_twin.get(
            "selected_plan",
            {}
        ).get(
            "plan_name"
        ),
    )


    print(
        "Candidate Plans:",
        digital_twin.get(
            "candidate_plan_count"
        ),
    )


    print(
        "Ticket:",
        ticket.get(
            "ticket_id"
        ),
    )


    print(
        "Ticket Status:",
        ticket.get(
            "status"
        ),
    )


    print(
        "Ticket Approval:",
        ticket.get(
            "approval_status"
        ),
    )


    print(
        "Response Actions:",
        response_section.get(
            "action_count"
        ),
    )


    print(
        "Real Response Executed:",
        safety.get(
            "real_response_executed"
        ),
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    setup_validation_pass = (
        setup_pass
        is True
    )


    incident_pass = (

        data.get(
            "incident_id"
        )
        == TEST_INCIDENT
    )


    persistence_pass = (

        persistence.get(
            "recovered_from_database"
        )
        is True
    )


    risk_pass = (

        risk.get(
            "initial_risk_score"
        )
        == 96
    )


    risk_level_pass = (

        risk.get(
            "initial_risk_level"
        )
        == "CRITICAL"
    )


    risk_model_pass = (

        risk.get(
            "model_type"
        )
        == "DETERMINISTIC_HEURISTIC"

        and

        risk.get(
            "calibrated_probability"
        )
        is False
    )


    digital_twin_pass = (

        digital_twin.get(
            "selected_plan",
            {}
        ).get(
            "plan_name"
        )
        == "Targeted Full Remediation"
    )


    plan_count_pass = (

        digital_twin.get(
            "candidate_plan_count",
            0,
        )
        >= 1
    )


    ticket_pass = (

        ticket.get(
            "ticket_id"
        )
        is not None
    )


    response_pass = (

        response_section.get(
            "action_count"
        )
        == 4
    )


    evidence_section_pass = (
        isinstance(
            evidence,
            dict,
        )
    )


    intelligence_section_pass = (
        isinstance(
            intelligence,
            dict,
        )
    )


    safety_pass = (

        safety.get(
            "simulation_mode"
        )
        is True

        and

        safety.get(
            "real_endpoint_modified"
        )
        is False

        and

        safety.get(
            "real_response_executed"
        )
        is False
    )


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    print()

    print(
        "=" * 80
    )

    print(
        "FINAL INCIDENT DETAIL API VALIDATION"
    )

    print(
        "=" * 80
    )


    print(
        "Test incident available:",
        "PASS"
        if setup_validation_pass
        else "FAIL",
    )


    print(
        "Incident identity:",
        "PASS"
        if incident_pass
        else "FAIL",
    )


    print(
        "Persistent recovery:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Risk information:",
        "PASS"
        if risk_pass
        else "FAIL",
    )


    print(
        "Critical risk level:",
        "PASS"
        if risk_level_pass
        else "FAIL",
    )


    print(
        "Risk model correctly identified as heuristic:",
        "PASS"
        if risk_model_pass
        else "FAIL",
    )


    print(
        "Evidence section returned:",
        "PASS"
        if evidence_section_pass
        else "FAIL",
    )


    print(
        "Agent intelligence section returned:",
        "PASS"
        if intelligence_section_pass
        else "FAIL",
    )


    print(
        "Digital Twin selected plan:",
        "PASS"
        if digital_twin_pass
        else "FAIL",
    )


    print(
        "Digital Twin plans returned:",
        "PASS"
        if plan_count_pass
        else "FAIL",
    )


    print(
        "SOC ticket returned:",
        "PASS"
        if ticket_pass
        else "FAIL",
    )


    print(
        "Four response actions returned:",
        "PASS"
        if response_pass
        else "FAIL",
    )


    print(
        "Simulation safety preserved:",
        "PASS"
        if safety_pass
        else "FAIL",
    )


    overall = all(
        [
            setup_validation_pass,
            incident_pass,
            persistence_pass,
            risk_pass,
            risk_level_pass,
            risk_model_pass,
            evidence_section_pass,
            intelligence_section_pass,
            digital_twin_pass,
            plan_count_pass,
            ticket_pass,
            response_pass,
            safety_pass,
        ]
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )

    print(
        "=" * 80
    )


if __name__ == "__main__":

    main()