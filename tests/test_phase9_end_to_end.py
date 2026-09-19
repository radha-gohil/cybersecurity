from uuid import uuid4

from fastapi.testclient import TestClient

from api.main import app

from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)

from response.incident_view_service import (
    IncidentViewService,
)

from response.backend_integrity_service import (
    BackendIntegrityService,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)


client = TestClient(app)


# ================================================================
# UNIQUE TEST INCIDENT
# ================================================================

TEST_INCIDENT = (
    "INC-PHASE9-E2E-"
    + uuid4().hex[:8].upper()
)


# ================================================================
# SYNTHETIC INCIDENT INTELLIGENCE
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

        # --------------------------------------------------------
        # MULTI-AGENT / INVESTIGATION INFORMATION
        # --------------------------------------------------------

        "agent_analysis": {

            "triage": {

                "severity":
                    "CRITICAL",

                "reason":
                    (
                        "Synthetic multi-source "
                        "security incident."
                    ),
            },

            "investigation": {

                "finding":
                    (
                        "Synthetic process, file, "
                        "network and persistence "
                        "artifacts are correlated."
                    ),
            },

            "risk": {

                "score":
                    96,

                "level":
                    "CRITICAL",
            },
        },

        # --------------------------------------------------------
        # CORRELATED EVIDENCE
        # --------------------------------------------------------

        "coordinated_analysis": {

            "evidence": {

                "processes": [

                    {
                        "pid":
                            9900,

                        "name":
                            "phase9-demo.exe",

                        "exe":
                            (
                                r"C:\Temp"
                                r"\phase9-demo.exe"
                            ),

                        "behavior_score":
                            91,

                        "anomaly_score":
                            86,

                        "combined_threat_score":
                            96,

                        "timestamp":
                            (
                                "2026-09-16"
                                "T10:00:00+00:00"
                            ),
                    }
                ],

                "files": [

                    {
                        "name":
                            "phase9-demo.exe",

                        "path":
                            (
                                r"C:\Temp"
                                r"\phase9-demo.exe"
                            ),

                        "sha256":
                            "PHASE9_E2E_SYNTHETIC_SHA256",

                        "malware_probability":
                            0.97,

                        "static_risk_score":
                            85,

                        "timestamp":
                            (
                                "2026-09-16"
                                "T10:00:03+00:00"
                            ),
                    }
                ],

                "network_connections": [

                    {
                        "pid":
                            9900,

                        "process_name":
                            "phase9-demo.exe",

                        # Documentation/test IP range
                        "remote_ip":
                            "203.0.113.254",

                        "remote_port":
                            443,

                        "timestamp":
                            (
                                "2026-09-16"
                                "T10:00:08+00:00"
                            ),
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
                            "Phase9Demo",

                        "value_data":
                            (
                                r"C:\Temp"
                                r"\phase9-demo.exe"
                            ),

                        "timestamp":
                            (
                                "2026-09-16"
                                "T10:00:12+00:00"
                            ),
                    }
                ],
            },
        },

        # --------------------------------------------------------
        # EXPLICIT ATTACK TIMELINE
        # --------------------------------------------------------

        "attack_timeline": [

            {
                "timestamp":
                    (
                        "2026-09-16"
                        "T10:00:00+00:00"
                    ),

                "event_type":
                    "PROCESS_ACTIVITY",

                "description":
                    (
                        "Synthetic suspicious "
                        "process observation."
                    ),

                "pid":
                    9900,
            },

            {
                "timestamp":
                    (
                        "2026-09-16"
                        "T10:00:03+00:00"
                    ),

                "event_type":
                    "FILE_ACTIVITY",

                "description":
                    (
                        "Synthetic suspicious "
                        "file observation."
                    ),

                "path":
                    (
                        r"C:\Temp"
                        r"\phase9-demo.exe"
                    ),
            },

            {
                "timestamp":
                    (
                        "2026-09-16"
                        "T10:00:08+00:00"
                    ),

                "event_type":
                    "NETWORK_ACTIVITY",

                "description":
                    (
                        "Synthetic network "
                        "connection observation."
                    ),

                "remote_ip":
                    "203.0.113.254",
            },

            {
                "timestamp":
                    (
                        "2026-09-16"
                        "T10:00:12+00:00"
                    ),

                "event_type":
                    "PERSISTENCE_ACTIVITY",

                "description":
                    (
                        "Synthetic registry "
                        "persistence observation."
                    ),
            },
        ],

        # --------------------------------------------------------
        # RESPONSE RECOMMENDATIONS
        # --------------------------------------------------------

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
# HELPER
# ================================================================

def print_check(
    name,
    passed,
):

    print(
        f"{name}:",
        "PASS" if passed else "FAIL",
    )


# ================================================================
# MAIN TEST
# ================================================================

def main():

    print()

    print("=" * 80)

    print(
        "SENTINEL-X PHASE 9 "
        "FULL END-TO-END BACKEND TEST"
    )

    print("=" * 80)

    print(
        "Incident:",
        TEST_INCIDENT,
    )


    # ============================================================
    # STEP 1 - HEALTH
    # ============================================================

    health_response = (
        client.get(
            "/api/v1/health"
        )
    )


    health_pass = (

        health_response.status_code
        == 200

        and

        health_response.json().get(
            "status"
        )
        == "HEALTHY"

        and

        health_response.json().get(
            "simulation_mode"
        )
        is True
    )


    # ============================================================
    # STEP 2 - CREATE INCIDENT
    # ============================================================

    create_response = (
        client.post(

            "/api/v1/cases",

            json={

                "incident_id":
                    TEST_INCIDENT,

                "intelligence":
                    build_intelligence(),
            },
        )
    )


    create_data = {}


    if (
        create_response.status_code
        == 200
    ):

        create_data = (
            create_response.json()
        )


    create_pass = (
        create_response.status_code
        == 200
    )


    # ============================================================
    # STEP 3 - RECOVER CASE THROUGH API
    # ============================================================

    case_response = (
        client.get(
            (
                "/api/v1/cases/"
                f"{TEST_INCIDENT}"
            )
        )
    )


    case_data = (
        case_response.json()
        if case_response.status_code == 200
        else {}
    )


    case_pass = (

        case_response.status_code
        == 200

        and

        case_data.get(
            "incident_id"
        )
        == TEST_INCIDENT
    )


    # ============================================================
    # STEP 4 - EVIDENCE
    # ============================================================

    evidence_response = (
        client.get(
            (
                "/api/v1/cases/"
                f"{TEST_INCIDENT}"
                "/evidence"
            )
        )
    )


    evidence_data = (
        evidence_response.json()
        if evidence_response.status_code == 200
        else {}
    )


    evidence = (
        evidence_data.get(
            "evidence",
            {}
        )
    )


    evidence_pass = (

        evidence_response.status_code
        == 200

        and

        len(
            evidence.get(
                "processes",
                []
            )
        )
        == 1

        and

        len(
            evidence.get(
                "files",
                []
            )
        )
        == 1

        and

        len(
            evidence.get(
                "network_connections",
                []
            )
        )
        == 1

        and

        len(
            evidence.get(
                "registry_artifacts",
                []
            )
        )
        == 1
    )


    # ============================================================
    # STEP 5 - ATTACK TIMELINE
    # ============================================================

    timeline_response = (
        client.get(
            (
                "/api/v1/cases/"
                f"{TEST_INCIDENT}"
                "/timeline"
            )
        )
    )


    timeline_data = (
        timeline_response.json()
        if timeline_response.status_code == 200
        else {}
    )


    timeline = (
        timeline_data.get(
            "timeline",
            []
        )
    )


    timeline_types = [

        item.get(
            "event_type"
        )

        for item in timeline
    ]


    timeline_pass = (

        timeline_response.status_code
        == 200

        and

        len(
            timeline
        )
        == 4

        and

        all(

            item in timeline_types

            for item in [

                "PROCESS_ACTIVITY",

                "FILE_ACTIVITY",

                "NETWORK_ACTIVITY",

                "PERSISTENCE_ACTIVITY",
            ]
        )
    )


    # ============================================================
    # STEP 6 - DIGITAL TWIN
    # ============================================================

    twin_response = (
        client.get(
            (
                "/api/v1/cases/"
                f"{TEST_INCIDENT}"
                "/digital-twin"
            )
        )
    )


    twin_data = (
        twin_response.json()
        if twin_response.status_code == 200
        else {}
    )


    decision = (
        twin_data.get(
            "decision",
            {}
        )
    )


    best_plan = (
        decision.get(
            "best_plan",
            {}
        )
    )


    digital_twin_pass = (

        twin_response.status_code
        == 200

        and

        best_plan.get(
            "plan_name"
        )
        == "Targeted Full Remediation"

        and

        twin_data.get(
            "real_endpoint_modified"
        )
        is False
    )


    # ============================================================
    # STEP 7 - RESPONSE ACTIONS BEFORE APPROVAL
    # ============================================================

    action_response = (
        client.get(
            (
                "/api/v1/cases/"
                f"{TEST_INCIDENT}"
                "/responses"
            )
        )
    )


    action_data = (
        action_response.json()
        if action_response.status_code == 200
        else {}
    )


    initial_actions = (
        action_data.get(
            "actions",
            []
        )
    )


    actions_created_pass = (

        action_response.status_code
        == 200

        and

        len(
            initial_actions
        )
        == 4
    )


    pending_actions_pass = all(

        action.get(
            "approval_status"
        )
        == "PENDING"

        for action in initial_actions
    )


    # ============================================================
    # STEP 8 - FULL INCIDENT BEFORE APPROVAL
    # ============================================================

    full_response_before = (
        client.get(
            (
                "/api/v1/incidents/"
                f"{TEST_INCIDENT}"
                "/full"
            )
        )
    )


    full_before = (
        full_response_before.json()
        if full_response_before.status_code == 200
        else {}
    )


    full_view_before_pass = (

        full_response_before.status_code
        == 200

        and

        full_before.get(
            "incident_id"
        )
        == TEST_INCIDENT

        and

        full_before.get(
            "evidence",
            {}
        ).get(
            "raw_evidence_available"
        )
        is True

        and

        full_before.get(
            "timeline",
            {}
        ).get(
            "event_count"
        )
        == 4
    )


    # ============================================================
    # STEP 9 - APPROVE CASE
    # ============================================================

    approve_response = (
        client.post(

            (
                "/api/v1/cases/"
                f"{TEST_INCIDENT}"
                "/approve"
            ),

            json={

                "analyst":
                    "Phase9SOCAnalyst",

                "comment":
                    (
                        "Approved during final "
                        "Phase 9 simulation test."
                    ),
            },
        )
    )


    approval_pass = (
        approve_response.status_code
        == 200
    )


    # ============================================================
    # STEP 10 - VERIFY ACTIONS AFTER APPROVAL
    # ============================================================

    approved_action_response = (
        client.get(
            (
                "/api/v1/cases/"
                f"{TEST_INCIDENT}"
                "/responses"
            )
        )
    )


    approved_action_data = (
        approved_action_response.json()
        if approved_action_response.status_code == 200
        else {}
    )


    approved_actions = (
        approved_action_data.get(
            "actions",
            []
        )
    )


    action_approval_pass = (

        len(
            approved_actions
        )
        == 4

        and

        all(

            action.get(
                "approval_status"
            )
            == "APPROVED"

            for action in approved_actions
        )
    )


    action_ready_pass = (

        len(
            approved_actions
        )
        == 4

        and

        all(

            action.get(
                "execution_status"
            )
            == "READY"

            for action in approved_actions
        )
    )


    # ============================================================
    # STEP 11 - SIMULATED BACKEND RESTART
    # ============================================================

    restarted_workflow = (
        PersistentSOCWorkflow(
            simulation_mode=True
        )
    )


    recovered = (
        restarted_workflow.recover_case(
            TEST_INCIDENT
        )
    )


    restart_recovery_pass = (

        recovered is not None

        and

        recovered.get(
            "recovered_from_database"
        )
        is True
    )


    recovered_actions = (

        recovered.get(
            "response_actions",
            []
        )

        if recovered

        else []
    )


    restart_action_state_pass = (

        len(
            recovered_actions
        )
        == 4

        and

        all(

            action.approval_status
            == "APPROVED"

            for action in recovered_actions
        )

        and

        all(

            action.execution_status
            == "READY"

            for action in recovered_actions
        )
    )


    # ============================================================
    # STEP 12 - VERIFY EVIDENCE AFTER RESTART
    # ============================================================

    recovered_evidence = (

        recovered.get(
            "evidence",
            {}
        )

        if recovered

        else {}
    )


    restart_evidence_pass = (

        len(
            recovered_evidence.get(
                "processes",
                []
            )
        )
        == 1

        and

        len(
            recovered_evidence.get(
                "files",
                []
            )
        )
        == 1

        and

        len(
            recovered_evidence.get(
                "network_connections",
                []
            )
        )
        == 1

        and

        len(
            recovered_evidence.get(
                "registry_artifacts",
                []
            )
        )
        == 1
    )


    recovered_timeline = (

        recovered.get(
            "timeline",
            []
        )

        if recovered

        else []
    )


    restart_timeline_pass = (
        len(
            recovered_timeline
        )
        == 4
    )


    # ============================================================
    # STEP 13 - NEW INCIDENT VIEW SERVICE AFTER RESTART
    # ============================================================

    restarted_ticket_store = (
        SOCTicketStore()
    )


    restarted_view_service = (
        IncidentViewService(

            workflow=
                restarted_workflow,

            ticket_store=
                restarted_ticket_store,
        )
    )


    restarted_full_view = (
        restarted_view_service.get_full_incident(
            TEST_INCIDENT
        )
    )


    restart_full_view_pass = (

        restarted_full_view
        is not None

        and

        restarted_full_view.get(
            "incident_id"
        )
        == TEST_INCIDENT

        and

        restarted_full_view.get(
            "evidence",
            {}
        ).get(
            "raw_evidence_available"
        )
        is True

        and

        restarted_full_view.get(
            "timeline",
            {}
        ).get(
            "event_count"
        )
        == 4
    )


    # ============================================================
    # STEP 14 - BACKEND INTEGRITY AFTER RESTART
    # ============================================================

    restarted_integrity = (
        BackendIntegrityService(

            case_store=
                restarted_workflow.case_store,

            ticket_store=
                restarted_ticket_store,

            action_store=
                restarted_workflow.action_store,

            evidence_store=
                restarted_workflow.evidence_store,
        )
    )


    integrity_result = (
        restarted_integrity.check_incident(
            TEST_INCIDENT
        )
    )


    integrity_pass = (

        integrity_result.get(
            "valid"
        )
        is True

        and

        integrity_result.get(
            "issues"
        )
        == []
    )


    # ============================================================
    # STEP 15 - SAFETY
    # ============================================================

    safety_pass = (

        restarted_full_view.get(
            "safety",
            {}
        ).get(
            "simulation_mode"
        )
        is True

        and

        restarted_full_view.get(
            "safety",
            {}
        ).get(
            "real_endpoint_modified"
        )
        is False

        and

        restarted_full_view.get(
            "safety",
            {}
        ).get(
            "real_response_executed"
        )
        is False
    )


    # ============================================================
    # DISPLAY DETAILS
    # ============================================================

    print()

    print(
        "Create HTTP:",
        create_response.status_code,
    )

    print(
        "Selected Plan:",
        best_plan.get(
            "plan_name"
        ),
    )

    print(
        "Initial Risk:",
        decision.get(
            "initial_risk_score"
        ),
    )

    print(
        "Predicted Residual Risk:",
        best_plan.get(
            "predicted_residual_risk"
        ),
    )

    print(
        "Evidence Records:",
        (
            len(
                evidence.get(
                    "processes",
                    []
                )
            )
            +
            len(
                evidence.get(
                    "files",
                    []
                )
            )
            +
            len(
                evidence.get(
                    "network_connections",
                    []
                )
            )
            +
            len(
                evidence.get(
                    "registry_artifacts",
                    []
                )
            )
        ),
    )

    print(
        "Timeline Events:",
        len(
            timeline
        ),
    )

    print(
        "Response Actions:",
        len(
            approved_actions
        ),
    )

    print(
        "Integrity Issues:",
        integrity_result.get(
            "issues"
        ),
    )


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    print()

    print("=" * 80)

    print(
        "FINAL PHASE 9 VALIDATION"
    )

    print("=" * 80)


    checks = [

        (
            "FastAPI backend health",
            health_pass,
        ),

        (
            "SOC case creation",
            create_pass,
        ),

        (
            "Persistent case retrieval",
            case_pass,
        ),

        (
            "Four evidence categories persisted",
            evidence_pass,
        ),

        (
            "Attack timeline persisted",
            timeline_pass,
        ),

        (
            "Digital Twin decision generated",
            digital_twin_pass,
        ),

        (
            "Four response actions generated",
            actions_created_pass,
        ),

        (
            "Response actions initially pending",
            pending_actions_pass,
        ),

        (
            "Unified incident view available",
            full_view_before_pass,
        ),

        (
            "Analyst approval processed",
            approval_pass,
        ),

        (
            "All response actions approved",
            action_approval_pass,
        ),

        (
            "All response actions READY",
            action_ready_pass,
        ),

        (
            "Case recovered after restart",
            restart_recovery_pass,
        ),

        (
            "Approval state survived restart",
            restart_action_state_pass,
        ),

        (
            "Evidence survived restart",
            restart_evidence_pass,
        ),

        (
            "Timeline survived restart",
            restart_timeline_pass,
        ),

        (
            "Full incident view survived restart",
            restart_full_view_pass,
        ),

        (
            "Backend integrity valid",
            integrity_pass,
        ),

        (
            "Simulation safety preserved",
            safety_pass,
        ),
    ]


    for name, passed in checks:

        print_check(
            name,
            passed,
        )


    overall = all(

        passed

        for _, passed
        in checks
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )

    print("=" * 80)


    if overall:

        print()

        print(
            "PHASE 9 STATUS: COMPLETED"
        )

        print(
            (
                "SENTINEL-X persistent SOC backend "
                "passed the end-to-end synthetic "
                "integration test."
            )
        )

        print(
            (
                "All response operations remained "
                "simulation-only."
            )
        )


if __name__ == "__main__":

    main()