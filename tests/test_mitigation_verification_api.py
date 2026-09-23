import sys
import tempfile

from pathlib import Path


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


# ================================================================
# IMPORTS
# ================================================================

from fastapi.testclient import TestClient

import api.main as api_main

from response.soc_case_store import (
    SOCCaseStore,
)

from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)

from response.mitigation_verifier import (
    MitigationVerifier,
)


# ================================================================
# IN-MEMORY RESPONSE ACTION STORE
# ================================================================

class InMemoryActionStore:

    def __init__(self):
        self.actions = {}

    def save_action(
        self,
        action,
    ):

        action = dict(
            action
        )

        action_id = (
            action.get(
                "action_id"
            )
            or (
                "api-test-action-"
                + str(
                    len(
                        self.actions
                    )
                    + 1
                )
            )
        )

        self.actions[
            action_id
        ] = action

        return action_id

    def get_by_incident(
        self,
        incident_id,
    ):

        return [

            dict(
                action
            )

            for action
            in self.actions.values()

            if (
                action.get(
                    "incident_id"
                )
                ==
                incident_id
            )
        ]

    def list_actions(
        self,
        limit=100,
    ):

        return list(
            self.actions.values()
        )[:limit]


# ================================================================
# IN-MEMORY EVIDENCE STORE
# ================================================================

class InMemoryEvidenceStore:

    def __init__(self):

        self.evidence = {}
        self.timelines = {}

    def save_evidence_bundle(
        self,
        incident_id,
        evidence,
        replace_existing=True,
    ):

        self.evidence[
            incident_id
        ] = dict(
            evidence
            or {}
        )

        return {
            "success": True,
            "incident_id": incident_id,
        }

    def save_timeline(
        self,
        incident_id,
        timeline,
        replace_existing=True,
    ):

        self.timelines[
            incident_id
        ] = list(
            timeline
            or []
        )

        return {
            "success": True,
            "incident_id": incident_id,
        }

    def get_evidence_bundle(
        self,
        incident_id,
    ):

        return dict(
            self.evidence.get(
                incident_id,
                {},
            )
        )

    def get_timeline(
        self,
        incident_id,
    ):

        return list(
            self.timelines.get(
                incident_id,
                [],
            )
        )


# ================================================================
# DISPLAY
# ================================================================

def separator():

    print(
        "\n"
        + "=" * 72
    )


# ================================================================
# MAIN
# ================================================================

def main():

    separator()

    print(
        "SENTINEL-X MITIGATION VERIFICATION "
        "FASTAPI INTEGRATION TEST"
    )

    separator()

    print(
        "\nSIMULATION ONLY"
    )

    print(
        "Uses FastAPI TestClient."
    )

    print(
        "Uses temporary SQLite SOC case database."
    )

    print(
        "Production database is not modified."
    )

    print(
        "No real endpoint response action is performed."
    )

    # ============================================================
    # TEMPORARY DATABASE
    # ============================================================

    with tempfile.TemporaryDirectory() as temp_dir:

        temp_dir = Path(
            temp_dir
        )

        database_path = (
            temp_dir
            / "mitigation_api_test.db"
        )

        print(
            "\nTemporary Database:",
            database_path,
        )

        # ========================================================
        # BUILD TEST WORKFLOW
        # ========================================================

        case_store = (
            SOCCaseStore(
                database_path=
                    database_path
            )
        )

        action_store = (
            InMemoryActionStore()
        )

        evidence_store = (
            InMemoryEvidenceStore()
        )

        verifier = (
            MitigationVerifier(

                verified_threshold=
                    0.70,

                partial_threshold=
                    0.30,

                acceptable_residual_risk=
                    30.0,
            )
        )

        test_workflow = (
            PersistentSOCWorkflow(

                simulation_mode=
                    True,

                case_store=
                    case_store,

                action_store=
                    action_store,

                evidence_store=
                    evidence_store,

                mitigation_verifier=
                    verifier,
            )
        )

        # ========================================================
        # REPLACE API WORKFLOW ONLY FOR THIS TEST
        # ========================================================

        original_workflow = (
            api_main.workflow
        )

        api_main.workflow = (
            test_workflow
        )

        # ========================================================
        # TEST CLIENT
        # ========================================================

        client = TestClient(
            api_main.app
        )

        incident_id = (
            "api-mitigation-test-001"
        )

        # ========================================================
        # SYNTHETIC SOC CASE
        # ========================================================

        case_store.save_case(
            {

                "incident_id":
                    incident_id,

                "status":
                    "AWAITING_ANALYST_REVIEW",

                "decision":
                    {

                        "initial_risk_score":
                            85,

                        "initial_risk_level":
                            "HIGH",

                        "best_plan":
                            {

                                "plan_name":
                                    "synthetic-api-plan",

                                "predicted_residual_risk":
                                    20,
                            },
                    },

                "explanation":
                    {

                        "summary":
                            (
                                "Synthetic FastAPI "
                                "mitigation test."
                            ),
                    },

                "ticket_data":
                    {

                        "ticket_id":
                            "ticket-api-test-001",

                        "incident_id":
                            incident_id,

                        "risk_score":
                            85,

                        "risk_level":
                            "HIGH",
                    },

                "mitigation_verification":
                    {},
            }
        )

        try:

            # ====================================================
            # TEST 1
            # GET BEFORE VERIFICATION
            # ====================================================

            separator()

            print(
                "TEST 1 - GET BEFORE VERIFICATION"
            )

            response = client.get(
                (
                    f"/api/v1/cases/"
                    f"{incident_id}/"
                    "mitigation-verification"
                )
            )

            print(
                "HTTP Status:",
                response.status_code,
            )

            print(
                "Response:",
                response.json(),
            )

            if response.status_code != 200:

                raise AssertionError(
                    "GET mitigation verification "
                    "endpoint did not return HTTP 200."
                )

            data = response.json()

            if (
                data.get(
                    "status"
                )
                !=
                "NOT_VERIFIED"
            ):

                raise AssertionError(
                    "Expected NOT_VERIFIED before "
                    "running mitigation verification."
                )

            if (
                data.get(
                    "verified"
                )
                is not False
            ):

                raise AssertionError(
                    "verified should be False "
                    "before verification."
                )

            print(
                "GET before verification: PASS"
            )

            # ====================================================
            # TEST 2
            # POST SIMULATED MITIGATION VERIFICATION
            # ====================================================

            separator()

            print(
                "TEST 2 - POST SIMULATED MITIGATION VERIFICATION"
            )

            request_body = {

                "before_state": {

                    "risk_score":
                        85,

                    "suspicious_event_count":
                        12,

                    "active_indicator_count":
                        8,

                    "exposure_score":
                        90,
                },

                "simulated_after_state": {

                    "risk_score":
                        20,

                    "suspicious_event_count":
                        2,

                    "active_indicator_count":
                        1,

                    "exposure_score":
                        20,
                },

                "response_result": {

                    "simulation_mode":
                        True,

                    "plan_id":
                        "synthetic-api-plan",

                    "action":
                        "SIMULATED_CONTAINMENT",
                },
            }

            response = client.post(
                (
                    f"/api/v1/cases/"
                    f"{incident_id}/"
                    "mitigation-verification"
                ),
                json=request_body,
            )

            print(
                "HTTP Status:",
                response.status_code,
            )

            print(
                "Response:",
                response.json(),
            )

            if response.status_code != 200:

                raise AssertionError(
                    "POST mitigation verification "
                    "endpoint did not return HTTP 200."
                )

            data = response.json()

            if (
                data.get(
                    "status"
                )
                !=
                "SIMULATION_VERIFIED"
            ):

                raise AssertionError(
                    "Expected SIMULATION_VERIFIED."
                )

            if (
                data.get(
                    "persisted"
                )
                is not True
            ):

                raise AssertionError(
                    "Mitigation verification "
                    "was not persisted."
                )

            if (
                data.get(
                    "real_response_executed"
                )
                is not False
            ):

                raise AssertionError(
                    "Real response execution "
                    "must remain False."
                )

            verification = data.get(
                "verification",
                {},
            )

            print(
                "Overall Improvement:",
                verification.get(
                    "overall_improvement"
                ),
            )

            print(
                "Residual Risk:",
                verification.get(
                    "residual_risk"
                ),
            )

            print(
                "POST mitigation verification: PASS"
            )

            # ====================================================
            # TEST 3
            # GET AFTER VERIFICATION
            # ====================================================

            separator()

            print(
                "TEST 3 - GET AFTER VERIFICATION"
            )

            response = client.get(
                (
                    f"/api/v1/cases/"
                    f"{incident_id}/"
                    "mitigation-verification"
                )
            )

            print(
                "HTTP Status:",
                response.status_code,
            )

            print(
                "Response:",
                response.json(),
            )

            if response.status_code != 200:

                raise AssertionError(
                    "GET after verification failed."
                )

            data = response.json()

            if (
                data.get(
                    "verified"
                )
                is not True
            ):

                raise AssertionError(
                    "verified should be True "
                    "after verification."
                )

            if (
                data.get(
                    "status"
                )
                !=
                "SIMULATION_VERIFIED"
            ):

                raise AssertionError(
                    "Persisted API verification "
                    "status is incorrect."
                )

            print(
                "GET after verification: PASS"
            )

            # ====================================================
            # TEST 4
            # VERIFY SQLITE DIRECTLY
            # ====================================================

            separator()

            print(
                "TEST 4 - SQLITE PERSISTENCE THROUGH API"
            )

            stored_case = (
                case_store.get_case(
                    incident_id
                )
            )

            stored_verification = (
                stored_case.get(
                    "mitigation_verification",
                    {},
                )
            )

            print(
                "Stored Status:",
                stored_verification.get(
                    "status"
                ),
            )

            print(
                "Stored Verification Type:",
                stored_verification.get(
                    "verification_type"
                ),
            )

            if (
                stored_verification.get(
                    "status"
                )
                !=
                "SIMULATION_VERIFIED"
            ):

                raise AssertionError(
                    "API verification result was "
                    "not persisted to SQLite."
                )

            print(
                "API -> SQLite persistence: PASS"
            )

            # ====================================================
            # TEST 5
            # SIMULATED APPLICATION RESTART
            # ====================================================

            separator()

            print(
                "TEST 5 - API RECOVERY AFTER SIMULATED RESTART"
            )

            restarted_case_store = (
                SOCCaseStore(
                    database_path=
                        database_path
                )
            )

            restarted_workflow = (
                PersistentSOCWorkflow(

                    simulation_mode=
                        True,

                    case_store=
                        restarted_case_store,

                    action_store=
                        InMemoryActionStore(),

                    evidence_store=
                        InMemoryEvidenceStore(),

                    mitigation_verifier=
                        MitigationVerifier(),
                )
            )

            api_main.workflow = (
                restarted_workflow
            )

            response = client.get(
                (
                    f"/api/v1/cases/"
                    f"{incident_id}/"
                    "mitigation-verification"
                )
            )

            print(
                "HTTP Status:",
                response.status_code,
            )

            print(
                "Recovered Response:",
                response.json(),
            )

            if response.status_code != 200:

                raise AssertionError(
                    "GET after simulated restart failed."
                )

            data = response.json()

            if (
                data.get(
                    "status"
                )
                !=
                "SIMULATION_VERIFIED"
            ):

                raise AssertionError(
                    "Verification did not survive "
                    "simulated API restart."
                )

            print(
                "API restart recovery: PASS"
            )

            # ====================================================
            # TEST 6
            # REAL RESPONSE MUST BE BLOCKED
            # ====================================================

            separator()

            print(
                "TEST 6 - REAL RESPONSE SAFETY GUARD"
            )

            unsafe_request = {

                "before_state": {

                    "risk_score":
                        85,

                    "suspicious_event_count":
                        12,

                    "active_indicator_count":
                        8,

                    "exposure_score":
                        90,
                },

                "simulated_after_state": {

                    "risk_score":
                        20,

                    "suspicious_event_count":
                        2,

                    "active_indicator_count":
                        1,

                    "exposure_score":
                        20,
                },

                "response_result": {

                    "simulation_mode":
                        False,

                    "plan_id":
                        "blocked-real-plan",

                    "action":
                        "REAL_RESPONSE",
                },
            }

            response = client.post(
                (
                    f"/api/v1/cases/"
                    f"{incident_id}/"
                    "mitigation-verification"
                ),
                json=unsafe_request,
            )

            print(
                "HTTP Status:",
                response.status_code,
            )

            print(
                "Response:",
                response.json(),
            )

            if response.status_code != 409:

                raise AssertionError(
                    "Real-response request should "
                    "return HTTP 409."
                )

            print(
                "Real response blocked: PASS"
            )

            # ====================================================
            # TEST 7
            # UNKNOWN INCIDENT
            # ====================================================

            separator()

            print(
                "TEST 7 - UNKNOWN INCIDENT"
            )

            response = client.get(
                (
                    "/api/v1/cases/"
                    "incident-does-not-exist/"
                    "mitigation-verification"
                )
            )

            print(
                "HTTP Status:",
                response.status_code,
            )

            if response.status_code != 404:

                raise AssertionError(
                    "Unknown incident should "
                    "return HTTP 404."
                )

            print(
                "Unknown incident handling: PASS"
            )

            # ====================================================
            # TEST 8
            # OPENAPI ROUTE DISCOVERY
            # ====================================================

            separator()

            print(
                "TEST 8 - OPENAPI ROUTE DISCOVERY"
            )

            response = client.get(
                "/openapi.json"
            )

            if response.status_code != 200:

                raise AssertionError(
                    "OpenAPI schema could not be read."
                )

            paths = (
                response.json().get(
                    "paths",
                    {},
                )
            )

            route = (
                "/api/v1/cases/"
                "{incident_id}/"
                "mitigation-verification"
            )

            print(
                "Route Present:",
                route in paths,
            )

            if route not in paths:

                raise AssertionError(
                    "Mitigation verification "
                    "API route is missing."
                )

            operations = (
                paths[
                    route
                ].keys()
            )

            print(
                "Operations:",
                list(
                    operations
                ),
            )

            if "get" not in operations:

                raise AssertionError(
                    "GET mitigation endpoint missing."
                )

            if "post" not in operations:

                raise AssertionError(
                    "POST mitigation endpoint missing."
                )

            print(
                "OpenAPI route registration: PASS"
            )

            # ====================================================
            # FINAL VALIDATION
            # ====================================================

            separator()

            print(
                "VALIDATION"
            )

            print(
                "FastAPI GET before verification: PASS"
            )

            print(
                "FastAPI POST verification: PASS"
            )

            print(
                "FastAPI GET after verification: PASS"
            )

            print(
                "API -> SQLite persistence: PASS"
            )

            print(
                "API restart recovery: PASS"
            )

            print(
                "Real response API guard: PASS"
            )

            print(
                "Unknown incident HTTP handling: PASS"
            )

            print(
                "OpenAPI GET route: PASS"
            )

            print(
                "OpenAPI POST route: PASS"
            )

            print(
                "Production database modified: NO"
            )

            print(
                "Real endpoint action performed: NO"
            )

            separator()

            print(
                "MITIGATION VERIFICATION FASTAPI "
                "INTEGRATION TEST COMPLETED SUCCESSFULLY"
            )

            separator()

        finally:

            # ====================================================
            # RESTORE ORIGINAL API WORKFLOW
            # ====================================================

            api_main.workflow = (
                original_workflow
            )


# ================================================================
# RUN
# ================================================================

if __name__ == "__main__":

    main()