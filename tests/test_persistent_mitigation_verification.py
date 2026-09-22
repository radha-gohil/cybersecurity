import sys
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

from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)

from response.mitigation_verifier import (
    MitigationVerifier,
)


# ================================================================
# IN-MEMORY CASE STORE
# ================================================================

class InMemoryCaseStore:

    def __init__(self):
        self.cases = {}

    def save_case(
        self,
        case,
    ):

        incident_id = case.get(
            "incident_id"
        )

        if not incident_id:
            raise ValueError(
                "incident_id missing."
            )

        self.cases[
            incident_id
        ] = dict(
            case
        )

        return incident_id

    def get_case(
        self,
        incident_id,
    ):

        case = self.cases.get(
            incident_id
        )

        if case is None:
            return None

        return dict(
            case
        )

    def list_cases(
        self,
        limit=100,
    ):

        return list(
            self.cases.values()
        )[:limit]


# ================================================================
# IN-MEMORY ACTION STORE
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
            or action.get(
                "response_action_id"
            )
            or (
                "synthetic-action-"
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

        results = []

        for action in self.actions.values():

            if (
                action.get(
                    "incident_id"
                )
                ==
                incident_id
            ):

                results.append(
                    dict(
                        action
                    )
                )

        return results


# ================================================================
# IN-MEMORY EVIDENCE STORE
# ================================================================

class InMemoryEvidenceStore:

    def __init__(self):

        self.evidence = {}
        self.timelines = {}

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


# ================================================================
# SEPARATOR
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
        "SENTINEL-X PERSISTENT MITIGATION VERIFICATION "
        "INTEGRATION TEST"
    )

    separator()

    print(
        "\nSIMULATION ONLY"
    )

    print(
        "No process is terminated."
    )

    print(
        "No IP address is blocked."
    )

    print(
        "No firewall configuration is changed."
    )

    print(
        "No endpoint is isolated."
    )

    print(
        "No file is quarantined."
    )

    # ============================================================
    # TEST STORES
    # ============================================================

    case_store = (
        InMemoryCaseStore()
    )

    action_store = (
        InMemoryActionStore()
    )

    evidence_store = (
        InMemoryEvidenceStore()
    )

    # ============================================================
    # MITIGATION VERIFIER
    # ============================================================

    verifier = (
        MitigationVerifier(

            verified_threshold=0.70,

            partial_threshold=0.30,

            acceptable_residual_risk=30.0,
        )
    )

    # ============================================================
    # PERSISTENT WORKFLOW
    # ============================================================

    workflow = (
        PersistentSOCWorkflow(

            simulation_mode=True,

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

    # ============================================================
    # SYNTHETIC CASE
    # ============================================================

    incident_id = (
        "synthetic-mitigation-verification-001"
    )

    case_store.save_case(
        {

            "workflow":
                "PersistentSOCWorkflow",

            "incident_id":
                incident_id,

            "status":
                "AWAITING_ANALYST_REVIEW",

            "decision":
                {
                    "selected_plan":
                        "synthetic-plan-001",
                },

            "explanation":
                {
                    "summary":
                        "Synthetic mitigation verification test.",
                },

            "ticket_data":
                {},

            "response_actions":
                [],

            "response_action_count":
                0,

            "created_at":
                None,

            "updated_at":
                None,

            "simulation_mode":
                True,

            "real_response_executed":
                False,
        }
    )

    # ============================================================
    # BEFORE STATE
    # ============================================================

    before_state = {

        "risk_score":
            85,

        "suspicious_event_count":
            12,

        "active_indicator_count":
            8,

        "exposure_score":
            90,
    }

    # ============================================================
    # SIMULATED AFTER STATE
    # ============================================================

    simulated_after_state = {

        "risk_score":
            20,

        "suspicious_event_count":
            2,

        "active_indicator_count":
            1,

        "exposure_score":
            20,
    }

    # ============================================================
    # SIMULATED RESPONSE RESULT
    # ============================================================

    response_result = {

        "simulation_mode":
            True,

        "plan_id":
            "synthetic-plan-001",

        "action":
            "SIMULATED_CONTAINMENT",
    }

    # ============================================================
    # TEST 1
    # PERSISTENT WORKFLOW VERIFICATION
    # ============================================================

    separator()

    print(
        "TEST 1 - PERSISTENT WORKFLOW VERIFICATION"
    )

    result = (
        workflow.verify_simulated_mitigation(

            incident_id=
                incident_id,

            before_state=
                before_state,

            simulated_after_state=
                simulated_after_state,

            response_result=
                response_result,
        )
    )

    print(
        "\nSuccess:",
        result.get(
            "success"
        ),
    )

    print(
        "Status:",
        result.get(
            "status"
        ),
    )

    print(
        "Persisted:",
        result.get(
            "persisted"
        ),
    )

    print(
        "Simulation Mode:",
        result.get(
            "simulation_mode"
        ),
    )

    print(
        "Real Response Executed:",
        result.get(
            "real_response_executed"
        ),
    )

    verification = result.get(
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

    if (
        result.get(
            "status"
        )
        !=
        "SIMULATION_VERIFIED"
    ):

        raise AssertionError(
            "Expected SIMULATION_VERIFIED."
        )

    if (
        result.get(
            "persisted"
        )
        is not True
    ):

        raise AssertionError(
            "Verification was not persisted."
        )

    if (
        result.get(
            "simulation_mode"
        )
        is not True
    ):

        raise AssertionError(
            "Simulation mode must remain True."
        )

    if (
        result.get(
            "real_response_executed"
        )
        is not False
    ):

        raise AssertionError(
            "Real response execution must remain False."
        )

    print(
        "Persistent workflow verification: PASS"
    )

    # ============================================================
    # TEST 2
    # RECOVER PERSISTED VERIFICATION
    # ============================================================

    separator()

    print(
        "TEST 2 - RECOVER PERSISTED VERIFICATION"
    )

    recovered = (
        workflow.recover_case(
            incident_id
        )
    )

    if recovered is None:

        raise AssertionError(
            "SOC case could not be recovered."
        )

    recovered_verification = (
        recovered.get(
            "mitigation_verification",
            {},
        )
    )

    print(
        "\nRecovered Status:",
        recovered_verification.get(
            "status"
        ),
    )

    print(
        "Recovered Verification Type:",
        recovered_verification.get(
            "verification_type"
        ),
    )

    print(
        "Recovered Simulation Mode:",
        recovered.get(
            "simulation_mode"
        ),
    )

    print(
        "Recovered Real Response Executed:",
        recovered.get(
            "real_response_executed"
        ),
    )

    if (
        recovered_verification.get(
            "status"
        )
        !=
        "SIMULATION_VERIFIED"
    ):

        raise AssertionError(
            "Persisted mitigation verification "
            "was not recovered."
        )

    if (
        recovered_verification.get(
            "verification_type"
        )
        !=
        "SIMULATED_MITIGATION_VERIFICATION"
    ):

        raise AssertionError(
            "Unexpected verification type."
        )

    if (
        recovered.get(
            "real_response_executed"
        )
        is not False
    ):

        raise AssertionError(
            "Recovered case indicates real execution."
        )

    print(
        "Mitigation verification recovery: PASS"
    )

    # ============================================================
    # TEST 3
    # VERIFICATION GETTER
    # ============================================================

    separator()

    print(
        "TEST 3 - MITIGATION VERIFICATION GETTER"
    )

    getter_result = (
        workflow.get_mitigation_verification(
            incident_id
        )
    )

    print(
        "\nGetter Status:",
        getter_result.get(
            "status"
        ),
    )

    if (
        getter_result.get(
            "status"
        )
        !=
        "SIMULATION_VERIFIED"
    ):

        raise AssertionError(
            "get_mitigation_verification returned "
            "unexpected data."
        )

    print(
        "Mitigation verification getter: PASS"
    )

    # ============================================================
    # TEST 4
    # REAL RESPONSE INPUT MUST BE BLOCKED
    # ============================================================

    separator()

    print(
        "TEST 4 - REAL RESPONSE RESULT SAFETY GUARD"
    )

    safety_guard_passed = False

    try:

        workflow.verify_simulated_mitigation(

            incident_id=
                incident_id,

            before_state=
                before_state,

            simulated_after_state=
                simulated_after_state,

            response_result=
                {

                    "simulation_mode":
                        False,

                    "plan_id":
                        "blocked-real-plan",

                    "action":
                        "REAL_RESPONSE",
                },
        )

    except ValueError as exc:

        safety_guard_passed = True

        print(
            "\nBlocked:",
            str(
                exc
            ),
        )

    if not safety_guard_passed:

        raise AssertionError(
            "Real-response safety guard failed."
        )

    print(
        "Real response result blocked: PASS"
    )

    # ============================================================
    # TEST 5
    # WORKFLOW ITSELF MUST BE SIMULATION MODE
    # ============================================================

    separator()

    print(
        "TEST 5 - WORKFLOW SIMULATION-MODE SAFETY GUARD"
    )

    non_simulated_workflow = (
        PersistentSOCWorkflow(

            simulation_mode=False,

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

    workflow_guard_passed = False

    try:

        non_simulated_workflow.verify_simulated_mitigation(

            incident_id=
                incident_id,

            before_state=
                before_state,

            simulated_after_state=
                simulated_after_state,

            response_result=
                response_result,
        )

    except ValueError as exc:

        workflow_guard_passed = True

        print(
            "\nBlocked:",
            str(
                exc
            ),
        )

    if not workflow_guard_passed:

        raise AssertionError(
            "Non-simulation workflow was not blocked."
        )

    print(
        "Workflow simulation-mode guard: PASS"
    )

    # ============================================================
    # TEST 6
    # UNKNOWN CASE
    # ============================================================

    separator()

    print(
        "TEST 6 - UNKNOWN INCIDENT SAFETY CHECK"
    )

    unknown_case_blocked = False

    try:

        workflow.verify_simulated_mitigation(

            incident_id=
                "incident-does-not-exist",

            before_state=
                before_state,

            simulated_after_state=
                simulated_after_state,

            response_result=
                response_result,
        )

    except ValueError as exc:

        unknown_case_blocked = True

        print(
            "\nBlocked:",
            str(
                exc
            ),
        )

    if not unknown_case_blocked:

        raise AssertionError(
            "Unknown incident was not rejected."
        )

    print(
        "Unknown incident validation: PASS"
    )

    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    separator()

    print(
        "VALIDATION"
    )

    print(
        "MitigationVerifier integration: PASS"
    )

    print(
        "Persistent case storage: PASS"
    )

    print(
        "Recovery after persistence: PASS"
    )

    print(
        "Verification getter: PASS"
    )

    print(
        "Real response input blocked: PASS"
    )

    print(
        "Non-simulation workflow blocked: PASS"
    )

    print(
        "Unknown incident validation: PASS"
    )

    print(
        "Real endpoint modification performed: NO"
    )

    separator()

    print(
        "PERSISTENT MITIGATION VERIFICATION "
        "INTEGRATION TEST COMPLETED SUCCESSFULLY"
    )

    separator()

    print(
        """
Verified path:

Synthetic SOC Case
       |
       v
PersistentSOCWorkflow
       |
       v
MitigationVerifier
       |
       v
Simulated Before/After Comparison
       |
       v
Mitigation Verification Result
       |
       v
Persistent SOC Case
       |
       v
Recovery / Analyst Review

Real endpoint action: DISABLED
"""
    )


# ================================================================
# RUN
# ================================================================

if __name__ == "__main__":

    main()