from __future__ import annotations

import json
import sys

from agents.protection_mode_policy import (
    ProtectionModePolicy,
)


def heading(text: str) -> None:
    print()
    print("=" * 108)
    print(text)
    print("=" * 108)


def show(value) -> None:
    print(
        json.dumps(
            value,
            indent=2,
            default=str,
        )
    )


def threat() -> dict:
    return {
        "id": "MODE-VALIDATION-001",
        "event_id": "MODE-EVENT-001",
        "incident_id": "MODE-INCIDENT-001",
        "device_id": "endpoint-01",
    }


def risk(
    assessment: str,
    level: str = "HIGH",
) -> dict:
    return {
        "agent": "AIRiskReasoningAgent",
        "agent_version": "7D.4-v3",
        "risk_score": 80,
        "risk_level": level,
        "confidence": 0.9,
        "threat_assessment": assessment,
        "evidence_strength": "STRONG",
    }


def response(
    digital_twin_required: bool = True,
) -> dict:
    return {
        "agent": "AIResponseRecommendationAgent",
        "agent_version": "7D.5-v2",
        "response_strategy": (
            "TARGETED_RESPONSE"
            if digital_twin_required
            else "MONITOR"
        ),
        "digital_twin_required":
            digital_twin_required,
        "execution_allowed": False,
        "automatic_execution_allowed": False,
        "real_response_executed": False,
    }


def selected_plan(
    *,
    with_isolation: bool = False,
) -> dict:
    actions = [
        {
            "action_type":
                "TERMINATE_PROCESS",
            "target": {
                "processes": [
                    {
                        "pid": 5501
                    }
                ]
            },
        },
        {
            "action_type":
                "QUARANTINE_FILE",
            "target": {
                "files": [
                    {
                        "path":
                            "C:\\Users\\Public\\payload.bin"
                    }
                ]
            },
        },
    ]

    if with_isolation:
        actions.append(
            {
                "action_type":
                    "ISOLATE_ENDPOINT",
                "target": {
                    "device_id":
                        "endpoint-01"
                },
            }
        )

    return {
        "agent":
            "AIDigitalTwinPlanSelectionAgent",
        "agent_version":
            "7D.6-v1",
        "selection_status":
            "SELECTED",
        "incident_id":
            "MODE-INCIDENT-001",
        "selected_plan_id":
            "DT-PLAN-3",
        "selected_plan": {
            "plan_id":
                "DT-PLAN-3",
            "plan_name":
                "Validation Plan",
            "actions":
                actions,
            "real_endpoint_modified":
                False,
        },
        "requires_analyst_approval":
            True,
        "simulation_only":
            True,
        "execution_allowed":
            False,
        "automatic_execution_allowed":
            False,
        "real_response_executed":
            False,
    }


def no_plan() -> dict:
    return {
        "agent":
            "AIDigitalTwinPlanSelectionAgent",
        "agent_version":
            "7D.6-v1",
        "selection_status":
            "NOT_REQUIRED",
        "selected_plan_id":
            None,
        "selected_plan":
            None,
        "requires_analyst_approval":
            False,
        "simulation_only":
            True,
        "execution_allowed":
            False,
        "automatic_execution_allowed":
            False,
        "real_response_executed":
            False,
    }


def unavailable_plan() -> dict:
    return {
        "agent":
            "AIDigitalTwinPlanSelectionAgent",
        "agent_version":
            "7D.6-v1",
        "selection_status":
            "AI_UNAVAILABLE",
        "selected_plan_id":
            None,
        "selected_plan":
            None,
        "requires_analyst_approval":
            False,
        "simulation_only":
            True,
        "execution_allowed":
            False,
        "automatic_execution_allowed":
            False,
        "real_response_executed":
            False,
    }


def assert_common_safety(
    result: dict,
    failures: list,
) -> None:
    if result.get(
        "simulation_only"
    ) is not True:
        failures.append(
            "simulation_only != True"
        )

    if result.get(
        "execution_allowed"
    ) is not False:
        failures.append(
            "execution_allowed != False"
        )

    if result.get(
        "automatic_execution_allowed"
    ) is not False:
        failures.append(
            "automatic_execution_allowed != False"
        )

    if result.get(
        "real_response_executed"
    ) is not False:
        failures.append(
            "real_response_executed != False"
        )


def main() -> int:
    heading(
        "SENTINEL-X 7D.7 — PROTECTION MODE POLICY VALIDATION"
    )

    policy = ProtectionModePolicy()

    scenarios = [
        {
            "name":
                "Recommended + likely malicious",
            "mode":
                "Recommended",
            "risk":
                risk(
                    "LIKELY_MALICIOUS",
                    "CRITICAL",
                ),
            "response":
                response(True),
            "plan":
                selected_plan(),
            "expected":
                "PROTECT_PREVIEW",
            "confirm":
                False,
            "auto_intent":
                True,
        },
        {
            "name":
                "Recommended + suspicious",
            "mode":
                "Recommended",
            "risk":
                risk(
                    "SUSPICIOUS",
                    "HIGH",
                ),
            "response":
                response(True),
            "plan":
                selected_plan(),
            "expected":
                "ASK_USER",
            "confirm":
                True,
            "auto_intent":
                False,
        },
        {
            "name":
                "Strict + suspicious",
            "mode":
                "Strict",
            "risk":
                risk(
                    "SUSPICIOUS",
                    "HIGH",
                ),
            "response":
                response(True),
            "plan":
                selected_plan(),
            "expected":
                "PROTECT_PREVIEW",
            "confirm":
                False,
            "auto_intent":
                True,
        },
        {
            "name":
                "Ask Me + malicious",
            "mode":
                "Ask Me",
            "risk":
                risk(
                    "MALICIOUS",
                    "CRITICAL",
                ),
            "response":
                response(True),
            "plan":
                selected_plan(
                    with_isolation=True
                ),
            "expected":
                "ASK_USER",
            "confirm":
                True,
            "auto_intent":
                False,
        },
        {
            "name":
                "Monitor Only + malicious",
            "mode":
                "Monitor Only",
            "risk":
                risk(
                    "MALICIOUS",
                    "CRITICAL",
                ),
            "response":
                response(True),
            "plan":
                selected_plan(
                    with_isolation=True
                ),
            "expected":
                "MONITOR",
            "confirm":
                False,
            "auto_intent":
                False,
        },
        {
            "name":
                "Recommended + low concern + no plan",
            "mode":
                "Recommended",
            "risk":
                risk(
                    "LOW_CONCERN",
                    "LOW",
                ),
            "response":
                response(False),
            "plan":
                no_plan(),
            "expected":
                "MONITOR",
            "confirm":
                False,
            "auto_intent":
                False,
        },
        {
            "name":
                "Strict + uncertain",
            "mode":
                "Strict",
            "risk":
                risk(
                    "UNCERTAIN",
                    "MEDIUM",
                ),
            "response":
                response(True),
            "plan":
                selected_plan(),
            "expected":
                "ASK_USER",
            "confirm":
                True,
            "auto_intent":
                False,
        },
        {
            "name":
                "Recommended + plan AI unavailable",
            "mode":
                "Recommended",
            "risk":
                risk(
                    "LIKELY_MALICIOUS",
                    "HIGH",
                ),
            "response":
                response(True),
            "plan":
                unavailable_plan(),
            "expected":
                "ASK_USER",
            "confirm":
                True,
            "auto_intent":
                False,
        },
    ]

    passed = 0

    for index, scenario in enumerate(
        scenarios,
        start=1,
    ):
        heading(
            f"MODE-{index:02d} — {scenario['name']}"
        )

        failures = []

        result = policy.apply(
            mode=
                scenario[
                    "mode"
                ],
            threat=
                threat(),
            risk_assessment=
                scenario[
                    "risk"
                ],
            response_recommendation=
                scenario[
                    "response"
                ],
            plan_selection=
                scenario[
                    "plan"
                ],
        )

        show(
            result
        )

        if result.get(
            "policy_decision"
        ) != scenario[
            "expected"
        ]:
            failures.append(
                "Wrong policy_decision. "
                f"Expected={scenario['expected']} "
                f"Actual={result.get('policy_decision')}"
            )

        if result.get(
            "requires_user_confirmation"
        ) is not scenario[
            "confirm"
        ]:
            failures.append(
                "requires_user_confirmation mismatch."
            )

        if result.get(
            "automatic_protection_intent"
        ) is not scenario[
            "auto_intent"
        ]:
            failures.append(
                "automatic_protection_intent mismatch."
            )

        if (
            result.get(
                "next_stage"
            )
            !=
            "AI_USER_EXPLANATION"
        ):
            failures.append(
                "next_stage is not AI_USER_EXPLANATION."
            )

        assert_common_safety(
            result,
            failures,
        )

        if failures:
            print()
            print(
                "SCENARIO RESULT: FAIL"
            )
            for failure in failures:
                print(
                    " -",
                    failure,
                )
        else:
            print()
            print(
                "SCENARIO RESULT: PASS"
            )
            passed += 1

    # ------------------------------------------------------------
    # Invalid upstream execution claim must be rejected.
    # ------------------------------------------------------------

    heading(
        "MODE-SAFETY — UPSTREAM EXECUTION CLAIM REJECTION"
    )

    safety_pass = False

    bad_plan = selected_plan()
    bad_plan[
        "execution_allowed"
    ] = True

    try:
        policy.apply(
            mode=
                "Recommended",
            threat=
                threat(),
            risk_assessment=
                risk(
                    "MALICIOUS",
                    "CRITICAL",
                ),
            response_recommendation=
                response(True),
            plan_selection=
                bad_plan,
        )

    except ValueError as error:
        safety_pass = True
        print(
            "Rejected:",
            str(
                error
            )
        )

    if safety_pass:
        print(
            "SCENARIO RESULT: PASS"
        )
        passed += 1
    else:
        print(
            "SCENARIO RESULT: FAIL"
        )

    total = (
        len(
            scenarios
        )
        + 1
    )

    heading(
        "7D.7 RESULT"
    )

    print(
        f"TOTAL : {passed}/{total} PASS"
    )

    if passed == total:
        print(
            "RESULT: PASS"
        )
        print(
            "SENTINEL-X 7D.7 Protection Modes is ready to close."
        )
        return 0

    print(
        "RESULT: FAIL"
    )
    return 1


if __name__ == "__main__":
    sys.exit(
        main()
    )
