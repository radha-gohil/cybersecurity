from __future__ import annotations

import json
import sys
import time


from agents.ai_user_explanation_agent import (
    AIUserExplanationAgent,
)


# ================================================================
# HELPERS
# ================================================================


def heading(
    text: str,
):

    print()

    print(
        "=" * 112
    )

    print(
        text
    )

    print(
        "=" * 112
    )


def show(
    value,
):

    print(
        json.dumps(
            value,
            indent=2,
            default=str,
        )
    )


# ================================================================
# COMMON BUILDERS
# ================================================================


def threat(
    *,
    security_id,
    assessment_hint,
    observed,
):

    return {

        "id":
            security_id,

        "event_id":
            f"{security_id}-EVENT",

        "incident_id":
            f"{security_id}-INCIDENT",

        "device_id":
            "endpoint-01",

        "category":
            observed.get(
                "category",
                "PROCESS",
            ),

        "event_type":
            observed.get(
                "event_type"
            ),

        "threat_type":
            assessment_hint,

        "severity":
            observed.get(
                "severity",
                "HIGH",
            ),

        "verdict":
            observed.get(
                "verdict",
                "SUSPICIOUS",
            ),

        "engine":
            "7D8_validation",

        "evidence": {

            "observed": [
                observed
            ]
        },

        "model_evidence": {

            "signals":
                observed.get(
                    "model_signals",
                    [],
                )
        },
    }


def risk(
    *,
    assessment,
    level,
    score,
    confidence,
    evidence_strength,
    summary,
    drivers,
    uncertainty,
):

    return {

        "agent":
            "AIRiskReasoningAgent",

        "agent_version":
            "7D.4-v3",

        "risk_score":
            score,

        "risk_level":
            level,

        "confidence":
            confidence,

        "threat_assessment":
            assessment,

        "evidence_strength":
            evidence_strength,

        "risk_summary": [
            summary
        ],

        "primary_risk_drivers":
            drivers,

        "corroborating_evidence":
            [],

        "mitigating_evidence":
            [],

        "uncertainties":
            uncertainty,

        "potential_impact":
            [],

        "why_this_level":
            summary,

        "why_not_higher":
            (
                "The supplied evidence does not "
                "justify a stronger certainty level."
            ),

        "why_not_lower":
            (
                "The observed evidence remains "
                "security-relevant."
            ),

        "risk_score_semantics":
            "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",
    }


def monitor_response():

    return {

        "agent":
            "AIResponseRecommendationAgent",

        "agent_version":
            "7D.5-v2",

        "response_strategy":
            "MONITOR",

        "response_summary": [
            "Continue monitoring without disruptive action."
        ],

        "recommendations": [

            {
                "action":
                    "MONITOR_INCIDENT",

                "priority":
                    "LOW",

                "target_reference":
                    "NONE",

                "reason":
                    "No disruptive response is justified.",
            }
        ],

        "why_this_response":
            "Monitoring is sufficient.",

        "why_not_more_aggressive":
            "Disruptive action is not justified.",

        "why_not_less_aggressive":
            "Continued monitoring remains useful.",

        "digital_twin_required":
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


def investigate_response():

    return {

        "agent":
            "AIResponseRecommendationAgent",

        "agent_version":
            "7D.5-v2",

        "response_strategy":
            "INVESTIGATE",

        "response_summary": [
            (
                "Continue investigation because the "
                "evidence is suspicious but incomplete."
            )
        ],

        "recommendations": [

            {
                "action":
                    "INVESTIGATE_INCIDENT",

                "priority":
                    "MEDIUM",

                "target_reference":
                    "NONE",

                "reason":
                    (
                        "Additional evidence is needed "
                        "before restrictive response."
                    ),
            }
        ],

        "why_this_response":
            "Investigation matches the current uncertainty.",

        "why_not_more_aggressive":
            "Containment is premature.",

        "why_not_less_aggressive":
            "The suspicious pattern warrants investigation.",

        "digital_twin_required":
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


def targeted_response():

    return {

        "agent":
            "AIResponseRecommendationAgent",

        "agent_version":
            "7D.5-v2",

        "response_strategy":
            "TARGETED_RESPONSE",

        "response_summary": [
            (
                "Targeted response candidates are available "
                "for Digital Twin simulation."
            )
        ],

        "recommendations": [

            {
                "action":
                    "PROCESS_TERMINATION_REVIEW",

                "priority":
                    "HIGH",

                "target_reference":
                    "PROCESS",

                "reason":
                    (
                        "Observed hidden encoded PowerShell "
                        "execution is a concrete process target."
                    ),
            },

            {
                "action":
                    "QUARANTINE_REVIEW",

                "priority":
                    "HIGH",

                "target_reference":
                    "FILE",

                "reason":
                    (
                        "Observed file artifact is a concrete "
                        "file target."
                    ),
            },
        ],

        "why_this_response":
            (
                "Strong evidence supports targeted "
                "response simulation."
            ),

        "why_not_more_aggressive":
            (
                "Broader endpoint isolation is not "
                "necessary if narrower controls are "
                "simulated as sufficient."
            ),

        "why_not_less_aggressive":
            (
                "Monitoring alone is insufficient for "
                "the observed multi-source behavior."
            ),

        "digital_twin_required":
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


def selected_plan():

    return {

        "agent":
            "AIDigitalTwinPlanSelectionAgent",

        "agent_version":
            "7D.6-v1",

        "ai_available":
            True,

        "selection_status":
            "SELECTED",

        "selected_plan_id":
            "DT-PLAN-2",

        "selection_summary": [
            (
                "The simulated targeted plan reduces "
                "risk while avoiding endpoint isolation."
            )
        ],

        "tradeoffs": [
            (
                "The plan uses targeted controls with "
                "lower operational impact than isolation."
            )
        ],

        "why_selected":
            "It balances simulated effectiveness and impact.",

        "why_not_more_aggressive":
            "Endpoint isolation adds disruption.",

        "why_not_less_aggressive":
            "The minimal plan leaves more simulated residual risk.",

        "isolation_justified":
            False,

        "selected_plan": {

            "plan_id":
                "DT-PLAN-2",

            "plan_name":
                "Targeted Containment",

            "actions": [

                {
                    "action_type":
                        "TERMINATE_PROCESS",

                    "target": {

                        "processes": [

                            {
                                "pid":
                                    5501,

                                "name":
                                    "powershell.exe",
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
                                    (
                                        "C:\\Users\\Public\\"
                                        "payload.bin"
                                    ),

                                "sha256":
                                    (
                                        "aaaaaaaaaaaaaaaa"
                                        "aaaaaaaaaaaaaaaa"
                                        "aaaaaaaaaaaaaaaa"
                                        "aaaaaaaaaaaaaaaa"
                                    ),
                            }
                        ]
                    },
                },
            ],

            "predicted_residual_risk":
                12,

            "predicted_residual_level":
                "INFO",

            "risk_reduction":
                80,

            "risk_reduction_percentage":
                86.96,

            "response_effectiveness":
                "VERY_HIGH",

            "operational_impact": {

                "impact_score":
                    35,

                "impact_level":
                    "MEDIUM",
            },

            "recommended_decision":
                "RESPONSE_PLAN_EFFECTIVE",

            "real_endpoint_modified":
                False,
        },

        "simulation_only":
            True,

        "execution_allowed":
            False,

        "automatic_execution_allowed":
            False,

        "real_response_executed":
            False,
    }


def no_plan():

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

        "simulation_only":
            True,

        "execution_allowed":
            False,

        "automatic_execution_allowed":
            False,

        "real_response_executed":
            False,
    }


def protection_policy(
    *,
    mode,
    decision,
    assessment,
    requires_confirmation,
    selected_plan_id=None,
):

    return {

        "schema_version":
            "sentinelx.ai.protection-mode-policy.v1",

        "policy":
            "ProtectionModePolicy",

        "policy_version":
            "7D.7-v1",

        "incident_id":
            "7D8-VALIDATION-INCIDENT",

        "protection_mode":
            mode,

        "protection_mode_display":
            (
                mode
                .replace(
                    "_",
                    " "
                )
                .title()
            ),

        "risk_level":
            (
                "CRITICAL"
                if assessment
                in {
                    "LIKELY_MALICIOUS",
                    "MALICIOUS",
                }
                else "MEDIUM"
            ),

        "threat_assessment":
            assessment,

        "response_strategy":
            (
                "TARGETED_RESPONSE"
                if selected_plan_id
                else "MONITOR"
            ),

        "plan_selection_status":
            (
                "SELECTED"
                if selected_plan_id
                else "NOT_REQUIRED"
            ),

        "selected_plan_id":
            selected_plan_id,

        "policy_decision":
            decision,

        "policy_reason":
            (
                "Validation policy result for "
                f"{decision}."
            ),

        "requires_user_confirmation":
            requires_confirmation,

        "policy_eligible_for_protection":
            (
                decision
                ==
                "PROTECT_PREVIEW"
            ),

        "automatic_protection_intent":
            (
                decision
                ==
                "PROTECT_PREVIEW"
            ),

        "simulation_only":
            True,

        "execution_allowed":
            False,

        "automatic_execution_allowed":
            False,

        "real_response_executed":
            False,

        "next_stage":
            "AI_USER_EXPLANATION",
    }


# ================================================================
# SCENARIOS
# ================================================================


def scenario_1():

    return {

        "name":
            "Low-concern trusted updater",

        "threat":
            threat(

                security_id=
                    "EXPLAIN-01",

                assessment_hint=
                    "TRUSTED_UPDATE_ACTIVITY",

                observed={

                    "category":
                        "PROCESS",

                    "event_type":
                        "process_network_activity",

                    "process_name":
                        "trusted_updater.exe",

                    "signature_valid":
                        True,

                    "publisher":
                        "Trusted Software Vendor",

                    "destination":
                        "updates.vendor.example",

                    "severity":
                        "LOW",

                    "verdict":
                        "LOW_CONCERN",
                },
            ),

        "risk":
            risk(

                assessment=
                    "LOW_CONCERN",

                level=
                    "LOW",

                score=
                    20,

                confidence=
                    0.85,

                evidence_strength=
                    "STRONG",

                summary=
                    (
                        "Activity matches a trusted "
                        "software update workflow."
                    ),

                drivers=[
                    (
                        "Periodic network activity "
                        "was observed."
                    )
                ],

                uncertainty=
                    [],
            ),

        "response":
            monitor_response(),

        "plan":
            no_plan(),

        "policy":
            protection_policy(

                mode=
                    "RECOMMENDED",

                decision=
                    "MONITOR",

                assessment=
                    "LOW_CONCERN",

                requires_confirmation=
                    False,
            ),

        "expected_status":
            "MONITORING",

        "expected_confirmation":
            False,

        "expect_actions":
            False,
    }


def scenario_2():

    return {

        "name":
            "Suspicious ambiguous network activity",

        "threat":
            threat(

                security_id=
                    "EXPLAIN-02",

                assessment_hint=
                    "SUSPICIOUS_BEACONING",

                observed={

                    "category":
                        "NETWORK",

                    "event_type":
                        "network_connection",

                    "process_name":
                        "background_service.exe",

                    "remote_ip":
                        "198.51.100.50",

                    "remote_port":
                        443,

                    "interval_seconds":
                        60,

                    "severity":
                        "MEDIUM",

                    "verdict":
                        "SUSPICIOUS",
                },
            ),

        "risk":
            risk(

                assessment=
                    "SUSPICIOUS",

                level=
                    "MEDIUM",

                score=
                    58,

                confidence=
                    0.61,

                evidence_strength=
                    "MODERATE",

                summary=
                    (
                        "Periodic outbound communication "
                        "is suspicious, but malicious "
                        "intent is not confirmed."
                    ),

                drivers=[
                    (
                        "Regular periodic outbound "
                        "connections were observed."
                    )
                ],

                uncertainty=[
                    "Remote IP reputation is unavailable.",
                    "Payload was not inspected.",
                    "Process legitimacy is unknown.",
                ],
            ),

        "response":
            investigate_response(),

        "plan":
            no_plan(),

        "policy":
            protection_policy(

                mode=
                    "RECOMMENDED",

                decision=
                    "ASK_USER",

                assessment=
                    "SUSPICIOUS",

                requires_confirmation=
                    True,
            ),

        "expected_status":
            "REVIEW_REQUIRED",

        "expected_confirmation":
            True,

        "expect_actions":
            False,
    }


def scenario_3():

    return {

        "name":
            "Likely malicious multi-source activity",

        "threat":
            threat(

                security_id=
                    "EXPLAIN-03",

                assessment_hint=
                    "MULTI_STAGE_SUSPICIOUS_ACTIVITY",

                observed={

                    "category":
                        "PROCESS",

                    "event_type":
                        "process_start",

                    "process_name":
                        "powershell.exe",

                    "pid":
                        5501,

                    "command_line":
                        (
                            "powershell.exe "
                            "-WindowStyle Hidden "
                            "-EncodedCommand AAAA"
                        ),

                    "severity":
                        "CRITICAL",

                    "verdict":
                        "LIKELY_THREAT",

                    "model_signals": [
                        "encoded_powershell",
                        "hidden_execution",
                    ],
                },
            ),

        "risk":
            risk(

                assessment=
                    "LIKELY_MALICIOUS",

                level=
                    "CRITICAL",

                score=
                    92,

                confidence=
                    0.95,

                evidence_strength=
                    "STRONG",

                summary=
                    (
                        "Multiple telemetry categories "
                        "support likely malicious "
                        "multi-stage behavior."
                    ),

                drivers=[
                    "Hidden encoded PowerShell execution",
                    "Observed file artifact",
                    "Observed persistence modification",
                    "Observed outbound network activity",
                ],

                uncertainty=[
                    (
                        "Remote destination reputation "
                        "is unavailable."
                    )
                ],
            ),

        "response":
            targeted_response(),

        "plan":
            selected_plan(),

        "policy":
            protection_policy(

                mode=
                    "RECOMMENDED",

                decision=
                    "PROTECT_PREVIEW",

                assessment=
                    "LIKELY_MALICIOUS",

                requires_confirmation=
                    False,

                selected_plan_id=
                    "DT-PLAN-2",
            ),

        "expected_status":
            "PROTECTION_PREPARED",

        "expected_confirmation":
            False,

        "expect_actions":
            True,
    }


def scenario_4():

    return {

        "name":
            "Confirmed malicious activity in Ask Me mode",

        "threat":
            threat(

                security_id=
                    "EXPLAIN-04",

                assessment_hint=
                    "CONFIRMED_MALWARE_ACTIVITY",

                observed={

                    "category":
                        "FILE",

                    "event_type":
                        "malware_detection",

                    "path":
                        "C:\\Users\\Public\\confirmed-malware.bin",

                    "severity":
                        "CRITICAL",

                    "verdict":
                        "THREAT",
                },
            ),

        "risk":
            risk(

                assessment=
                    "MALICIOUS",

                level=
                    "CRITICAL",

                score=
                    96,

                confidence=
                    0.97,

                evidence_strength=
                    "VERY_STRONG",

                summary=
                    (
                        "Supplied evidence supports a "
                        "MALICIOUS assessment."
                    ),

                drivers=[
                    "Confirmed malware classification"
                ],

                uncertainty=[
                    (
                        "Digital Twin outcomes remain "
                        "simulated."
                    )
                ],
            ),

        "response":
            targeted_response(),

        "plan":
            selected_plan(),

        "policy":
            protection_policy(

                mode=
                    "ASK_ME",

                decision=
                    "ASK_USER",

                assessment=
                    "MALICIOUS",

                requires_confirmation=
                    True,

                selected_plan_id=
                    "DT-PLAN-2",
            ),

        "expected_status":
            "REVIEW_REQUIRED",

        "expected_confirmation":
            True,

        "expect_actions":
            True,
    }


# ================================================================
# RESULT VALIDATION
# ================================================================


def validate_result(
    result,
    scenario,
):

    failures = []


    if (
        result.get(
            "ai_available"
        )
        is not True
    ):

        failures.append(
            "AI unavailable."
        )


    if (
        result.get(
            "agent_version"
        )
        !=
        "7D.8-v1"
    ):

        failures.append(
            "Wrong agent version."
        )


    if (
        result.get(
            "display_status"
        )
        !=
        scenario[
            "expected_status"
        ]
    ):

        failures.append(
            (
                "Wrong display_status. "
                f"Expected={scenario['expected_status']} "
                f"Actual={result.get('display_status')}"
            )
        )


    if (
        result.get(
            "requires_user_confirmation"
        )
        is not
        scenario[
            "expected_confirmation"
        ]
    ):

        failures.append(
            (
                "requires_user_confirmation "
                "does not match policy."
            )
        )


    planned_actions = (
        result.get(
            "planned_actions"
        )
        or []
    )


    if (
        scenario[
            "expect_actions"
        ]
        and
        not planned_actions
    ):

        failures.append(
            "Expected planned actions are missing."
        )


    if (
        not scenario[
            "expect_actions"
        ]
        and
        planned_actions
    ):

        failures.append(
            "Unexpected planned actions were returned."
        )


    for field in [

        "headline",
        "plain_language_summary",
        "why_it_matters",
        "recommended_action_explanation",
        "uncertainty_note",
        "digital_twin_note",
        "execution_message",

    ]:

        if not str(
            result.get(
                field
            )
            or ""
        ).strip():

            failures.append(
                f"{field} is empty."
            )


    why_flagged = (
        result.get(
            "why_flagged"
        )
        or []
    )


    if not (
        1
        <=
        len(
            why_flagged
        )
        <=
        4
    ):

        failures.append(
            "why_flagged count invalid."
        )


    if (
        result.get(
            "simulation_only"
        )
        is not True
    ):

        failures.append(
            "simulation_only != True."
        )


    if (
        result.get(
            "execution_allowed"
        )
        is not False
    ):

        failures.append(
            "execution_allowed != False."
        )


    if (
        result.get(
            "automatic_execution_allowed"
        )
        is not False
    ):

        failures.append(
            (
                "automatic_execution_allowed "
                "!= False."
            )
        )


    if (
        result.get(
            "real_response_executed"
        )
        is not False
    ):

        failures.append(
            "real_response_executed != False."
        )


    if (
        result.get(
            "next_stage"
        )
        !=
        "USER_FACING_API"
    ):

        failures.append(
            "next_stage != USER_FACING_API."
        )


    return failures


# ================================================================
# DIRECT SAFETY TESTS
# ================================================================


def deterministic_safety_tests(
    agent,
):

    failures = []


    low_risk = risk(

        assessment=
            "LIKELY_MALICIOUS",

        level=
            "HIGH",

        score=
            80,

        confidence=
            0.8,

        evidence_strength=
            "STRONG",

        summary=
            "Likely malicious activity.",

        drivers=[
            "Observed suspicious activity"
        ],

        uncertainty=[
            "Intent remains not fully confirmed."
        ],
    )


    policy = protection_policy(

        mode=
            "RECOMMENDED",

        decision=
            "PROTECT_PREVIEW",

        assessment=
            "LIKELY_MALICIOUS",

        requires_confirmation=
            False,

        selected_plan_id=
            "DT-PLAN-2",
    )


    # ------------------------------------------------------------
    # Confirmed-malicious wording must be rejected.
    # ------------------------------------------------------------

    bad_certainty = {

        "headline":
            "Malicious activity detected",

        "plain_language_summary":
            (
                "Sentinel-X confirmed malicious "
                "activity on the endpoint."
            ),

        "why_flagged": [
            "Suspicious behavior was observed."
        ],

        "why_it_matters":
            "The activity could affect endpoint security.",

        "recommended_action_explanation":
            "A simulated plan is available.",

        "uncertainty_note":
            "Some evidence remains uncertain.",

        "digital_twin_note":
            "The Digital Twin result is simulated.",
    }


    try:

        agent.validate_output(

            result=
                bad_certainty,

            risk_assessment=
                low_risk,

            protection_policy=
                policy,
        )


        failures.append(
            (
                "Definitive malicious wording was "
                "accepted for LIKELY_MALICIOUS."
            )
        )


    except ValueError:

        pass


    # ------------------------------------------------------------
    # Completed execution claim must be rejected.
    # ------------------------------------------------------------

    bad_execution = {

        "headline":
            "Protection completed",

        "plain_language_summary":
            (
                "The suspicious process has been "
                "terminated."
            ),

        "why_flagged": [
            "Suspicious behavior was observed."
        ],

        "why_it_matters":
            "The activity could affect endpoint security.",

        "recommended_action_explanation":
            (
                "The file has been quarantined."
            ),

        "uncertainty_note":
            "The threat is likely malicious.",

        "digital_twin_note":
            "The Digital Twin result is simulated.",
    }


    try:

        agent.validate_output(

            result=
                bad_execution,

            risk_assessment=
                low_risk,

            protection_policy=
                policy,
        )


        failures.append(
            (
                "Completed execution language was "
                "accepted in simulation-only mode."
            )
        )


    except ValueError:

        pass


    return failures


# ================================================================
# MAIN
# ================================================================


def main():

    heading(
        (
            "SENTINEL-X 7D.8 — "
            "AI USER EXPLANATION SUITE"
        )
    )


    agent = (
        AIUserExplanationAgent()
    )


    scenarios = [

        scenario_1(),
        scenario_2(),
        scenario_3(),
        scenario_4(),
    ]


    passed = 0


    for index, scenario in enumerate(
        scenarios,
        start=1,
    ):

        heading(
            (
                f"EXPLAIN-{index:02d} — "
                f"{scenario['name']}"
            )
        )


        result = (
            agent.explain(

                threat=
                    scenario[
                        "threat"
                    ],

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

                protection_policy=
                    scenario[
                        "policy"
                    ],
            )
        )


        show(
            result
        )


        failures = (
            validate_result(
                result,
                scenario,
            )
        )


        print()


        if failures:

            print(
                "SCENARIO RESULT: FAIL"
            )


            for failure in failures:

                print(
                    " -",
                    failure,
                )


        else:

            print(
                "SCENARIO RESULT: PASS"
            )

            passed += 1


        if index < len(
            scenarios
        ):

            print()

            print(
                "Waiting 6 seconds..."
            )

            time.sleep(
                6
            )


    # ============================================================
    # DETERMINISTIC VALIDATOR TEST
    # ============================================================

    heading(
        "EXPLAIN-SAFETY — DETERMINISTIC LANGUAGE GUARDS"
    )


    safety_failures = (
        deterministic_safety_tests(
            agent
        )
    )


    if safety_failures:

        print(
            "SCENARIO RESULT: FAIL"
        )


        for failure in (
            safety_failures
        ):

            print(
                " -",
                failure,
            )


    else:

        print(
            "Certainty escalation rejection : PASS"
        )

        print(
            "Execution-claim rejection      : PASS"
        )

        print(
            "SCENARIO RESULT: PASS"
        )

        passed += 1


    total = (
        len(
            scenarios
        )
        +
        1
    )


    heading(
        "7D.8 RESULT"
    )


    print(
        f"TOTAL : {passed}/{total} PASS"
    )


    if passed == total:

        print()

        print(
            "RESULT: PASS"
        )

        print(
            (
                "SENTINEL-X 7D.8 AI User "
                "Explanation is ready to close."
            )
        )

        return 0


    print()

    print(
        "RESULT: FAIL"
    )

    print(
        (
            "Do not expose AI explanation "
            "through user-facing APIs yet."
        )
    )

    return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )
