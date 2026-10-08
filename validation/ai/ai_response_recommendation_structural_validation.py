from __future__ import annotations

import json
import sys


from agents.ai_response_recommendation_agent import (
    AIResponseRecommendationAgent,
)

from response.endpoint_digital_twin import (
    EndpointDigitalTwin,
)

from response.digital_twin_decision_integration import (
    DigitalTwinDecisionIntegration,
)


# ================================================================
# HELPERS
# ================================================================


def heading(
    text: str,
):

    print()

    print(
        "=" * 110
    )

    print(
        text
    )

    print(
        "=" * 110
    )


def print_json(
    value,
):

    print(
        json.dumps(
            value,
            indent=2,
            default=str,
        )
    )


def expect_error(
    name,
    function,
):

    try:

        function()

    except ValueError as error:

        print(
            f"{name}: PASS"
        )

        print(
            "  Rejected:",
            str(
                error
            ),
        )

        return True


    print(
        f"{name}: FAIL"
    )

    print(
        "  Expected ValueError but none occurred."
    )

    return False


# ================================================================
# CONTROLLED THREAT
# ================================================================


def build_threat():

    return {

        "id":
            "RESP-STRUCT-001",

        "detection_id":
            5001,

        "event_id":
            "RESP-STRUCT-EVENT-001",

        "incident_id":
            "RESP-STRUCT-INC-001",

        "device_id":
            "endpoint-01",

        "category":
            "PROCESS",

        "event_type":
            "process_start",

        "threat_type":
            "MULTI_STAGE_SUSPICIOUS_ACTIVITY",

        "engine":
            "response_structural_validation",

        "severity":
            "CRITICAL",

        "verdict":
            "LIKELY_THREAT",

        "confidence":
            0.94,

        "confidence_semantics":
            "DETECTOR_CONFIDENCE_NOT_PROBABILITY",

        "risk": {

            "detection": {

                "score":
                    92,

                "semantics":
                    "DETECTOR_RISK_SCORE_NOT_PROBABILITY",

                "source":
                    "STRUCTURAL_VALIDATION",
            }
        },

        "evidence": {

            "observed": [

                {
                    "event_type":
                        "process_start",

                    "process_name":
                        "powershell.exe",

                    "pid":
                        4242,

                    "command_line":
                        (
                            "powershell.exe "
                            "-WindowStyle Hidden "
                            "-EncodedCommand AAAA"
                        ),
                }
            ]
        },

        "model_evidence": {

            "signals": [

                "encoded_powershell",

                "hidden_execution",
            ]
        },

        "visibility": {

            "synthetic":
                True,
        },
    }


# ================================================================
# OBSERVED ENRICHED EVIDENCE
# ================================================================


def build_evidence():

    return {

        "incident_id":
            "RESP-STRUCT-INC-001",

        "processes": [

            {
                "pid":
                    4242,

                "name":
                    "powershell.exe",

                "exe":
                    (
                        "C:\\Windows\\System32\\"
                        "WindowsPowerShell\\v1.0\\"
                        "powershell.exe"
                    ),

                "process_create_time":
                    1791400000.0,

                "device_id":
                    "endpoint-01",
            }
        ],

        "files": [

            {
                "path":
                    "C:\\Users\\Public\\payload.bin",

                "sha256":
                    (
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    ),

                "device_id":
                    "endpoint-01",
            }
        ],

        "network_connections": [

            {
                "remote_ip":
                    "203.0.113.90",

                "remote_port":
                    443,

                "pid":
                    4242,

                "process_name":
                    "powershell.exe",

                "device_id":
                    "endpoint-01",
            }
        ],

        "registry_artifacts": [

            {
                "key":
                    (
                        "HKCU\\Software\\Microsoft\\Windows\\"
                        "CurrentVersion\\Run"
                    ),

                "value_name":
                    "Updater",

                "data":
                    "C:\\Users\\Public\\payload.bin",

                "device_id":
                    "endpoint-01",
            }
        ],

        "relationships":
            [],

        "identity_links":
            [],
    }


# ================================================================
# GROUNDED 7D.4 RISK RESULT
# ================================================================


def build_high_risk():

    return {

        "schema_version":
            "sentinelx.ai.risk-reasoning.v1",

        "agent":
            "AIRiskReasoningAgent",

        "agent_version":
            "7D.4-v3",

        "ai_available":
            True,

        "risk_score":
            92.0,

        "risk_level":
            "CRITICAL",

        "confidence":
            0.95,

        "threat_assessment":
            "LIKELY_MALICIOUS",

        "evidence_strength":
            "STRONG",

        "risk_summary": [

            (
                "Multiple endpoint evidence sources "
                "indicate suspicious multi-stage behavior."
            )
        ],

        "primary_risk_drivers": [

            "Hidden encoded PowerShell execution",

            "Observed file artifact",

            "Observed outbound network activity",

            "Observed persistence modification",
        ],

        "corroborating_evidence": [

            "Multiple telemetry categories corroborate activity"
        ],

        "mitigating_evidence":
            [],

        "uncertainties": [

            "Malicious intent is not independently attributed"
        ],

        "potential_impact": [

            "Potential endpoint compromise"
        ],

        "why_this_level":
            (
                "Multiple independent evidence sources "
                "support a high-priority security assessment."
            ),

        "why_not_higher":
            (
                "CRITICAL is already the highest supported "
                "risk level."
            ),

        "why_not_lower":
            (
                "Multiple endpoint categories corroborate "
                "the suspicious behavior."
            ),

        "risk_score_semantics":
            "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",

        "action_selected":
            False,

        "simulation_only":
            True,

        "execution_allowed":
            False,
    }


def build_low_risk():

    return {

        "agent":
            "AIRiskReasoningAgent",

        "agent_version":
            "7D.4-v3",

        "risk_score":
            20.0,

        "risk_level":
            "LOW",

        "confidence":
            0.82,

        "threat_assessment":
            "LOW_CONCERN",

        "evidence_strength":
            "STRONG",

        "risk_score_semantics":
            "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",
    }


def build_suspicious_risk():

    return {

        "agent":
            "AIRiskReasoningAgent",

        "agent_version":
            "7D.4-v3",

        "risk_score":
            65.0,

        "risk_level":
            "HIGH",

        "confidence":
            0.75,

        "threat_assessment":
            "SUSPICIOUS",

        "evidence_strength":
            "MODERATE",

        "risk_score_semantics":
            "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",
    }


# ================================================================
# CONTROLLED AI OUTPUT
#
# NOTE:
# Some deliberately invented "target" objects are inserted below.
#
# AIResponseRecommendationAgent MUST IGNORE them.
#
# Concrete targets must instead come from build_evidence().
# ================================================================


def build_controlled_ai_output():

    return {

        "response_strategy":
            "CONTAINMENT_REVIEW",

        "confidence":
            0.91,

        "response_summary": [

            (
                "Use evidence-backed targeted response review "
                "and endpoint containment review."
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
                        "Suspicious process execution has an "
                        "observed process target."
                    ),

                # ------------------------------------------------
                # MALICIOUS TEST INPUT
                #
                # This MUST be ignored by the deterministic target
                # resolver.
                # ------------------------------------------------
                "target": {

                    "pid":
                        999999,

                    "name":
                        "invented.exe",
                },
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
                        "Observed file artifact should be "
                        "evaluated for quarantine."
                    ),

                "target": {

                    "path":
                        "C:\\INVENTED\\fake-malware.exe",
                },
            },

            {
                "action":
                    "NETWORK_BLOCK_REVIEW",

                "priority":
                    "HIGH",

                "target_reference":
                    "NETWORK",

                "reason":
                    (
                        "Observed external connection should "
                        "be evaluated for network containment."
                    ),

                "target": {

                    "remote_ip":
                        "1.2.3.4",
                },
            },

            {
                "action":
                    "PERSISTENCE_REMEDIATION_REVIEW",

                "priority":
                    "HIGH",

                "target_reference":
                    "PERSISTENCE",

                "reason":
                    (
                        "Observed persistence artifact should "
                        "be evaluated for remediation."
                    ),

                "target": {

                    "key":
                        "HKCU\\INVENTED\\Fake",
                },
            },

            {
                "action":
                    "ENDPOINT_ISOLATION_REVIEW",

                "priority":
                    "CRITICAL",

                "target_reference":
                    "ENDPOINT",

                "reason":
                    (
                        "Broad endpoint containment should be "
                        "available for Digital Twin evaluation."
                    ),

                "target": {

                    "device_id":
                        "invented-device",
                },
            },
        ],

        "why_this_response":
            (
                "Multiple independently observed endpoint "
                "artifacts justify response review."
            ),

        "why_not_more_aggressive":
            (
                "No response may execute before Digital Twin "
                "simulation and policy review."
            ),

        "why_not_less_aggressive":
            (
                "Monitoring alone would not evaluate the "
                "available targeted response options."
            ),
    }


# ================================================================
# NON-DISRUPTIVE CONTROL OUTPUT
# ================================================================


def build_non_disruptive_output():

    return {

        "response_strategy":
            "INVESTIGATE",

        "confidence":
            0.8,

        "response_summary": [

            "Continue monitoring and investigation."
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
                    "Retain and monitor evidence.",
            },

            {
                "action":
                    "INVESTIGATE_INCIDENT",

                "priority":
                    "MEDIUM",

                "target_reference":
                    "NONE",

                "reason":
                    "Additional analyst investigation is appropriate.",
            },
        ],

        "why_this_response":
            (
                "The current evidence does not justify "
                "a disruptive response."
            ),

        "why_not_more_aggressive":
            (
                "No sufficiently grounded disruptive target "
                "has been justified."
            ),

        "why_not_less_aggressive":
            (
                "Investigation remains appropriate."
            ),
    }


# ================================================================
# MAIN
# ================================================================


def main() -> int:

    heading(
        (
            "SENTINEL-X 7D.5 — "
            "AI RESPONSE STRUCTURAL VALIDATION"
        )
    )


    failures = []


    agent = (
        AIResponseRecommendationAgent()
    )


    integration = (
        DigitalTwinDecisionIntegration()
    )


    threat = (
        build_threat()
    )


    evidence = (
        build_evidence()
    )


    high_risk = (
        build_high_risk()
    )


    # ============================================================
    # 1. BUILD NORMALIZED EVIDENCE CONTEXT
    # ============================================================

    context = (
        agent.build_context(

            threat=
                threat,

            enriched_evidence=
                evidence,
        )
    )


    heading(
        "1 — CONTROLLED AI OUTPUT -> DETERMINISTIC TARGETS"
    )


    validated = (
        agent.validate_output(

            result=
                build_controlled_ai_output(),

            threat=
                threat,

            context=
                context,

            risk_assessment=
                high_risk,

            enriched_evidence=
                evidence,
        )
    )


    print_json(
        validated
    )


    recommendations = (
        validated.get(
            "recommendations",
            []
        )
    )


    if len(
        recommendations
    ) != 5:

        failures.append(
            "Expected exactly 5 disruptive recommendations."
        )


    by_action = {

        item.get(
            "action"
        ):
            item

        for item in recommendations
    }


    # ============================================================
    # 2. VERIFY AI-PROVIDED TARGETS WERE IGNORED
    # ============================================================

    process_target = (
        by_action[
            "PROCESS_TERMINATION_REVIEW"
        ][
            "target"
        ]
    )


    processes = (
        process_target.get(
            "processes",
            []
        )
    )


    if (
        not processes
        or
        processes[
            0
        ].get(
            "pid"
        )
        !=
        4242
    ):

        failures.append(
            (
                "Process target was not resolved from "
                "observed evidence."
            )
        )


    if any(
        item.get(
            "pid"
        )
        ==
        999999

        for item in processes
    ):

        failures.append(
            "Invented AI PID leaked into response target."
        )


    file_target = (
        by_action[
            "QUARANTINE_REVIEW"
        ][
            "target"
        ]
    )


    files = (
        file_target.get(
            "files",
            []
        )
    )


    if (
        not files
        or
        files[
            0
        ].get(
            "path"
        )
        !=
        "C:\\Users\\Public\\payload.bin"
    ):

        failures.append(
            (
                "File target was not resolved from "
                "observed evidence."
            )
        )


    network_target = (
        by_action[
            "NETWORK_BLOCK_REVIEW"
        ][
            "target"
        ]
    )


    connections = (
        network_target.get(
            "connections",
            []
        )
    )


    if (
        not connections
        or
        connections[
            0
        ].get(
            "remote_ip"
        )
        !=
        "203.0.113.90"
    ):

        failures.append(
            (
                "Network target was not resolved from "
                "observed evidence."
            )
        )


    persistence_target = (
        by_action[
            "PERSISTENCE_REMEDIATION_REVIEW"
        ][
            "target"
        ]
    )


    artifacts = (
        persistence_target.get(
            "registry_artifacts",
            []
        )
    )


    expected_registry_key = (
        "HKCU\\Software\\Microsoft\\Windows\\"
        "CurrentVersion\\Run"
    )


    if (
        not artifacts
        or
        artifacts[
            0
        ].get(
            "key"
        )
        !=
        expected_registry_key
    ):

        failures.append(
            (
                "Persistence target was not resolved "
                "from observed evidence."
            )
        )


    endpoint_target = (
        by_action[
            "ENDPOINT_ISOLATION_REVIEW"
        ][
            "target"
        ]
    )


    if (
        endpoint_target.get(
            "device_id"
        )
        !=
        "endpoint-01"
    ):

        failures.append(
            (
                "Endpoint target was not resolved "
                "from canonical threat evidence."
            )
        )


    # ============================================================
    # 3. VERIFY RESPONSE SAFETY FLAGS
    # ============================================================

    for item in recommendations:

        if (
            item.get(
                "execution_allowed"
            )
            is not False
        ):

            failures.append(
                (
                    "Recommendation unexpectedly permits "
                    "execution."
                )
            )


        if (
            item.get(
                "requires_approval"
            )
            is not True
        ):

            failures.append(
                (
                    f"{item.get('action')} does not "
                    "require approval."
                )
            )


        if (
            item.get(
                "digital_twin_candidate"
            )
            is not True
        ):

            failures.append(
                (
                    f"{item.get('action')} was not "
                    "marked as a Digital Twin candidate."
                )
            )


    # ============================================================
    # 4. DIGITAL TWIN CANDIDATE TRANSLATION
    #
    # IMPORTANT:
    # This does NOT simulate the plan.
    #
    # 7D.6 will perform Digital Twin plan simulation/ranking.
    # ============================================================

    heading(
        "2 — DIGITAL TWIN CANDIDATE TRANSLATION"
    )


    twin = (
        EndpointDigitalTwin(

            incident_id=
                threat[
                    "incident_id"
                ],

            initial_risk_score=
                high_risk[
                    "risk_score"
                ],

            initial_risk_level=
                high_risk[
                    "risk_level"
                ],
        )
    )


    twin.load_evidence(
        evidence
    )


    intelligence = {

        "response": {

            "recommendations":
                recommendations,
        }
    }


    candidate_actions = (
        integration.build_candidate_actions(

            intelligence=
                intelligence,

            twin=
                twin,
        )
    )


    print_json(
        candidate_actions
    )


    expected_action_types = {

        "TERMINATE_PROCESS",

        "QUARANTINE_FILE",

        "BLOCK_NETWORK",

        "REMEDIATE_PERSISTENCE",

        "ISOLATE_ENDPOINT",
    }


    actual_action_types = {

        item.get(
            "action_type"
        )

        for item in candidate_actions
    }


    if (
        actual_action_types
        !=
        expected_action_types
    ):

        failures.append(
            (
                "Digital Twin action translation mismatch. "
                f"Expected={sorted(expected_action_types)} "
                f"Actual={sorted(actual_action_types)}"
            )
        )


    if (
        len(
            candidate_actions
        )
        !=
        5
    ):

        failures.append(
            (
                "Digital Twin candidate action count "
                "is not 5."
            )
        )


    # ============================================================
    # 5. LOW-CONCERN RESPONSE MUST REMAIN NON-DISRUPTIVE
    # ============================================================

    heading(
        "3 — NON-DISRUPTIVE LOW-CONCERN RESPONSE"
    )


    low_validated = (
        agent.validate_output(

            result=
                build_non_disruptive_output(),

            threat=
                threat,

            context=
                context,

            risk_assessment=
                build_low_risk(),

            enriched_evidence=
                evidence,
        )
    )


    print_json(
        low_validated
    )


    for item in low_validated[
        "recommendations"
    ]:

        if (
            item.get(
                "target"
            )
            !=
            {}
        ):

            failures.append(
                (
                    "Non-disruptive recommendation "
                    "received a response target."
                )
            )


        if (
            item.get(
                "requires_approval"
            )
            is not False
        ):

            failures.append(
                (
                    "MONITOR/INVESTIGATE unexpectedly "
                    "requires response approval."
                )
            )


        if (
            item.get(
                "digital_twin_candidate"
            )
            is not False
        ):

            failures.append(
                (
                    "MONITOR/INVESTIGATE unexpectedly "
                    "became a Digital Twin action."
                )
            )


    # ============================================================
    # 6. POLICY REJECTION TESTS
    # ============================================================

    heading(
        "4 — RESPONSE POLICY REJECTION"
    )


    passed = (
        expect_error(

            (
                "LOW_CONCERN disruptive action "
                "rejection"
            ),

            lambda:
                agent.validate_action_for_assessment(

                    action=
                        "PROCESS_TERMINATION_REVIEW",

                    risk_assessment=
                        build_low_risk(),
                ),
        )
    )


    if not passed:

        failures.append(
            (
                "LOW_CONCERN allowed disruptive "
                "process response."
            )
        )


    passed = (
        expect_error(

            (
                "SUSPICIOUS endpoint-isolation "
                "rejection"
            ),

            lambda:
                agent.validate_action_for_assessment(

                    action=
                        "ENDPOINT_ISOLATION_REVIEW",

                    risk_assessment=
                        build_suspicious_risk(),
                ),
        )
    )


    if not passed:

        failures.append(
            (
                "SUSPICIOUS assessment allowed "
                "endpoint isolation."
            )
        )


    # ============================================================
    # 7. MISSING TARGET REJECTION
    # ============================================================

    def validate_missing_file_target():

        empty_context = (
            agent.build_context(

                threat=
                    threat,

                enriched_evidence=
                    {},
            )
        )


        result = {

            "response_strategy":
                "TARGETED_RESPONSE",

            "confidence":
                0.85,

            "response_summary": [

                "File response review requested."
            ],

            "recommendations": [

                {
                    "action":
                        "QUARANTINE_REVIEW",

                    "priority":
                        "HIGH",

                    "target_reference":
                        "FILE",

                    "reason":
                        (
                            "Attempt to recommend quarantine "
                            "without an observed file target."
                        ),

                    "target": {

                        "path":
                            "C:\\INVENTED\\fake.exe",
                    },
                }
            ],

            "why_this_response":
                "Targeted review.",

            "why_not_more_aggressive":
                "Broader action unnecessary.",

            "why_not_less_aggressive":
                "File review requested.",
        }


        agent.validate_output(

            result=
                result,

            threat=
                threat,

            context=
                empty_context,

            risk_assessment=
                high_risk,

            enriched_evidence=
                {},
        )


    passed = (
        expect_error(

            "Missing FILE target rejection",

            validate_missing_file_target,
        )
    )


    if not passed:

        failures.append(
            (
                "AI invented file target was accepted "
                "without observed evidence."
            )
        )


    # ============================================================
    # FINAL
    # ============================================================

    heading(
        "7D.5 STRUCTURAL VALIDATION RESULT"
    )


    if failures:

        print(
            f"TOTAL FAILURES: {len(failures)}"
        )


        for failure in failures:

            print(
                "FAIL:",
                failure,
            )


        print()

        print(
            "RESULT: FAIL"
        )

        return 1


    print(
        "Allowed action validation            : PASS"
    )

    print(
        "Deterministic process target          : PASS"
    )

    print(
        "Deterministic file target             : PASS"
    )

    print(
        "Deterministic network target          : PASS"
    )

    print(
        "Deterministic persistence target      : PASS"
    )

    print(
        "Deterministic endpoint target         : PASS"
    )

    print(
        "AI target hallucination isolation     : PASS"
    )

    print(
        "Digital Twin action translation       : PASS"
    )

    print(
        "Low-concern non-disruptive policy     : PASS"
    )

    print(
        "Suspicious isolation safety gate      : PASS"
    )

    print(
        "Missing-target rejection              : PASS"
    )

    print(
        "Execution boundary                    : PASS"
    )

    print()

    print(
        "RESULT: PASS"
    )

    print(
        (
            "SENTINEL-X 7D.5 structural response "
            "pipeline is ready for AI reasoning validation."
        )
    )


    return 0


if __name__ == "__main__":

    sys.exit(
        main()
    )