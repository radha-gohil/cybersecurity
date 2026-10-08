from __future__ import annotations

import json
import sys
import time


from agents.ai_response_recommendation_agent import (
    AIResponseRecommendationAgent,
)


# ================================================================
# HELPERS
# ================================================================


def heading(text):

    print()
    print("=" * 110)
    print(text)
    print("=" * 110)


def show(value):

    print(
        json.dumps(
            value,
            indent=2,
            default=str,
        )
    )


# ================================================================
# COMMON THREAT FACTORY
# ================================================================


def make_threat(
    *,
    security_id,
    event_id,
    category,
    threat_type,
    severity,
    verdict,
    confidence,
    observed,
):

    return {

        "id":
            security_id,

        "detection_id":
            None,

        "event_id":
            event_id,

        "incident_id":
            f"{event_id}-INC",

        "device_id":
            "endpoint-01",

        "category":
            category,

        "event_type":
            observed.get(
                "event_type",
                category.lower(),
            ),

        "threat_type":
            threat_type,

        "engine":
            "response_reasoning_validation",

        "severity":
            severity,

        "verdict":
            verdict,

        "confidence":
            confidence,

        "confidence_semantics":
            "DETECTOR_CONFIDENCE_NOT_PROBABILITY",

        "evidence": {

            "observed": [
                observed
            ]
        },

        "visibility": {

            "synthetic":
                True,
        },
    }


# ================================================================
# SCENARIO 1
# LEGITIMATE ACTIVITY
# ================================================================


def scenario_1():

    threat = make_threat(

        security_id=
            "RESP-AI-01",

        event_id=
            "RESP-AI-EVT-01",

        category=
            "PROCESS",

        threat_type=
            "PERIODIC_NETWORK_ACTIVITY",

        severity=
            "LOW",

        verdict=
            "LOW_CONCERN",

        confidence=
            0.82,

        observed={

            "event_type":
                "process_network_activity",

            "process_name":
                "trusted_updater.exe",

            "path":
                (
                    "C:\\Program Files\\Vendor\\"
                    "trusted_updater.exe"
                ),

            "signature_valid":
                True,

            "publisher":
                "Trusted Software Vendor",

            "destination":
                "updates.vendor.example",
        },
    )


    risk = {

        "agent":
            "AIRiskReasoningAgent",

        "agent_version":
            "7D.4-v3",

        "risk_score":
            20.0,

        "risk_level":
            "LOW",

        "confidence":
            0.85,

        "threat_assessment":
            "LOW_CONCERN",

        "evidence_strength":
            "STRONG",

        "risk_summary": [

            (
                "Observed activity matches a legitimate "
                "software-update workflow."
            )
        ],

        "primary_risk_drivers": [

            "Detector originally flagged periodic activity"
        ],

        "corroborating_evidence": [

            "Valid trusted signature",

            "Expected installation path",

            "Expected vendor update destination",
        ],

        "mitigating_evidence": [

            "Trusted publisher",

            "Expected software-update workflow",
        ],

        "uncertainties":
            [],

        "potential_impact":
            [],

        "why_this_level":
            "Strong legitimate evidence supports low concern.",

        "why_not_higher":
            "Observed behavior is consistent with trusted activity.",

        "why_not_lower":
            "Some monitoring remains appropriate.",

        "risk_score_semantics":
            "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",
    }


    investigation = {

        "available":
            True,

        "status":
            "COMPLETED",

        "summary":
            (
                "Process behavior matches the expected "
                "software update workflow."
            ),
    }


    return {

        "name":
            "Legitimate updater",

        "threat":
            threat,

        "risk":
            risk,

        "investigation":
            investigation,

        "allowed_actions": {
            "MONITOR_INCIDENT",
            "INVESTIGATE_INCIDENT",
        },

        "must_have_disruptive":
            False,
    }


# ================================================================
# SCENARIO 2
# AMBIGUOUS NETWORK ACTIVITY
# ================================================================


def scenario_2():

    threat = make_threat(

        security_id=
            "RESP-AI-02",

        event_id=
            "RESP-AI-EVT-02",

        category=
            "NETWORK",

        threat_type=
            "SUSPICIOUS_BEACONING",

        severity=
            "MEDIUM",

        verdict=
            "SUSPICIOUS",

        confidence=
            0.61,

        observed={

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
        },
    )


    risk = {

        "agent":
            "AIRiskReasoningAgent",

        "agent_version":
            "7D.4-v3",

        "risk_score":
            58.0,

        "risk_level":
            "MEDIUM",

        "confidence":
            0.61,

        "threat_assessment":
            "SUSPICIOUS",

        "evidence_strength":
            "MODERATE",

        "risk_summary": [

            (
                "Periodic outbound communication was observed "
                "but malicious intent is not established."
            )
        ],

        "primary_risk_drivers": [

            "Regular periodic outbound connections",

            "Detector classification of suspicious beaconing",
        ],

        "corroborating_evidence": [

            "Periodic network pattern model signal"
        ],

        "mitigating_evidence":
            [],

        "uncertainties": [

            "Remote IP reputation unavailable",

            "Payload not inspected",

            "Process legitimacy unknown",
        ],

        "potential_impact": [

            (
                "If malicious, periodic communication could "
                "support remote control."
            )
        ],

        "why_this_level":
            "Observed pattern warrants investigation.",

        "why_not_higher":
            (
                "Malicious communication is not confirmed."
            ),

        "why_not_lower":
            (
                "Periodic external traffic remains suspicious."
            ),

        "risk_score_semantics":
            "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",
    }


    enrichment = {

        "processes":
            [],

        "files":
            [],

        "network_connections": [

            {
                "remote_ip":
                    "198.51.100.50",

                "remote_port":
                    443,

                "process_name":
                    "background_service.exe",

                "device_id":
                    "endpoint-01",
            }
        ],

        "registry_artifacts":
            [],

        "relationships":
            [],

        "identity_links":
            [],
    }


    investigation = {

        "available":
            True,

        "status":
            "INCOMPLETE",

        "summary":
            (
                "No payload, reputation, or confirmed "
                "malicious process evidence is available."
            ),
    }


    return {

        "name":
            "Ambiguous network behavior",

        "threat":
            threat,

        "risk":
            risk,

        "investigation":
            investigation,

        "enrichment":
            enrichment,

        # Targeted network block is intentionally NOT accepted
        # here because evidence remains ambiguous.
        "allowed_actions": {
            "MONITOR_INCIDENT",
            "INVESTIGATE_INCIDENT",
        },

        "must_have_disruptive":
            False,
    }


# ================================================================
# SCENARIO 3
# STRONG MULTI-SOURCE MALICIOUS ACTIVITY
# ================================================================


def scenario_3():

    threat = make_threat(

        security_id=
            "RESP-AI-03",

        event_id=
            "RESP-AI-EVT-03",

        category=
            "PROCESS",

        threat_type=
            "MULTI_STAGE_MALICIOUS_BEHAVIOR",

        severity=
            "CRITICAL",

        verdict=
            "LIKELY_THREAT",

        confidence=
            0.95,

        observed={

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
        },
    )


    risk = {

        "agent":
            "AIRiskReasoningAgent",

        "agent_version":
            "7D.4-v3",

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
                "Multiple telemetry categories corroborate "
                "suspicious multi-stage behavior."
            )
        ],

        "primary_risk_drivers": [

            "Hidden encoded PowerShell execution",

            "Observed file artifact",

            "Observed outbound network connection",

            "Observed persistence modification",
        ],

        "corroborating_evidence": [

            "Temporal anomaly",

            "Graph anomaly",

            "Multi-model fusion evidence",
        ],

        "mitigating_evidence":
            [],

        "uncertainties": [

            "Remote destination reputation unavailable"
        ],

        "potential_impact": [

            "Potential endpoint compromise"
        ],

        "why_this_level":
            (
                "Multiple independent sources corroborate "
                "high-risk behavior."
            ),

        "why_not_higher":
            "CRITICAL is already the highest risk level.",

        "why_not_lower":
            (
                "Observed execution, persistence, network and "
                "file activity strongly corroborate concern."
            ),

        "risk_score_semantics":
            "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",
    }


    enrichment = {

        "processes": [

            {
                "pid":
                    5501,

                "name":
                    "powershell.exe",

                "exe":
                    (
                        "C:\\Windows\\System32\\"
                        "WindowsPowerShell\\v1.0\\"
                        "powershell.exe"
                    ),

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
                "pid":
                    5501,

                "remote_ip":
                    "203.0.113.90",

                "remote_port":
                    443,

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


    investigation = {

        "available":
            True,

        "status":
            "COMPLETED",

        "summary":
            (
                "Hidden execution, file activity, outbound "
                "network activity and persistence are "
                "corroborated."
            ),
    }


    return {

        "name":
            "Strong multi-source malicious behavior",

        "threat":
            threat,

        "risk":
            risk,

        "investigation":
            investigation,

        "enrichment":
            enrichment,

        "allowed_actions": {
            "INVESTIGATE_INCIDENT",
            "PROCESS_TERMINATION_REVIEW",
            "QUARANTINE_REVIEW",
            "NETWORK_BLOCK_REVIEW",
            "PERSISTENCE_REMEDIATION_REVIEW",
            "ENDPOINT_ISOLATION_REVIEW",
        },

        "must_have_disruptive":
            True,
    }


# ================================================================
# SCENARIO 4
# SUSPICIOUS EXECUTABLE WITH LIMITED CORROBORATION
# ================================================================


def scenario_4():

    threat = make_threat(

        security_id=
            "RESP-AI-04",

        event_id=
            "RESP-AI-EVT-04",

        category=
            "FILE",

        threat_type=
            "SUSPICIOUS_EXECUTABLE_CREATION",

        severity=
            "HIGH",

        verdict=
            "SUSPICIOUS",

        confidence=
            0.89,

        observed={

            "event_type":
                "file_create",

            "path":
                "C:\\Users\\Public\\unknown.exe",

            "extension":
                ".exe",
        },
    )


    risk = {

        "agent":
            "AIRiskReasoningAgent",

        "agent_version":
            "7D.4-v3",

        "risk_score":
            68.0,

        "risk_level":
            "MEDIUM",

        "confidence":
            0.85,

        "threat_assessment":
            "SUSPICIOUS",

        "evidence_strength":
            "MODERATE",

        "risk_summary": [

            (
                "Unknown executable was created in a "
                "user-writable directory."
            )
        ],

        "primary_risk_drivers": [

            "Unknown executable creation",

            "User-writable location",

            "High-severity detector alert",
        ],

        "corroborating_evidence": [

            "File creation model signal"
        ],

        "mitigating_evidence":
            [],

        "uncertainties": [

            "Execution not observed",

            "Signature unknown",

            "Reputation unknown",
        ],

        "potential_impact": [

            (
                "If malicious and executed, the file could "
                "affect endpoint security."
            )
        ],

        "why_this_level":
            "Suspicious file creation warrants review.",

        "why_not_higher":
            "Execution or malicious classification is absent.",

        "why_not_lower":
            (
                "Executable creation in a writable location "
                "remains security-relevant."
            ),

        "risk_score_semantics":
            "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",
    }


    enrichment = {

        "processes":
            [],

        "files": [

            {
                "path":
                    "C:\\Users\\Public\\unknown.exe",

                "sha256":
                    None,

                "device_id":
                    "endpoint-01",
            }
        ],

        "network_connections":
            [],

        "registry_artifacts":
            [],

        "relationships":
            [],

        "identity_links":
            [],
    }


    investigation = {

        "available":
            True,

        "status":
            "INCOMPLETE",

        "summary":
            (
                "File creation is observed but execution "
                "and malicious classification are not."
            ),
    }


    return {

        "name":
            "Suspicious executable with limited corroboration",

        "threat":
            threat,

        "risk":
            risk,

        "investigation":
            investigation,

        "enrichment":
            enrichment,

        "allowed_actions": {
            "MONITOR_INCIDENT",
            "INVESTIGATE_INCIDENT",
            "QUARANTINE_REVIEW",
        },

        "must_have_disruptive":
            False,

        "forbidden_actions": {
            "ENDPOINT_ISOLATION_REVIEW",
            "PROCESS_TERMINATION_REVIEW",
            "NETWORK_BLOCK_REVIEW",
            "PERSISTENCE_REMEDIATION_REVIEW",
        },
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
        "7D.5-v2"
    ):

        failures.append(
            "Unexpected agent version."
        )


    recommendations = (
        result.get(
            "recommendations"
        )
        or []
    )


    if not recommendations:

        failures.append(
            "No recommendations returned."
        )


    actions = {

        item.get(
            "action"
        )

        for item in recommendations
    }


    unexpected = (
        actions
        -
        scenario[
            "allowed_actions"
        ]
    )


    if unexpected:

        failures.append(
            (
                "Unexpected actions: "
                f"{sorted(unexpected)}"
            )
        )


    forbidden = (
        scenario.get(
            "forbidden_actions",
            set(),
        )
    )


    used_forbidden = (
        actions
        &
        forbidden
    )


    if used_forbidden:

        failures.append(
            (
                "Forbidden actions used: "
                f"{sorted(used_forbidden)}"
            )
        )


    disruptive = {

        item.get(
            "action"
        )

        for item in recommendations

        if item.get(
            "digital_twin_candidate"
        )
        is True
    }


    if (
        scenario[
            "must_have_disruptive"
        ]
        and
        not disruptive
    ):

        failures.append(
            (
                "Strong malicious scenario produced "
                "no disruptive Digital Twin candidate."
            )
        )


    if (
        not scenario[
            "must_have_disruptive"
        ]
        and
        scenario[
            "risk"
        ].get(
            "threat_assessment"
        )
        ==
        "LOW_CONCERN"
        and
        disruptive
    ):

        failures.append(
            (
                "LOW_CONCERN scenario produced "
                "a disruptive response."
            )
        )


    for item in recommendations:

        if (
            item.get(
                "execution_allowed"
            )
            is not False
        ):

            failures.append(
                (
                    f"{item.get('action')} "
                    "allows execution."
                )
            )


    if (
        result.get(
            "execution_allowed"
        )
        is not False
    ):

        failures.append(
            "Top-level execution_allowed != False."
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
            (
                "real_response_executed != False."
            )
        )


    expected_digital_twin = bool(
        disruptive
    )


    if (
        result.get(
            "digital_twin_required"
        )
        is not
        expected_digital_twin
    ):

        failures.append(
            (
                "digital_twin_required does not "
                "match returned actions."
            )
        )


    return failures


# ================================================================
# MAIN
# ================================================================


def main():

    heading(
        (
            "SENTINEL-X 7D.5 — "
            "AI RESPONSE REASONING SUITE"
        )
    )


    agent = (
        AIResponseRecommendationAgent()
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
                f"RESP-AI-{index:02d} — "
                f"{scenario['name']}"
            )
        )


        result = (
            agent.recommend(

                threat=
                    scenario[
                        "threat"
                    ],

                risk_assessment=
                    scenario[
                        "risk"
                    ],

                investigation=
                    scenario.get(
                        "investigation"
                    ),

                enriched_evidence=
                    scenario.get(
                        "enrichment"
                    ),
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


    heading(
        "7D.5 AI RESPONSE REASONING RESULT"
    )


    print(
        f"TOTAL : {passed}/4 PASS"
    )


    if passed == 4:

        print()
        print(
            "RESULT: PASS"
        )

        print(
            (
                "SENTINEL-X 7D.5 AI Response "
                "Recommendation is ready to close."
            )
        )

        return 0


    print()
    print(
        "RESULT: FAIL"
    )

    print(
        (
            "Do not connect AI response decisions "
            "to Digital Twin plan simulation yet."
        )
    )

    return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )