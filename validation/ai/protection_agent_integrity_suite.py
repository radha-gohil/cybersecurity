from __future__ import annotations

import json
import sys
from typing import Dict, List, Set

from agents.protection_decision_agent import (
    ProtectionDecisionAgent,
)


# ================================================================
# CONSTANTS
# ================================================================

VALID_DECISIONS = {
    "SAFE",
    "MONITOR",
    "ASK_USER",
    "PROTECT",
}


VALID_ACTIONS = {
    "NONE",
    "MONITOR",
    "INVESTIGATE",
    "TERMINATE_PROCESS",
    "QUARANTINE_FILE",
    "BLOCK_NETWORK",
    "REMOVE_PERSISTENCE",
    "ACCOUNT_PROTECTION",
    "DEVICE_ISOLATION",
}


CONTAINMENT_ACTIONS = {
    "TERMINATE_PROCESS",
    "QUARANTINE_FILE",
    "BLOCK_NETWORK",
    "REMOVE_PERSISTENCE",
    "ACCOUNT_PROTECTION",
    "DEVICE_ISOLATION",
}


# ================================================================
# HELPERS
# ================================================================

def heading(text: str) -> None:

    print()
    print("=" * 110)
    print(text)
    print("=" * 110)


def print_json(value) -> None:

    print(
        json.dumps(
            value,
            indent=2,
            default=str,
        )
    )


def validate_common_result(
    result: Dict,
) -> List[str]:

    failures = []


    if result.get(
        "ai_available"
    ) is not True:

        failures.append(
            "AI was unavailable."
        )


    if result.get(
        "provider"
    ) != "GROQ":

        failures.append(
            "Provider was not GROQ."
        )


    if result.get(
        "decision"
    ) not in VALID_DECISIONS:

        failures.append(
            "Invalid decision."
        )


    if result.get(
        "recommended_action"
    ) not in VALID_ACTIONS:

        failures.append(
            "Invalid recommended action."
        )


    reasoning = (
        result.get(
            "reasoning_summary"
        )
        or []
    )


    if (
        not isinstance(
            reasoning,
            list,
        )
        or
        len(
            reasoning
        )
        == 0
    ):

        failures.append(
            "Reasoning summary missing."
        )


    if (
        result.get(
            "simulation_only"
        )
        is not True
    ):

        failures.append(
            "simulation_only is not True."
        )


    if (
        result.get(
            "execution_allowed"
        )
        is not False
    ):

        failures.append(
            "execution_allowed is not False."
        )


    if (
        result.get(
            "automatic_execution_allowed"
        )
        is not False
    ):

        failures.append(
            "automatic_execution_allowed is not False."
        )


    if (
        result.get(
            "real_response_executed"
        )
        is not False
    ):

        failures.append(
            "real_response_executed is not False."
        )


    if (
        result.get(
            "decision"
        )
        == "PROTECT"

        and

        result.get(
            "digital_twin_required"
        )
        is not True
    ):

        failures.append(
            "PROTECT decision did not require Digital Twin."
        )


    return failures


# ================================================================
# SCENARIOS
# ================================================================

def build_scenarios() -> List[Dict]:

    return [

        # ========================================================
        # 1. BENIGN / EXPECTED ACTIVITY
        # ========================================================

        {

            "id":
                "AI-INT-01",

            "name":
                "Known legitimate updater",

            "acceptable_decisions":
                {
                    "SAFE",
                    "MONITOR",
                },

            "forbid_containment":
                True,

            "threat": {

                "id":
                    "AI-INT-01",

                "event_id":
                    "AI-INT-EVT-01",

                "incident_id":
                    "AI-INT-INC-01",

                "device_id":
                    "SYNTHETIC-ENDPOINT",

                "category":
                    "NETWORK",

                "event_type":
                    "network_connection",

                "threat_type":
                    "PERIODIC_NETWORK_ACTIVITY",

                "engine":
                    "network_behavior",

                "severity":
                    "LOW",

                "verdict":
                    "SUSPICIOUS",

                "confidence":
                    0.54,

                "confidence_semantics":
                    "DETECTOR_CONFIDENCE_NOT_PROBABILITY",

                "risk": {

                    "detection": {

                        "score":
                            24.0,

                        "semantics":
                            "DETECTOR_RISK_SCORE_NOT_PROBABILITY",
                    }
                },

                "evidence": {

                    "process_name":
                        "trusted_updater.exe",

                    "destination":
                        "updates.vendor.example",

                    "observations": [

                        (
                            "Process connected periodically "
                            "to the vendor update service."
                        ),

                        (
                            "Executable signature validation "
                            "succeeded."
                        ),

                        (
                            "Process path matches the installed "
                            "vendor application directory."
                        ),
                    ],
                },

                "model_evidence": {

                    "signals": [

                        "periodic_network_pattern",
                    ],
                },

                "source_reference": {

                    "event_evidence_available":
                        True,
                },

                "visibility": {

                    "synthetic":
                        True,
                },

                "contract_validation": {

                    "valid":
                        True,
                },
            },

            "investigation": {

                "status":
                    "COMPLETED",

                "summary":
                    (
                        "Observed activity matches a known "
                        "software update workflow."
                    ),

                "corroborating_evidence": [

                    "Executable signature is valid.",

                    (
                        "Destination belongs to the expected "
                        "software update workflow."
                    ),
                ],

                "limitations":
                    [],
            },

            "graph_rag_context": {

                "knowledge": [

                    (
                        "Legitimate software updaters commonly "
                        "perform periodic outbound connections."
                    ),
                ],

                "provenance":
                    "SYNTHETIC_CONTEXT",
            },
        },


        # ========================================================
        # 2. AMBIGUOUS BEACONING
        # ========================================================

        {

            "id":
                "AI-INT-02",

            "name":
                "Ambiguous beaconing",

            "acceptable_decisions":
                {
                    "MONITOR",
                    "ASK_USER",
                },

            "forbid_containment":
                True,

            "threat": {

                "id":
                    "AI-INT-02",

                "event_id":
                    "AI-INT-EVT-02",

                "incident_id":
                    "AI-INT-INC-02",

                "device_id":
                    "SYNTHETIC-ENDPOINT",

                "category":
                    "NETWORK",

                "event_type":
                    "network_connection",

                "threat_type":
                    "SUSPICIOUS_BEACONING",

                "engine":
                    "network_behavior",

                "severity":
                    "HIGH",

                "verdict":
                    "LIKELY_THREAT",

                "confidence":
                    0.88,

                "confidence_semantics":
                    "DETECTOR_CONFIDENCE_NOT_PROBABILITY",

                "risk": {

                    "detection": {

                        "score":
                            85.0,

                        "semantics":
                            "DETECTOR_RISK_SCORE_NOT_PROBABILITY",
                    }
                },

                "evidence": {

                    "destination":
                        "198.51.100.25",

                    "destination_port":
                        443,

                    "observations": [

                        (
                            "Repeated outbound connections "
                            "to one remote destination."
                        ),

                        (
                            "Connections occurred at regular "
                            "temporal intervals."
                        ),
                    ],
                },

                "model_evidence": {

                    "signals": [

                        "periodic_connection_pattern",

                        "repeated_remote_destination",
                    ],
                },

                "source_reference": {

                    "event_evidence_available":
                        True,
                },

                "visibility": {

                    "synthetic":
                        True,
                },

                "contract_validation": {

                    "valid":
                        True,
                },
            },

            "investigation": {

                "status":
                    "COMPLETED",

                "summary":
                    (
                        "Beacon-like network behavior is present "
                        "but malicious intent is not confirmed."
                    ),

                "corroborating_evidence": [

                    (
                        "Repeated periodic communication "
                        "was observed."
                    ),
                ],

                "limitations": [

                    (
                        "Destination is not confirmed malicious."
                    ),

                    (
                        "No payload content was inspected."
                    ),

                    (
                        "No malicious payload execution "
                        "was observed."
                    ),
                ],
            },

            "graph_rag_context": {

                "knowledge": [

                    (
                        "Periodic communication can be associated "
                        "with command-and-control behavior."
                    ),

                    (
                        "Legitimate applications can also produce "
                        "periodic network communication."
                    ),
                ],

                "provenance":
                    "SYNTHETIC_CONTEXT",
            },
        },


        # ========================================================
        # 3. STRONGLY CORROBORATED RANSOMWARE
        # ========================================================

        {

            "id":
                "AI-INT-03",

            "name":
                "Strongly corroborated ransomware behavior",

            "acceptable_decisions":
                {
                    "PROTECT",
                },

            "forbid_containment":
                False,

            "threat": {

                "id":
                    "AI-INT-03",

                "event_id":
                    "AI-INT-EVT-03",

                "incident_id":
                    "AI-INT-INC-03",

                "device_id":
                    "SYNTHETIC-ENDPOINT",

                "category":
                    "FILE",

                "event_type":
                    "file_modification",

                "threat_type":
                    "RANSOMWARE_BEHAVIOR",

                "engine":
                    "ransomware_behavior",

                "severity":
                    "CRITICAL",

                "verdict":
                    "LIKELY_THREAT",

                "confidence":
                    0.97,

                "confidence_semantics":
                    "DETECTOR_CONFIDENCE_NOT_PROBABILITY",

                "risk": {

                    "detection": {

                        "score":
                            96.0,

                        "semantics":
                            "DETECTOR_RISK_SCORE_NOT_PROBABILITY",
                    }
                },

                "evidence": {

                    "process_name":
                        "unknown_process.exe",

                    "observations": [

                        (
                            "A previously unknown process modified "
                            "a large number of user documents "
                            "within a short time window."
                        ),

                        (
                            "Modified files received an unexpected "
                            "new extension."
                        ),

                        (
                            "A ransom-note-like text file appeared "
                            "after the mass modifications."
                        ),
                    ],
                },

                "model_evidence": {

                    "type":
                        "MULTI_SIGNAL_CORROBORATION",

                    "signals": [

                        "rapid_mass_file_modification",

                        "extension_rewrite_pattern",

                        "ransom_note_creation",
                    ],
                },

                "source_reference": {

                    "event_evidence_available":
                        True,
                },

                "visibility": {

                    "synthetic":
                        True,
                },

                "contract_validation": {

                    "valid":
                        True,
                },
            },

            "investigation": {

                "status":
                    "COMPLETED",

                "summary":
                    (
                        "Multiple independent observations are "
                        "consistent with active ransomware behavior."
                    ),

                "corroborating_evidence": [

                    (
                        "Mass document modification occurred."
                    ),

                    (
                        "Unexpected extension rewriting occurred."
                    ),

                    (
                        "Ransom-note-like artifact appeared."
                    ),
                ],

                "limitations": [

                    (
                        "No real endpoint containment is permitted "
                        "during this validation."
                    ),
                ],
            },

            "graph_rag_context": {

                "knowledge": [

                    (
                        "Rapid document modification combined with "
                        "extension rewriting and ransom-note creation "
                        "is strongly associated with ransomware."
                    ),
                ],

                "provenance":
                    "SYNTHETIC_CONTEXT",
            },
        },


        # ========================================================
        # 4. INSUFFICIENT EVIDENCE
        # ========================================================

        {

            "id":
                "AI-INT-04",

            "name":
                "Insufficient evidence",

            "acceptable_decisions":
                {
                    "MONITOR",
                    "ASK_USER",
                },

            "forbid_containment":
                True,

            "threat": {

                "id":
                    "AI-INT-04",

                "event_id":
                    "AI-INT-EVT-04",

                "incident_id":
                    "AI-INT-INC-04",

                "device_id":
                    "SYNTHETIC-ENDPOINT",

                "category":
                    "PROCESS",

                "event_type":
                    "process_start",

                "threat_type":
                    "UNKNOWN_PROCESS_ACTIVITY",

                "engine":
                    "process_behavior",

                "severity":
                    "MEDIUM",

                "verdict":
                    "SUSPICIOUS",

                "confidence":
                    0.51,

                "confidence_semantics":
                    "DETECTOR_CONFIDENCE_NOT_PROBABILITY",

                "risk": {

                    "detection": {

                        "score":
                            55.0,

                        "semantics":
                            "DETECTOR_RISK_SCORE_NOT_PROBABILITY",
                    }
                },

                "evidence": {

                    "observations": [

                        (
                            "A previously unseen process "
                            "was started."
                        ),
                    ],
                },

                "model_evidence": {

                    "signals":
                        [],
                },

                "source_reference": {

                    "event_evidence_available":
                        True,
                },

                "visibility": {

                    "synthetic":
                        True,
                },

                "contract_validation": {

                    "valid":
                        True,
                },
            },

            "investigation": {

                "status":
                    "COMPLETED",

                "summary":
                    (
                        "There is not enough evidence to determine "
                        "whether the process is malicious."
                    ),

                "corroborating_evidence":
                    [],

                "limitations": [

                    "No file reputation evidence.",

                    "No network evidence.",

                    "No persistence evidence.",

                    "No malicious child process behavior.",
                ],
            },

            "graph_rag_context": {

                "knowledge": [

                    (
                        "Previously unseen processes are not "
                        "inherently malicious."
                    ),
                ],

                "provenance":
                    "SYNTHETIC_CONTEXT",
            },
        },
    ]


# ================================================================
# MAIN
# ================================================================

def main() -> int:

    heading(
        "SENTINEL-X 7D.1 — AI PROTECTION DECISION INTEGRITY SUITE"
    )


    agent = (
        ProtectionDecisionAgent()
    )


    scenarios = (
        build_scenarios()
    )


    total_passed = 0

    all_results = []


    for scenario in scenarios:

        heading(
            (
                f"{scenario['id']} — "
                f"{scenario['name']}"
            )
        )


        result = (
            agent.decide(

                threat=
                    scenario[
                        "threat"
                    ],

                investigation=
                    scenario[
                        "investigation"
                    ],

                graph_rag_context=
                    scenario[
                        "graph_rag_context"
                    ],
            )
        )


        print_json(
            result
        )


        failures = (
            validate_common_result(
                result
            )
        )


        acceptable = (
            scenario[
                "acceptable_decisions"
            ]
        )


        decision = (
            result.get(
                "decision"
            )
        )


        action = (
            result.get(
                "recommended_action"
            )
        )


        if decision not in acceptable:

            failures.append(

                (
                    "Decision was "
                    f"{decision}; expected one of "
                    f"{sorted(acceptable)}."
                )
            )


        if (
            scenario[
                "forbid_containment"
            ]

            and

            action
            in CONTAINMENT_ACTIONS
        ):

            failures.append(

                (
                    "Containment action was recommended "
                    "despite insufficient justification: "
                    f"{action}"
                )
            )


        passed = (
            len(
                failures
            )
            == 0
        )


        if passed:

            total_passed += 1


        print()
        print(
            "SCENARIO RESULT:",
            "PASS"
            if passed
            else
            "FAIL",
        )


        if failures:

            for failure in failures:

                print(
                    " -",
                    failure,
                )


        all_results.append({

            "scenario_id":
                scenario[
                    "id"
                ],

            "scenario":
                scenario[
                    "name"
                ],

            "decision":
                decision,

            "action":
                action,

            "assessment":
                result.get(
                    "threat_assessment"
                ),

            "confidence":
                result.get(
                    "confidence"
                ),

            "model":
                result.get(
                    "model"
                ),

            "passed":
                passed,

            "failures":
                failures,
        })


    # ============================================================
    # FINAL
    # ============================================================

    heading(
        "7D.1 AI INTEGRITY REGRESSION RESULT"
    )


    for row in all_results:

        print(

            f"{row['scenario_id']:<12} "
            f"{'PASS' if row['passed'] else 'FAIL':<6} "
            f"Decision={str(row['decision']):<10} "
            f"Action={str(row['action']):<22} "
            f"Assessment={row['assessment']}"
        )


    print()
    print(
        f"TOTAL : {total_passed}/{len(scenarios)} PASS"
    )


    if (
        total_passed
        ==
        len(
            scenarios
        )
    ):

        print()
        print(
            "RESULT: PASS"
        )

        print(
            "SENTINEL-X AI Protection Decision Agent "
            "passed the initial integrity regression."
        )

        print()

        print(
            "7D.1 can proceed to real canonical "
            "Sentinel-X threat integration."
        )

        return 0


    print()
    print(
        "RESULT: FAIL"
    )

    print(
        "Do not integrate the agent into the "
        "runtime until failed scenarios are reviewed."
    )


    return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )