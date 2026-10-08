from __future__ import annotations

import json
import sys


from ai_config import (
    AI_CONFIG,
)


from ai_provider_manager import (
    shared_ai_provider_manager,
)


from agents.protection_decision_agent import (
    ProtectionDecisionAgent,
)


# ================================================================
# HELPERS
# ================================================================

def heading(
    text: str,
) -> None:

    print()

    print(
        "=" * 100
    )

    print(
        text
    )

    print(
        "=" * 100
    )


def print_json(
    value,
) -> None:

    print(
        json.dumps(
            value,
            indent=2,
            default=str,
        )
    )


# ================================================================
# MAIN
# ================================================================

def main() -> int:

    heading(
        "SENTINEL-X 7D — GROQ AI PHASE READINESS CHECK"
    )


    failures = []


    # ============================================================
    # 1. CONFIGURATION
    # ============================================================

    print()
    print(
        "[1] CENTRAL AI CONFIGURATION"
    )


    config_status = (
        AI_CONFIG.status()
    )


    print_json(
        config_status
    )


    if (
        AI_CONFIG.primary_provider
        !=
        "GROQ"
    ):

        failures.append(
            "Primary provider is not GROQ."
        )


    if not AI_CONFIG.groq_api_key:

        failures.append(
            "GROQ_API_KEY is missing."
        )


    if not AI_CONFIG.simulation_only:

        failures.append(
            "AI runtime is not simulation-only."
        )


    # ============================================================
    # 2. PROVIDER MANAGER
    # ============================================================

    print()
    print(
        "[2] AI PROVIDER MANAGER"
    )


    provider_status = (
        shared_ai_provider_manager
        .status()
    )


    print_json(
        provider_status
    )


    # ============================================================
    # 3. GROQ MODEL DISCOVERY
    # ============================================================

    print()
    print(
        "[3] GROQ MODEL DISCOVERY"
    )


    model_result = (
        shared_ai_provider_manager
        .list_groq_models()
    )


    if not model_result.get(
        "success"
    ):

        print_json(
            model_result
        )

        failures.append(
            "Groq model discovery failed."
        )


    else:

        available_models = set(
            model_result.get(
                "models",
                []
            )
        )


        print(
            "Groq model endpoint: PASS"
        )

        print(
            "Available model count:",
            len(
                available_models
            ),
        )


        print()
        print(
            "Configured Sentinel-X models:"
        )


        for model in (
            AI_CONFIG.groq_models
        ):

            available = (
                model
                in
                available_models
            )


            print(
                f"  {model:<32} "
                f"{'AVAILABLE' if available else 'NOT FOUND'}"
            )


            if not available:

                failures.append(
                    (
                        "Configured Groq model "
                        f"is unavailable: {model}"
                    )
                )


    # ============================================================
    # 4. BASIC GENERATION
    # ============================================================

    print()
    print(
        "[4] GROQ GENERATION TEST"
    )


    generation_result = (
        shared_ai_provider_manager
        .generate(

            prompt=
                (
                    "Reply only with the exact text "
                    "SENTINELX_READY"
                ),

            json_mode=
                False,

            temperature=
                0.0,
        )
    )


    print_json(
        generation_result
    )


    generation_pass = (

        generation_result.get(
            "success"
        )
        is True

        and

        "SENTINELX_READY"
        in str(
            generation_result.get(
                "text",
                ""
            )
        )
    )


    if not generation_pass:

        failures.append(
            "Basic Groq generation failed."
        )


    # ============================================================
    # 5. AI PROTECTION DECISION AGENT
    # ============================================================

    print()
    print(
        "[5] AI PROTECTION DECISION AGENT"
    )


    agent = (
        ProtectionDecisionAgent()
    )


    print_json(
        agent.status()
    )


    # ============================================================
    # 6. SYNTHETIC REASONING FIXTURE
    #
    # Does not touch 7C.3 DB or real telemetry.
    # ============================================================

    threat = {

        "id":
            "AI-READINESS-001",

        "detection_id":
            "AI-READINESS-DETECTION-001",

        "event_id":
            "AI-READINESS-EVENT-001",

        "incident_id":
            "AI-READINESS-INCIDENT-001",

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
            (
                "DETECTOR_CONFIDENCE_"
                "NOT_PROBABILITY"
            ),

        "risk": {

            "detection": {

                "score":
                    85.0,

                "semantics":
                    (
                        "DETECTOR_RISK_SCORE_"
                        "NOT_PROBABILITY"
                    ),
            }
        },

        "evidence": {

            "observations": [

                (
                    "Repeated outbound connections "
                    "to the same destination."
                ),

                (
                    "Connections occurred at "
                    "regular temporal intervals."
                ),
            ],

            "destination":
                "198.51.100.25",

            "destination_port":
                443,
        },

        "model_evidence": {

            "type":
                "BEHAVIORAL_CORROBORATION",

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
    }


    investigation = {

        "status":
            "COMPLETED",

        "summary":
            (
                "Repeated periodic outbound "
                "network connections were observed."
            ),

        "corroborating_evidence": [

            (
                "Network timing shows repeated "
                "periodic communication."
            ),
        ],

        "limitations": [

            (
                "No payload content was inspected."
            ),

            (
                "The remote destination has not "
                "been independently confirmed "
                "as malicious."
            ),

            (
                "No malicious payload execution "
                "was directly observed."
            ),
        ],
    }


    graph_rag_context = {

        "knowledge": [

            (
                "Periodic outbound communication "
                "can occur during command-and-control "
                "activity."
            ),

            (
                "Periodic communication can also "
                "be produced by legitimate update, "
                "monitoring or synchronization "
                "software."
            ),
        ],

        "provenance":
            "SYNTHETIC_READINESS_CONTEXT",
    }


    print()
    print(
        "[6] STRUCTURED AI REASONING TEST"
    )


    decision = (
        agent.decide(

            threat=
                threat,

            investigation=
                investigation,

            graph_rag_context=
                graph_rag_context,
        )
    )


    print_json(
        decision
    )


    # ============================================================
    # 7. DECISION VALIDATION
    # ============================================================

    print()
    print(
        "[7] PROTECTION DECISION VALIDATION"
    )


    valid_decisions = {

        "SAFE",
        "MONITOR",
        "ASK_USER",
        "PROTECT",
    }


    valid_actions = {

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


    ai_available = (

        decision.get(
            "ai_available"
        )
        is True
    )


    provider_is_groq = (

        decision.get(
            "provider"
        )
        ==
        "GROQ"
    )


    decision_valid = (

        decision.get(
            "decision"
        )
        in
        valid_decisions
    )


    action_valid = (

        decision.get(
            "recommended_action"
        )
        in
        valid_actions
    )


    reasoning_present = (

        isinstance(
            decision.get(
                "reasoning_summary"
            ),
            list,
        )

        and

        len(
            decision.get(
                "reasoning_summary"
            )
        )
        > 0
    )


    safety_pass = (

        decision.get(
            "simulation_only"
        )
        is True

        and

        decision.get(
            "execution_allowed"
        )
        is False

        and

        decision.get(
            "automatic_execution_allowed"
        )
        is False

        and

        decision.get(
            "real_response_executed"
        )
        is False
    )


    print(
        "AI available           :",
        ai_available,
    )

    print(
        "Provider is Groq       :",
        provider_is_groq,
    )

    print(
        "Decision valid         :",
        decision_valid,
    )

    print(
        "Action valid           :",
        action_valid,
    )

    print(
        "Reasoning present      :",
        reasoning_present,
    )

    print(
        "Safety boundary        :",
        safety_pass,
    )


    if not ai_available:

        failures.append(
            "Protection AI was unavailable."
        )


    if not provider_is_groq:

        failures.append(
            "Protection Agent did not use Groq."
        )


    if not decision_valid:

        failures.append(
            "Protection decision was invalid."
        )


    if not action_valid:

        failures.append(
            "Recommended action was invalid."
        )


    if not reasoning_present:

        failures.append(
            "AI reasoning summary is missing."
        )


    if not safety_pass:

        failures.append(
            "Safety boundary failed."
        )


    # ============================================================
    # FINAL RESULT
    # ============================================================

    heading(
        "FINAL 7D GROQ READINESS RESULT"
    )


    if failures:

        print(
            "RESULT: FAIL"
        )

        print()


        for failure in failures:

            print(
                " -",
                failure,
            )


        print()
        print(
            "Do NOT integrate the AI agent "
            "into the runtime yet."
        )


        return 1


    print(
        "RESULT: PASS"
    )

    print()

    print(
        "Groq configuration           : PASS"
    )

    print(
        "Groq authentication          : PASS"
    )

    print(
        "Groq model discovery         : PASS"
    )

    print(
        "Groq text generation         : PASS"
    )

    print(
        "Protection AI reasoning      : PASS"
    )

    print(
        "Structured decision          : PASS"
    )

    print(
        "Simulation-only boundary     : PASS"
    )

    print()

    print(
        "SENTINEL-X 7D AI PHASE IS READY "
        "TO CONTINUE."
    )


    return 0


if __name__ == "__main__":

    sys.exit(
        main()
    )