from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Dict, List

import requests

from agents.protection_decision_agent import (
    ProtectionDecisionAgent,
)


# ================================================================
# API
# ================================================================

API_BASE = (
    "http://127.0.0.1:8003/api/v1"
)


# ================================================================
# AUTHORITATIVE 7C.3 THREAT SET
# ================================================================

EXPECTED_EVENT_IDS = [

    # PROCESS
    "SYNTH-EVT-PROC-POWERSHELL",
    "SYNTH-EVT-PROC-LOLBIN",

    # FILE
    "SYNTH-EVT-FILE-EXECUTABLE",
    "SYNTH-EVT-FILE-MALWARE",
    "SYNTH-EVT-FILE-RANSOMWARE",

    # NETWORK
    "SYNTH-EVT-NET-BEACON",
    "SYNTH-EVT-NET-SCAN",
    "SYNTH-EVT-NET-DOS",
    "SYNTH-EVT-NET-DDOS",

    # REGISTRY
    "SYNTH-EVT-REG-RUN",
    "SYNTH-EVT-REG-SERVICE",

    # AUTHENTICATION
    "SYNTH-EVT-AUTH-BRUTE",

    # SYSTEM
    "SYNTH-EVT-SYSTEM-PRIV",
    "SYNTH-EVT-SYSTEM-STARTUP-TASK",
]


# ================================================================
# FIRST REAL AI INTEGRATION SAMPLE
#
# One representative threat from major detector families.
# ================================================================

REPRESENTATIVE_EVENT_IDS = [

    "SYNTH-EVT-PROC-POWERSHELL",

    "SYNTH-EVT-FILE-RANSOMWARE",

    "SYNTH-EVT-NET-BEACON",

    "SYNTH-EVT-AUTH-BRUTE",
]


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


# ================================================================
# HELPERS
# ================================================================

def heading(
    text: str,
) -> None:

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
) -> None:

    print(
        json.dumps(
            value,
            indent=2,
            default=str,
        )
    )


def get_json(
    path: str,
) -> Dict:

    response = requests.get(

        f"{API_BASE}{path}",

        timeout=15,
    )


    response.raise_for_status()


    return response.json()


# ================================================================
# COMMON AI RESULT VALIDATION
# ================================================================

def validate_ai_result(
    *,
    threat: Dict,
    result: Dict,
) -> List[str]:

    failures = []


    # ------------------------------------------------------------
    # AI
    # ------------------------------------------------------------

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
            "provider"
        )
        !=
        "GROQ"
    ):

        failures.append(
            (
                "Expected GROQ provider, got "
                f"{result.get('provider')}"
            )
        )


    # ------------------------------------------------------------
    # ID PRESERVATION
    # ------------------------------------------------------------

    if (
        result.get(
            "security_id"
        )
        !=
        threat.get(
            "id"
        )
    ):

        failures.append(
            "Canonical security ID was not preserved."
        )


    if (
        result.get(
            "event_id"
        )
        !=
        threat.get(
            "event_id"
        )
    ):

        failures.append(
            "Canonical event ID was not preserved."
        )


    # ------------------------------------------------------------
    # STRUCTURED DECISION
    # ------------------------------------------------------------

    decision = (
        result.get(
            "decision"
        )
    )


    if (
        decision
        not in
        VALID_DECISIONS
    ):

        failures.append(
            f"Invalid AI decision: {decision}"
        )


    action = (
        result.get(
            "recommended_action"
        )
    )


    if (
        action
        not in
        VALID_ACTIONS
    ):

        failures.append(
            f"Invalid AI action: {action}"
        )


    # ------------------------------------------------------------
    # REASONING
    # ------------------------------------------------------------

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
            "AI reasoning summary is missing."
        )


    evidence_used = (
        result.get(
            "evidence_used"
        )
        or []
    )


    if (
        not isinstance(
            evidence_used,
            list,
        )
        or
        len(
            evidence_used
        )
        == 0
    ):

        failures.append(
            "AI did not identify evidence used."
        )


    # ------------------------------------------------------------
    # SAFETY
    # ------------------------------------------------------------

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


    # ------------------------------------------------------------
    # DIGITAL TWIN
    # ------------------------------------------------------------

    if (
        decision
        ==
        "PROTECT"

        and

        result.get(
            "digital_twin_required"
        )
        is not True
    ):

        failures.append(
            (
                "PROTECT decision did not "
                "require Digital Twin."
            )
        )


    return failures


# ================================================================
# MAIN
# ================================================================

def main() -> int:

    parser = argparse.ArgumentParser()


    parser.add_argument(

        "--all",

        action="store_true",

        help=(
            "Run AI reasoning against all "
            "14 canonical 7C.3 threats."
        ),
    )


    args = parser.parse_args()


    heading(
        "SENTINEL-X 7D.1 — REAL CANONICAL THREAT AI INTEGRATION"
    )


    # ============================================================
    # 1. BACKEND HEALTH
    # ============================================================

    print()
    print(
        "[1] BACKEND HEALTH"
    )


    try:

        health = (
            get_json(
                "/health"
            )
        )

    except Exception as error:

        print(
            "FAIL: FastAPI backend unavailable."
        )

        print(
            error
        )

        print()
        print(
            "Start backend with:"
        )

        print(
            "uvicorn api.main:app "
            "--reload --host 127.0.0.1 --port 8003"
        )

        return 1


    print_json(
        health
    )


    if (
        health.get(
            "status"
        )
        !=
        "HEALTHY"
    ):

        print(
            "FAIL: backend is not HEALTHY."
        )

        return 1


    if (
        health.get(
            "simulation_mode"
        )
        is not True
    ):

        print(
            "FAIL: backend is not simulation mode."
        )

        return 1


    if (
        health.get(
            "real_response_execution"
        )
        is not False
    ):

        print(
            "FAIL: real response execution is enabled."
        )

        return 1


    print()
    print(
        "Backend safety: PASS"
    )


    # ============================================================
    # 2. CANONICAL THREAT FEED
    # ============================================================

    print()
    print(
        "[2] CANONICAL SECURITY THREAT FEED"
    )


    try:

        feed = (
            get_json(
                "/security/threats?limit=1000"
            )
        )

    except Exception as error:

        print(
            "FAIL: cannot load canonical threat feed."
        )

        print(
            error
        )

        return 1


    threats = (
        feed.get(
            "threats",
            []
        )
    )


    if not isinstance(
        threats,
        list,
    ):

        print(
            "FAIL: feed.threats is not a list."
        )

        return 1


    print(
        "Threat feed schema :",
        feed.get(
            "schema_version"
        ),
    )

    print(
        "Threat feed count  :",
        len(
            threats
        ),
    )


    # ============================================================
    # 3. INDEX BY EVENT ID
    # ============================================================

    threat_by_event = {

        str(
            threat.get(
                "event_id"
            )
        ):
            threat

        for threat
        in threats

        if isinstance(
            threat,
            dict,
        )
    }


    missing = [

        event_id

        for event_id
        in EXPECTED_EVENT_IDS

        if event_id
        not in
        threat_by_event
    ]


    if missing:

        print()
        print(
            "FAIL: expected 7C.3 threats are missing:"
        )

        for event_id in missing:

            print(
                " -",
                event_id,
            )

        return 1


    print()
    print(
        "Expected canonical threat set: 14/14 PRESENT"
    )


    # ============================================================
    # 4. CONTRACT VALIDATION
    # ============================================================

    invalid_contracts = []


    for event_id in EXPECTED_EVENT_IDS:

        threat = (
            threat_by_event[
                event_id
            ]
        )


        if (
            threat.get(
                "schema_version"
            )
            !=
            "sentinelx.security.v1"
        ):

            invalid_contracts.append(
                (
                    event_id,
                    "invalid schema_version",
                )
            )


        contract_validation = (
            threat.get(
                "contract_validation"
            )
            or {}
        )


        if (
            contract_validation.get(
                "valid"
            )
            is not True
        ):

            invalid_contracts.append(
                (
                    event_id,
                    "contract_validation.valid != true",
                )
            )


        visibility = (
            threat.get(
                "visibility"
            )
            or {}
        )


        if (
            visibility.get(
                "internal_regression"
            )
            is True
        ):

            invalid_contracts.append(
                (
                    event_id,
                    "internal regression threat exposed",
                )
            )


        risk = (
            threat.get(
                "risk"
            )
            or {}
        )


        detection_risk = (
            risk.get(
                "detection"
            )
            or {}
        )


        if (
            detection_risk.get(
                "semantics"
            )
            !=
            "DETECTOR_RISK_SCORE_NOT_PROBABILITY"
        ):

            invalid_contracts.append(
                (
                    event_id,
                    "invalid detector risk semantics",
                )
            )


    if invalid_contracts:

        print()
        print(
            "FAIL: canonical contract problems:"
        )

        for item in invalid_contracts:

            print(
                " -",
                item,
            )

        return 1


    print(
        "Canonical contract validation: PASS"
    )


    # ============================================================
    # 5. SELECT AI TEST SET
    # ============================================================

    if args.all:

        selected_ids = (
            EXPECTED_EVENT_IDS
        )

        mode = (
            "ALL 14 CANONICAL THREATS"
        )

    else:

        selected_ids = (
            REPRESENTATIVE_EVENT_IDS
        )

        mode = (
            "4 REPRESENTATIVE CANONICAL THREATS"
        )


    print()
    print(
        "[3] AI INTEGRATION MODE"
    )

    print(
        mode
    )


    # ============================================================
    # 6. AI AGENT
    # ============================================================

    agent = (
        ProtectionDecisionAgent()
    )


    results = []

    passed_count = 0


    for index, event_id in enumerate(
        selected_ids,
        start=1,
    ):

        threat = (
            threat_by_event[
                event_id
            ]
        )


        heading(
            (
                f"[{index}/{len(selected_ids)}] "
                f"{event_id}"
            )
        )


        print(
            "Category    :",
            threat.get(
                "category"
            ),
        )

        print(
            "Engine      :",
            threat.get(
                "engine"
            ),
        )

        print(
            "Threat type :",
            threat.get(
                "threat_type"
            ),
        )

        print(
            "Severity    :",
            threat.get(
                "severity"
            ),
        )

        print(
            "Verdict     :",
            threat.get(
                "verdict"
            ),
        )


        # ========================================================
        # IMPORTANT:
        #
        # This is the real canonical 7C.3 object.
        #
        # No synthetic AI fixture is created here.
        # ========================================================

        result = (
            agent.decide(

                threat=
                    threat,

                incident=
                    threat.get(
                        "incident"
                    ),

                investigation=
                    threat.get(
                        "investigation"
                    ),

                graph_rag_context=
                    None,
            )
        )


        print()
        print(
            "AI RESULT"
        )


        print_json(
            result
        )


        failures = (
            validate_ai_result(

                threat=
                    threat,

                result=
                    result,
            )
        )


        passed = (
            len(
                failures
            )
            == 0
        )


        if passed:

            passed_count += 1


        print()
        print(
            "RESULT:",
            "PASS"
            if passed
            else
            "FAIL",
        )


        for failure in failures:

            print(
                " -",
                failure,
            )


        results.append({

            "event_id":
                event_id,

            "category":
                threat.get(
                    "category"
                ),

            "threat_type":
                threat.get(
                    "threat_type"
                ),

            "canonical_verdict":
                threat.get(
                    "verdict"
                ),

            "ai_decision":
                result.get(
                    "decision"
                ),

            "ai_assessment":
                result.get(
                    "threat_assessment"
                ),

            "ai_action":
                result.get(
                    "recommended_action"
                ),

            "ai_confidence":
                result.get(
                    "confidence"
                ),

            "provider":
                result.get(
                    "provider"
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


        # Small spacing between free-tier requests.
        if (
            index
            <
            len(
                selected_ids
            )
        ):

            time.sleep(
                2
            )


    # ============================================================
    # FINAL SUMMARY
    # ============================================================

    heading(
        "7D.1 CANONICAL THREAT AI INTEGRATION RESULT"
    )


    for row in results:

        print(

            f"{row['event_id']:<34} "
            f"{'PASS' if row['passed'] else 'FAIL':<6} "
            f"AI={str(row['ai_decision']):<10} "
            f"Action={str(row['ai_action']):<22} "
            f"Assessment={row['ai_assessment']}"
        )


    print()

    print(
        f"TOTAL : "
        f"{passed_count}/{len(results)} PASS"
    )


    if (
        passed_count
        ==
        len(
            results
        )
    ):

        print()
        print(
            "RESULT: PASS"
        )


        if not args.all:

            print(
                (
                    "Real canonical Sentinel-X threats "
                    "successfully reached the AI "
                    "Protection Decision Agent."
                )
            )

            print()

            print(
                "Next command for the full 14-threat run:"
            )

            print()

            print(
                "python -m "
                "validation.ai."
                "canonical_threat_ai_integration "
                "--all"
            )

        else:

            print(
                (
                    "All 14 canonical 7C.3 threats "
                    "successfully passed through the "
                    "AI Protection Decision Agent."
                )
            )


        return 0


    print()
    print(
        "RESULT: FAIL"
    )

    print(
        (
            "Do not connect the AI Protection Agent "
            "to the runtime/API pipeline yet."
        )
    )


    return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )