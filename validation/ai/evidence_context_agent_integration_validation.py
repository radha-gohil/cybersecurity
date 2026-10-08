from __future__ import annotations

import sys

import requests


from agents.protection_decision_agent import (
    ProtectionDecisionAgent,
)


API_BASE = (
    "http://127.0.0.1:8003/api/v1"
)


EXPECTED_EVENT_IDS = [

    "SYNTH-EVT-PROC-POWERSHELL",
    "SYNTH-EVT-PROC-LOLBIN",

    "SYNTH-EVT-FILE-EXECUTABLE",
    "SYNTH-EVT-FILE-MALWARE",
    "SYNTH-EVT-FILE-RANSOMWARE",

    "SYNTH-EVT-NET-BEACON",
    "SYNTH-EVT-NET-SCAN",
    "SYNTH-EVT-NET-DOS",
    "SYNTH-EVT-NET-DDOS",

    "SYNTH-EVT-REG-RUN",
    "SYNTH-EVT-REG-SERVICE",

    "SYNTH-EVT-AUTH-BRUTE",

    "SYNTH-EVT-SYSTEM-PRIV",
    "SYNTH-EVT-SYSTEM-STARTUP-TASK",
]


FORBIDDEN_REASONING_SECTIONS = {
    "provenance_context",
    "safety_context",
}


def heading(
    text: str,
):

    print()
    print("=" * 110)
    print(text)
    print("=" * 110)


def main() -> int:

    heading(
        "SENTINEL-X 7D.2 — AGENT / EVIDENCE CONTEXT INTEGRATION"
    )


    response = requests.get(

        (
            f"{API_BASE}/"
            "security/threats?limit=1000"
        ),

        timeout=15,
    )


    response.raise_for_status()


    feed = response.json()


    threats = {

        item.get(
            "event_id"
        ):
            item

        for item
        in feed.get(
            "threats",
            []
        )

        if isinstance(
            item,
            dict,
        )
    }


    agent = (
        ProtectionDecisionAgent()
    )


    passed = 0

    results = []


    for index, event_id in enumerate(
        EXPECTED_EVENT_IDS,
        start=1,
    ):

        heading(
            (
                f"[{index}/14] "
                f"{event_id}"
            )
        )


        failures = []


        threat = threats.get(
            event_id
        )


        if not threat:

            failures.append(
                "Threat missing."
            )

            context = {}

        else:

            context = (
                agent.build_ai_context(

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
                )
            )


        # ========================================================
        # CONTEXT VERSION
        # ========================================================

        if (
            context.get(
                "schema_version"
            )
            !=
            "sentinelx.ai.evidence-context.v1"
        ):

            failures.append(
                "Wrong evidence context schema."
            )


        if (
            context.get(
                "builder_version"
            )
            !=
            "7D.2-v1"
        ):

            failures.append(
                "Wrong context builder version."
            )


        # ========================================================
        # SECURITY CONTEXT
        # ========================================================

        security = (
            context.get(
                "security_context"
            )
            or {}
        )


        if not security:

            failures.append(
                "Security context empty."
            )


        detector = (
            security.get(
                "detector"
            )
            or {}
        )


        if (
            detector.get(
                "threat_type"
            )
            !=
            threat.get(
                "threat_type"
            )
        ):

            failures.append(
                "Threat type changed."
            )


        # ========================================================
        # REASONING PAYLOAD
        #
        # This is exactly what the LLM will receive.
        # ========================================================

        payload = (
            agent.build_reasoning_payload(
                context
            )
        )


        for forbidden in (
            FORBIDDEN_REASONING_SECTIONS
        ):

            if forbidden in payload:

                failures.append(
                    (
                        "Forbidden reasoning section "
                        f"exposed: {forbidden}"
                    )
                )


        if (
            "security_context"
            not in payload
        ):

            failures.append(
                "security_context missing from AI payload."
            )


        if (
            "evidence_quality"
            not in payload
        ):

            failures.append(
                "evidence_quality missing."
            )


        if (
            "reasoning_policy"
            not in payload
        ):

            failures.append(
                "reasoning_policy missing."
            )


        # ========================================================
        # IDENTITY MUST STAY OUTSIDE AI REASONING
        # ========================================================

        if (
            "identity"
            in payload
        ):

            failures.append(
                "Canonical identity leaked into reasoning payload."
            )


        # ========================================================
        # PROVENANCE MUST STILL EXIST FOR AUDIT
        # ========================================================

        provenance = (
            context.get(
                "provenance_context"
            )
            or {}
        )


        if (
            provenance.get(
                "reasoning_use"
            )
            !=
            "AUDIT_ONLY_NOT_SECURITY_EVIDENCE"
        ):

            failures.append(
                "Audit provenance missing."
            )


        # ========================================================
        # SAFETY
        # ========================================================

        safety = (
            context.get(
                "safety_context"
            )
            or {}
        )


        if (
            safety.get(
                "simulation_only"
            )
            is not True
        ):

            failures.append(
                "simulation_only is not True."
            )


        if (
            safety.get(
                "execution_allowed"
            )
            is not False
        ):

            failures.append(
                "execution_allowed is not False."
            )


        # ========================================================
        # AVAILABILITY
        # ========================================================

        availability = (
            context.get(
                "evidence_availability"
            )
            or {}
        )


        if (
            availability.get(
                "observed_evidence"
            )
            is not True
        ):

            failures.append(
                "Observed evidence missing."
            )


        if (
            availability.get(
                "model_evidence"
            )
            is not True
        ):

            failures.append(
                "Model evidence missing."
            )


        scenario_pass = (
            len(
                failures
            )
            == 0
        )


        if scenario_pass:

            passed += 1


        results.append({

            "event_id":
                event_id,

            "category":
                detector.get(
                    "category"
                ),

            "passed":
                scenario_pass,

            "failures":
                failures,
        })


        print(
            "Context schema    :",
            context.get(
                "schema_version"
            ),
        )

        print(
            "Builder version   :",
            context.get(
                "builder_version"
            ),
        )

        print(
            "Category          :",
            detector.get(
                "category"
            ),
        )

        print(
            "Threat type       :",
            detector.get(
                "threat_type"
            ),
        )

        print(
            "Observed evidence :",
            availability.get(
                "observed_evidence"
            ),
        )

        print(
            "Model evidence    :",
            availability.get(
                "model_evidence"
            ),
        )

        print(
            "RESULT            :",
            (
                "PASS"
                if scenario_pass
                else
                "FAIL"
            ),
        )


        for failure in failures:

            print(
                " -",
                failure,
            )


    heading(
        "7D.2 AGENT INTEGRATION RESULT"
    )


    for row in results:

        print(

            f"{row['event_id']:<34} "

            f"{'PASS' if row['passed'] else 'FAIL':<6} "

            f"{row['category']}"
        )


    print()

    print(
        f"TOTAL : {passed}/14 PASS"
    )


    if passed == 14:

        print()
        print(
            "RESULT: PASS"
        )

        print(
            (
                "EvidenceContextBuilder is correctly "
                "integrated with ProtectionDecisionAgent."
            )
        )

        return 0


    print()
    print(
        "RESULT: FAIL"
    )


    return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )