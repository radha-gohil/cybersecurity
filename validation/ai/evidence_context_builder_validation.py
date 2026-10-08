from __future__ import annotations

import json
import sys

import requests


from agents.evidence_context_builder import (
    EvidenceContextBuilder,
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


FORBIDDEN_SECURITY_KEYS = {

    "synthetic",
    "synthetic_validation",
    "synthetic_demo",

    "simulation_mode",

    "validation_only",
    "production_eligible",

    "internal_regression",
    "user_visible",

    "contract_validation",
    "dataset",
}


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


def contains_forbidden_key(
    value,
) -> bool:

    if isinstance(
        value,
        dict,
    ):

        for key, item in (
            value.items()
        ):

            if (
                str(
                    key
                )
                .strip()
                .lower()
                in
                FORBIDDEN_SECURITY_KEYS
            ):

                return True


            if contains_forbidden_key(
                item
            ):

                return True


    elif isinstance(
        value,
        list,
    ):

        for item in value:

            if contains_forbidden_key(
                item
            ):

                return True


    return False


def main() -> int:

    heading(
        "SENTINEL-X 7D.2 — EVIDENCE CONTEXT BUILDER VALIDATION"
    )


    # ============================================================
    # LOAD CANONICAL THREATS
    # ============================================================

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


    builder = (
        EvidenceContextBuilder()
    )


    print(
        json.dumps(
            builder.status(),
            indent=2,
        )
    )


    passed = 0

    results = []


    for index, event_id in enumerate(
        EXPECTED_EVENT_IDS,
        start=1,
    ):

        heading(
            (
                f"[{index}/"
                f"{len(EXPECTED_EVENT_IDS)}] "
                f"{event_id}"
            )
        )


        failures = []


        threat = threats.get(
            event_id
        )


        if threat is None:

            failures.append(
                "Canonical threat missing."
            )

            context = {}

        else:

            context = (
                builder.build(

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
        # SCHEMA
        # ========================================================

        if (
            context.get(
                "schema_version"
            )
            !=
            "sentinelx.ai.evidence-context.v1"
        ):

            failures.append(
                "Invalid context schema."
            )


        if (
            context.get(
                "builder_version"
            )
            !=
            "7D.2-v1"
        ):

            failures.append(
                "Invalid builder version."
            )


        # ========================================================
        # IDENTITY
        # ========================================================

        identity = (
            context.get(
                "identity"
            )
            or {}
        )


        if (
            identity.get(
                "event_id"
            )
            !=
            event_id
        ):

            failures.append(
                "Event identity not preserved."
            )


        if (
            threat
            and
            identity.get(
                "security_id"
            )
            !=
            threat.get(
                "id"
            )
        ):

            failures.append(
                "Security ID not preserved."
            )


        # ========================================================
        # SECURITY CONTEXT
        # ========================================================

        security_context = (
            context.get(
                "security_context"
            )
            or {}
        )


        if not security_context:

            failures.append(
                "Security context empty."
            )


        if contains_forbidden_key(
            security_context
        ):

            failures.append(
                (
                    "Validation provenance leaked "
                    "into security_context."
                )
            )


        detector = (
            security_context.get(
                "detector"
            )
            or {}
        )


        if not detector.get(
            "threat_type"
        ):

            failures.append(
                "Threat type missing."
            )


        risk = (
            detector.get(
                "risk"
            )
            or {}
        )


        if (
            risk.get(
                "semantics"
            )
            !=
            "DETECTOR_RISK_SCORE_NOT_PROBABILITY"
        ):

            failures.append(
                "Detector risk semantics invalid."
            )


        # ========================================================
        # OBSERVED/MODEL EVIDENCE
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
                "Observed evidence unavailable."
            )


        if (
            availability.get(
                "model_evidence"
            )
            is not True
        ):

            failures.append(
                "Model evidence unavailable."
            )


        # ========================================================
        # PROVENANCE
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
                "Provenance reasoning policy missing."
            )


        if (
            provenance.get(
                "synthetic"
            )
            is not True
        ):

            failures.append(
                "Synthetic provenance not preserved."
            )


        # ========================================================
        # REASONING POLICY
        # ========================================================

        policy = (
            context.get(
                "reasoning_policy"
            )
            or {}
        )


        if (
            policy.get(
                "evaluate_behavior_as_real"
            )
            is not True
        ):

            failures.append(
                "Behavior-as-real policy missing."
            )


        if (
            policy.get(
                "synthetic_provenance_is_not_benign_evidence"
            )
            is not True
        ):

            failures.append(
                (
                    "Synthetic provenance separation "
                    "policy missing."
                )
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


        safety_pass = (

            safety.get(
                "simulation_only"
            )
            is True

            and

            safety.get(
                "execution_allowed"
            )
            is False

            and

            safety.get(
                "automatic_execution_allowed"
            )
            is False

            and

            safety.get(
                "real_response_executed"
            )
            is False
        )


        if not safety_pass:

            failures.append(
                "Safety boundary invalid."
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
                (
                    detector.get(
                        "category"
                    )
                ),

            "threat_type":
                (
                    detector.get(
                        "threat_type"
                    )
                ),

            "observed":
                availability.get(
                    "observed_evidence"
                ),

            "model":
                availability.get(
                    "model_evidence"
                ),

            "incident":
                availability.get(
                    "incident_context"
                ),

            "passed":
                scenario_pass,

            "failures":
                failures,
        })


        print(
            "Category       :",
            detector.get(
                "category"
            ),
        )

        print(
            "Threat type    :",
            detector.get(
                "threat_type"
            ),
        )

        print(
            "Observed       :",
            availability.get(
                "observed_evidence"
            ),
        )

        print(
            "Model evidence :",
            availability.get(
                "model_evidence"
            ),
        )

        print(
            "Incident       :",
            availability.get(
                "incident_context"
            ),
        )

        print(
            "Provenance     :",
            provenance.get(
                "reasoning_use"
            ),
        )

        print(
            "RESULT         :",
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


    # ============================================================
    # FINAL
    # ============================================================

    heading(
        "7D.2 EVIDENCE CONTEXT BUILDER RESULT"
    )


    for row in results:

        print(

            f"{row['event_id']:<34} "

            f"{'PASS' if row['passed'] else 'FAIL':<6} "

            f"{str(row['category']):<16} "

            f"{row['threat_type']}"
        )


    print()

    print(
        f"TOTAL : "
        f"{passed}/"
        f"{len(EXPECTED_EVENT_IDS)} PASS"
    )


    if (
        passed
        ==
        len(
            EXPECTED_EVENT_IDS
        )
    ):

        print()

        print(
            "RESULT: PASS"
        )

        print(
            (
                "SENTINEL-X Evidence Context Builder "
                "is ready for AI integration."
            )
        )

        return 0


    print()

    print(
        "RESULT: FAIL"
    )

    print(
        (
            "Do not connect EvidenceContextBuilder "
            "to ProtectionDecisionAgent yet."
        )
    )


    return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )