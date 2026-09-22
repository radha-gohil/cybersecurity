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


from response.mitigation_verifier import (
    MitigationVerifier,
)


def separator():

    print(
        "\n"
        + "=" * 72
    )


def print_result(
    result,
):

    print(
        "\nStatus:",
        result.get(
            "status"
        ),
    )

    print(
        "Overall Improvement:",
        result.get(
            "overall_improvement"
        ),
    )

    print(
        "Residual Risk:",
        result.get(
            "residual_risk"
        ),
    )

    print(
        "Recommendation:",
        result.get(
            "recommendation"
        ),
    )

    print(
        "\nMETRICS:"
    )

    for (
        metric_name,
        metric,
    ) in (
        result.get(
            "metrics",
            {}
        ).items()
    ):

        print(
            " -",
            metric_name,
            "| Before:",
            metric.get(
                "before"
            ),
            "| After:",
            metric.get(
                "after"
            ),
            "| Reduction:",
            metric.get(
                "reduction"
            ),
        )


def main():

    separator()

    print(
        "SENTINEL-X SIMULATED MITIGATION VERIFIER TEST"
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

    verifier = (
        MitigationVerifier(

            verified_threshold=0.70,

            partial_threshold=0.30,

            acceptable_residual_risk=30.0,
        )
    )

    # ============================================================
    # TEST 1 — STRONG SIMULATED IMPROVEMENT
    # ============================================================

    separator()

    print(
        "TEST 1 - STRONG SIMULATED MITIGATION"
    )

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

    response_result = {

        "simulation_mode":
            True,

        "plan_id":
            "synthetic-plan-001",

        "action":
            "SIMULATED_CONTAINMENT",
    }

    result = (
        verifier.verify(

            before_state,

            simulated_after_state,

            response_result,
        )
    )

    print_result(
        result
    )

    if (
        result[
            "status"
        ]
        !=
        "SIMULATION_VERIFIED"
    ):

        raise AssertionError(
            "Expected SIMULATION_VERIFIED."
        )

    print(
        "Strong simulation verification: PASS"
    )

    # ============================================================
    # TEST 2 — PARTIAL IMPROVEMENT
    # ============================================================

    separator()

    print(
        "TEST 2 - PARTIAL SIMULATED MITIGATION"
    )

    partial_after_state = {

        "risk_score":
            55,

        "suspicious_event_count":
            8,

        "active_indicator_count":
            5,

        "exposure_score":
            65,
    }

    partial_result = (
        verifier.verify(

            before_state,

            partial_after_state,

            {
                "simulation_mode":
                    True,

                "plan_id":
                    "synthetic-plan-002",

                "action":
                    "SIMULATED_PARTIAL_RESPONSE",
            },
        )
    )

    print_result(
        partial_result
    )

    if (
        partial_result[
            "status"
        ]
        !=
        "SIMULATION_PARTIAL"
    ):

        raise AssertionError(
            "Expected SIMULATION_PARTIAL."
        )

    print(
        "Partial simulation verification: PASS"
    )

    # ============================================================
    # TEST 3 — NO USEFUL IMPROVEMENT
    # ============================================================

    separator()

    print(
        "TEST 3 - NO SIMULATED IMPROVEMENT"
    )

    poor_after_state = {

        "risk_score":
            82,

        "suspicious_event_count":
            12,

        "active_indicator_count":
            8,

        "exposure_score":
            88,
    }

    poor_result = (
        verifier.verify(

            before_state,

            poor_after_state,

            {
                "simulation_mode":
                    True,

                "plan_id":
                    "synthetic-plan-003",

                "action":
                    "SIMULATED_INEFFECTIVE_RESPONSE",
            },
        )
    )

    print_result(
        poor_result
    )

    if (
        poor_result[
            "status"
        ]
        !=
        "SIMULATION_NO_IMPROVEMENT"
    ):

        raise AssertionError(
            "Expected "
            "SIMULATION_NO_IMPROVEMENT."
        )

    print(
        "No-improvement detection: PASS"
    )

    # ============================================================
    # TEST 4 — REAL EXECUTION SAFETY GUARD
    # ============================================================

    separator()

    print(
        "TEST 4 - REAL EXECUTION SAFETY GUARD"
    )

    safety_guard_passed = False

    try:

        verifier.verify(

            before_state,

            simulated_after_state,

            {
                "simulation_mode":
                    False,

                "plan_id":
                    "blocked-plan",

                "action":
                    "REAL_RESPONSE",
            },
        )

    except ValueError as exc:

        safety_guard_passed = True

        print(
            "Blocked:",
            str(
                exc
            ),
        )

    if not safety_guard_passed:

        raise AssertionError(
            "Simulation-only safety guard failed."
        )

    print(
        "Simulation-only safety guard: PASS"
    )

    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    separator()

    print(
        "VALIDATION"
    )

    print(
        "Strong mitigation simulation: PASS"
    )

    print(
        "Partial mitigation simulation: PASS"
    )

    print(
        "No-improvement simulation: PASS"
    )

    print(
        "Real execution blocked: PASS"
    )

    separator()

    print(
        "ALL SIMULATED MITIGATION VERIFIER "
        "TESTS PASSED"
    )

    separator()


if __name__ == "__main__":

    main()