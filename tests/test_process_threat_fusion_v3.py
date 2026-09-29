from __future__ import annotations

import sys

from pathlib import Path


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)


if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from ai_detection.behavior.process_threat_fusion_v3 import (
    ProcessThreatFusionV3,
)


# ================================================================
# HELPERS
# ================================================================

def rule(
    score,
):

    return {
        "available":
            True,

        "score":
            float(
                score
            ),
    }


def statistical(
    score,
):

    return {
        "available":
            True,

        "score":
            float(
                score
            ),
    }


def isolation(
    score,
):

    return {
        "available":
            True,

        "anomaly_confidence":
            float(
                score
            ),
    }


def autoencoder(
    score,
):

    return {
        "available":
            True,

        "anomaly_confidence":
            float(
                score
            ),
    }


def temporal(
    score,
):

    return {
        "available":
            True,

        "anomaly_score":
            float(
                score
            ),

        "anomaly_confidence":
            float(
                score
            ),
    }


def unavailable_temporal():

    return {
        "available":
            False,

        "state":
            "COLLECTING_HISTORY",
    }


# ================================================================
# PRINT SCENARIO
# ================================================================

def print_result(
    name,
    result,
):

    print()

    print(
        "=" * 90
    )

    print(
        name
    )

    print(
        "=" * 90
    )


    print(
        "Rule:",
        result[
            "scores"
        ][
            "rules"
        ],
    )


    print(
        "Statistical:",
        result[
            "scores"
        ][
            "statistical"
        ],
    )


    print(
        "Behavior AI:",
        result[
            "scores"
        ][
            "behavioral_ai_consensus"
        ],
    )


    print(
        "Temporal AI:",
        result[
            "scores"
        ][
            "temporal_ai"
        ],
    )


    print(
        "Temporal available:",
        result[
            "temporal_ai_available"
        ],
    )


    print(
        "Active categories:",
        result[
            "active_categories"
        ],
    )


    print(
        "Strong categories:",
        result[
            "strong_categories"
        ],
    )


    print(
        "Active count:",
        result[
            "active_signal_count"
        ],
    )


    print(
        "Strong count:",
        result[
            "strong_signal_count"
        ],
    )


    print(
        "Fusion:",
        result[
            "fusion_score"
        ],
    )


    print(
        "Severity:",
        result[
            "severity"
        ],
    )


    print(
        "Critical allowed:",
        result[
            "critical_allowed"
        ],
    )


    print(
        "Alert:",
        result[
            "should_alert"
        ],
    )


    print(
        "Reasons:",
        result[
            "reasons"
        ],
    )


# ================================================================
# MAIN
# ================================================================

def main():

    engine = (
        ProcessThreatFusionV3()
    )


    print()

    print(
        "=" * 90
    )

    print(
        "SENTINEL-X PROCESS THREAT FUSION V3 E2E"
    )

    print(
        "=" * 90
    )


    # ============================================================
    # CASE 1
    # NORMAL
    # ============================================================

    normal = (
        engine.calculate(

            rule_result=
                rule(
                    5
                ),

            statistical_result=
                statistical(
                    8
                ),

            isolation_result=
                isolation(
                    10
                ),

            autoencoder_result=
                autoencoder(
                    12
                ),

            temporal_result=
                temporal(
                    10
                ),
        )
    )


    print_result(
        "CASE 1 — NORMAL",
        normal,
    )


    assert normal[
        "should_alert"
    ] is False


    assert normal[
        "severity"
    ] in {
        "INFO",
        "LOW",
    }


    # ============================================================
    # CASE 2
    # TEMPORAL MODEL NOT READY YET
    # ============================================================

    no_temporal = (
        engine.calculate(

            rule_result=
                rule(
                    90
                ),

            statistical_result=
                statistical(
                    15
                ),

            isolation_result=
                isolation(
                    94
                ),

            autoencoder_result=
                autoencoder(
                    91
                ),

            temporal_result=
                unavailable_temporal(),
        )
    )


    print_result(
        "CASE 2 — TEMPORAL HISTORY NOT READY",
        no_temporal,
    )


    assert no_temporal[
        "temporal_ai_available"
    ] is False


    assert (
        "temporal_ai"

        not in no_temporal[
            "available_categories"
        ]
    )


    # ============================================================
    # CASE 3
    # TEMPORAL STRONG ONLY
    # ============================================================

    temporal_only = (
        engine.calculate(

            rule_result=
                rule(
                    0
                ),

            statistical_result=
                statistical(
                    0
                ),

            isolation_result=
                isolation(
                    10
                ),

            autoencoder_result=
                autoencoder(
                    12
                ),

            temporal_result=
                temporal(
                    100
                ),
        )
    )


    print_result(
        "CASE 3 — TEMPORAL STRONG ONLY",
        temporal_only,
    )


    assert temporal_only[
        "critical_allowed"
    ] is False


    assert temporal_only[
        "fusion_score"
    ] < 80


    # ============================================================
    # CASE 4
    # BEHAVIOR + TEMPORAL STRONG
    #
    # AI-only evidence must never be CRITICAL.
    # ============================================================

    ai_pair = (
        engine.calculate(

            rule_result=
                rule(
                    0
                ),

            statistical_result=
                statistical(
                    0
                ),

            isolation_result=
                isolation(
                    94
                ),

            autoencoder_result=
                autoencoder(
                    91
                ),

            temporal_result=
                temporal(
                    95
                ),
        )
    )


    print_result(
        "CASE 4 — BEHAVIOR + TEMPORAL STRONG",
        ai_pair,
    )


    assert ai_pair[
        "critical_allowed"
    ] is False


    assert ai_pair[
        "fusion_score"
    ] <= 79


    assert ai_pair[
        "active_signal_count"
    ] == 2


    assert ai_pair[
        "strong_signal_count"
    ] == 2


    # ============================================================
    # CASE 5
    # RULE + TEMPORAL STRONG
    # ============================================================

    rule_temporal = (
        engine.calculate(

            rule_result=
                rule(
                    90
                ),

            statistical_result=
                statistical(
                    10
                ),

            isolation_result=
                isolation(
                    10
                ),

            autoencoder_result=
                autoencoder(
                    12
                ),

            temporal_result=
                temporal(
                    95
                ),
        )
    )


    print_result(
        "CASE 5 — RULE + TEMPORAL STRONG",
        rule_temporal,
    )


    assert rule_temporal[
        "critical_allowed"
    ] is True


    assert rule_temporal[
        "severity"
    ] == "CRITICAL"


    # ============================================================
    # CASE 6
    # RULE + BEHAVIOR STRONG
    # ============================================================

    rule_behavior = (
        engine.calculate(

            rule_result=
                rule(
                    90
                ),

            statistical_result=
                statistical(
                    10
                ),

            isolation_result=
                isolation(
                    95
                ),

            autoencoder_result=
                autoencoder(
                    92
                ),

            temporal_result=
                temporal(
                    20
                ),
        )
    )


    print_result(
        "CASE 6 — RULE + BEHAVIOR STRONG",
        rule_behavior,
    )


    assert rule_behavior[
        "critical_allowed"
    ] is True


    assert rule_behavior[
        "severity"
    ] == "CRITICAL"


    # ============================================================
    # CASE 7
    # STATISTICAL + TEMPORAL ONLY
    #
    # Two-source pair, but no strong rule and fewer than three
    # active categories. Must not become CRITICAL.
    # ============================================================

    statistical_temporal = (
        engine.calculate(

            rule_result=
                rule(
                    0
                ),

            statistical_result=
                statistical(
                    90
                ),

            isolation_result=
                isolation(
                    10
                ),

            autoencoder_result=
                autoencoder(
                    12
                ),

            temporal_result=
                temporal(
                    95
                ),
        )
    )


    print_result(
        "CASE 7 — STATISTICAL + TEMPORAL STRONG",
        statistical_temporal,
    )


    assert statistical_temporal[
        "critical_allowed"
    ] is False


    assert statistical_temporal[
        "fusion_score"
    ] <= 79


    # ============================================================
    # CASE 8
    # STAT + BEHAVIOR + TEMPORAL
    #
    # Three corroborating categories permit CRITICAL even without
    # rules if statistical evidence is strong.
    # ============================================================

    three_source = (
        engine.calculate(

            rule_result=
                rule(
                    0
                ),

            statistical_result=
                statistical(
                    90
                ),

            isolation_result=
                isolation(
                    94
                ),

            autoencoder_result=
                autoencoder(
                    92
                ),

            temporal_result=
                temporal(
                    95
                ),
        )
    )


    print_result(
        "CASE 8 — STAT + BEHAVIOR + TEMPORAL",
        three_source,
    )


    assert three_source[
        "critical_allowed"
    ] is True


    assert three_source[
        "severity"
    ] == "CRITICAL"


    # ============================================================
    # CASE 9
    # ALL FOUR
    # ============================================================

    all_four = (
        engine.calculate(

            rule_result=
                rule(
                    92
                ),

            statistical_result=
                statistical(
                    85
                ),

            isolation_result=
                isolation(
                    96
                ),

            autoencoder_result=
                autoencoder(
                    93
                ),

            temporal_result=
                temporal(
                    97
                ),
        )
    )


    print_result(
        "CASE 9 — ALL FOUR STRONG",
        all_four,
    )


    assert all_four[
        "critical_allowed"
    ] is True


    assert all_four[
        "severity"
    ] == "CRITICAL"


    assert all_four[
        "active_signal_count"
    ] == 4


    # ============================================================
    # CASE 10
    # BEHAVIORAL/TEMPORAL DISAGREEMENT
    # ============================================================

    disagreement = (
        engine.calculate(

            rule_result=
                rule(
                    0
                ),

            statistical_result=
                statistical(
                    0
                ),

            isolation_result=
                isolation(
                    96
                ),

            autoencoder_result=
                autoencoder(
                    93
                ),

            temporal_result=
                temporal(
                    10
                ),
        )
    )


    print_result(
        "CASE 10 — AI TEMPORAL DISAGREEMENT",
        disagreement,
    )


    assert disagreement[
        "ai_temporal_disagreement"
    ] is True


    assert (

        disagreement[
            "modifiers"
        ][
            "disagreement_penalty"
        ]

        > 0
    )


    assert disagreement[
        "critical_allowed"
    ] is False


    # ============================================================
    # FINAL
    # ============================================================

    print()

    print(
        "=" * 90
    )

    print(
        "FUSION V3 E2E TEST: PASS"
    )

    print(
        "=" * 90
    )


if __name__ == "__main__":

    main()