from pathlib import Path
import sys


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


from ai_detection.behavior.process_threat_fusion import (
    ProcessThreatFusionEngine,
)


def ai_result(
    score: float,
):

    return {

        "available":
            True,

        "prediction_failed":
            False,

        "anomaly_confidence":
            score,

        "anomaly_label":
            (
                "HIGH_ANOMALY"
                if score >= 80
                else
                "SUSPICIOUS"
                if score >= 60
                else
                "UNUSUAL"
                if score >= 40
                else
                "NORMAL"
            ),
    }


def print_result(
    name,
    result,
):

    print()

    print(
        "=" * 78
    )

    print(
        name
    )

    print(
        "=" * 78
    )

    print(
        "Rule:",
        result[
            "rule_score"
        ],
    )

    print(
        "Stat:",
        result[
            "statistical_score"
        ],
    )

    print(
        "Isolation Forest:",
        result[
            "isolation_forest_score"
        ],
    )

    print(
        "Autoencoder:",
        result[
            "autoencoder_score"
        ],
    )

    print(
        "AI consensus:",
        result[
            "ai_consensus_score"
        ],
    )

    print(
        "AI agreement:",
        result[
            "ai_agreement"
        ],
    )

    print(
        "AI gap:",
        result[
            "ai_score_gap"
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
        "Evidence confidence:",
        result[
            "evidence_confidence"
        ],
    )


def main():

    engine = (
        ProcessThreatFusionEngine()
    )


    checks = {}


    # ============================================================
    # 1. NORMAL
    # ============================================================

    normal = engine.fuse(

        behavior_result={
            "behavior_score": 0
        },

        anomaly_result={
            "anomaly_score": 0
        },

        ai_prediction=
            ai_result(
                8
            ),

        autoencoder_prediction=
            ai_result(
                14
            ),
    )


    print_result(
        "TEST 1 — BOTH AI NORMAL",
        normal,
    )


    checks[
        "normal_not_alert"
    ] = (

        normal[
            "should_alert"
        ]
        is False
    )


    # ============================================================
    # 2. ISOLATION FOREST SATURATION
    #
    # IF = 100
    # AE = 10
    #
    # Should be disagreement.
    # ============================================================

    disagreement = engine.fuse(

        behavior_result={
            "behavior_score": 0
        },

        anomaly_result={
            "anomaly_score": 0
        },

        ai_prediction=
            ai_result(
                100
            ),

        autoencoder_prediction=
            ai_result(
                10
            ),
    )


    print_result(
        "TEST 2 — IF=100 / AE=10",
        disagreement,
    )


    checks[
        "disagreement_detected"
    ] = (

        disagreement[
            "ai_disagreement"
        ]
        is True
    )


    checks[
        "disagreement_not_critical"
    ] = (

        disagreement[
            "severity"
        ]
        != "CRITICAL"
    )


    # ============================================================
    # 3. BOTH AI STRONG
    #
    # No rule/stat evidence.
    #
    # Should be strong AI evidence but still not CRITICAL.
    # ============================================================

    ai_only = engine.fuse(

        behavior_result={
            "behavior_score": 0
        },

        anomaly_result={
            "anomaly_score": 0
        },

        ai_prediction=
            ai_result(
                92
            ),

        autoencoder_prediction=
            ai_result(
                89
            ),
    )


    print_result(
        "TEST 3 — BOTH AI STRONG",
        ai_only,
    )


    checks[
        "strong_ai_agreement"
    ] = (

        ai_only[
            "ai_agreement"
        ]
        == "STRONG_ANOMALY_AGREEMENT"
    )


    checks[
        "ai_only_not_critical"
    ] = (

        ai_only[
            "critical_allowed"
        ]
        is False
    )


    checks[
        "ai_only_max_high"
    ] = (

        ai_only[
            "fusion_score"
        ]
        <= 79
    )


    # ============================================================
    # 4. RULE + DUAL AI
    # ============================================================

    rule_ai = engine.fuse(

        behavior_result={
            "behavior_score": 85
        },

        anomaly_result={
            "anomaly_score": 10
        },

        ai_prediction=
            ai_result(
                93
            ),

        autoencoder_prediction=
            ai_result(
                91
            ),
    )


    print_result(
        "TEST 4 — RULE + DUAL-AI AGREEMENT",
        rule_ai,
    )


    checks[
        "rule_ai_critical_allowed"
    ] = (

        rule_ai[
            "critical_allowed"
        ]
        is True
    )


    # ============================================================
    # 5. STAT + DUAL AI
    # ============================================================

    stat_ai = engine.fuse(

        behavior_result={
            "behavior_score": 0
        },

        anomaly_result={
            "anomaly_score": 80
        },

        ai_prediction=
            ai_result(
                90
            ),

        autoencoder_prediction=
            ai_result(
                88
            ),
    )


    print_result(
        "TEST 5 — STAT + DUAL-AI AGREEMENT",
        stat_ai,
    )


    checks[
        "stat_ai_critical_allowed"
    ] = (

        stat_ai[
            "critical_allowed"
        ]
        is True
    )


    # ============================================================
    # 6. RULE + STAT, AI DISAGREES
    #
    # Strong non-AI evidence should still remain meaningful.
    # ============================================================

    rule_stat = engine.fuse(

        behavior_result={
            "behavior_score": 85
        },

        anomaly_result={
            "anomaly_score": 75
        },

        ai_prediction=
            ai_result(
                95
            ),

        autoencoder_prediction=
            ai_result(
                15
            ),
    )


    print_result(
        "TEST 6 — RULE + STAT / AI DISAGREEMENT",
        rule_stat,
    )


    checks[
        "non_ai_evidence_survives_disagreement"
    ] = (

        rule_stat[
            "critical_allowed"
        ]
        is True
    )


    # ============================================================
    # RESULTS
    # ============================================================

    print()

    print(
        "=" * 78
    )

    print(
        "CHECKS"
    )

    print(
        "=" * 78
    )


    failed = 0


    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<50}: "
            f"{'PASS' if passed else 'FAIL'}"
        )


        if not passed:

            failed += 1


    print()

    print(
        "=" * 78
    )


    if failed == 0:

        print(
            "DUAL-AI FUSION V2 TEST: PASS"
        )

        return 0


    print(
        "DUAL-AI FUSION V2 TEST: FAIL"
    )

    return 1


if __name__ == "__main__":

    raise SystemExit(
        main()
    )