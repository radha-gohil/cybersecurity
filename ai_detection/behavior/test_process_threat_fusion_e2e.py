from __future__ import annotations

from pathlib import Path
import sys


# ================================================================
# PROJECT ROOT
#
# Allows this test to run directly:
#
# python .\tests\test_process_threat_fusion_e2e.py
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


from ai_detection.behavior.process_threat_fusion import (
    ProcessThreatFusionEngine,
)


# ================================================================
# SENTINEL-X
# CONTROLLED PROCESS THREAT FUSION E2E TEST
#
# IMPORTANT:
#
# This test does NOT:
#
# - execute malware
# - launch suspicious processes
# - modify registry
# - modify files
# - create network traffic
#
# It only supplies synthetic detector RESULT DICTIONARIES to the
# fusion engine.
# ================================================================


# ================================================================
# PRINT HELPERS
# ================================================================

def print_section(
    title: str,
) -> None:

    print()

    print(
        "=" * 82
    )

    print(
        title
    )

    print(
        "=" * 82
    )


def print_result(
    title: str,
    result: dict,
) -> None:

    print()

    print(
        "-" * 82
    )

    print(
        title
    )

    print(
        "-" * 82
    )

    print(
        "Rule score          :",
        result.get(
            "rule_score"
        ),
    )

    print(
        "Statistical score   :",
        result.get(
            "statistical_score"
        ),
    )

    print(
        "AI score            :",
        result.get(
            "ai_score"
        ),
    )

    print(
        "AI available        :",
        result.get(
            "ai_available"
        ),
    )

    print(
        "Active signals      :",
        result.get(
            "active_signals"
        ),
    )

    print(
        "Strong signals      :",
        result.get(
            "strong_signals"
        ),
    )

    print(
        "Active count        :",
        result.get(
            "active_signal_count"
        ),
    )

    print(
        "Strong count        :",
        result.get(
            "strong_signal_count"
        ),
    )

    print(
        "Weighted score      :",
        result.get(
            "weighted_score"
        ),
    )

    print(
        "Agreement bonus     :",
        result.get(
            "agreement_bonus"
        ),
    )

    print(
        "Strong bonus        :",
        result.get(
            "strong_bonus"
        ),
    )

    print(
        "Fusion score        :",
        result.get(
            "fusion_score"
        ),
    )

    print(
        "Severity            :",
        result.get(
            "severity"
        ),
    )

    print(
        "Suspicious          :",
        result.get(
            "suspicious"
        ),
    )

    print(
        "Should alert        :",
        result.get(
            "should_alert"
        ),
    )

    print(
        "Critical allowed    :",
        result.get(
            "critical_allowed"
        ),
    )

    print(
        "Evidence confidence :",
        result.get(
            "evidence_confidence"
        ),
    )

    print(
        "Engines             :",
        result.get(
            "contributing_engines"
        ),
    )

    print(
        "\nReasons:"
    )

    for reason in (
        result.get(
            "reasons",
            []
        )
    ):

        print(
            f"  - {reason}"
        )


# ================================================================
# CHECK HELPER
# ================================================================

def check(
    name: str,
    condition: bool,
    checks: dict,
) -> None:

    checks[
        name
    ] = bool(
        condition
    )


# ================================================================
# MAIN TEST
# ================================================================

def main() -> int:

    print_section(
        "SENTINEL-X CONTROLLED PROCESS THREAT FUSION E2E TEST"
    )

    print(
        """
This test uses synthetic detector outputs only.

NO malware is executed.
NO suspicious process is started.
NO file is changed.
NO registry key is changed.
NO network traffic is generated.
"""
    )

    fusion = (
        ProcessThreatFusionEngine()
    )

    checks = {}


    # ============================================================
    # TEST 1
    # NORMAL BEHAVIOR
    #
    # Rule = 0
    # Statistical = 0
    # AI = 5
    #
    # Expected:
    #
    # INFO
    # no alert
    # no active evidence
    # ============================================================

    normal_result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    0,

                "suspicious":
                    False,

                "indicators":
                    [],

                "reasons":
                    [],
            },

            anomaly_result={

                "anomaly_score":
                    0,

                "anomalous":
                    False,

                "indicators":
                    [],

                "reasons":
                    [],
            },

            ai_prediction={

                "available":
                    True,

                "anomaly_confidence":
                    5,

                "anomaly_label":
                    "NORMAL",

                "model_outlier":
                    False,

                "feature_deviations":
                    [],
            },
        )
    )

    print_result(
        "TEST 1 — NORMAL BEHAVIOR",
        normal_result,
    )

    check(

        "normal_not_suspicious",

        normal_result[
            "suspicious"
        ] is False,

        checks,
    )

    check(

        "normal_no_alert",

        normal_result[
            "should_alert"
        ] is False,

        checks,
    )

    check(

        "normal_not_critical",

        normal_result[
            "severity"
        ] != "CRITICAL",

        checks,
    )

    check(

        "normal_zero_active_signals",

        normal_result[
            "active_signal_count"
        ] == 0,

        checks,
    )


    # ============================================================
    # TEST 2
    # AI ONLY EXTREME ANOMALY
    #
    # This is the important saturation-protection test.
    #
    # AI = 100
    #
    # Expected:
    #
    # AI alone must NOT create CRITICAL.
    # ============================================================

    ai_only_result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    0,

                "suspicious":
                    False,
            },

            anomaly_result={

                "anomaly_score":
                    0,

                "anomalous":
                    False,
            },

            ai_prediction={

                "available":
                    True,

                "anomaly_confidence":
                    100,

                "anomaly_label":
                    "HIGH_ANOMALY",

                "model_outlier":
                    True,

                "feature_deviations": [

                    {
                        "feature":
                            "network_connection_count",

                        "deviation_std":
                            40.0,
                    }
                ],
            },
        )
    )

    print_result(
        "TEST 2 — AI-ONLY EXTREME ANOMALY",
        ai_only_result,
    )

    check(

        "ai_only_active_count_one",

        ai_only_result[
            "active_signal_count"
        ] == 1,

        checks,
    )

    check(

        "ai_only_not_critical",

        ai_only_result[
            "severity"
        ] != "CRITICAL",

        checks,
    )

    check(

        "ai_only_critical_not_allowed",

        ai_only_result[
            "critical_allowed"
        ] is False,

        checks,
    )

    check(

        "ai_only_score_capped",

        ai_only_result[
            "fusion_score"
        ] <= 59,

        checks,
    )


    # ============================================================
    # TEST 3
    # RULE ONLY
    #
    # Strong deterministic evidence.
    #
    # Expected:
    #
    # Can reach HIGH.
    # Cannot reach CRITICAL alone.
    # ============================================================

    rule_only_result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    100,

                "suspicious":
                    True,

                "indicators": [

                    "document_to_script",

                    "temp_execution",
                ],

                "reasons": [

                    "Document application launched script interpreter",

                    "Process executed from temporary directory",
                ],
            },

            anomaly_result={

                "anomaly_score":
                    0,

                "anomalous":
                    False,
            },

            ai_prediction={

                "available":
                    True,

                "anomaly_confidence":
                    10,

                "anomaly_label":
                    "NORMAL",

                "model_outlier":
                    False,
            },
        )
    )

    print_result(
        "TEST 3 — RULE-ONLY STRONG EVIDENCE",
        rule_only_result,
    )

    check(

        "rule_only_active_one",

        rule_only_result[
            "active_signal_count"
        ] == 1,

        checks,
    )

    check(

        "rule_only_not_critical",

        rule_only_result[
            "severity"
        ] != "CRITICAL",

        checks,
    )

    check(

        "rule_only_critical_not_allowed",

        rule_only_result[
            "critical_allowed"
        ] is False,

        checks,
    )

    check(

        "rule_only_max_79",

        rule_only_result[
            "fusion_score"
        ] <= 79,

        checks,
    )


    # ============================================================
    # TEST 4
    # STATISTICAL ONLY
    #
    # Statistical anomaly alone should remain conservative.
    # ============================================================

    statistical_only_result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    0,

                "suspicious":
                    False,
            },

            anomaly_result={

                "anomaly_score":
                    100,

                "anomalous":
                    True,

                "indicators": [

                    "cpu_z_score",

                    "memory_z_score",
                ],

                "reasons": [

                    "CPU behavior strongly deviated from history",

                    "Memory behavior strongly deviated from history",
                ],
            },

            ai_prediction={

                "available":
                    True,

                "anomaly_confidence":
                    5,

                "anomaly_label":
                    "NORMAL",

                "model_outlier":
                    False,
            },
        )
    )

    print_result(
        "TEST 4 — STATISTICAL-ONLY STRONG ANOMALY",
        statistical_only_result,
    )

    check(

        "stat_only_active_one",

        statistical_only_result[
            "active_signal_count"
        ] == 1,

        checks,
    )

    check(

        "stat_only_not_critical",

        statistical_only_result[
            "severity"
        ] != "CRITICAL",

        checks,
    )

    check(

        "stat_only_score_capped",

        statistical_only_result[
            "fusion_score"
        ] <= 59,

        checks,
    )


    # ============================================================
    # TEST 5
    # RULE + AI AGREEMENT
    #
    # Two independent strong engines agree.
    #
    # Expected:
    #
    # CRITICAL is now allowed.
    # ============================================================

    rule_ai_result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    90,

                "suspicious":
                    True,

                "indicators": [

                    "document_to_script",

                    "encoded_command",
                ],

                "reasons": [

                    "Office application launched script interpreter",

                    "Encoded command behavior observed",
                ],
            },

            anomaly_result={

                "anomaly_score":
                    20,

                "anomalous":
                    False,
            },

            ai_prediction={

                "available":
                    True,

                "anomaly_confidence":
                    95,

                "anomaly_label":
                    "HIGH_ANOMALY",

                "model_outlier":
                    True,

                "feature_deviations": [

                    {
                        "feature":
                            "network_connection_count",

                        "deviation_std":
                            12.0,
                    },

                    {
                        "feature":
                            "command_line_length",

                        "deviation_std":
                            8.0,
                    },
                ],
            },
        )
    )

    print_result(
        "TEST 5 — RULE + AI STRONG AGREEMENT",
        rule_ai_result,
    )

    check(

        "rule_ai_active_two",

        rule_ai_result[
            "active_signal_count"
        ] == 2,

        checks,
    )

    check(

        "rule_ai_strong_two",

        rule_ai_result[
            "strong_signal_count"
        ] >= 2,

        checks,
    )

    check(

        "rule_ai_critical_allowed",

        rule_ai_result[
            "critical_allowed"
        ] is True,

        checks,
    )

    check(

        "rule_ai_high_or_critical",

        rule_ai_result[
            "severity"
        ] in {
            "HIGH",
            "CRITICAL",
        },

        checks,
    )


    # ============================================================
    # TEST 6
    # STATISTICAL + AI AGREEMENT
    #
    # Two behavioral anomaly engines agree, but no deterministic
    # rule evidence exists.
    #
    # CRITICAL is technically allowed by the current fusion policy
    # if both are strong, but actual severity still depends on
    # total fusion score.
    # ============================================================

    statistical_ai_result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    0,

                "suspicious":
                    False,
            },

            anomaly_result={

                "anomaly_score":
                    80,

                "anomalous":
                    True,

                "indicators": [

                    "cpu_z_score",

                    "thread_z_score",
                ],
            },

            ai_prediction={

                "available":
                    True,

                "anomaly_confidence":
                    90,

                "anomaly_label":
                    "HIGH_ANOMALY",

                "model_outlier":
                    True,
            },
        )
    )

    print_result(
        "TEST 6 — STATISTICAL + AI AGREEMENT",
        statistical_ai_result,
    )

    check(

        "stat_ai_active_two",

        statistical_ai_result[
            "active_signal_count"
        ] == 2,

        checks,
    )

    check(

        "stat_ai_strong_two",

        statistical_ai_result[
            "strong_signal_count"
        ] == 2,

        checks,
    )

    check(

        "stat_ai_critical_allowed",

        statistical_ai_result[
            "critical_allowed"
        ] is True,

        checks,
    )

    check(

        "stat_ai_more_severe_than_ai_only",

        statistical_ai_result[
            "fusion_score"
        ]

        > ai_only_result[
            "fusion_score"
        ],

        checks,
    )


    # ============================================================
    # TEST 7
    # ALL THREE ENGINES AGREE
    #
    # Expected strongest evidence.
    # ============================================================

    all_three_result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    85,

                "suspicious":
                    True,

                "indicators": [

                    "document_to_script",

                    "temp_execution",

                    "encoded_command",
                ],
            },

            anomaly_result={

                "anomaly_score":
                    75,

                "anomalous":
                    True,

                "indicators": [

                    "cpu_z_score",

                    "memory_z_score",
                ],
            },

            ai_prediction={

                "available":
                    True,

                "anomaly_confidence":
                    94,

                "anomaly_label":
                    "HIGH_ANOMALY",

                "model_outlier":
                    True,

                "feature_deviations": [

                    {
                        "feature":
                            "network_connection_count",

                        "deviation_std":
                            15.0,
                    }
                ],
            },
        )
    )

    print_result(
        "TEST 7 — ALL THREE ENGINES AGREE",
        all_three_result,
    )

    check(

        "all_three_active",

        all_three_result[
            "active_signal_count"
        ] == 3,

        checks,
    )

    check(

        "all_three_multiple_strong",

        all_three_result[
            "strong_signal_count"
        ] >= 2,

        checks,
    )

    check(

        "all_three_critical_allowed",

        all_three_result[
            "critical_allowed"
        ] is True,

        checks,
    )

    check(

        "all_three_critical",

        all_three_result[
            "severity"
        ] == "CRITICAL",

        checks,
    )

    check(

        "all_three_very_high_confidence",

        all_three_result[
            "evidence_confidence"
        ] == "VERY_HIGH",

        checks,
    )


    # ============================================================
    # TEST 8
    # AI MODEL UNAVAILABLE
    #
    # Fusion must still work using existing detectors.
    # ============================================================

    ai_unavailable_result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    70,

                "suspicious":
                    True,
            },

            anomaly_result={

                "anomaly_score":
                    65,

                "anomalous":
                    True,
            },

            ai_prediction={

                "available":
                    False,

                "error":
                    "Synthetic model unavailable test",
            },
        )
    )

    print_result(
        "TEST 8 — AI MODEL UNAVAILABLE",
        ai_unavailable_result,
    )

    check(

        "ai_unavailable_fusion_still_works",

        ai_unavailable_result[
            "fusion_score"
        ] > 0,

        checks,
    )

    check(

        "ai_unavailable_flag_correct",

        ai_unavailable_result[
            "ai_available"
        ] is False,

        checks,
    )

    check(

        "ai_unavailable_two_existing_signals",

        ai_unavailable_result[
            "active_signal_count"
        ] == 2,

        checks,
    )


    # ============================================================
    # TEST 9
    # BELOW-THRESHOLD NOISE
    #
    # None of the engines crosses the active signal threshold.
    # ============================================================

    low_noise_result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    20,
            },

            anomaly_result={

                "anomaly_score":
                    25,
            },

            ai_prediction={

                "available":
                    True,

                "anomaly_confidence":
                    35,

                "anomaly_label":
                    "NORMAL",

                "model_outlier":
                    False,
            },
        )
    )

    print_result(
        "TEST 9 — BELOW-THRESHOLD NOISE",
        low_noise_result,
    )

    check(

        "noise_no_active_signals",

        low_noise_result[
            "active_signal_count"
        ] == 0,

        checks,
    )

    check(

        "noise_not_critical",

        low_noise_result[
            "severity"
        ] != "CRITICAL",

        checks,
    )

    check(

        "noise_no_alert",

        low_noise_result[
            "should_alert"
        ] is False,

        checks,
    )


    # ============================================================
    # SUMMARY
    # ============================================================

    print_section(
        "FUSION TEST CHECKS"
    )

    passed_count = 0

    failed_count = 0

    for (
        check_name,
        passed,
    ) in checks.items():

        if passed:

            status = (
                "PASS"
            )

            passed_count += 1

        else:

            status = (
                "FAIL"
            )

            failed_count += 1

        print(

            f"{check_name:<55}: "
            f"{status}"
        )


    # ============================================================
    # CORE SAFETY CONDITIONS
    # ============================================================

    core_safety_checks = [

        checks[
            "normal_not_suspicious"
        ],

        checks[
            "normal_no_alert"
        ],

        checks[
            "ai_only_not_critical"
        ],

        checks[
            "ai_only_critical_not_allowed"
        ],

        checks[
            "rule_only_not_critical"
        ],

        checks[
            "stat_only_not_critical"
        ],

        checks[
            "rule_ai_critical_allowed"
        ],

        checks[
            "all_three_critical_allowed"
        ],

        checks[
            "all_three_critical"
        ],

        checks[
            "ai_unavailable_fusion_still_works"
        ],

        checks[
            "noise_no_alert"
        ],
    ]


    # ============================================================
    # FINAL RESULT
    # ============================================================

    print_section(
        "FINAL RESULT"
    )

    print(
        f"Total checks : {len(checks)}"
    )

    print(
        f"Passed       : {passed_count}"
    )

    print(
        f"Failed       : {failed_count}"
    )

    print()


    if (
        failed_count == 0

        and all(
            core_safety_checks
        )
    ):

        print(
            "PROCESS THREAT FUSION E2E TEST: PASS"
        )

        print()

        print(
            "Verified:"
        )

        print(
            "  ✓ Normal behavior remains low."
        )

        print(
            "  ✓ AI=100 alone cannot become CRITICAL."
        )

        print(
            "  ✓ Rule-only evidence cannot become CRITICAL."
        )

        print(
            "  ✓ Statistical-only evidence cannot become CRITICAL."
        )

        print(
            "  ✓ Independent engine agreement increases confidence."
        )

        print(
            "  ✓ Multiple strong signals can permit CRITICAL."
        )

        print(
            "  ✓ All-three agreement produces strongest evidence."
        )

        print(
            "  ✓ Fusion continues working if the AI model is unavailable."
        )

        print()

        print(
            "No real suspicious system activity was performed."
        )

        return 0


    print(
        "PROCESS THREAT FUSION E2E TEST: FAIL"
    )

    print()

    print(
        "Do not continue to automated response logic yet."
    )

    print(
        "Inspect the failed fusion conditions first."
    )

    return 1


# ================================================================
# ENTRY POINT
# ================================================================

if __name__ == "__main__":

    exit_code = (
        main()
    )

    sys.exit(
        exit_code
    )