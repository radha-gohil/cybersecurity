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


from ai_detection.behavior.process_threat_fusion_v2 import (
    ProcessThreatFusionV2,
)


def main():

    engine = (
        ProcessThreatFusionV2()
    )


    cases = [

        {
            "name":
                "NORMAL ALL",

            "rule":
                0,

            "stat":
                0,

            "iforest":
                8,

            "autoencoder":
                12,
        },

        {
            "name":
                "ISOLATION FOREST FALSE-ALARM STYLE",

            "rule":
                0,

            "stat":
                0,

            "iforest":
                100,

            "autoencoder":
                10,
        },

        {
            "name":
                "DUAL AI STRONG AGREEMENT ONLY",

            "rule":
                0,

            "stat":
                0,

            "iforest":
                94,

            "autoencoder":
                91,
        },

        {
            "name":
                "RULE + DUAL AI",

            "rule":
                90,

            "stat":
                15,

            "iforest":
                94,

            "autoencoder":
                91,
        },

        {
            "name":
                "STAT + DUAL AI",

            "rule":
                0,

            "stat":
                85,

            "iforest":
                91,

            "autoencoder":
                88,
        },

        {
            "name":
                "ALL THREE CATEGORIES",

            "rule":
                90,

            "stat":
                80,

            "iforest":
                95,

            "autoencoder":
                92,
        },
    ]


    checks = {}


    for case in cases:

        result = (
            engine.fuse(

                behavior_result={

                    "behavior_score":
                        case[
                            "rule"
                        ],
                },

                anomaly_result={

                    "anomaly_score":
                        case[
                            "stat"
                        ],
                },

                isolation_result={

                    "available":
                        True,

                    "anomaly_confidence":
                        case[
                            "iforest"
                        ],
                },

                autoencoder_result={

                    "available":
                        True,

                    "anomaly_confidence":
                        case[
                            "autoencoder"
                        ],
                },
            )
        )


        print()

        print(
            "=" * 80
        )

        print(
            case[
                "name"
            ]
        )

        print(
            "=" * 80
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
            "IF:",
            result[
                "ai_consensus"
            ][
                "isolation_forest_score"
            ],
        )


        print(
            "AE:",
            result[
                "ai_consensus"
            ][
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
                "ai_consensus"
            ][
                "agreement"
            ],
        )


        print(
            "AI disagreement:",
            result[
                "ai_consensus"
            ][
                "disagreement"
            ],
        )


        print(
            "Active categories:",
            result[
                "active_signal_count"
            ],
        )


        print(
            "Strong categories:",
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


        if case[
            "name"
        ] == "NORMAL ALL":

            checks[
                "normal_no_alert"
            ] = (

                result[
                    "should_alert"
                ]
                is False
            )


        if case[
            "name"
        ] == "ISOLATION FOREST FALSE-ALARM STYLE":

            checks[
                "ai_disagreement_detected"
            ] = (

                result[
                    "ai_consensus"
                ][
                    "disagreement"
                ]
                is True
            )


            checks[
                "ai_disagreement_not_critical"
            ] = (

                result[
                    "severity"
                ]
                != "CRITICAL"
            )


        if case[
            "name"
        ] == "DUAL AI STRONG AGREEMENT ONLY":

            checks[
                "dual_ai_strong_agreement"
            ] = (

                result[
                    "ai_consensus"
                ][
                    "both_strong"
                ]
                is True
            )


            checks[
                "dual_ai_alone_not_critical"
            ] = (

                result[
                    "critical_allowed"
                ]
                is False
            )


        if case[
            "name"
        ] == "RULE + DUAL AI":

            checks[
                "rule_ai_critical_allowed"
            ] = (

                result[
                    "critical_allowed"
                ]
                is True
            )


        if case[
            "name"
        ] == "ALL THREE CATEGORIES":

            checks[
                "all_categories_very_high"
            ] = (

                result[
                    "evidence_confidence"
                ]
                == "VERY_HIGH"
            )


            checks[
                "all_categories_critical"
            ] = (

                result[
                    "severity"
                ]
                == "CRITICAL"
            )


    print()

    print(
        "=" * 80
    )

    print(
        "CHECKS"
    )

    print(
        "=" * 80
    )


    failed = 0


    for (
        name,
        passed,
    ) in checks.items():

        print(

            f"{name:<45}: "

            + (
                "PASS"
                if passed
                else "FAIL"
            )
        )


        if not passed:

            failed += 1


    print()

    if failed == 0:

        print(
            "DUAL-AI FUSION E2E TEST: PASS"
        )

        return 0


    print(
        "DUAL-AI FUSION E2E TEST: FAIL"
    )

    return 1


if __name__ == "__main__":

    sys.exit(
        main()
    )