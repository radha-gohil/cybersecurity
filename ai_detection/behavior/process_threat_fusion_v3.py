from __future__ import annotations

import math

from typing import (
    Any,
    Dict,
    Optional,
)


from ai_detection.behavior.dual_ai_agreement import (
    DualAIAgreementEngine,
)


# ================================================================
# SENTINEL-X PROCESS THREAT FUSION V3
#
# Evidence categories:
#
#   1. Rules
#   2. Statistical behavior
#   3. Behavioral AI consensus
#        Isolation Forest + Autoencoder
#   4. Temporal AI
#        Temporal Transformer
#
#
# IMPORTANT
# ================================================================
#
# Isolation Forest and Autoencoder are NOT counted as two
# independent evidence categories.
#
# They become:
#
#       Behavioral AI Consensus
#
#
# Temporal AI is counted separately because it evaluates:
#
#       sequence consistency across time
#
# rather than only one instantaneous observation.
#
#
# However:
#
#       Behavioral AI + Temporal AI
#
# alone cannot produce CRITICAL.
#
# CRITICAL requires corroboration from a non-AI evidence source.
# ================================================================


FUSION_NAME = (
    "sentinelx_process_threat_fusion"
)

FUSION_VERSION = "v3"


# ================================================================
# CATEGORY THRESHOLDS
# ================================================================

RULE_ACTIVE_THRESHOLD = 35.0
RULE_STRONG_THRESHOLD = 60.0

STATISTICAL_ACTIVE_THRESHOLD = 35.0
STATISTICAL_STRONG_THRESHOLD = 60.0

BEHAVIOR_AI_ACTIVE_THRESHOLD = 60.0
BEHAVIOR_AI_STRONG_THRESHOLD = 80.0

TEMPORAL_AI_ACTIVE_THRESHOLD = 60.0
TEMPORAL_AI_STRONG_THRESHOLD = 80.0


# ================================================================
# CATEGORY WEIGHTS
#
# Rules retain the largest individual influence.
#
# Behavioral AI and Temporal AI receive equal weighting.
#
# Statistical evidence is supportive but lower-weighted.
# ================================================================

CATEGORY_WEIGHTS = {
    "rules":
        0.35,

    "statistical":
        0.15,

    "behavioral_ai":
        0.25,

    "temporal_ai":
        0.25,
}


# ================================================================
# SCORE POLICY
# ================================================================

ALERT_THRESHOLD = 60.0

CRITICAL_THRESHOLD = 80.0


# ================================================================
# HELPERS
# ================================================================

def safe_float(
    value: Any,
) -> Optional[float]:

    try:

        number = float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return None


    if not math.isfinite(
        number
    ):

        return None


    return float(
        max(
            0.0,
            min(
                100.0,
                number,
            ),
        )
    )


# ================================================================
# FUSION ENGINE
# ================================================================

class ProcessThreatFusionV3:

    def __init__(
        self,
    ):

        self.dual_ai_engine = (
            DualAIAgreementEngine()
        )


    # ============================================================
    # GENERIC SCORE EXTRACTION
    # ============================================================

    def extract_score(
        self,
        result: Optional[
            Dict[str, Any]
        ],
        candidate_keys,
    ) -> Dict[str, Any]:

        if not isinstance(
            result,
            dict,
        ):

            return {
                "available":
                    False,

                "score":
                    0.0,
            }


        if result.get(
            "available"
        ) is False:

            return {
                "available":
                    False,

                "score":
                    0.0,
            }


        for key in candidate_keys:

            if key not in result:

                continue


            score = (
                safe_float(
                    result.get(
                        key
                    )
                )
            )


            if score is not None:

                return {
                    "available":
                        True,

                    "score":
                        score,

                    "source_key":
                        key,
                }


        return {
            "available":
                True,

            "score":
                0.0,

            "source_key":
                None,
        }


    # ============================================================
    # RULE SCORE
    # ============================================================

    def extract_rule_score(
        self,
        result,
    ):

        return self.extract_score(

            result,

            [
                "score",
                "risk_score",
                "threat_score",
                "behavior_score",
                "anomaly_score",
                "confidence",
            ],
        )


    # ============================================================
    # STATISTICAL SCORE
    # ============================================================

    def extract_statistical_score(
        self,
        result,
    ):

        return self.extract_score(

            result,

            [
                "score",
                "anomaly_score",
                "anomaly_confidence",
                "risk_score",
                "confidence",
            ],
        )


    # ============================================================
    # TEMPORAL SCORE
    # ============================================================

    def extract_temporal_score(
        self,
        result,
    ):

        return self.extract_score(

            result,

            [
                "anomaly_score",
                "anomaly_confidence",
                "score",
                "risk_score",
            ],
        )


    # ============================================================
    # SEVERITY
    # ============================================================

    def severity_from_score(
        self,
        score: float,
    ) -> str:

        if score >= 80.0:

            return "CRITICAL"


        if score >= 60.0:

            return "HIGH"


        if score >= 35.0:

            return "MEDIUM"


        if score >= 15.0:

            return "LOW"


        return "INFO"


    # ============================================================
    # EVIDENCE CONFIDENCE
    # ============================================================

    def evidence_confidence(
        self,
        *,
        active_count: int,
        strong_count: int,
        critical_allowed: bool,
    ) -> str:

        if (
            critical_allowed
            and strong_count >= 2
        ):

            return "VERY_HIGH"


        if (
            active_count >= 3
            or strong_count >= 2
        ):

            return "HIGH"


        if active_count >= 2:

            return "MODERATE"


        if active_count == 1:

            return "LIMITED"


        return "LOW"


    # ============================================================
    # CALCULATE
    # ============================================================

    def calculate(
        self,
        *,
        rule_result: Optional[
            Dict[str, Any]
        ] = None,
        statistical_result: Optional[
            Dict[str, Any]
        ] = None,
        isolation_result: Optional[
            Dict[str, Any]
        ] = None,
        autoencoder_result: Optional[
            Dict[str, Any]
        ] = None,
        temporal_result: Optional[
            Dict[str, Any]
        ] = None,
    ) -> Dict[str, Any]:

        # ========================================================
        # RULES
        # ========================================================

        rule = (
            self.extract_rule_score(
                rule_result
            )
        )


        rule_score = (
            rule[
                "score"
            ]
        )


        rule_available = (
            rule[
                "available"
            ]
        )


        # ========================================================
        # STATISTICAL
        # ========================================================

        statistical = (
            self.extract_statistical_score(
                statistical_result
            )
        )


        statistical_score = (
            statistical[
                "score"
            ]
        )


        statistical_available = (
            statistical[
                "available"
            ]
        )


        # ========================================================
        # BEHAVIORAL AI CONSENSUS
        # ========================================================

        behavioral_ai = (
            self.dual_ai_engine.calculate(

                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,
            )
        )


        behavioral_score = (
            safe_float(

                behavioral_ai.get(
                    "consensus_score"
                )
            )

            or 0.0
        )


        behavioral_available = bool(

            behavioral_ai.get(
                "available",
                True,
            )
        )


        # ========================================================
        # TEMPORAL AI
        #
        # Temporal inference is unavailable while buffer depth < 8.
        # That must NOT be treated as an anomaly or disagreement.
        # ========================================================

        temporal = (
            self.extract_temporal_score(
                temporal_result
            )
        )


        temporal_score = (
            temporal[
                "score"
            ]
        )


        temporal_available = (
            temporal[
                "available"
            ]
        )


        # ========================================================
        # CATEGORY STATES
        # ========================================================

        categories = {
            "rules": {
                "available":
                    rule_available,

                "score":
                    rule_score,

                "active":
                    (
                        rule_available
                        and rule_score
                        >= RULE_ACTIVE_THRESHOLD
                    ),

                "strong":
                    (
                        rule_available
                        and rule_score
                        >= RULE_STRONG_THRESHOLD
                    ),
            },

            "statistical": {
                "available":
                    statistical_available,

                "score":
                    statistical_score,

                "active":
                    (
                        statistical_available
                        and statistical_score
                        >= STATISTICAL_ACTIVE_THRESHOLD
                    ),

                "strong":
                    (
                        statistical_available
                        and statistical_score
                        >= STATISTICAL_STRONG_THRESHOLD
                    ),
            },

            "behavioral_ai": {
                "available":
                    behavioral_available,

                "score":
                    behavioral_score,

                "active":
                    (
                        behavioral_available
                        and behavioral_score
                        >= BEHAVIOR_AI_ACTIVE_THRESHOLD
                    ),

                "strong":
                    (
                        behavioral_available
                        and behavioral_score
                        >= BEHAVIOR_AI_STRONG_THRESHOLD
                    ),
            },

            "temporal_ai": {
                "available":
                    temporal_available,

                "score":
                    temporal_score,

                "active":
                    (
                        temporal_available
                        and temporal_score
                        >= TEMPORAL_AI_ACTIVE_THRESHOLD
                    ),

                "strong":
                    (
                        temporal_available
                        and temporal_score
                        >= TEMPORAL_AI_STRONG_THRESHOLD
                    ),
            },
        }


        active_categories = [

            name

            for (
                name,
                category,
            ) in categories.items()

            if category[
                "active"
            ]
        ]


        strong_categories = [

            name

            for (
                name,
                category,
            ) in categories.items()

            if category[
                "strong"
            ]
        ]


        available_categories = [

            name

            for (
                name,
                category,
            ) in categories.items()

            if category[
                "available"
            ]
        ]


        active_count = len(
            active_categories
        )


        strong_count = len(
            strong_categories
        )


        # ========================================================
        # BASE SCORE ACROSS AVAILABLE EVIDENCE
        # ========================================================

        available_weight = sum(

            CATEGORY_WEIGHTS[
                name
            ]

            for name
            in available_categories
        )


        if available_weight > 0.0:

            overall_weighted_score = (

                sum(

                    categories[
                        name
                    ][
                        "score"
                    ]
                    * CATEGORY_WEIGHTS[
                        name
                    ]

                    for name
                    in available_categories

                )

                / available_weight
            )

        else:

            overall_weighted_score = 0.0


        # ========================================================
        # ACTIVE-EVIDENCE SCORE
        #
        # Once a category becomes meaningful, corroborating active
        # sources should influence the final score more strongly
        # than inactive background categories.
        # ========================================================

        if active_categories:

            active_weight = sum(

                CATEGORY_WEIGHTS[
                    name
                ]

                for name
                in active_categories
            )


            active_weighted_score = (

                sum(

                    categories[
                        name
                    ][
                        "score"
                    ]
                    * CATEGORY_WEIGHTS[
                        name
                    ]

                    for name
                    in active_categories

                )

                / active_weight
            )


            fusion_score = (

                0.65
                * active_weighted_score

                + 0.35
                * overall_weighted_score
            )


        else:

            active_weighted_score = 0.0

            fusion_score = (
                overall_weighted_score
            )


        # ========================================================
        # CORROBORATION BONUSES
        # ========================================================

        active_bonus = 0.0


        if active_count == 2:

            active_bonus = 4.0


        elif active_count == 3:

            active_bonus = 7.0


        elif active_count >= 4:

            active_bonus = 10.0


        strong_bonus = 0.0


        if strong_count >= 2:

            strong_bonus += 5.0


        if strong_count >= 3:

            strong_bonus += 3.0


        # ========================================================
        # RULE + AI CORROBORATION
        # ========================================================

        rule_behavior_bonus = 0.0


        if (
            categories[
                "rules"
            ][
                "strong"
            ]

            and

            categories[
                "behavioral_ai"
            ][
                "strong"
            ]
        ):

            rule_behavior_bonus = 3.0


        rule_temporal_bonus = 0.0


        if (
            categories[
                "rules"
            ][
                "strong"
            ]

            and

            categories[
                "temporal_ai"
            ][
                "strong"
            ]
        ):

            rule_temporal_bonus = 3.0


        # ========================================================
        # BEHAVIORAL + TEMPORAL AGREEMENT
        #
        # Small bonus only because the two sources are correlated.
        # ========================================================

        ai_temporal_agreement_bonus = 0.0


        ai_temporal_score_difference = None


        if (
            behavioral_available
            and temporal_available
        ):

            ai_temporal_score_difference = abs(

                behavioral_score

                - temporal_score
            )


            if (
                categories[
                    "behavioral_ai"
                ][
                    "active"
                ]

                and

                categories[
                    "temporal_ai"
                ][
                    "active"
                ]

                and

                ai_temporal_score_difference <= 15.0
            ):

                ai_temporal_agreement_bonus = 2.0


        # ========================================================
        # TEMPORAL / BEHAVIORAL DISAGREEMENT
        #
        # Example:
        #
        # behavioral AI = 95
        # temporal AI   = 10
        #
        # Do not escalate aggressively from one model family.
        # ========================================================

        ai_temporal_disagreement = False

        disagreement_penalty = 0.0


        if (
            behavioral_available
            and temporal_available
        ):

            if (
                (
                    behavioral_score >= 80.0
                    and temporal_score < 40.0
                )

                or

                (
                    temporal_score >= 80.0
                    and behavioral_score < 40.0
                )
            ):

                ai_temporal_disagreement = True

                disagreement_penalty = 8.0


        # ========================================================
        # APPLY MODIFIERS
        # ========================================================

        fusion_score += (

            active_bonus

            + strong_bonus

            + rule_behavior_bonus

            + rule_temporal_bonus

            + ai_temporal_agreement_bonus

            - disagreement_penalty
        )


        fusion_score = max(
            0.0,
            min(
                100.0,
                fusion_score,
            ),
        )


        # ========================================================
        # SINGLE-EVIDENCE PROTECTION
        # ========================================================

        single_source_cap = None


        if active_count == 1:

            only_active = (
                active_categories[
                    0
                ]
            )


            if only_active == "rules":

                single_source_cap = 79.0


            elif only_active == "statistical":

                single_source_cap = 59.0


            elif only_active == "behavioral_ai":

                single_source_cap = 69.0


            elif only_active == "temporal_ai":

                single_source_cap = 69.0


            if single_source_cap is not None:

                fusion_score = min(

                    fusion_score,

                    single_source_cap,
                )


        # ========================================================
        # AI-ONLY PROTECTION
        #
        # Behavioral AI + Temporal AI are complementary but not
        # fully independent because both originate from endpoint
        # process behavior.
        #
        # Therefore they cannot produce CRITICAL by themselves.
        # ========================================================

        non_ai_active = (

            categories[
                "rules"
            ][
                "active"
            ]

            or

            categories[
                "statistical"
            ][
                "active"
            ]
        )


        ai_only_evidence = (

            active_count > 0

            and

            not non_ai_active
        )


        if ai_only_evidence:

            fusion_score = min(

                fusion_score,

                79.0,
            )


        # ========================================================
        # CRITICAL GATE
        #
        # CRITICAL requires:
        #
        #   - at least two active categories
        #   - at least two strong categories
        #
        # and either:
        #
        #   strong rule evidence
        #
        # OR
        #
        #   strong statistical evidence + at least 3 active
        #   categories
        #
        # Therefore:
        #
        # behavioral + temporal alone -> NOT CRITICAL
        #
        # statistical + temporal alone -> NOT CRITICAL
        #
        # rule + temporal -> may be CRITICAL
        #
        # rule + behavioral -> may be CRITICAL
        # ========================================================

        rule_strong = (

            categories[
                "rules"
            ][
                "strong"
            ]
        )


        statistical_strong = (

            categories[
                "statistical"
            ][
                "strong"
            ]
        )


        critical_evidence_gate = (

            active_count >= 2

            and

            strong_count >= 2

            and

            (
                rule_strong

                or

                (
                    statistical_strong

                    and

                    active_count >= 3
                )
            )
        )


        critical_allowed = (

            critical_evidence_gate

            and

            fusion_score
            >= CRITICAL_THRESHOLD
        )


        # --------------------------------------------------------
        # If mathematical score crosses 80 but evidence policy
        # rejects CRITICAL, cap at 79.
        # --------------------------------------------------------

        if (
            fusion_score >= CRITICAL_THRESHOLD

            and

            not critical_allowed
        ):

            fusion_score = 79.0


        # ========================================================
        # FINAL OUTPUT
        # ========================================================

        severity = (
            self.severity_from_score(
                fusion_score
            )
        )


        should_alert = (

            fusion_score
            >= ALERT_THRESHOLD
        )


        suspicious = (
            should_alert
        )


        evidence_confidence = (
            self.evidence_confidence(

                active_count=
                    active_count,

                strong_count=
                    strong_count,

                critical_allowed=
                    critical_allowed,
            )
        )


        reasons = []


        if categories[
            "rules"
        ][
            "active"
        ]:

            reasons.append(
                "RULE_EVIDENCE"
            )


        if categories[
            "statistical"
        ][
            "active"
        ]:

            reasons.append(
                "STATISTICAL_EVIDENCE"
            )


        if categories[
            "behavioral_ai"
        ][
            "active"
        ]:

            reasons.append(
                "BEHAVIORAL_AI_EVIDENCE"
            )


        if categories[
            "temporal_ai"
        ][
            "active"
        ]:

            reasons.append(
                "TEMPORAL_AI_EVIDENCE"
            )


        if ai_temporal_agreement_bonus > 0:

            reasons.append(
                "BEHAVIORAL_TEMPORAL_AGREEMENT"
            )


        if ai_temporal_disagreement:

            reasons.append(
                "BEHAVIORAL_TEMPORAL_DISAGREEMENT"
            )


        if critical_allowed:

            reasons.append(
                "CRITICAL_MULTI_SOURCE_CORROBORATION"
            )


        return {
            "fusion_name":
                FUSION_NAME,

            "fusion_version":
                FUSION_VERSION,

            "fusion_score":
                round(
                    fusion_score,
                    4,
                ),

            "severity":
                severity,

            "suspicious":
                suspicious,

            "should_alert":
                should_alert,

            "critical_allowed":
                critical_allowed,

            "critical_evidence_gate":
                critical_evidence_gate,

            "evidence_confidence":
                evidence_confidence,

            "available_category_count":
                len(
                    available_categories
                ),

            "active_signal_count":
                active_count,

            "strong_signal_count":
                strong_count,

            "available_categories":
                available_categories,

            "active_categories":
                active_categories,

            "strong_categories":
                strong_categories,

            "scores": {
                "rules":
                    rule_score,

                "statistical":
                    statistical_score,

                "behavioral_ai_consensus":
                    behavioral_score,

                "temporal_ai":
                    temporal_score,
            },

            "categories":
                categories,

            "behavioral_ai_consensus":
                behavioral_ai,

            "temporal_ai_available":
                temporal_available,

            "ai_temporal_score_difference":
                ai_temporal_score_difference,

            "ai_temporal_disagreement":
                ai_temporal_disagreement,

            "modifiers": {
                "active_bonus":
                    active_bonus,

                "strong_bonus":
                    strong_bonus,

                "rule_behavior_bonus":
                    rule_behavior_bonus,

                "rule_temporal_bonus":
                    rule_temporal_bonus,

                "behavioral_temporal_agreement_bonus":
                    ai_temporal_agreement_bonus,

                "disagreement_penalty":
                    disagreement_penalty,

                "single_source_cap":
                    single_source_cap,

                "ai_only_evidence_cap_applied":
                    ai_only_evidence,
            },

            "overall_weighted_score":
                round(
                    overall_weighted_score,
                    4,
                ),

            "active_weighted_score":
                round(
                    active_weighted_score,
                    4,
                ),

            "reasons":
                reasons,

            "interpretation":
                (
                    "Fusion score combines rules, statistical "
                    "behavior, dual behavioral AI consensus and "
                    "temporal AI. It is a defensive risk score, "
                    "not a probability of compromise."
                ),
        }


# ================================================================
# SHARED ENGINE
# ================================================================

shared_process_threat_fusion_v3 = (
    ProcessThreatFusionV3()
)