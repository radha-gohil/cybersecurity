from __future__ import annotations

from typing import (
    Any,
    Dict,
    Optional,
)


from ai_detection.behavior.dual_ai_agreement import (
    DualAIAgreementEngine,
)


# ================================================================
# SENTINEL-X PROCESS THREAT FUSION V2
#
# Inputs:
#
#   1. Rule-based behavior detector
#   2. Statistical anomaly detector
#   3. Dual-AI behavioral consensus
#
#
# Dual AI itself consists of:
#
#   Isolation Forest
#   +
#   Autoencoder
#
#
# This prevents two related AI models from being counted as two
# completely independent endpoint-security verdicts.
#
# They first become ONE AI consensus signal.
# ================================================================


class ProcessThreatFusionV2:

    def __init__(
        self,
    ):

        self.ai_agreement_engine = (
            DualAIAgreementEngine()
        )


    # ============================================================
    # THRESHOLDS
    # ============================================================

    RULE_ACTIVE = 35.0

    STAT_ACTIVE = 35.0

    AI_ACTIVE = 60.0


    RULE_STRONG = 60.0

    STAT_STRONG = 60.0

    AI_STRONG = 80.0


    # ============================================================
    # WEIGHTS
    # ============================================================

    RULE_WEIGHT = 0.45

    STAT_WEIGHT = 0.20

    AI_WEIGHT = 0.35


    # ============================================================
    # SCORE
    # ============================================================

    def clamp(
        self,
        value: Any,
    ) -> float:

        try:

            number = float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return 0.0

        return max(
            0.0,
            min(
                100.0,
                number,
            ),
        )


    # ============================================================
    # SEVERITY
    # ============================================================

    def score_to_severity(
        self,
        score: float,
    ) -> str:

        if score >= 80:

            return "CRITICAL"

        if score >= 60:

            return "HIGH"

        if score >= 35:

            return "MEDIUM"

        if score >= 15:

            return "LOW"

        return "INFO"


    # ============================================================
    # FUSION
    # ============================================================

    def fuse(

        self,

        behavior_result: Optional[
            Dict[
                str,
                Any,
            ]
        ] = None,

        anomaly_result: Optional[
            Dict[
                str,
                Any,
            ]
        ] = None,

        isolation_result: Optional[
            Dict[
                str,
                Any,
            ]
        ] = None,

        autoencoder_result: Optional[
            Dict[
                str,
                Any,
            ]
        ] = None,

    ) -> Dict[
        str,
        Any,
    ]:


        behavior_result = (
            behavior_result
            or {}
        )


        anomaly_result = (
            anomaly_result
            or {}
        )


        # ========================================================
        # RULE SCORE
        # ========================================================

        rule_score = (
            self.clamp(

                behavior_result.get(
                    "behavior_score",
                    0.0,
                )
            )
        )


        # ========================================================
        # STATISTICAL SCORE
        # ========================================================

        statistical_score = (
            self.clamp(

                anomaly_result.get(
                    "anomaly_score",
                    0.0,
                )
            )
        )


        # ========================================================
        # DUAL-AI CONSENSUS
        # ========================================================

        ai_consensus = (

            self.ai_agreement_engine.calculate(

                isolation_result=
                    isolation_result,

                autoencoder_result=
                    autoencoder_result,
            )
        )


        ai_score = (
            self.clamp(

                ai_consensus.get(
                    "consensus_score",
                    0.0,
                )
            )
        )


        ai_available = (
            ai_consensus.get(
                "available",
                False,
            )
        )


        # ========================================================
        # ACTIVE SIGNALS
        # ========================================================

        rule_active = (

            rule_score
            >= self.RULE_ACTIVE
        )


        stat_active = (

            statistical_score
            >= self.STAT_ACTIVE
        )


        ai_active = (

            ai_available

            and

            ai_score
            >= self.AI_ACTIVE
        )


        active_signals = {

            "rules":
                rule_active,

            "statistical":
                stat_active,

            "behavioral_ai_consensus":
                ai_active,
        }


        active_count = sum(

            1

            for value
            in active_signals.values()

            if value
        )


        # ========================================================
        # STRONG SIGNALS
        # ========================================================

        rule_strong = (

            rule_score
            >= self.RULE_STRONG
        )


        stat_strong = (

            statistical_score
            >= self.STAT_STRONG
        )


        ai_strong = (

            ai_active

            and

            ai_score
            >= self.AI_STRONG
        )


        strong_signals = {

            "rules":
                rule_strong,

            "statistical":
                stat_strong,

            "behavioral_ai_consensus":
                ai_strong,
        }


        strong_count = sum(

            1

            for value
            in strong_signals.values()

            if value
        )


        # ========================================================
        # BASE FUSION SCORE
        # ========================================================

        if ai_available:

            weighted_score = (

                rule_score
                * self.RULE_WEIGHT

                +

                statistical_score
                * self.STAT_WEIGHT

                +

                ai_score
                * self.AI_WEIGHT
            )


        else:

            weighted_score = (

                rule_score
                * 0.70

                +

                statistical_score
                * 0.30
            )


        # ========================================================
        # AGREEMENT BONUS
        # ========================================================

        agreement_bonus = 0.0


        if active_count == 2:

            agreement_bonus += 10.0


        elif active_count == 3:

            agreement_bonus += 18.0


        # ========================================================
        # STRONG EVIDENCE BONUS
        # ========================================================

        strong_bonus = 0.0


        if strong_count >= 2:

            strong_bonus += 10.0


        if (

            rule_strong

            and

            ai_strong

        ):

            strong_bonus += 5.0


        # ========================================================
        # AI INTERNAL AGREEMENT BONUS
        #
        # This is smaller because Isolation Forest and Autoencoder
        # operate on the same underlying endpoint feature vector.
        # ========================================================

        ai_internal_bonus = 0.0


        if (

            ai_consensus.get(
                "both_strong",
                False,
            )

            and

            ai_consensus.get(
                "confidence"
            )
            == "VERY_HIGH"

        ):

            ai_internal_bonus = 4.0


        # ========================================================
        # AI DISAGREEMENT PENALTY
        # ========================================================

        ai_disagreement_penalty = 0.0


        if ai_consensus.get(
            "disagreement",
            False,
        ):

            ai_disagreement_penalty = 8.0


        # ========================================================
        # INITIAL SCORE
        # ========================================================

        fusion_score = (

            weighted_score

            + agreement_bonus

            + strong_bonus

            + ai_internal_bonus

            - ai_disagreement_penalty
        )


        # ========================================================
        # SINGLE-SOURCE PROTECTION
        # ========================================================

        if active_count == 1:

            # ----------------------------------------------------
            # RULE ONLY
            # ----------------------------------------------------

            if rule_active:

                fusion_score = max(

                    fusion_score,

                    rule_score
                    * 0.75,
                )


                fusion_score = min(

                    fusion_score,

                    79.0,
                )


            # ----------------------------------------------------
            # STAT ONLY
            # ----------------------------------------------------

            elif stat_active:

                fusion_score = max(

                    fusion_score,

                    statistical_score
                    * 0.55,
                )


                fusion_score = min(

                    fusion_score,

                    59.0,
                )


            # ----------------------------------------------------
            # AI CONSENSUS ONLY
            #
            # Even BOTH AI models agreeing strongly cannot
            # independently force CRITICAL endpoint severity.
            # ----------------------------------------------------

            elif ai_active:

                fusion_score = max(

                    fusion_score,

                    ai_score
                    * 0.60,
                )


                fusion_score = min(

                    fusion_score,

                    69.0,
                )


        # ========================================================
        # CRITICAL GATING
        #
        # CRITICAL requires at least two independent security
        # evidence categories.
        #
        # Examples:
        #
        # Rules + AI
        # Rules + Statistical
        # Statistical + AI
        #
        # Two AI models alone still count as ONE AI category.
        # ========================================================

        critical_allowed = (

            active_count >= 2

            and

            strong_count >= 2
        )


        if (

            fusion_score >= 80

            and

            not critical_allowed

        ):

            fusion_score = 79.0


        fusion_score = round(

            self.clamp(
                fusion_score
            ),

            2,
        )


        severity = (
            self.score_to_severity(
                fusion_score
            )
        )


        # ========================================================
        # EVIDENCE CONFIDENCE
        # ========================================================

        if (

            active_count == 3

            and

            strong_count >= 2

        ):

            evidence_confidence = (
                "VERY_HIGH"
            )


        elif (

            active_count >= 2

            and

            strong_count >= 1

        ):

            evidence_confidence = (
                "HIGH"
            )


        elif active_count >= 2:

            evidence_confidence = (
                "MODERATE"
            )


        elif active_count == 1:

            evidence_confidence = (
                "LOW"
            )


        else:

            evidence_confidence = (
                "NONE"
            )


        # ========================================================
        # REASONS
        # ========================================================

        reasons = []


        if rule_active:

            reasons.append(

                f"Rule evidence score={rule_score:.2f}"
            )


        if stat_active:

            reasons.append(

                (
                    "Statistical anomaly "
                    f"score={statistical_score:.2f}"
                )
            )


        if ai_active:

            reasons.append(

                (
                    "Dual-AI behavioral consensus "
                    f"score={ai_score:.2f}"
                )
            )


        if ai_consensus.get(
            "disagreement",
            False,
        ):

            reasons.append(

                "Isolation Forest and Autoencoder disagree."
            )


        if ai_consensus.get(
            "both_strong",
            False,
        ):

            reasons.append(

                "Isolation Forest and Autoencoder "
                "both report strong anomaly evidence."
            )


        if active_count >= 2:

            reasons.append(

                (
                    f"{active_count} independent security "
                    "evidence categories agree."
                )
            )


        if not reasons:

            reasons.append(

                "No detection category crossed its "
                "suspicious threshold."
            )


        # ========================================================
        # FINAL
        # ========================================================

        return {

            "rule_score":
                round(
                    rule_score,
                    2,
                ),

            "statistical_score":
                round(
                    statistical_score,
                    2,
                ),

            "ai_consensus_score":
                round(
                    ai_score,
                    2,
                ),

            "ai_consensus":
                ai_consensus,

            "active_signals":
                active_signals,

            "strong_signals":
                strong_signals,

            "active_signal_count":
                active_count,

            "strong_signal_count":
                strong_count,

            "weighted_score":
                round(
                    weighted_score,
                    2,
                ),

            "agreement_bonus":
                agreement_bonus,

            "strong_bonus":
                strong_bonus,

            "ai_internal_bonus":
                ai_internal_bonus,

            "ai_disagreement_penalty":
                ai_disagreement_penalty,

            "fusion_score":
                fusion_score,

            "severity":
                severity,

            "suspicious":
                fusion_score >= 35,

            "should_alert":
                fusion_score >= 60,

            "critical_allowed":
                critical_allowed,

            "evidence_confidence":
                evidence_confidence,

            "reasons":
                reasons,

            "behavior_indicators":
                behavior_result.get(
                    "indicators",
                    [],
                ),

            "statistical_indicators":
                anomaly_result.get(
                    "indicators",
                    [],
                ),
        }


# ================================================================
# MANUAL TEST
# ================================================================

if __name__ == "__main__":

    fusion = (
        ProcessThreatFusionV2()
    )


    result = (
        fusion.fuse(

            behavior_result={

                "behavior_score":
                    0,
            },

            anomaly_result={

                "anomaly_score":
                    0,
            },

            isolation_result={

                "available":
                    True,

                "anomaly_confidence":
                    100,
            },

            autoencoder_result={

                "available":
                    True,

                "anomaly_confidence":
                    10,
            },
        )
    )


    print(
        result
    )