from __future__ import annotations

from typing import (
    Any,
    Dict,
    List,
    Optional,
)


from ai_detection.behavior.dual_ai_agreement import (
    DualAIAgreementEngine,
)


# ================================================================
# SENTINEL-X PROCESS THREAT FUSION ENGINE V2
#
# Signals:
#
#   1. Rule-based behavioral evidence
#   2. Statistical anomaly evidence
#   3. Dual-AI behavioral consensus
#
# Dual-AI consensus itself contains:
#
#   Isolation Forest
#   +
#   Autoencoder
#
#
# Safety rules:
#
# - one AI model cannot force CRITICAL
# - two AI models agreeing cannot alone force CRITICAL
# - AI disagreement reduces confidence
# - CRITICAL requires corroborating non-AI evidence
# ================================================================


class ProcessThreatFusionEngine:

    RULE_ACTIVE_THRESHOLD = 35.0

    STATISTICAL_ACTIVE_THRESHOLD = 35.0

    AI_ACTIVE_THRESHOLD = 60.0


    RULE_STRONG_THRESHOLD = 60.0

    STATISTICAL_STRONG_THRESHOLD = 60.0

    AI_STRONG_THRESHOLD = 80.0


    RULE_WEIGHT = 0.40

    STATISTICAL_WEIGHT = 0.20

    AI_CONSENSUS_WEIGHT = 0.40


    def __init__(
        self,
    ):

        self.dual_ai_engine = (
            DualAIAgreementEngine()
        )


    # ============================================================
    # SCORE
    # ============================================================

    def clamp_score(
        self,
        value: Any,
    ) -> float:

        try:

            value = float(
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
                value,
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
    # EVIDENCE CONFIDENCE
    # ============================================================

    def evidence_confidence(

        self,

        active_channels: int,

        strong_channels: int,

        ai_agreement_level: str,

    ) -> str:

        if (

            active_channels >= 3

            and

            strong_channels >= 2

        ):

            return "VERY_HIGH"


        if (

            active_channels >= 2

            and

            strong_channels >= 1

        ):

            return "HIGH"


        if active_channels >= 2:

            return "MODERATE"


        if (

            active_channels == 1

            and

            ai_agreement_level
            in {
                "HIGH",
                "VERY_HIGH",
            }

        ):

            return "MODERATE"


        if active_channels == 1:

            return "LOW"


        return "NONE"


    # ============================================================
    # FUSE
    #
    # ai_prediction remains for backward compatibility and means
    # Isolation Forest.
    # ============================================================

    def fuse(

        self,

        behavior_result: Optional[
            Dict[str, Any]
        ] = None,

        anomaly_result: Optional[
            Dict[str, Any]
        ] = None,

        ai_prediction: Optional[
            Dict[str, Any]
        ] = None,

        autoencoder_prediction: Optional[
            Dict[str, Any]
        ] = None,

    ) -> Dict[str, Any]:


        behavior_result = (
            behavior_result
            or {}
        )


        anomaly_result = (
            anomaly_result
            or {}
        )


        # ========================================================
        # RAW NON-AI SCORES
        # ========================================================

        rule_score = (
            self.clamp_score(

                behavior_result.get(
                    "behavior_score",
                    0,
                )
            )
        )


        statistical_score = (
            self.clamp_score(

                anomaly_result.get(
                    "anomaly_score",
                    0,
                )
            )
        )


        # ========================================================
        # DUAL-AI AGREEMENT
        # ========================================================

        ai_consensus = (
            self.dual_ai_engine.analyze(

                isolation_forest=
                    ai_prediction,

                autoencoder=
                    autoencoder_prediction,
            )
        )


        ai_consensus_score = (
            self.clamp_score(

                ai_consensus.get(
                    "consensus_score",
                    0,
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
        # ACTIVE CHANNELS
        #
        # These are evidence CHANNELS:
        #
        # rule
        # statistics
        # AI consensus
        #
        # Isolation Forest + Autoencoder are retained separately
        # inside AI consensus diagnostics.
        # ========================================================

        rule_active = (

            rule_score
            >= self.RULE_ACTIVE_THRESHOLD
        )


        statistical_active = (

            statistical_score
            >= self.STATISTICAL_ACTIVE_THRESHOLD
        )


        ai_active = (

            ai_available

            and

            ai_consensus_score
            >= self.AI_ACTIVE_THRESHOLD
        )


        active_signals = {

            "behavior_rules":
                rule_active,

            "statistical_anomaly":
                statistical_active,

            "dual_ai_consensus":
                ai_active,
        }


        active_count = sum(

            1

            for value
            in active_signals.values()

            if value
        )


        # ========================================================
        # STRONG CHANNELS
        # ========================================================

        rule_strong = (

            rule_score
            >= self.RULE_STRONG_THRESHOLD
        )


        statistical_strong = (

            statistical_score
            >= self.STATISTICAL_STRONG_THRESHOLD
        )


        ai_strong = (

            ai_available

            and

            ai_consensus.get(
                "strong",
                False,
            )

            and

            ai_consensus_score
            >= self.AI_STRONG_THRESHOLD
        )


        strong_signals = {

            "behavior_rules":
                rule_strong,

            "statistical_anomaly":
                statistical_strong,

            "dual_ai_consensus":
                ai_strong,
        }


        strong_count = sum(

            1

            for value
            in strong_signals.values()

            if value
        )


        # ========================================================
        # WEIGHTED SCORE
        # ========================================================

        if ai_available:

            weighted_score = (

                rule_score
                * self.RULE_WEIGHT

                +

                statistical_score
                * self.STATISTICAL_WEIGHT

                +

                ai_consensus_score
                * self.AI_CONSENSUS_WEIGHT
            )


        else:

            # AI unavailable:
            # redistribute only over rule/statistical channels.

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


        elif active_count >= 3:

            agreement_bonus += 18.0


        # ========================================================
        # STRONG EVIDENCE BONUS
        # ========================================================

        strong_bonus = 0.0


        if strong_count >= 2:

            strong_bonus += 10.0


        # Concrete rule evidence + AI agreement is particularly
        # meaningful.

        if (

            rule_strong

            and

            ai_active

        ):

            strong_bonus += 5.0


        # ========================================================
        # AI DISAGREEMENT PENALTY
        # ========================================================

        disagreement_penalty = 0.0


        if ai_consensus.get(
            "agreement"
        ) == "STRONG_DISAGREEMENT":

            disagreement_penalty = 10.0


        elif ai_consensus.get(
            "agreement"
        ) == "MODERATE_DISAGREEMENT":

            disagreement_penalty = 5.0


        # ========================================================
        # RAW FUSION
        # ========================================================

        fusion_score = (

            weighted_score

            + agreement_bonus

            + strong_bonus

            - disagreement_penalty
        )


        # ========================================================
        # SINGLE-CHANNEL SAFETY
        # ========================================================

        if active_count == 1:

            # Rule only can become HIGH but not CRITICAL.

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


            # Statistical only stays conservative.

            elif statistical_active:

                fusion_score = max(

                    fusion_score,

                    statistical_score
                    * 0.55,
                )


                fusion_score = min(
                    fusion_score,
                    59.0,
                )


            # Dual-AI agreement alone can be stronger than one AI
            # model but cannot reach CRITICAL.

            elif ai_active:

                fusion_score = max(

                    fusion_score,

                    ai_consensus_score
                    * 0.70,
                )


                fusion_score = min(
                    fusion_score,
                    69.0,
                )


        # ========================================================
        # CRITICAL GATING
        #
        # AI agreement alone is NOT enough.
        #
        # CRITICAL is allowed when:
        #
        # 1. strong rules + strong statistics
        #
        # OR
        #
        # 2. strong rules + active dual-AI consensus
        #
        # OR
        #
        # 3. strong statistics + strong dual-AI consensus
        #
        # ========================================================

        critical_allowed = (

            (
                rule_strong

                and

                statistical_strong
            )

            or

            (
                rule_strong

                and

                ai_active
            )

            or

            (
                statistical_strong

                and

                ai_strong
            )
        )


        if (

            fusion_score >= 80.0

            and

            not critical_allowed

        ):

            fusion_score = 79.0


        fusion_score = round(

            self.clamp_score(
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
        # CONTRIBUTING CHANNELS
        # ========================================================

        contributing_engines: List[str] = []


        if rule_active:

            contributing_engines.append(
                "behavior_rules"
            )


        if statistical_active:

            contributing_engines.append(
                "statistical_anomaly"
            )


        if ai_active:

            contributing_engines.append(
                "dual_ai_consensus"
            )


        # ========================================================
        # REASONS
        # ========================================================

        reasons = []


        if rule_active:

            reasons.append(

                f"Rule-based behavior score={rule_score:.2f}"
            )


        if statistical_active:

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
                    f"score={ai_consensus_score:.2f}"
                )
            )


        for reason in (
            ai_consensus.get(
                "reasons",
                []
            )
        ):

            reasons.append(
                f"AI: {reason}"
            )


        if active_count >= 2:

            reasons.append(

                (
                    f"{active_count} independent evidence "
                    "channels crossed their thresholds."
                )
            )


        if not reasons:

            reasons.append(

                "No process threat channel crossed "
                "its suspicious threshold."
            )


        evidence_confidence = (
            self.evidence_confidence(

                active_channels=
                    active_count,

                strong_channels=
                    strong_count,

                ai_agreement_level=
                    ai_consensus.get(
                        "agreement_level",
                        "NONE",
                    ),
            )
        )


        suspicious = (

            fusion_score
            >= 35.0
        )


        should_alert = (

            fusion_score
            >= 60.0
        )


        # ========================================================
        # RETURN
        # ========================================================

        return {

            # ----------------------------------------------------
            # Raw scores
            # ----------------------------------------------------

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

            # Backward-compatible field.
            "ai_score":
                round(
                    ai_consensus_score,
                    2,
                ),

            "ai_available":
                ai_available,


            # ----------------------------------------------------
            # Individual AI
            # ----------------------------------------------------

            "isolation_forest_score":
                ai_consensus.get(
                    "isolation_forest_score",
                    0.0,
                ),

            "autoencoder_score":
                ai_consensus.get(
                    "autoencoder_score",
                    0.0,
                ),

            "ai_consensus_score":
                round(
                    ai_consensus_score,
                    2,
                ),

            "ai_agreement":
                ai_consensus.get(
                    "agreement"
                ),

            "ai_agreement_level":
                ai_consensus.get(
                    "agreement_level"
                ),

            "ai_score_gap":
                ai_consensus.get(
                    "score_gap"
                ),

            "ai_disagreement":
                ai_consensus.get(
                    "disagreement",
                    False,
                ),

            "ai_models_available":
                ai_consensus.get(
                    "available_model_count",
                    0,
                ),

            "ai_consensus":
                ai_consensus,


            # ----------------------------------------------------
            # Channels
            # ----------------------------------------------------

            "active_signals":
                active_signals,

            "strong_signals":
                strong_signals,

            "active_signal_count":
                active_count,

            "strong_signal_count":
                strong_count,


            # ----------------------------------------------------
            # Math
            # ----------------------------------------------------

            "weighted_score":
                round(
                    weighted_score,
                    2,
                ),

            "agreement_bonus":
                round(
                    agreement_bonus,
                    2,
                ),

            "strong_bonus":
                round(
                    strong_bonus,
                    2,
                ),

            "disagreement_penalty":
                round(
                    disagreement_penalty,
                    2,
                ),


            # ----------------------------------------------------
            # Final
            # ----------------------------------------------------

            "fusion_score":
                fusion_score,

            "severity":
                severity,

            "suspicious":
                suspicious,

            "should_alert":
                should_alert,

            "critical_allowed":
                critical_allowed,

            "evidence_confidence":
                evidence_confidence,

            "contributing_engines":
                contributing_engines,

            "reasons":
                reasons,


            # ----------------------------------------------------
            # Existing evidence
            # ----------------------------------------------------

            "behavior_indicators":
                behavior_result.get(
                    "indicators",
                    [],
                ),

            "behavior_reasons":
                behavior_result.get(
                    "reasons",
                    [],
                ),

            "statistical_indicators":
                anomaly_result.get(
                    "indicators",
                    [],
                ),

            "statistical_reasons":
                anomaly_result.get(
                    "reasons",
                    [],
                ),
        }