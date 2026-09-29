from __future__ import annotations

from typing import Any, Dict, Optional


class DualAIAgreementEngine:

    ACTIVE_THRESHOLD = 60.0
    STRONG_THRESHOLD = 80.0

    VERY_CLOSE_DISTANCE = 10.0
    CLOSE_DISTANCE = 20.0
    MODERATE_DISTANCE = 35.0


    # ============================================================
    # SCORE NORMALIZATION
    # ============================================================

    def clamp(
        self,
        value: Any,
    ) -> float:

        try:
            number = float(value)

        except (TypeError, ValueError):
            return 0.0

        return max(
            0.0,
            min(100.0, number),
        )


    # ============================================================
    # VALID MODEL RESULT
    # ============================================================

    def valid_model_result(
        self,
        result: Optional[Dict[str, Any]],
    ) -> bool:

        if not result:
            return False

        if not result.get(
            "available",
            False,
        ):
            return False

        if result.get(
            "prediction_failed",
            False,
        ):
            return False

        return (
            result.get(
                "anomaly_confidence"
            )
            is not None
        )


    # ============================================================
    # AGREEMENT LEVEL
    # ============================================================

    def agreement_level(
        self,
        difference: float,
    ) -> str:

        if difference <= self.VERY_CLOSE_DISTANCE:
            return "VERY_HIGH"

        if difference <= self.CLOSE_DISTANCE:
            return "HIGH"

        if difference <= self.MODERATE_DISTANCE:
            return "MODERATE"

        return "LOW"


    # ============================================================
    # DUAL-AI CONSENSUS
    # ============================================================

    def calculate(
        self,
        isolation_result: Optional[Dict[str, Any]],
        autoencoder_result: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:

        isolation_available = (
            self.valid_model_result(
                isolation_result
            )
        )

        autoencoder_available = (
            self.valid_model_result(
                autoencoder_result
            )
        )


        isolation_score = (
            self.clamp(
                isolation_result.get(
                    "anomaly_confidence",
                    0.0,
                )
            )
            if isolation_available
            else 0.0
        )


        autoencoder_score = (
            self.clamp(
                autoencoder_result.get(
                    "anomaly_confidence",
                    0.0,
                )
            )
            if autoencoder_available
            else 0.0
        )


        # ========================================================
        # NO MODELS AVAILABLE
        # ========================================================

        if (
            not isolation_available
            and not autoencoder_available
        ):

            return {
                "available": False,
                "model_count": 0,

                "isolation_forest_available": False,
                "autoencoder_available": False,

                "isolation_forest_score": 0.0,
                "autoencoder_score": 0.0,

                "average_score": 0.0,
                "consensus_score": 0.0,
                "consensus_label": "NORMAL",

                "agreement": "NONE",
                "agreement_difference": None,

                "isolation_forest_active": False,
                "autoencoder_active": False,

                "isolation_forest_strong": False,
                "autoencoder_strong": False,

                "both_active": False,
                "both_strong": False,

                "disagreement": False,

                "confidence": "NONE",

                "reason":
                    "No behavioral AI model result is available.",
            }


        # ========================================================
        # ISOLATION FOREST ONLY
        # ========================================================

        if (
            isolation_available
            and not autoencoder_available
        ):

            consensus_score = (
                isolation_score
                * 0.65
            )

            consensus_score = round(
                self.clamp(
                    consensus_score
                ),
                2,
            )

            return {
                "available": True,
                "model_count": 1,

                "isolation_forest_available": True,
                "autoencoder_available": False,

                "isolation_forest_score":
                    round(
                        isolation_score,
                        2,
                    ),

                "autoencoder_score": 0.0,

                "average_score":
                    round(
                        isolation_score,
                        2,
                    ),

                "consensus_score":
                    consensus_score,

                "consensus_label":
                    self.score_to_label(
                        consensus_score
                    ),

                "agreement": "SINGLE_MODEL",
                "agreement_difference": None,

                "isolation_forest_active":
                    (
                        isolation_score
                        >= self.ACTIVE_THRESHOLD
                    ),

                "autoencoder_active": False,

                "isolation_forest_strong":
                    (
                        isolation_score
                        >= self.STRONG_THRESHOLD
                    ),

                "autoencoder_strong": False,

                "both_active": False,
                "both_strong": False,

                "disagreement": False,

                "confidence": "LOW",

                "reason":
                    (
                        "Only Isolation Forest is available; "
                        "AI confidence reduced."
                    ),
            }


        # ========================================================
        # AUTOENCODER ONLY
        # ========================================================

        if (
            autoencoder_available
            and not isolation_available
        ):

            consensus_score = (
                autoencoder_score
                * 0.65
            )

            consensus_score = round(
                self.clamp(
                    consensus_score
                ),
                2,
            )

            return {
                "available": True,
                "model_count": 1,

                "isolation_forest_available": False,
                "autoencoder_available": True,

                "isolation_forest_score": 0.0,

                "autoencoder_score":
                    round(
                        autoencoder_score,
                        2,
                    ),

                "average_score":
                    round(
                        autoencoder_score,
                        2,
                    ),

                "consensus_score":
                    consensus_score,

                "consensus_label":
                    self.score_to_label(
                        consensus_score
                    ),

                "agreement": "SINGLE_MODEL",
                "agreement_difference": None,

                "isolation_forest_active": False,

                "autoencoder_active":
                    (
                        autoencoder_score
                        >= self.ACTIVE_THRESHOLD
                    ),

                "isolation_forest_strong": False,

                "autoencoder_strong":
                    (
                        autoencoder_score
                        >= self.STRONG_THRESHOLD
                    ),

                "both_active": False,
                "both_strong": False,

                "disagreement": False,

                "confidence": "LOW",

                "reason":
                    (
                        "Only Autoencoder is available; "
                        "AI confidence reduced."
                    ),
            }


        # ========================================================
        # BOTH MODELS AVAILABLE
        # ========================================================

        difference = abs(
            isolation_score
            - autoencoder_score
        )


        average_score = (
            isolation_score
            + autoencoder_score
        ) / 2.0


        isolation_active = (
            isolation_score
            >= self.ACTIVE_THRESHOLD
        )


        autoencoder_active = (
            autoencoder_score
            >= self.ACTIVE_THRESHOLD
        )


        isolation_strong = (
            isolation_score
            >= self.STRONG_THRESHOLD
        )


        autoencoder_strong = (
            autoencoder_score
            >= self.STRONG_THRESHOLD
        )


        both_active = (
            isolation_active
            and autoencoder_active
        )


        both_strong = (
            isolation_strong
            and autoencoder_strong
        )


        agreement = (
            self.agreement_level(
                difference
            )
        )


        # ========================================================
        # CASE 1
        # BOTH STRONGLY AGREE
        # ========================================================

        if both_strong:

            if difference <= 10.0:

                consensus_score = min(
                    100.0,
                    average_score + 8.0,
                )

                confidence = (
                    "VERY_HIGH"
                )

            elif difference <= 20.0:

                consensus_score = min(
                    100.0,
                    average_score + 4.0,
                )

                confidence = (
                    "HIGH"
                )

            else:

                consensus_score = (
                    average_score
                )

                confidence = (
                    "MODERATE"
                )

            disagreement = False


        # ========================================================
        # CASE 2
        # BOTH ACTIVE
        # ========================================================

        elif both_active:

            consensus_score = min(
                89.0,
                average_score + 3.0,
            )

            if difference <= 20.0:

                confidence = (
                    "HIGH"
                )

            else:

                confidence = (
                    "MODERATE"
                )

            disagreement = (
                difference
                > self.MODERATE_DISTANCE
            )


        # ========================================================
        # CASE 3
        # ONE MODEL HIGH, OTHER LOW
        #
        # Example:
        #
        # Isolation Forest = 100
        # Autoencoder      = 12
        #
        # This is disagreement.
        # ========================================================

        elif (
            isolation_active
            != autoencoder_active
        ):

            high_score = max(
                isolation_score,
                autoencoder_score,
            )

            low_score = min(
                isolation_score,
                autoencoder_score,
            )


            consensus_score = (
                high_score
                * 0.45
                +
                low_score
                * 0.20
            )


            consensus_score = min(
                consensus_score,
                59.0,
            )


            disagreement = True

            confidence = (
                "LOW"
            )


        # ========================================================
        # CASE 4
        # BOTH LOW
        # ========================================================

        else:

            consensus_score = (
                average_score
            )


            disagreement = False


            if difference <= 20.0:

                confidence = (
                    "MODERATE"
                )

            else:

                confidence = (
                    "LOW"
                )


        consensus_score = round(
            self.clamp(
                consensus_score
            ),
            2,
        )


        # ========================================================
        # REASON
        # ========================================================

        if disagreement:

            reason = (
                "Behavioral AI models disagree; "
                "consensus confidence was reduced."
            )

        elif both_strong:

            reason = (
                "Isolation Forest and Autoencoder both report "
                "strong behavioral anomaly evidence."
            )

        elif both_active:

            reason = (
                "Isolation Forest and Autoencoder both report "
                "suspicious behavioral activity."
            )

        else:

            reason = (
                "Behavioral AI models do not jointly report "
                "a strong anomaly."
            )


        return {
            "available": True,
            "model_count": 2,

            "isolation_forest_available": True,
            "autoencoder_available": True,

            "isolation_forest_score":
                round(
                    isolation_score,
                    2,
                ),

            "autoencoder_score":
                round(
                    autoencoder_score,
                    2,
                ),

            "average_score":
                round(
                    average_score,
                    2,
                ),

            "consensus_score":
                consensus_score,

            "consensus_label":
                self.score_to_label(
                    consensus_score
                ),

            "agreement":
                agreement,

            "agreement_difference":
                round(
                    difference,
                    2,
                ),

            "isolation_forest_active":
                isolation_active,

            "autoencoder_active":
                autoencoder_active,

            "isolation_forest_strong":
                isolation_strong,

            "autoencoder_strong":
                autoencoder_strong,

            "both_active":
                both_active,

            "both_strong":
                both_strong,

            "disagreement":
                disagreement,

            "confidence":
                confidence,

            "reason":
                reason,
        }


    # ============================================================
    # SCORE → LABEL
    # ============================================================

    def score_to_label(
        self,
        score: float,
    ) -> str:

        if score >= 80.0:
            return "HIGH_ANOMALY"

        if score >= 60.0:
            return "SUSPICIOUS"

        if score >= 40.0:
            return "UNUSUAL"

        return "NORMAL"


# ================================================================
# MANUAL TEST
# ================================================================

if __name__ == "__main__":

    engine = (
        DualAIAgreementEngine()
    )


    cases = [
        (
            "NORMAL AGREEMENT",
            10,
            15,
        ),

        (
            "STRONG AGREEMENT",
            92,
            89,
        ),

        (
            "EXTREME DISAGREEMENT",
            100,
            12,
        ),

        (
            "MODERATE AGREEMENT",
            70,
            66,
        ),
    ]


    for (
        title,
        isolation_score,
        autoencoder_score,
    ) in cases:

        print()

        print(
            "=" * 70
        )

        print(
            title
        )

        print(
            "=" * 70
        )


        result = (
            engine.calculate(

                isolation_result={
                    "available": True,
                    "anomaly_confidence":
                        isolation_score,
                },

                autoencoder_result={
                    "available": True,
                    "anomaly_confidence":
                        autoencoder_score,
                },
            )
        )


        print(
            result
        )