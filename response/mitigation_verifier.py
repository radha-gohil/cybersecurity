from typing import Dict, List


class MitigationVerifier:
    """
    SENTINEL-X Mitigation Verification Layer.

    IMPORTANT:

    This verifier is simulation-only.

    It does NOT:

        - kill processes
        - block IP addresses
        - change firewall rules
        - quarantine files
        - isolate endpoints
        - change registry values
        - modify operating-system configuration

    It compares:

        before_state
            vs
        simulated_after_state

    and determines whether a candidate response plan appears
    effective inside the simulation model.
    """

    def __init__(
        self,
        verified_threshold: float = 0.70,
        partial_threshold: float = 0.30,
        acceptable_residual_risk: float = 30.0,
    ):

        self.verified_threshold = (
            verified_threshold
        )

        self.partial_threshold = (
            partial_threshold
        )

        self.acceptable_residual_risk = (
            acceptable_residual_risk
        )

        # ========================================================
        # METRIC WEIGHTS
        # ========================================================

        self.metric_weights = {

            "risk_score":
                0.40,

            "suspicious_event_count":
                0.25,

            "active_indicator_count":
                0.20,

            "exposure_score":
                0.15,
        }

    # ============================================================
    # HELPERS
    # ============================================================

    def safe_float(
        self,
        value,
        default=0.0,
    ) -> float:

        try:

            if value is None:
                return default

            return float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return default

    # ============================================================
    # REDUCTION
    # ============================================================

    def calculate_reduction(
        self,
        before_value: float,
        after_value: float,
    ) -> float:

        """
        Returns improvement from 0.0 to 1.0.

        Example:

            before = 100
            after  = 20

            reduction = 0.80
        """

        before_value = (
            self.safe_float(
                before_value
            )
        )

        after_value = (
            self.safe_float(
                after_value
            )
        )

        if before_value <= 0:

            if after_value <= 0:
                return 0.0

            return 0.0

        reduction = (

            before_value
            - after_value

        ) / before_value

        return max(
            0.0,
            min(
                1.0,
                reduction,
            ),
        )

    # ============================================================
    # METRIC COMPARISON
    # ============================================================

    def compare_metrics(
        self,
        before_state: Dict,
        after_state: Dict,
    ) -> Dict:

        metric_results = {}

        weighted_total = 0.0

        total_weight = 0.0

        for (
            metric_name,
            weight,
        ) in self.metric_weights.items():

            before_value = (
                self.safe_float(
                    before_state.get(
                        metric_name
                    )
                )
            )

            after_value = (
                self.safe_float(
                    after_state.get(
                        metric_name
                    )
                )
            )

            reduction = (
                self.calculate_reduction(

                    before_value,

                    after_value,
                )
            )

            metric_results[
                metric_name
            ] = {

                "before":
                    before_value,

                "after":
                    after_value,

                "reduction":
                    round(
                        reduction,
                        4,
                    ),

                "weight":
                    weight,
            }

            weighted_total += (
                reduction
                * weight
            )

            total_weight += (
                weight
            )

        if total_weight <= 0:

            overall_improvement = 0.0

        else:

            overall_improvement = (
                weighted_total
                / total_weight
            )

        return {

            "metrics":
                metric_results,

            "overall_improvement":
                round(
                    overall_improvement,
                    4,
                ),
        }

    # ============================================================
    # STATUS
    # ============================================================

    def determine_status(
        self,
        overall_improvement: float,
        residual_risk: float,
    ) -> str:

        if (
            overall_improvement
            >= self.verified_threshold
            and residual_risk
            <= self.acceptable_residual_risk
        ):

            return (
                "SIMULATION_VERIFIED"
            )

        if (
            overall_improvement
            >= self.partial_threshold
        ):

            return (
                "SIMULATION_PARTIAL"
            )

        return (
            "SIMULATION_NO_IMPROVEMENT"
        )

    # ============================================================
    # NEXT STEP
    # ============================================================

    def get_recommendation(
        self,
        status: str,
    ) -> str:

        if (
            status
            ==
            "SIMULATION_VERIFIED"
        ):

            return (
                "Candidate response plan produced strong modeled "
                "risk reduction. Retain it as a response candidate "
                "for analyst/policy review."
            )

        if (
            status
            ==
            "SIMULATION_PARTIAL"
        ):

            return (
                "Candidate response plan produced partial modeled "
                "improvement. Refine the plan or compare it with "
                "an alternative simulation."
            )

        return (
            "Candidate response plan did not produce sufficient "
            "modeled improvement. Do not promote this candidate "
            "based on the current simulation."
        )

    # ============================================================
    # MAIN VERIFICATION
    # ============================================================

    def verify(
        self,
        before_state: Dict,
        simulated_after_state: Dict,
        response_result: Dict,
    ) -> Dict:

        # ========================================================
        # SAFETY GUARD
        #
        # SENTINEL-X verification in this project must remain
        # simulation-only.
        # ========================================================

        simulation_mode = (
            response_result.get(
                "simulation_mode",
                True,
            )
        )

        if simulation_mode is not True:

            raise ValueError(
                "MitigationVerifier only accepts "
                "simulation-mode response results."
            )

        comparison = (
            self.compare_metrics(

                before_state,

                simulated_after_state,
            )
        )

        overall_improvement = (
            comparison[
                "overall_improvement"
            ]
        )

        residual_risk = (
            self.safe_float(

                simulated_after_state.get(
                    "risk_score"
                )
            )
        )

        status = (
            self.determine_status(

                overall_improvement,

                residual_risk,
            )
        )

        recommendation = (
            self.get_recommendation(
                status
            )
        )

        # ========================================================
        # IDENTIFY IMPROVED METRICS
        # ========================================================

        improved_metrics: List[str] = []

        unchanged_or_worse_metrics: List[str] = []

        for (
            metric_name,
            metric_data,
        ) in (
            comparison[
                "metrics"
            ].items()
        ):

            if (
                metric_data[
                    "reduction"
                ]
                > 0
            ):

                improved_metrics.append(
                    metric_name
                )

            else:

                unchanged_or_worse_metrics.append(
                    metric_name
                )

        return {

            "verification_type":
                "SIMULATED_MITIGATION_VERIFICATION",

            "simulation_mode":
                True,

            "status":
                status,

            "response_action":
                response_result.get(
                    "action"
                ),

            "response_plan_id":
                response_result.get(
                    "plan_id"
                ),

            "overall_improvement":
                overall_improvement,

            # ----------------------------------------------------
            # This is a model/heuristic risk score,
            # not a probability.
            # ----------------------------------------------------

            "residual_risk":
                residual_risk,

            "acceptable_residual_risk":
                self.acceptable_residual_risk,

            "metrics":
                comparison[
                    "metrics"
                ],

            "improved_metrics":
                improved_metrics,

            "unchanged_or_worse_metrics":
                unchanged_or_worse_metrics,

            "recommendation":
                recommendation,

            "interpretation":
                (
                    "This result evaluates a simulated response "
                    "outcome only. It does not confirm that a real "
                    "endpoint has been remediated."
                ),
        }