from datetime import datetime, timezone

from agents.agent_coordinator import (
    AgentCoordinator,
)

from agents.decision_factory import (
    DecisionFactory,
)

from agents.agent_consensus import (
    AgentConsensusEngine,
)

from agents.response_recommendation_agent import (
    ResponseRecommendationAgent,
)

from agents.policy_autonomy_gate import (
    PolicyAutonomyGate,
)


class MultiAgentSecurityPipeline:

    def __init__(
        self,
        autonomy_level: int = 2,
    ):

        self.name = "MultiAgentSecurityPipeline"

        self.autonomy_level = autonomy_level

        self.coordinator = (
            AgentCoordinator()
        )

        self.consensus_engine = (
            AgentConsensusEngine()
        )

        self.response_agent = (
            ResponseRecommendationAgent()
        )

        self.policy_gate = (
            PolicyAutonomyGate(
                autonomy_level=autonomy_level
            )
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(
        self,
    ) -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_dict(
        self,
        value,
    ) -> dict:

        if isinstance(
            value,
            dict,
        ):

            return value

        return {}


    def safe_list(
        self,
        value,
    ) -> list:

        if isinstance(
            value,
            list,
        ):

            return value

        return []


    # ============================================================
    # BUILD STANDARD AGENT DECISIONS
    # ============================================================

    def build_decisions(
        self,
        coordinated_result: dict,
    ) -> list:

        agent_outputs = (
            self.safe_dict(
                coordinated_result.get(
                    "agent_outputs"
                )
            )
        )


        decisions = []


        # --------------------------------------------------------
        # TRIAGE DECISION
        # --------------------------------------------------------

        triage = (
            self.safe_dict(
                agent_outputs.get(
                    "TriageAgent"
                )
            )
        )


        if triage:

            decisions.append(
                DecisionFactory.from_triage(
                    triage
                )
            )


        # --------------------------------------------------------
        # INVESTIGATION DECISION
        # --------------------------------------------------------

        investigation = (
            self.safe_dict(
                agent_outputs.get(
                    "InvestigationAgent"
                )
            )
        )


        if investigation:

            decisions.append(
                DecisionFactory.from_investigation(
                    investigation
                )
            )


        # --------------------------------------------------------
        # RISK DECISION
        # --------------------------------------------------------

        risk = (
            self.safe_dict(
                agent_outputs.get(
                    "RiskAssessmentAgent"
                )
            )
        )


        if risk:

            decisions.append(
                DecisionFactory.from_risk(
                    risk
                )
            )


        return decisions


    # ============================================================
    # SERIALIZE DECISIONS
    # ============================================================

    def serialize_decisions(
        self,
        decisions: list,
    ) -> list:

        serialized = []


        for decision in decisions:

            if hasattr(
                decision,
                "to_dict",
            ):

                serialized.append(
                    decision.to_dict()
                )

            elif isinstance(
                decision,
                dict,
            ):

                serialized.append(
                    decision
                )


        return serialized


    # ============================================================
    # DETERMINE FINAL SECURITY STATE
    # ============================================================

    def determine_security_state(
        self,
        consensus: dict,
        risk: dict,
    ) -> str:

        decision = str(
            consensus.get(
                "final_decision",
                "MONITOR",
            )
        ).upper()


        risk_level = str(
            risk.get(
                "risk_level",
                "INFO",
            )
        ).upper()


        if (
            decision
            == "CONTAINMENT_RECOMMENDED"

            or risk_level
            == "CRITICAL"
        ):

            return "CRITICAL_RESPONSE_REVIEW"


        if decision in {

            "RESPONSE_RECOMMENDED",

            "RESPONSE_REVIEW",
        }:

            return "RESPONSE_REVIEW"


        if decision in {

            "INVESTIGATE",

            "CONTINUE_ANALYSIS",
        }:

            return "UNDER_INVESTIGATION"


        return "MONITORING"


    # ============================================================
    # DETERMINE PIPELINE STATUS
    # ============================================================

    def determine_pipeline_status(
        self,
        coordinated_result: dict,
        decisions: list,
        consensus: dict,
        response: dict,
        policy: dict,
    ) -> str:

        errors = (
            self.safe_list(
                coordinated_result.get(
                    "errors"
                )
            )
        )


        if errors:

            return "COMPLETED_WITH_ERRORS"


        if not decisions:

            return "INCOMPLETE"


        if not consensus:

            return "INCOMPLETE"


        if not response:

            return "INCOMPLETE"


        if not policy:

            return "INCOMPLETE"


        return "COMPLETED"


    # ============================================================
    # RUN COMPLETE MULTI-AGENT PIPELINE
    # ============================================================

    def process_incident(
        self,
        incident: dict,
    ) -> dict:

        incident = (
            self.safe_dict(
                incident
            )
        )


        # ========================================================
        # STEP 1
        # COORDINATED INCIDENT ANALYSIS
        # ========================================================

        coordinated_result = (
            self.coordinator.coordinate(
                incident
            )
        )


        # ========================================================
        # STEP 2
        # STANDARDIZE AGENT DECISIONS
        # ========================================================

        decisions = (
            self.build_decisions(
                coordinated_result
            )
        )


        # ========================================================
        # STEP 3
        # AGENT CONSENSUS
        # ========================================================

        consensus = (
            self.consensus_engine.reach_consensus(
                decisions
            )
        )


        # ========================================================
        # STEP 4
        # RESPONSE RECOMMENDATIONS
        # ========================================================

        risk = (
            self.safe_dict(
                coordinated_result.get(
                    "risk"
                )
            )
        )


        evidence = (
            self.safe_dict(
                coordinated_result.get(
                    "evidence"
                )
            )
        )


        attack_timeline = (
            self.safe_dict(
                coordinated_result.get(
                    "attack_timeline"
                )
            )
        )


        response = (
            self.response_agent.generate(
                consensus,
                risk,
                evidence,
                attack_timeline,
            )
        )


        # ========================================================
        # STEP 5
        # POLICY / AUTONOMY CONTROL
        # ========================================================

        policy = (
            self.policy_gate.evaluate_recommendations(
                response
            )
        )


        # ========================================================
        # STEP 6
        # FINAL SECURITY STATE
        # ========================================================

        security_state = (
            self.determine_security_state(
                consensus,
                risk,
            )
        )


        # ========================================================
        # STEP 7
        # FINAL STATUS
        # ========================================================

        status = (
            self.determine_pipeline_status(
                coordinated_result,
                decisions,
                consensus,
                response,
                policy,
            )
        )


        # ========================================================
        # FINAL RESULT
        # ========================================================

        return {

            "pipeline":
                self.name,

            "processed_at":
                self.now_iso(),

            "incident_id":
                incident.get(
                    "incident_id"
                ),

            "status":
                status,

            "security_state":
                security_state,

            "autonomy_level":
                self.autonomy_level,

            "autonomy_mode":
                policy.get(
                    "autonomy_mode"
                ),

            "coordinated_analysis":
                coordinated_result,

            "agent_decisions":
                self.serialize_decisions(
                    decisions
                ),

            "consensus":
                consensus,

            "response":
                response,

            "policy":
                policy,

            "risk_score":
                risk.get(
                    "risk_score",
                    0,
                ),

            "risk_level":
                risk.get(
                    "risk_level",
                    "INFO",
                ),

            "final_decision":
                consensus.get(
                    "final_decision",
                    "MONITOR",
                ),

            "execution_enabled":
                False,

            "note":
                (
                    "The current SENTINEL-X development build "
                    "performs analysis, consensus, response "
                    "recommendation and policy evaluation only. "
                    "Active containment execution is disabled."
                ),
        }