from agents.shared_context import (
    SharedIncidentContext,
)

from agents.triage_agent import (
    TriageAgent,
)

from agents.investigation_agent import (
    InvestigationAgent,
)

from agents.evidence_enrichment_agent import (
    EvidenceEnrichmentAgent,
)

from agents.attack_timeline_agent import (
    AttackTimelineAgent,
)

from agents.attack_graph_agent import (
    AttackGraphAgent,
)

from agents.risk_assessment_agent import (
    RiskAssessmentAgent,
)

from agents.investigation_report_agent import (
    InvestigationReportAgent,
)


class AgentCoordinator:

    def __init__(self):

        self.name = "AgentCoordinator"

        self.triage_agent = (
            TriageAgent()
        )

        self.investigation_agent = (
            InvestigationAgent()
        )

        self.evidence_agent = (
            EvidenceEnrichmentAgent()
        )

        self.timeline_agent = (
            AttackTimelineAgent()
        )

        self.graph_agent = (
            AttackGraphAgent()
        )

        self.risk_agent = (
            RiskAssessmentAgent()
        )

        self.report_agent = (
            InvestigationReportAgent()
        )


    # ============================================================
    # RUN TRIAGE AGENT
    # ============================================================

    def run_triage(
        self,
        context: SharedIncidentContext,
    ):

        try:

            result = (
                self.triage_agent.triage(
                    context.incident
                )
            )

            context.set_agent_output(
                "TriageAgent",
                result,
            )


            priority = (
                result.get(
                    "priority",
                    "P4",
                )
            )


            confidence = (
                result.get(
                    "triage_score",
                    0,
                )
            )


            if result.get(
                "requires_investigation",
                False,
            ):

                context.add_decision(
                    "TriageAgent",
                    "INVESTIGATE",
                    confidence=confidence,
                    reason=(
                        f"Triage priority is {priority}."
                    ),
                )

            else:

                context.add_decision(
                    "TriageAgent",
                    "MONITOR",
                    confidence=confidence,
                    reason=(
                        f"Triage priority is {priority}."
                    ),
                )


            recommendation = (
                result.get(
                    "recommendation"
                )
            )


            if recommendation:

                context.add_recommendation(
                    "TriageAgent",
                    recommendation,
                    priority=priority,
                )


            return result


        except Exception as error:

            context.add_error(
                "TriageAgent",
                error,
            )

            return {}


    # ============================================================
    # RUN INVESTIGATION AGENT
    # ============================================================

    def run_investigation(
        self,
        context: SharedIncidentContext,
    ):

        try:

            result = (
                self.investigation_agent.investigate(
                    context.incident
                )
            )

            context.set_agent_output(
                "InvestigationAgent",
                result,
            )


            if result.get(
                "requires_response",
                False,
            ):

                context.add_decision(
                    "InvestigationAgent",
                    "RESPONSE_REVIEW",
                    confidence=80,
                    reason=(
                        "Investigation identified a high-priority incident."
                    ),
                )

            else:

                context.add_decision(
                    "InvestigationAgent",
                    "CONTINUE_ANALYSIS",
                    confidence=60,
                    reason=(
                        "Further analysis is appropriate."
                    ),
                )


            return result


        except Exception as error:

            context.add_error(
                "InvestigationAgent",
                error,
            )

            return {}


    # ============================================================
    # RUN EVIDENCE ENRICHMENT
    # ============================================================

    def run_evidence(
        self,
        context: SharedIncidentContext,
    ):

        try:

            result = (
                self.evidence_agent.enrich(
                    context.incident
                )
            )

            context.set_agent_output(
                "EvidenceEnrichmentAgent",
                result,
            )

            context.set_evidence(
                result
            )


            return result


        except Exception as error:

            context.add_error(
                "EvidenceEnrichmentAgent",
                error,
            )

            return {}


    # ============================================================
    # RUN TIMELINE AGENT
    # ============================================================

    def run_timeline(
        self,
        context: SharedIncidentContext,
    ):

        try:

            result = (
                self.timeline_agent.reconstruct(
                    context.incident
                )
            )

            context.set_agent_output(
                "AttackTimelineAgent",
                result,
            )

            context.set_attack_timeline(
                result
            )


            return result


        except Exception as error:

            context.add_error(
                "AttackTimelineAgent",
                error,
            )

            return {}


    # ============================================================
    # RUN ATTACK GRAPH AGENT
    # ============================================================

    def run_graph(
        self,
        context: SharedIncidentContext,
    ):

        try:

            result = (
                self.graph_agent.generate(
                    context.evidence
                )
            )

            context.set_agent_output(
                "AttackGraphAgent",
                result,
            )

            context.set_attack_graph(
                result
            )


            return result


        except Exception as error:

            context.add_error(
                "AttackGraphAgent",
                error,
            )

            return {}


    # ============================================================
    # RUN RISK AGENT
    # ============================================================

    def run_risk(
        self,
        context: SharedIncidentContext,
    ):

        try:

            investigation = (
                context.get_agent_output(
                    "InvestigationAgent"
                )
            )


            result = (
                self.risk_agent.assess(
                    context.incident,
                    investigation,
                    context.evidence,
                    context.attack_timeline,
                    context.attack_graph,
                )
            )


            context.set_agent_output(
                "RiskAssessmentAgent",
                result,
            )

            context.set_risk(
                result
            )


            risk_level = (
                result.get(
                    "risk_level",
                    "INFO",
                )
            )


            risk_score = (
                result.get(
                    "risk_score",
                    0,
                )
            )


            if result.get(
                "requires_response",
                False,
            ):

                context.add_decision(
                    "RiskAssessmentAgent",
                    "RESPONSE_RECOMMENDED",
                    confidence=risk_score,
                    reason=(
                        f"Risk level is {risk_level}."
                    ),
                )

            else:

                context.add_decision(
                    "RiskAssessmentAgent",
                    "MONITOR",
                    confidence=risk_score,
                    reason=(
                        f"Risk level is {risk_level}."
                    ),
                )


            recommendation = (
                result.get(
                    "recommended_action"
                )
            )


            if recommendation:

                context.add_recommendation(
                    "RiskAssessmentAgent",
                    recommendation,
                    priority=risk_level,
                )


            return result


        except Exception as error:

            context.add_error(
                "RiskAssessmentAgent",
                error,
            )

            return {}


    # ============================================================
    # RUN REPORT AGENT
    # ============================================================

    def run_report(
        self,
        context: SharedIncidentContext,
    ):

        try:

            triage = (
                context.get_agent_output(
                    "TriageAgent"
                )
            )

            investigation = (
                context.get_agent_output(
                    "InvestigationAgent"
                )
            )


            result = (
                self.report_agent.generate(
                    context.incident,
                    triage,
                    investigation,
                    context.evidence,
                    context.attack_timeline,
                    context.attack_graph,
                    context.risk,
                )
            )


            context.set_agent_output(
                "InvestigationReportAgent",
                result,
            )


            return result


        except Exception as error:

            context.add_error(
                "InvestigationReportAgent",
                error,
            )

            return {}


    # ============================================================
    # RUN COMPLETE MULTI-AGENT ANALYSIS
    # ============================================================

    def coordinate(
        self,
        incident: dict,
    ) -> dict:

        context = (
            SharedIncidentContext(
                incident
            )
        )


        # --------------------------------------------------------
        # AGENT 1
        # Triage
        # --------------------------------------------------------

        self.run_triage(
            context
        )


        # --------------------------------------------------------
        # AGENT 2
        # Investigation
        # --------------------------------------------------------

        self.run_investigation(
            context
        )


        # --------------------------------------------------------
        # AGENT 3
        # Evidence
        # --------------------------------------------------------

        self.run_evidence(
            context
        )


        # --------------------------------------------------------
        # AGENT 4
        # Timeline
        # --------------------------------------------------------

        self.run_timeline(
            context
        )


        # --------------------------------------------------------
        # AGENT 5
        # Graph
        # --------------------------------------------------------

        self.run_graph(
            context
        )


        # --------------------------------------------------------
        # AGENT 6
        # Risk
        # --------------------------------------------------------

        self.run_risk(
            context
        )


        # --------------------------------------------------------
        # AGENT 7
        # Report
        # --------------------------------------------------------

        self.run_report(
            context
        )


        result = (
            context.to_dict()
        )


        result[
            "coordinator"
        ] = self.name


        result[
            "status"
        ] = (
            "COMPLETED"
            if not result[
                "errors"
            ]
            else "COMPLETED_WITH_ERRORS"
        )


        return result