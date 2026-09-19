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


class IncidentIntelligenceOrchestrator:

    def __init__(self):

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
    # SAFE DICT
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


    # ============================================================
    # PROCESS INCIDENT
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
        # STEP 1 - TRIAGE
        # ========================================================

        triage = (
            self.triage_agent.triage(
                incident
            )
        )


        # ========================================================
        # STEP 2 - INVESTIGATION
        # ========================================================

        investigation = (
            self.investigation_agent.investigate(
                incident
            )
        )


        # ========================================================
        # STEP 3 - EVIDENCE ENRICHMENT
        # ========================================================

        evidence = (
            self.evidence_agent.enrich(
                incident
            )
        )


        # ========================================================
        # STEP 4 - ATTACK TIMELINE
        # ========================================================

        attack_timeline = (
            self.timeline_agent.reconstruct(
                incident
            )
        )


        # ========================================================
        # STEP 5 - ATTACK GRAPH
        # ========================================================

        attack_graph = (
            self.graph_agent.generate(
                evidence
            )
        )


        # ========================================================
        # STEP 6 - RISK ASSESSMENT
        # ========================================================

        risk = (
            self.risk_agent.assess(
                incident,
                investigation,
                evidence,
                attack_timeline,
                attack_graph,
            )
        )


        # ========================================================
        # STEP 7 - FINAL REPORT
        # ========================================================

        report = (
            self.report_agent.generate(
                incident,
                triage,
                investigation,
                evidence,
                attack_timeline,
                attack_graph,
                risk,
            )
        )


        # ========================================================
        # FINAL ORCHESTRATION RESULT
        # ========================================================

        return {

            "incident_id":
                incident.get(
                    "incident_id"
                ),

            "triage":
                triage,

            "investigation":
                investigation,

            "evidence":
                evidence,

            "attack_timeline":
                attack_timeline,

            "attack_graph":
                attack_graph,

            "risk":
                risk,

            "report":
                report,

            "status":
                "COMPLETED",
        }