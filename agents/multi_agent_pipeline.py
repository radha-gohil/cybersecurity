
from datetime import datetime, timezone

from agents.agent_coordinator import AgentCoordinator
from agents.decision_factory import DecisionFactory
from agents.agent_consensus import AgentConsensusEngine
from agents.response_recommendation_agent import (
    ResponseRecommendationAgent,
)
from agents.policy_autonomy_gate import PolicyAutonomyGate


class MultiAgentSecurityPipeline:

    def __init__(self, autonomy_level: int = 2):
        self.name = "MultiAgentSecurityPipeline"
        self.autonomy_level = autonomy_level
        self.coordinator = AgentCoordinator()
        self.consensus_engine = AgentConsensusEngine()
        self.response_agent = ResponseRecommendationAgent()
        self.policy_gate = PolicyAutonomyGate(
            autonomy_level=autonomy_level
        )

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def safe_dict(self, value) -> dict:
        return value if isinstance(value, dict) else {}

    def safe_list(self, value) -> list:
        return value if isinstance(value, list) else []

    # ============================================================
    # EVIDENCE QUALITY GATE
    # ============================================================

    def validate_evidence(self, incident: dict) -> dict:
        events = self.safe_list(incident.get("timeline"))

        seen_ids = set()
        authoritative = []
        rejected = []

        for event in events:
            if not isinstance(event, dict):
                rejected.append("INVALID_EVENT")
                continue

            event_id = str(
                event.get("event_id") or ""
            ).strip()

            if not event_id or event_id in seen_ids:
                rejected.append("MISSING_OR_DUPLICATE_ID")
                continue

            seen_ids.add(event_id)

            severity = str(
                event.get("severity") or "INFO"
            ).upper()

            if severity not in {
                "MEDIUM", "HIGH", "CRITICAL"
            }:
                rejected.append("INFORMATIONAL_OR_LOW")
                continue

            metadata = self.safe_dict(
                event.get("metadata")
            )

            mode = str(
                metadata.get("detection_mode")
                or metadata.get("operating_mode")
                or metadata.get("mode")
                or event.get("detection_mode")
                or event.get("mode")
                or ""
            ).upper()

            if (
                "SHADOW" in mode
                or mode in {"OFF", "DISABLED", "SIMULATION"}
            ):
                rejected.append("NON_AUTHORITATIVE_MODE")
                continue

            if (
                event.get("simulation_mode") is True
                or metadata.get("simulation_mode") is True
                or metadata.get("synthetic") is True
            ):
                rejected.append("SYNTHETIC_EVENT")
                continue

            device = str(
                event.get("device_id")
                or metadata.get("device_id")
                or ""
            ).strip()

            if not device:
                rejected.append("MISSING_DEVICE")
                continue

            event_type = str(
                event.get("event_type") or ""
            ).lower()

            category = str(
                event.get("event_category")
                or metadata.get("event_category")
                or ""
            ).upper()

            if category not in {
                "PROCESS", "NETWORK", "FILE", "REGISTRY"
            }:
                if event_type.startswith("process"):
                    category = "PROCESS"
                elif event_type.startswith("network"):
                    category = "NETWORK"
                elif event_type.startswith("file"):
                    category = "FILE"
                elif event_type.startswith("registry"):
                    category = "REGISTRY"
                else:
                    rejected.append("UNKNOWN_CATEGORY")
                    continue

            process = self.safe_dict(event.get("process"))
            network = self.safe_dict(event.get("network"))

            if category in {"PROCESS", "NETWORK"}:
                pid = (
                    process.get("pid")
                    if category == "PROCESS"
                    else network.get("pid")
                )

                try:
                    pid = int(pid)
                except (TypeError, ValueError):
                    pid = None

                if pid is None or pid in {0, 4} or pid < 0:
                    rejected.append("UNRELIABLE_PROCESS_ID")
                    continue

            authoritative.append({
                "event_id": event_id,
                "category": category,
                "device_id": device,
                "severity": severity,
            })

        categories_by_device = {}

        for event in authoritative:
            device = event["device_id"]
            categories_by_device.setdefault(device, set()).add(
                event["category"]
            )

        corroborated = any(
            len(categories) >= 2
            for categories in categories_by_device.values()
        )

        reasons = []

        if len(authoritative) < 2:
            reasons.append(
                "Fewer than two authoritative events."
            )

        if not corroborated:
            reasons.append(
                "No two independent event categories "
                "are corroborated on one identified device."
            )

        return {
            "passed": (
                len(authoritative) >= 2
                and corroborated
            ),
            "authoritative_event_count": len(authoritative),
            "categories_by_device": {
                device: sorted(categories)
                for device, categories
                in categories_by_device.items()
            },
            "rejected_event_count": len(rejected),
            "rejected_reasons": rejected,
            "reasons": reasons,
            "validation_policy": "CONSERVATIVE_V1",
        }

    # ============================================================
    # AGENT DECISIONS
    # ============================================================

    def build_decisions(self, coordinated_result: dict) -> list:
        outputs = self.safe_dict(
            coordinated_result.get("agent_outputs")
        )

        decisions = []

        triage = self.safe_dict(outputs.get("TriageAgent"))
        investigation = self.safe_dict(
            outputs.get("InvestigationAgent")
        )
        risk = self.safe_dict(
            outputs.get("RiskAssessmentAgent")
        )

        if triage:
            decisions.append(
                DecisionFactory.from_triage(triage)
            )

        if investigation:
            decisions.append(
                DecisionFactory.from_investigation(
                    investigation
                )
            )

        if risk:
            decisions.append(
                DecisionFactory.from_risk(risk)
            )

        return decisions

    def serialize_decisions(self, decisions: list) -> list:
        result = []

        for decision in decisions:
            if hasattr(decision, "to_dict"):
                result.append(decision.to_dict())
            elif isinstance(decision, dict):
                result.append(decision)

        return result

    def determine_security_state(
        self,
        consensus: dict,
        risk: dict,
    ) -> str:
        decision = str(
            consensus.get("final_decision", "MONITOR")
        ).upper()

        risk_level = str(
            risk.get("risk_level", "INFO")
        ).upper()

        if (
            decision == "CONTAINMENT_RECOMMENDED"
            or risk_level == "CRITICAL"
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

    def determine_pipeline_status(
        self,
        coordinated_result: dict,
        decisions: list,
        consensus: dict,
        response: dict,
        policy: dict,
    ) -> str:
        coordinated_result = self.safe_dict(
            coordinated_result
        )

        errors = self.safe_list(
            coordinated_result.get("errors")
        )

        if errors:
            return "COMPLETED_WITH_ERRORS"

        agent_outputs = self.safe_dict(
            coordinated_result.get("agent_outputs")
        )

        required_agents = (
            "TriageAgent",
            "InvestigationAgent",
            "EvidenceEnrichmentAgent",
            "AttackTimelineAgent",
            "AttackGraphAgent",
            "RiskAssessmentAgent",
            "InvestigationReportAgent",
        )

        for agent_name in required_agents:
            output = agent_outputs.get(agent_name)

            if not isinstance(output, dict) or not output:
                return "INCOMPLETE"

        if not isinstance(decisions, list):
            return "INCOMPLETE"

        if len(decisions) < 3:
            return "INCOMPLETE"

        if not isinstance(consensus, dict) or not consensus:
            return "INCOMPLETE"

        if not isinstance(response, dict) or not response:
            return "INCOMPLETE"

        if not isinstance(policy, dict) or not policy:
            return "INCOMPLETE"

        # Analysis may complete while containment remains
        # unauthorized. COMPLETED does not mean threat confirmed.
        return "COMPLETED"

    # ============================================================
    # READ-ONLY PREVIEW (NEVER PROMOTES INCIDENTS)
    # ============================================================

    def preview_incident(self, incident: dict) -> dict:
        """Run the existing analytical agents without SOC persistence.

        This is an observational preview. It never calls the SOC
        workflow, creates a ticket, performs containment, or grants
        response authorization. Failing evidence quality remains
        INCOMPLETE even when the analytical agents return findings.
        """
        incident = self.safe_dict(incident)
        validation = self.validate_evidence(incident)

        if validation["passed"]:
            result = self.process_incident(incident)
            result["preview_only"] = True
            result["soc_promotion_allowed"] = (
                result.get("status") == "COMPLETED"
            )
            result["execution_enabled"] = False
            result["read_only"] = True
            return result

        try:
            coordinated = self.coordinator.coordinate(incident)
            if not isinstance(coordinated, dict):
                coordinated = {}
        except Exception as error:
            coordinated = {
                "agent_outputs": {},
                "errors": [{
                    "agent": "AgentCoordinator",
                    "error": str(error),
                }],
            }

        errors = self.safe_list(coordinated.get("errors"))
        outputs = self.safe_dict(coordinated.get("agent_outputs"))
        required = (
            "TriageAgent",
            "InvestigationAgent",
            "EvidenceEnrichmentAgent",
            "AttackTimelineAgent",
            "AttackGraphAgent",
            "RiskAssessmentAgent",
            "InvestigationReportAgent",
        )
        missing = [
            name for name in required
            if not isinstance(outputs.get(name), dict)
            or not outputs.get(name)
        ]

        return {
            "pipeline": self.name,
            "processed_at": self.now_iso(),
            "incident_id": incident.get("incident_id"),
            "status": "INCOMPLETE",
            "preview_only": True,
            "read_only": True,
            "soc_promotion_allowed": False,
            "security_state": "EVIDENCE_REVIEW_REQUIRED",
            "evidence_validation": validation,
            "autonomy_level": self.autonomy_level,
            "autonomy_mode": "REVIEW_ONLY",
            "coordinated_analysis": coordinated,
            # Raw analytical findings are for inspection only.
            # Unqualified evidence must not generate a decision,
            # consensus, or response plan.
            "agent_decisions": [],
            "consensus": {},
            "response": {},
            "policy": {},
            "risk_score": 0,
            "risk_level": "INFO",
            "final_decision": "CONTINUE_ANALYSIS",
            "execution_enabled": False,
            "agent_diagnostics": {
                "missing_agent_outputs": missing,
                "agent_errors": errors,
                "available_agent_outputs": sorted(outputs),
            },
            "note": (
                "Read-only analytical preview only. Evidence quality "
                "did not pass promotion requirements; any agent output "
                "is provisional, unverified, and cannot authorize response. "
                "No SOC case, ticket, or action was created."
            ),
        }

    # ============================================================
    # MAIN INVESTIGATION PIPELINE
    # ============================================================

    def process_incident(self, incident: dict) -> dict:
        incident = self.safe_dict(incident)

        validation = self.validate_evidence(incident)

        # Reject before any agent, case or response planning.
        if not validation["passed"]:
            return {
                "pipeline": self.name,
                "processed_at": self.now_iso(),
                "incident_id": incident.get("incident_id"),
                "status": "INCOMPLETE",
                "security_state": "EVIDENCE_REVIEW_REQUIRED",
                "evidence_validation": validation,
                "autonomy_level": self.autonomy_level,
                "autonomy_mode": "REVIEW_ONLY",
                "coordinated_analysis": {},
                "agent_decisions": [],
                "consensus": {},
                "response": {},
                "policy": {},
                "risk_score": 0,
                "risk_level": "INFO",
                "final_decision": "CONTINUE_ANALYSIS",
                "execution_enabled": False,
                "note": (
                    "Independent authoritative evidence was "
                    "insufficient. No agent conclusions or "
                    "response recommendations were generated."
                ),
            }

        coordinated = self.coordinator.coordinate(incident)
        decisions = self.build_decisions(coordinated)

        consensus = self.consensus_engine.reach_consensus(
            decisions
        )

        risk = self.safe_dict(coordinated.get("risk"))
        evidence = self.safe_dict(coordinated.get("evidence"))
        timeline = self.safe_dict(
            coordinated.get("attack_timeline")
        )

        response = self.response_agent.generate(
            consensus,
            risk,
            evidence,
            timeline,
        )

        policy = self.policy_gate.evaluate_recommendations(
            response
        )

        security_state = self.determine_security_state(
            consensus,
            risk,
        )

        status = self.determine_pipeline_status(
            coordinated,
            decisions,
            consensus,
            response,
            policy,
        )

        return {
            "pipeline": self.name,
            "processed_at": self.now_iso(),
            "incident_id": incident.get("incident_id"),
            "status": status,
            "security_state": security_state,
            "evidence_validation": validation,
            "autonomy_level": self.autonomy_level,
            "autonomy_mode": policy.get("autonomy_mode"),
            "coordinated_analysis": coordinated,
            "agent_decisions": self.serialize_decisions(
                decisions
            ),
            "consensus": consensus,
            "response": response,
            "policy": policy,
            "risk_score": risk.get("risk_score", 0),
            "risk_level": risk.get("risk_level", "INFO"),
            "final_decision": consensus.get(
                "final_decision", "MONITOR"
            ),
            "execution_enabled": False,
            "note": (
                "Analysis and recommendations only. "
                "Real containment execution is disabled."
            ),
        }
