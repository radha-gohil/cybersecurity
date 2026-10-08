from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ai_provider_manager import shared_ai_provider_manager
from response.digital_twin_decision_integration import (
    DigitalTwinDecisionIntegration,
)


class AIDigitalTwinPlanSelectionAgent:
    """SENTINEL-X 7D.6 Digital Twin + AI Plan Selection Agent.

    Flow:
        7D.4 grounded AI risk
        -> 7D.5 grounded AI response recommendations
        -> deterministic Digital Twin simulation/ranking
        -> AI selects exactly one already-simulated plan
        -> deterministic hydration of the selected plan

    The LLM cannot invent plans, actions, or targets and cannot execute anything.
    """

    VERSION = "7D.6-v1"
    SCHEMA_VERSION = "sentinelx.ai.digital-twin-plan-selection.v1"

    def __init__(
        self,
        provider_manager=None,
        digital_twin_integration=None,
    ):
        self.name = "AIDigitalTwinPlanSelectionAgent"
        self.provider_manager = (
            provider_manager
            if provider_manager is not None
            else shared_ai_provider_manager
        )
        self.digital_twin_integration = (
            digital_twin_integration
            if digital_twin_integration is not None
            else DigitalTwinDecisionIntegration()
        )

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def safe_dict(value: Any) -> Dict:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def safe_list(value: Any) -> List:
        return value if isinstance(value, list) else []

    @staticmethod
    def safe_string(value: Any) -> str:
        return str(value or "").strip()

    def status(self) -> Dict:
        return {
            "agent": self.name,
            "version": self.VERSION,
            "schema_version": self.SCHEMA_VERSION,
            "selection_source": "SIMULATED_DIGITAL_TWIN_PLANS_ONLY",
            "ai_can_invent_plan": False,
            "ai_can_modify_plan": False,
            "ai_can_execute": False,
            "simulation_only": True,
            "execution_allowed": False,
            "provider_manager": self.provider_manager.status(),
            "digital_twin_integration": getattr(
                self.digital_twin_integration,
                "name",
                self.digital_twin_integration.__class__.__name__,
            ),
        }

    def build_intelligence(
        self,
        *,
        threat: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        enriched_evidence: Optional[Dict] = None,
        incident: Optional[Dict] = None,
        investigation: Optional[Dict] = None,
    ) -> Dict:
        evidence = deepcopy(self.safe_dict(enriched_evidence))
        incident = deepcopy(self.safe_dict(incident))
        investigation = deepcopy(self.safe_dict(investigation))

        return {
            "risk": deepcopy(self.safe_dict(risk_assessment)),
            "risk_score": risk_assessment.get("risk_score"),
            "risk_level": risk_assessment.get("risk_level"),
            "response": deepcopy(self.safe_dict(response_recommendation)),
            "coordinated_analysis": {
                "evidence": evidence,
                "context": {
                    "evidence": deepcopy(evidence),
                    "investigation": investigation,
                },
            },
            "source_incident": incident,
            "security_identity": {
                "security_id": threat.get("id"),
                "event_id": threat.get("event_id"),
                "incident_id": threat.get("incident_id"),
                "device_id": threat.get("device_id"),
            },
        }

    def evaluate_digital_twin(
        self,
        *,
        threat: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        enriched_evidence: Optional[Dict] = None,
        incident: Optional[Dict] = None,
        investigation: Optional[Dict] = None,
    ) -> Dict:
        incident_id = (
            threat.get("incident_id")
            or response_recommendation.get("incident_id")
            or risk_assessment.get("incident_id")
            or "SENTINELX-UNSCOPED-INCIDENT"
        )

        intelligence = self.build_intelligence(
            threat=threat,
            risk_assessment=risk_assessment,
            response_recommendation=response_recommendation,
            enriched_evidence=enriched_evidence,
            incident=incident,
            investigation=investigation,
        )

        result = self.digital_twin_integration.evaluate(
            incident_id=incident_id,
            intelligence=intelligence,
        )

        result = self.safe_dict(result)
        if result.get("real_endpoint_modified") is not False:
            raise ValueError(
                "Digital Twin evaluation violated simulation boundary."
            )
        return result

    def compact_plan(self, plan: Dict) -> Dict:
        plan = self.safe_dict(plan)
        actions = []
        for item in self.safe_list(plan.get("actions")):
            item = self.safe_dict(item)
            actions.append(
                {
                    "action_type": item.get("action_type"),
                    # Targets are retained as observed/simulated references.
                    # They are not editable by the LLM.
                    "target": deepcopy(self.safe_dict(item.get("target"))),
                }
            )

        return {
            "plan_id": plan.get("plan_id"),
            "plan_name": plan.get("plan_name"),
            "description": plan.get("description"),
            "actions": actions,
            "predicted_residual_risk": plan.get("predicted_residual_risk"),
            "predicted_residual_level": plan.get("predicted_residual_level"),
            "risk_reduction": plan.get("risk_reduction"),
            "risk_reduction_percentage": plan.get(
                "risk_reduction_percentage"
            ),
            "response_effectiveness": plan.get("response_effectiveness"),
            "operational_impact": plan.get("operational_impact"),
            "recommended_decision": plan.get("recommended_decision"),
            "plan_score": plan.get("plan_score"),
        }

    def build_reasoning_payload(
        self,
        *,
        risk_assessment: Dict,
        response_recommendation: Dict,
        digital_twin_result: Dict,
    ) -> Dict:
        ranked_plans = [
            self.compact_plan(plan)
            for plan in self.safe_list(
                digital_twin_result.get("ranked_plans")
            )
        ]

        return {
            "risk_assessment": {
                key: risk_assessment.get(key)
                for key in (
                    "risk_score",
                    "risk_level",
                    "confidence",
                    "threat_assessment",
                    "evidence_strength",
                    "risk_summary",
                    "primary_risk_drivers",
                    "uncertainties",
                    "why_this_level",
                )
                if key in risk_assessment
            },
            "response_recommendation": {
                "response_strategy": response_recommendation.get(
                    "response_strategy"
                ),
                "confidence": response_recommendation.get("confidence"),
                "recommendations": [
                    {
                        "action": item.get("action"),
                        "priority": item.get("priority"),
                        "target_reference": item.get("target_reference"),
                        "reason": item.get("reason"),
                    }
                    for item in self.safe_list(
                        response_recommendation.get("recommendations")
                    )
                ],
                "why_this_response": response_recommendation.get(
                    "why_this_response"
                ),
                "why_not_more_aggressive": response_recommendation.get(
                    "why_not_more_aggressive"
                ),
                "why_not_less_aggressive": response_recommendation.get(
                    "why_not_less_aggressive"
                ),
            },
            "digital_twin": {
                "initial_risk_score": digital_twin_result.get(
                    "initial_risk_score"
                ),
                "initial_risk_level": digital_twin_result.get(
                    "initial_risk_level"
                ),
                "plans_evaluated": digital_twin_result.get(
                    "plans_evaluated"
                ),
                "ranked_plans": ranked_plans,
            },
            "selection_policy": {
                "select_existing_plan_only": True,
                "prefer_effective_lower_impact_plan": True,
                "do_not_treat_plan_score_as_probability": True,
                "do_not_treat_predicted_risk_as_calibrated_probability": True,
                "endpoint_isolation_is_broadest_option": True,
                "preserve_risk_uncertainty": True,
                "real_execution_allowed": False,
            },
        }

    def build_system_instruction(self) -> str:
        return """
You are the SENTINEL-X AI Digital Twin Plan Selection Agent.

You receive response plans that have ALREADY been generated and simulated by the
SENTINEL-X Digital Twin. Your job is to select the most appropriate existing
simulated plan.

You MUST NOT invent a plan, action, target, PID, IP, file, registry key, or
endpoint identity. Return exactly one selected_plan_id from the supplied plans.

Balance:
- security risk reduction
- response effectiveness
- operational impact
- evidence strength
- remaining uncertainty
- whether narrower controls sufficiently address the risk

The deterministic Digital Twin plan_score and predicted residual risk are
simulation outputs, not probabilities and not guarantees of real-world efficacy.
Use them as decision-support evidence, not absolute truth.

Endpoint isolation is the broadest and most disruptive option. Select a plan
containing ISOLATE_ENDPOINT only when the supplied risk/response context and
simulated trade-offs justify it. Do not select isolation merely because the risk
level is HIGH or CRITICAL.

Preserve threat certainty. LIKELY_MALICIOUS is not the same as confirmed
MALICIOUS.

This stage selects a SIMULATED PLAN ONLY. It never authorizes or executes a real
endpoint response. All disruptive plans remain subject to later protection mode,
policy, approval, and execution gates.

Return JSON only.
""".strip()

    def build_prompt(self, payload: Dict) -> str:
        plan_ids = [
            plan.get("plan_id")
            for plan in self.safe_list(
                self.safe_dict(payload.get("digital_twin")).get(
                    "ranked_plans"
                )
            )
            if plan.get("plan_id")
        ]

        return f"""
Select the best existing SENTINEL-X Digital Twin plan.

Allowed plan IDs:
{json.dumps(plan_ids)}

Return exactly one JSON object:
{{
  "selected_plan_id": "one allowed plan ID",
  "confidence": 0.0,
  "selection_summary": [
    "concise evidence-grounded explanation"
  ],
  "tradeoffs": [
    "important security versus operational trade-off"
  ],
  "why_selected": "why this simulated plan is preferred",
  "why_not_more_aggressive": "why a broader plan is not required, or why this is already appropriate",
  "why_not_less_aggressive": "why a weaker plan is insufficient, or why this minimal plan is sufficient",
  "isolation_justified": false
}}

Requirements:
- selected_plan_id must be one of the allowed plan IDs
- do not invent or modify plans/actions/targets
- do not describe LIKELY_MALICIOUS as confirmed MALICIOUS
- plan_score is not probability
- predicted residual risk is a heuristic simulation estimate, not a guarantee
- prefer a narrower plan when it achieves adequate simulated risk reduction
- use endpoint isolation only when justified by evidence and trade-offs
- no real execution authorization
- JSON only; no markdown

INPUT:
{json.dumps(payload, indent=2, default=str)}
""".strip()

    def build_repair_prompt(
        self,
        *,
        payload: Dict,
        validation_error: str,
    ) -> str:
        return f"""
{self.build_prompt(payload)}

Your previous response failed SENTINEL-X plan-selection validation.

VALIDATION ERROR:
{validation_error}

Return the COMPLETE corrected JSON object.
Select only an existing plan_id. Do not invent or modify plan contents.

Preserve threat certainty.

If threat_assessment is LIKELY_MALICIOUS, do not describe it as
confirmed malicious activity.

Use "likely malicious activity", "suspicious activity", or
"observed suspicious behavior".

Negative statements such as "no confirmed malicious activity" are
allowed and must not be rewritten as positive malicious claims.

Also preserve uncertainty forms such as:
"malicious intent has not been confirmed"
"no evidence confirming malicious activity"
"likely part of malicious activity"

Do not turn missing evidence into a benign conclusion.
Do not describe simulated plan results as guarantees or probabilities.

Return JSON only.
""".strip()

    def parse_json_response(self, raw_text: str) -> Dict:
        raw_text = self.safe_string(raw_text)
        if not raw_text:
            raise ValueError("AI provider returned empty response.")
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start < 0 or end < start:
            raise ValueError("AI response contains no valid JSON object.")
        parsed = json.loads(raw_text[start : end + 1])
        if not isinstance(parsed, dict):
            raise ValueError("AI response must be a JSON object.")
        return parsed

    def find_plan(self, digital_twin_result: Dict, plan_id: str) -> Optional[Dict]:
        for plan in self.safe_list(digital_twin_result.get("ranked_plans")):
            if self.safe_string(plan.get("plan_id")) == plan_id:
                return plan
        return None

    def validate_selection_grounding(
        self,
        *,
        result: Dict,
        risk_assessment: Dict,
    ) -> None:
        """
        Preserve the certainty produced by 7D.4.

        LIKELY_MALICIOUS is not the same as confirmed MALICIOUS.
        Negative, uncertain, and hypothetical references to malicious
        activity are allowed when they do not assert that it occurred.
        """
        assessment = self.safe_string(
            risk_assessment.get("threat_assessment")
        ).upper()

        if assessment == "MALICIOUS":
            return

        parts = []

        for key in (
            "selection_summary",
            "tradeoffs",
        ):
            for item in self.safe_list(result.get(key)):
                text = self.safe_string(item)
                if text:
                    parts.append(text)

        for key in (
            "why_selected",
            "why_not_more_aggressive",
            "why_not_less_aggressive",
        ):
            text = self.safe_string(result.get(key))
            if text:
                parts.append(text)

        output_text = " ".join(parts).lower()

        statements = [
            item.strip()
            for item in (
                output_text
                .replace(";", ".")
                .replace("\n", ".")
                .split(".")
            )
            if item.strip()
        ]

        definitive_phrases = (
            "malicious activity",
            "malicious behavior",
            "malicious component",
            "malicious components",
            "malicious file",
            "malicious payload",
            "confirmed malicious",
            "known malicious",
        )

        def is_non_assertive(statement: str) -> bool:
            statement = self.safe_string(statement).lower()

            markers = (
                "likely malicious",
                "potentially malicious",
                "possibly malicious",
                "suspected malicious",
                "suspicious",
                "if malicious",
                "if confirmed",
                "if later confirmed",
                "likely part of",
                "likely associated with",
                "may be part of",
                "might be part of",
                "could be part of",

                "no direct evidence of",
                "no evidence of",
                "no observed evidence of",
                "no confirmed evidence of",
                "without direct evidence of",
                "without evidence of",
                "lack of direct evidence",
                "lack of evidence",
                "absence of direct evidence",
                "absence of evidence",
                "insufficient evidence",
                "evidence does not establish",
                "evidence does not confirm",
                "not confirmed",
                "not established",
                "not verified",
                "not observed",
                "not demonstrated",
                "has not been observed",
                "have not been observed",
                "cannot confirm",
                "cannot establish",
                "cannot determine",
                "unable to confirm",
                "unable to establish",
                "preventing confirmation of",
                "prevents confirmation of",

                "lack of confirmed malicious",
                "lack of confirmed malicious intent",
                "no confirmed malicious",
                "no confirmed malicious intent",
                "without confirmed malicious",
                "absence of confirmed malicious",
                "not confirmed malicious",
                "no malicious behavior",
                "no malicious activity",
                "no malicious classification",

                "could ",
                "could potentially",
                "may ",
                "might ",
                "potential ",
                "potentially ",
                "possible ",
                "possibly ",
                "risk of",
            )

            if any(marker in statement for marker in markers):
                return True

            if re.search(
                r"\bno\b.{0,120}\b(evidence|confirmation|indication|proof)\b",
                statement,
            ):
                return True

            if re.search(
                r"\bno\b.{0,120}\b(has|have|was|were)\s+"
                r"(?:not\s+)?(?:been\s+)?observed\b",
                statement,
            ):
                return True

            return False

        for statement in statements:
            if not any(
                phrase in statement
                for phrase in definitive_phrases
            ):
                continue

            if is_non_assertive(statement):
                continue

            raise ValueError(
                "Plan-selection reasoning upgraded "
                f"{assessment or 'UNKNOWN'} into confirmed malicious "
                f"activity. Statement: {statement}"
            )

    def validate_output(
        self,
        *,
        result: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        digital_twin_result: Dict,
    ) -> Dict:
        result = self.safe_dict(result)
        selected_plan_id = self.safe_string(result.get("selected_plan_id"))
        if not selected_plan_id:
            raise ValueError("selected_plan_id is empty.")

        selected_plan = self.find_plan(
            digital_twin_result,
            selected_plan_id,
        )
        if selected_plan is None:
            raise ValueError(
                f"AI selected unknown Digital Twin plan: {selected_plan_id}"
            )

        try:
            confidence = float(result.get("confidence"))
        except (TypeError, ValueError):
            raise ValueError("confidence must be numeric.")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1.")

        selection_summary = [
            self.safe_string(item)
            for item in self.safe_list(result.get("selection_summary"))
            if self.safe_string(item)
        ]
        if not selection_summary:
            raise ValueError("selection_summary is empty.")

        tradeoffs = [
            self.safe_string(item)
            for item in self.safe_list(result.get("tradeoffs"))
            if self.safe_string(item)
        ]
        if not tradeoffs:
            raise ValueError("tradeoffs is empty.")

        why_selected = self.safe_string(result.get("why_selected"))
        why_not_more_aggressive = self.safe_string(
            result.get("why_not_more_aggressive")
        )
        why_not_less_aggressive = self.safe_string(
            result.get("why_not_less_aggressive")
        )
        if not why_selected:
            raise ValueError("why_selected is empty.")
        if not why_not_more_aggressive:
            raise ValueError("why_not_more_aggressive is empty.")
        if not why_not_less_aggressive:
            raise ValueError("why_not_less_aggressive is empty.")

        isolation_justified = result.get("isolation_justified")
        if not isinstance(isolation_justified, bool):
            raise ValueError("isolation_justified must be boolean.")

        selected_action_types = {
            self.safe_string(action.get("action_type")).upper()
            for action in self.safe_list(selected_plan.get("actions"))
            if self.safe_string(action.get("action_type"))
        }
        selected_has_isolation = "ISOLATE_ENDPOINT" in selected_action_types

        if selected_has_isolation and not isolation_justified:
            raise ValueError(
                "Selected plan contains endpoint isolation but AI did not justify it."
            )
        if not selected_has_isolation and isolation_justified:
            raise ValueError(
                "isolation_justified=True but selected plan has no isolation action."
            )

        response_actions = {
            self.safe_string(item.get("action")).upper()
            for item in self.safe_list(
                response_recommendation.get("recommendations")
            )
        }
        if selected_has_isolation and "ENDPOINT_ISOLATION_REVIEW" not in response_actions:
            raise ValueError(
                "AI selected isolation although 7D.5 did not recommend isolation review."
            )

        assessment = self.safe_string(
            risk_assessment.get("threat_assessment")
        ).upper()
        if selected_has_isolation and assessment not in {
            "LIKELY_MALICIOUS",
            "MALICIOUS",
        }:
            raise ValueError(
                f"Endpoint isolation is not permitted for assessment {assessment}."
            )

        if selected_plan.get("real_endpoint_modified") is not False:
            raise ValueError(
                "Selected Digital Twin plan does not preserve simulation boundary."
            )

        validated = {
            "selected_plan_id": selected_plan_id,
            "confidence": confidence,
            "selection_summary": selection_summary,
            "tradeoffs": tradeoffs,
            "why_selected": why_selected,
            "why_not_more_aggressive": why_not_more_aggressive,
            "why_not_less_aggressive": why_not_less_aggressive,
            "isolation_justified": isolation_justified,
            # Hydrated deterministically; not supplied by the LLM.
            "selected_plan": deepcopy(selected_plan),
        }

        self.validate_selection_grounding(
            result=validated,
            risk_assessment=risk_assessment,
        )

        return validated

    def call_provider(self, *, prompt: str, temperature: float = 0.1) -> Dict:
        return self.provider_manager.generate(
            prompt=prompt,
            system_instruction=self.build_system_instruction(),
            json_mode=True,
            temperature=temperature,
        )

    def skipped_result(
        self,
        *,
        threat: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        reason: str,
        digital_twin_result: Optional[Dict] = None,
    ) -> Dict:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "agent": self.name,
            "agent_version": self.VERSION,
            "generated_at": self.now_iso(),
            "ai_available": None,
            "selection_status": "NOT_REQUIRED",
            "selection_reason": reason,
            "security_id": threat.get("id"),
            "event_id": threat.get("event_id"),
            "incident_id": threat.get("incident_id"),
            "risk_level": risk_assessment.get("risk_level"),
            "threat_assessment": risk_assessment.get("threat_assessment"),
            "response_strategy": response_recommendation.get(
                "response_strategy"
            ),
            "digital_twin": deepcopy(digital_twin_result or {}),
            "selected_plan_id": None,
            "selected_plan": None,
            "simulation_only": True,
            "execution_allowed": False,
            "automatic_execution_allowed": False,
            "real_response_executed": False,
        }

    def unavailable_result(
        self,
        *,
        threat: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        digital_twin_result: Dict,
        provider_result: Dict,
        validation_error: Optional[str] = None,
        repair_attempted: bool = False,
    ) -> Dict:
        return {
            "schema_version": self.SCHEMA_VERSION,
            "agent": self.name,
            "agent_version": self.VERSION,
            "generated_at": self.now_iso(),
            "ai_available": False,
            "provider": provider_result.get("provider"),
            "model": provider_result.get("model"),
            "provider_error_type": provider_result.get("error_type"),
            "provider_error": provider_result.get("error"),
            "output_validation_error": validation_error,
            "output_repair_attempted": repair_attempted,
            "selection_status": "AI_UNAVAILABLE",
            "security_id": threat.get("id"),
            "event_id": threat.get("event_id"),
            "incident_id": threat.get("incident_id"),
            "risk_level": risk_assessment.get("risk_level"),
            "threat_assessment": risk_assessment.get("threat_assessment"),
            "response_strategy": response_recommendation.get(
                "response_strategy"
            ),
            "digital_twin": deepcopy(digital_twin_result),
            "selected_plan_id": None,
            "selected_plan": None,
            "simulation_only": True,
            "execution_allowed": False,
            "automatic_execution_allowed": False,
            "real_response_executed": False,
        }

    def select_plan(
        self,
        *,
        threat: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        enriched_evidence: Optional[Dict] = None,
        incident: Optional[Dict] = None,
        investigation: Optional[Dict] = None,
    ) -> Dict:
        if not isinstance(threat, dict):
            raise TypeError("threat must be a dictionary.")
        if not isinstance(risk_assessment, dict):
            raise TypeError("risk_assessment must be a dictionary.")
        if not isinstance(response_recommendation, dict):
            raise TypeError("response_recommendation must be a dictionary.")

        if response_recommendation.get("digital_twin_required") is not True:
            return self.skipped_result(
                threat=threat,
                risk_assessment=risk_assessment,
                response_recommendation=response_recommendation,
                reason="7D.5 response contains no disruptive Digital Twin candidate.",
            )

        digital_twin_result = self.evaluate_digital_twin(
            threat=threat,
            risk_assessment=risk_assessment,
            response_recommendation=response_recommendation,
            enriched_evidence=enriched_evidence,
            incident=incident,
            investigation=investigation,
        )

        ranked_plans = self.safe_list(digital_twin_result.get("ranked_plans"))
        if not ranked_plans:
            return self.skipped_result(
                threat=threat,
                risk_assessment=risk_assessment,
                response_recommendation=response_recommendation,
                reason="Digital Twin produced no response plan to select.",
                digital_twin_result=digital_twin_result,
            )

        payload = self.build_reasoning_payload(
            risk_assessment=risk_assessment,
            response_recommendation=response_recommendation,
            digital_twin_result=digital_twin_result,
        )

        provider_result = self.call_provider(
            prompt=self.build_prompt(payload),
            temperature=0.1,
        )

        if not provider_result.get("success"):
            return self.unavailable_result(
                threat=threat,
                risk_assessment=risk_assessment,
                response_recommendation=response_recommendation,
                digital_twin_result=digital_twin_result,
                provider_result=provider_result,
            )

        repair_used = False
        try:
            parsed = self.parse_json_response(provider_result["text"])
            validated = self.validate_output(
                result=parsed,
                risk_assessment=risk_assessment,
                response_recommendation=response_recommendation,
                digital_twin_result=digital_twin_result,
            )
        except Exception as first_error:
            repair_result = self.call_provider(
                prompt=self.build_repair_prompt(
                    payload=payload,
                    validation_error=str(first_error),
                ),
                temperature=0.0,
            )
            if not repair_result.get("success"):
                return self.unavailable_result(
                    threat=threat,
                    risk_assessment=risk_assessment,
                    response_recommendation=response_recommendation,
                    digital_twin_result=digital_twin_result,
                    provider_result=repair_result,
                    validation_error=str(first_error),
                    repair_attempted=True,
                )
            try:
                repaired = self.parse_json_response(repair_result["text"])
                validated = self.validate_output(
                    result=repaired,
                    risk_assessment=risk_assessment,
                    response_recommendation=response_recommendation,
                    digital_twin_result=digital_twin_result,
                )
                provider_result = repair_result
                repair_used = True
            except Exception as repair_error:
                return self.unavailable_result(
                    threat=threat,
                    risk_assessment=risk_assessment,
                    response_recommendation=response_recommendation,
                    digital_twin_result=digital_twin_result,
                    provider_result=repair_result,
                    validation_error=str(repair_error),
                    repair_attempted=True,
                )

        return {
            "schema_version": self.SCHEMA_VERSION,
            "agent": self.name,
            "agent_version": self.VERSION,
            "generated_at": self.now_iso(),
            "ai_available": True,
            "provider": provider_result.get("provider"),
            "model": provider_result.get("model"),
            "fallback_used": provider_result.get("fallback_used", False),
            "output_repair_used": repair_used,
            "selection_status": "SELECTED",
            "security_id": threat.get("id"),
            "event_id": threat.get("event_id"),
            "incident_id": threat.get("incident_id"),
            "risk_level": risk_assessment.get("risk_level"),
            "threat_assessment": risk_assessment.get("threat_assessment"),
            "response_strategy": response_recommendation.get(
                "response_strategy"
            ),
            "digital_twin_integration": digital_twin_result.get("integration"),
            "plans_evaluated": digital_twin_result.get("plans_evaluated", 0),
            "digital_twin_decision": digital_twin_result.get("decision"),
            "requires_analyst_approval": digital_twin_result.get(
                "requires_analyst_approval",
                False,
            ),
            "digital_twin": deepcopy(digital_twin_result),
            **validated,
            "next_stage": "PROTECTION_MODE_POLICY",
            "simulation_only": True,
            "execution_allowed": False,
            "automatic_execution_allowed": False,
            "real_response_executed": False,
        }


shared_ai_digital_twin_plan_selection_agent = (
    AIDigitalTwinPlanSelectionAgent()
)
