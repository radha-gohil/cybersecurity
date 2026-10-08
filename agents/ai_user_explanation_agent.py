from __future__ import annotations

import json
import re

from copy import deepcopy

from datetime import (
    datetime,
    timezone,
)

from typing import (
    Any,
    Dict,
    List,
    Optional,
)


from ai_provider_manager import (
    shared_ai_provider_manager,
)


# ================================================================
# SENTINEL-X 7D.8 — AI USER EXPLANATION
# ================================================================


class AIUserExplanationAgent:
    """
    Converts the grounded 7D.4–7D.7 security decision chain into a
    concise user-facing explanation.

    Inputs:
        7D.4 AI risk reasoning
        7D.5 AI response recommendation
        7D.6 Digital Twin + AI plan selection
        7D.7 Protection Mode policy

    This stage does NOT:
        - reclassify the threat
        - choose a response
        - choose a Digital Twin plan
        - change protection mode policy
        - execute anything

    The LLM is used only to explain already-grounded decisions.
    """

    VERSION = "7D.8-v1"

    SCHEMA_VERSION = (
        "sentinelx.ai.user-explanation.v1"
    )


    VALID_POLICY_DECISIONS = {
        "MONITOR",
        "ASK_USER",
        "PROTECT_PREVIEW",
    }


    DISPLAY_STATUS = {
        "MONITOR":
            "MONITORING",

        "ASK_USER":
            "REVIEW_REQUIRED",

        "PROTECT_PREVIEW":
            "PROTECTION_PREPARED",
    }


    ACTION_LABELS = {
        "TERMINATE_PROCESS":
            "End the suspicious process",

        "QUARANTINE_FILE":
            "Quarantine the observed file",

        "BLOCK_NETWORK":
            "Block the observed network connection",

        "REMEDIATE_PERSISTENCE":
            "Remove the observed persistence entry",

        "ISOLATE_ENDPOINT":
            "Isolate the endpoint",
    }


    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
        provider_manager=None,
    ):

        self.name = (
            "AIUserExplanationAgent"
        )


        self.provider_manager = (
            provider_manager
            if provider_manager is not None
            else shared_ai_provider_manager
        )


    # ============================================================
    # HELPERS
    # ============================================================

    @staticmethod
    def now_iso() -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()


    @staticmethod
    def safe_dict(
        value: Any,
    ) -> Dict:

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )


    @staticmethod
    def safe_list(
        value: Any,
    ) -> List:

        return (
            value
            if isinstance(
                value,
                list,
            )
            else []
        )


    @staticmethod
    def safe_string(
        value: Any,
    ) -> str:

        return str(
            value
            or ""
        ).strip()


    # ============================================================
    # STATUS
    # ============================================================

    def status(
        self,
    ) -> Dict:

        return {

            "agent":
                self.name,

            "version":
                self.VERSION,

            "schema_version":
                self.SCHEMA_VERSION,

            "purpose":
                "USER_FACING_SECURITY_EXPLANATION",

            "decision_authority":
                False,

            "response_authority":
                False,

            "plan_selection_authority":
                False,

            "execution_authority":
                False,

            "certainty_preserved":
                True,

            "simulation_boundary_preserved":
                True,

            "provider_manager":
                self.provider_manager.status(),

            "simulation_only":
                True,

            "execution_allowed":
                False,
        }


    # ============================================================
    # COMPACT THREAT
    # ============================================================

    def compact_threat(
        self,
        threat: Dict,
    ) -> Dict:

        threat = (
            self.safe_dict(
                threat
            )
        )


        evidence = (
            self.safe_dict(
                threat.get(
                    "evidence"
                )
            )
        )


        model_evidence = (
            self.safe_dict(
                threat.get(
                    "model_evidence"
                )
            )
        )


        return {

            "category":
                threat.get(
                    "category"
                ),

            "event_type":
                threat.get(
                    "event_type"
                ),

            "threat_type":
                threat.get(
                    "threat_type"
                ),

            "severity":
                threat.get(
                    "severity"
                ),

            "verdict":
                threat.get(
                    "verdict"
                ),

            "engine":
                threat.get(
                    "engine"
                ),

            "observed_evidence":
                deepcopy(
                    self.safe_list(
                        evidence.get(
                            "observed"
                        )
                    )
                ),

            "model_signals":
                deepcopy(
                    self.safe_list(
                        model_evidence.get(
                            "signals"
                        )
                    )
                ),
        }


    # ============================================================
    # COMPACT RISK
    # ============================================================

    def compact_risk(
        self,
        risk_assessment: Dict,
    ) -> Dict:

        risk_assessment = (
            self.safe_dict(
                risk_assessment
            )
        )


        keys = [

            "risk_score",
            "risk_level",
            "confidence",
            "threat_assessment",
            "evidence_strength",

            "risk_summary",
            "primary_risk_drivers",
            "corroborating_evidence",
            "mitigating_evidence",
            "uncertainties",
            "potential_impact",

            "why_this_level",
            "why_not_higher",
            "why_not_lower",

            "risk_score_semantics",
        ]


        return {

            key:
                deepcopy(
                    risk_assessment.get(
                        key
                    )
                )

            for key in keys

            if key
            in risk_assessment
        }


    # ============================================================
    # COMPACT RESPONSE
    # ============================================================

    def compact_response(
        self,
        response_recommendation: Dict,
    ) -> Dict:

        response_recommendation = (
            self.safe_dict(
                response_recommendation
            )
        )


        recommendations = []


        for item in self.safe_list(
            response_recommendation.get(
                "recommendations"
            )
        ):

            item = (
                self.safe_dict(
                    item
                )
            )


            recommendations.append({

                "action":
                    item.get(
                        "action"
                    ),

                "priority":
                    item.get(
                        "priority"
                    ),

                "target_reference":
                    item.get(
                        "target_reference"
                    ),

                "reason":
                    item.get(
                        "reason"
                    ),
            })


        return {

            "response_strategy":
                response_recommendation.get(
                    "response_strategy"
                ),

            "response_summary":
                deepcopy(
                    self.safe_list(
                        response_recommendation.get(
                            "response_summary"
                        )
                    )
                ),

            "recommendations":
                recommendations,

            "why_this_response":
                response_recommendation.get(
                    "why_this_response"
                ),

            "why_not_more_aggressive":
                response_recommendation.get(
                    "why_not_more_aggressive"
                ),

            "why_not_less_aggressive":
                response_recommendation.get(
                    "why_not_less_aggressive"
                ),

            "digital_twin_required":
                response_recommendation.get(
                    "digital_twin_required"
                ),
        }


    # ============================================================
    # COMPACT TARGET
    # ============================================================

    def compact_target(
        self,
        action_type: str,
        target: Dict,
    ) -> Dict:

        target = (
            self.safe_dict(
                target
            )
        )


        action_type = (
            self.safe_string(
                action_type
            )
            .upper()
        )


        if action_type == "TERMINATE_PROCESS":

            items = (
                self.safe_list(
                    target.get(
                        "processes"
                    )
                )
            )


            if not items:

                return {}


            item = (
                self.safe_dict(
                    items[
                        0
                    ]
                )
            )


            return {

                "pid":
                    item.get(
                        "pid"
                    ),

                "name":
                    (
                        item.get(
                            "name"
                        )
                        or
                        item.get(
                            "process_name"
                        )
                    ),
            }


        if action_type == "QUARANTINE_FILE":

            items = (
                self.safe_list(
                    target.get(
                        "files"
                    )
                )
            )


            if not items:

                return {}


            item = (
                self.safe_dict(
                    items[
                        0
                    ]
                )
            )


            return {

                "path":
                    item.get(
                        "path"
                    ),

                "sha256":
                    item.get(
                        "sha256"
                    ),
            }


        if action_type == "BLOCK_NETWORK":

            items = (
                self.safe_list(
                    target.get(
                        "connections"
                    )
                )
            )


            if not items:

                return {}


            item = (
                self.safe_dict(
                    items[
                        0
                    ]
                )
            )


            return {

                "remote_ip":
                    item.get(
                        "remote_ip"
                    ),

                "remote_port":
                    item.get(
                        "remote_port"
                    ),

                "process_name":
                    item.get(
                        "process_name"
                    ),
            }


        if action_type == "REMEDIATE_PERSISTENCE":

            items = (
                self.safe_list(
                    target.get(
                        "registry_artifacts"
                    )
                )
            )


            if not items:

                return {}


            item = (
                self.safe_dict(
                    items[
                        0
                    ]
                )
            )


            return {

                "key":
                    item.get(
                        "key"
                    ),

                "value_name":
                    item.get(
                        "value_name"
                    ),
            }


        if action_type == "ISOLATE_ENDPOINT":

            return {

                "device_id":
                    target.get(
                        "device_id"
                    ),
            }


        return {}


    # ============================================================
    # SELECTED PLAN
    # ============================================================

    def compact_plan_selection(
        self,
        plan_selection: Dict,
    ) -> Dict:

        plan_selection = (
            self.safe_dict(
                plan_selection
            )
        )


        selected_plan = (
            self.safe_dict(
                plan_selection.get(
                    "selected_plan"
                )
            )
        )


        actions = []


        for item in self.safe_list(
            selected_plan.get(
                "actions"
            )
        ):

            item = (
                self.safe_dict(
                    item
                )
            )


            action_type = (
                self.safe_string(
                    item.get(
                        "action_type"
                    )
                )
                .upper()
            )


            actions.append({

                "action_type":
                    action_type,

                "action_label":
                    self.ACTION_LABELS.get(
                        action_type,
                        action_type,
                    ),

                "target":
                    self.compact_target(

                        action_type,

                        self.safe_dict(
                            item.get(
                                "target"
                            )
                        ),
                    ),
            })


        operational_impact = (
            self.safe_dict(
                selected_plan.get(
                    "operational_impact"
                )
            )
        )


        return {

            "selection_status":
                plan_selection.get(
                    "selection_status"
                ),

            "selected_plan_id":
                plan_selection.get(
                    "selected_plan_id"
                ),

            "selection_summary":
                deepcopy(
                    self.safe_list(
                        plan_selection.get(
                            "selection_summary"
                        )
                    )
                ),

            "tradeoffs":
                deepcopy(
                    self.safe_list(
                        plan_selection.get(
                            "tradeoffs"
                        )
                    )
                ),

            "why_selected":
                plan_selection.get(
                    "why_selected"
                ),

            "why_not_more_aggressive":
                plan_selection.get(
                    "why_not_more_aggressive"
                ),

            "why_not_less_aggressive":
                plan_selection.get(
                    "why_not_less_aggressive"
                ),

            "isolation_justified":
                plan_selection.get(
                    "isolation_justified"
                ),

            "selected_plan": {

                "plan_id":
                    selected_plan.get(
                        "plan_id"
                    ),

                "plan_name":
                    selected_plan.get(
                        "plan_name"
                    ),

                "actions":
                    actions,

                "predicted_residual_risk":
                    selected_plan.get(
                        "predicted_residual_risk"
                    ),

                "predicted_residual_level":
                    selected_plan.get(
                        "predicted_residual_level"
                    ),

                "risk_reduction":
                    selected_plan.get(
                        "risk_reduction"
                    ),

                "risk_reduction_percentage":
                    selected_plan.get(
                        "risk_reduction_percentage"
                    ),

                "response_effectiveness":
                    selected_plan.get(
                        "response_effectiveness"
                    ),

                "operational_impact": {

                    "impact_score":
                        operational_impact.get(
                            "impact_score"
                        ),

                    "impact_level":
                        operational_impact.get(
                            "impact_level"
                        ),
                },

                "recommended_decision":
                    selected_plan.get(
                        "recommended_decision"
                    ),
            }
            if selected_plan
            else None,
        }


    # ============================================================
    # COMPACT POLICY
    # ============================================================

    def compact_policy(
        self,
        protection_policy: Dict,
    ) -> Dict:

        protection_policy = (
            self.safe_dict(
                protection_policy
            )
        )


        return {

            "protection_mode":
                protection_policy.get(
                    "protection_mode"
                ),

            "protection_mode_display":
                protection_policy.get(
                    "protection_mode_display"
                ),

            "policy_decision":
                protection_policy.get(
                    "policy_decision"
                ),

            "policy_reason":
                protection_policy.get(
                    "policy_reason"
                ),

            "requires_user_confirmation":
                protection_policy.get(
                    "requires_user_confirmation"
                ),

            "policy_eligible_for_protection":
                protection_policy.get(
                    "policy_eligible_for_protection"
                ),

            "automatic_protection_intent":
                protection_policy.get(
                    "automatic_protection_intent"
                ),

            "simulation_only":
                protection_policy.get(
                    "simulation_only"
                ),

            "execution_allowed":
                protection_policy.get(
                    "execution_allowed"
                ),

            "automatic_execution_allowed":
                protection_policy.get(
                    "automatic_execution_allowed"
                ),

            "real_response_executed":
                protection_policy.get(
                    "real_response_executed"
                ),
        }


    # ============================================================
    # REASONING PAYLOAD
    # ============================================================

    def build_reasoning_payload(
        self,
        *,
        threat: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        plan_selection: Dict,
        protection_policy: Dict,
    ) -> Dict:

        return {

            "threat":
                self.compact_threat(
                    threat
                ),

            "risk":
                self.compact_risk(
                    risk_assessment
                ),

            "response":
                self.compact_response(
                    response_recommendation
                ),

            "digital_twin_plan":
                self.compact_plan_selection(
                    plan_selection
                ),

            "protection_policy":
                self.compact_policy(
                    protection_policy
                ),

            "explanation_policy": {

                "plain_language":
                    True,

                "preserve_threat_certainty":
                    True,

                "never_claim_real_execution":
                    True,

                "digital_twin_is_simulation":
                    True,

                "risk_score_is_not_probability":
                    True,

                "do_not_change_policy_decision":
                    True,

                "do_not_change_selected_plan":
                    True,

                "do_not_invent_evidence":
                    True,
            },
        }


    # ============================================================
    # SYSTEM INSTRUCTION
    # ============================================================

    def build_system_instruction(
        self,
    ) -> str:

        return """
You are the SENTINEL-X AI User Explanation Agent.

Your job is to explain an already-completed security decision chain
to a normal user in clear, calm language.

You are NOT allowed to:

- reclassify the threat
- change the risk level
- change the response recommendation
- choose a different Digital Twin plan
- change the protection mode
- change the policy decision
- invent evidence
- invent actions
- claim a real response action was executed

THREAT CERTAINTY:

Preserve the supplied threat_assessment exactly.

BENIGN:
The evidence supports benign activity.

LOW_CONCERN:
The activity currently appears low concern.

UNCERTAIN:
The available evidence is insufficient for a confident conclusion.

SUSPICIOUS:
The activity is concerning, but malicious intent is not confirmed.

LIKELY_MALICIOUS:
Strong evidence suggests malicious activity, but do NOT describe it
as confirmed MALICIOUS.

MALICIOUS:
Only this label may be described as confirmed malicious.

EXECUTION SAFETY:

The current SENTINEL-X Phase 7 build is simulation-only.

Never say that Sentinel-X:

- terminated a process
- quarantined a file
- blocked a connection
- removed persistence
- isolated an endpoint
- protected the endpoint by executing a response

unless the input explicitly says real_response_executed=true.

The supplied policy should currently say real_response_executed=false.

If a Digital Twin plan exists, describe its actions as:

- simulated
- prepared
- recommended
- proposed
- would be applied if later authorized and execution is enabled

Never describe simulated actions as already completed.

DIGITAL TWIN:

Digital Twin results are simulated estimates.

Do not describe:

- predicted residual risk
- risk reduction
- plan_score

as real-world guarantees or probabilities.

RISK SCORE:

The risk score is a review-priority/security reasoning score.

It is NOT the probability that an attack occurred.

STYLE:

- clear language
- concise
- calm, not alarmist
- avoid unnecessary SOC jargon
- explain important uncertainty
- explain why the selected plan or monitoring choice makes sense
- explain why Sentinel-X did not use a broader action when relevant

Return JSON only.
""".strip()


    # ============================================================
    # PROMPT
    # ============================================================

    def build_prompt(
        self,
        payload: Dict,
    ) -> str:

        return f"""
Create the user-facing SENTINEL-X explanation.

Return exactly one JSON object:

{{
  "headline":
    "short user-facing security headline",

  "plain_language_summary":
    "2 to 4 sentence explanation of what Sentinel-X observed and how serious it appears",

  "why_flagged": [
    "1 to 4 concise evidence-grounded reasons"
  ],

  "why_it_matters":
    "short explanation of the security significance",

  "recommended_action_explanation":
    "explain the monitoring/review/simulated protection plan without claiming execution",

  "uncertainty_note":
    "clearly state the important uncertainty or confidence limitation",

  "digital_twin_note":
    "explain what the Digital Twin showed; if no plan was simulated, say no Digital Twin response plan was required"
}}

Requirements:

- preserve the exact threat certainty
- do not turn SUSPICIOUS into MALICIOUS
- do not turn LIKELY_MALICIOUS into confirmed MALICIOUS
- comparisons such as "matches known malicious patterns" describe similarity only; do not phrase them as proof the current event is malicious
- investigation language such as "check for any malicious activity" is allowed, but must not be rewritten as a claim that malicious activity is present
- do not invent security evidence
- do not invent response actions
- do not invent plan results
- do not claim any real containment/remediation action occurred
- if actions are mentioned, describe them as simulated/prepared/proposed
- do not say that an action WILL execute
- explain Digital Twin results as simulated estimates only
- do not describe the risk score as attack probability
- use 1 to 4 why_flagged items
- JSON only
- no markdown

INPUT:

{json.dumps(payload, indent=2, default=str)}
""".strip()


    # ============================================================
    # REPAIR PROMPT
    # ============================================================

    def build_repair_prompt(
        self,
        *,
        payload: Dict,
        validation_error: str,
    ) -> str:

        return f"""
{self.build_prompt(payload)}

Your previous response failed SENTINEL-X user-explanation
validation.

VALIDATION ERROR:

{validation_error}

Repair the COMPLETE JSON object.

Important repair rules:

- preserve threat_assessment certainty
- "LIKELY_MALICIOUS" must stay "likely malicious", not confirmed
  malicious
- "SUSPICIOUS" must stay suspicious, not malicious
- a comparison to known malicious patterns/techniques is NOT confirmation that the current activity is malicious
- "check for any malicious activity" is investigative language, not a factual malicious classification
- simulated actions must not be described as completed
- do not say Sentinel-X will execute a response
- Digital Twin results are simulated estimates
- do not invent evidence
- do not delete genuine observed evidence simply to satisfy the
  validator

Return JSON only.
""".strip()


    # ============================================================
    # JSON PARSER
    # ============================================================

    def parse_json_response(
        self,
        raw_text: str,
    ) -> Dict:

        raw_text = (
            self.safe_string(
                raw_text
            )
        )


        if not raw_text:

            raise ValueError(
                "AI provider returned empty response."
            )


        try:

            result = json.loads(
                raw_text
            )


            if isinstance(
                result,
                dict,
            ):

                return result


        except json.JSONDecodeError:

            pass


        start = (
            raw_text.find(
                "{"
            )
        )


        end = (
            raw_text.rfind(
                "}"
            )
        )


        if (
            start < 0
            or
            end < start
        ):

            raise ValueError(
                "No JSON object found."
            )


        result = json.loads(
            raw_text[
                start:
                end + 1
            ]
        )


        if not isinstance(
            result,
            dict,
        ):

            raise ValueError(
                "Response must be a JSON object."
            )


        return result


    # ============================================================
    # TEXT COLLECTION
    # ============================================================

    def collect_explanation_text(
        self,
        result: Dict,
    ) -> str:

        parts = []


        for key in [

            "headline",
            "plain_language_summary",
            "why_it_matters",
            "recommended_action_explanation",
            "uncertainty_note",
            "digital_twin_note",

        ]:

            text = (
                self.safe_string(
                    result.get(
                        key
                    )
                )
            )


            if text:

                parts.append(
                    text
                )


        for item in self.safe_list(
            result.get(
                "why_flagged"
            )
        ):

            text = (
                self.safe_string(
                    item
                )
            )


            if text:

                parts.append(
                    text
                )


        # Preserve field/item boundaries so a qualifier in one field
        # cannot accidentally weaken certainty validation for a different
        # statement in another field.
        return (
            " . ".join(
                parts
            )
            .lower()
        )


    @staticmethod
    def split_statements(
        text: str,
    ) -> List[str]:

        return [

            item.strip()

            for item in re.split(
                r"(?<=[.!?])\s+|[\n;]+",
                text,
            )

            if item.strip()
        ]


    # ============================================================
    # CERTAINTY VALIDATION
    # ============================================================

    def validate_certainty(
        self,
        *,
        result: Dict,
        risk_assessment: Dict,
    ) -> None:
        """
        Preserve the threat certainty produced by 7D.4.

        The user explanation may describe suspicious/likely-malicious
        behavior, uncertainty, and similarity to known malicious
        techniques. It must not upgrade a non-MALICIOUS assessment into
        a statement that the current activity is confirmed malicious.

        Important distinction:

            "this process is malicious"
                -> definitive classification

            "this behavior matches a known malicious macro pattern"
                -> contextual pattern comparison; NOT a definitive
                   classification of the current event

            "check for any malicious activity"
                -> investigation instruction; NOT a factual claim
        """

        assessment = (
            self.safe_string(
                risk_assessment.get(
                    "threat_assessment"
                )
            )
            .upper()
        )

        if assessment == "MALICIOUS":
            return

        text = (
            self.collect_explanation_text(
                result
            )
        )

        statements = (
            self.split_statements(
                text
            )
        )

        definitive_phrases = [
            "malicious activity",
            "malicious behavior",
            "malicious process",
            "malicious file",
            "malicious payload",
            "confirmed malicious",
            "known malicious",
            "the attack",
            "this attack",
        ]

        # Language that explicitly preserves uncertainty or does not
        # classify the CURRENT event as confirmed malicious.
        qualifiers = [
            "likely malicious",
            "potentially malicious",
            "possibly malicious",
            "suspected malicious",
            "suspicious",

            "if malicious",
            "if confirmed",
            "if this is malicious",
            "if the activity is malicious",
            "if an attack",
            "if this attack",

            "not confirmed malicious",
            "no confirmed malicious",
            "lack of confirmed malicious",
            "without confirmed malicious",
            "absence of confirmed malicious",

            "no malicious activity",
            "no malicious behavior",
            "no evidence of malicious activity",
            "no evidence of malicious behavior",
            "no direct evidence of malicious activity",
            "no direct evidence of malicious behavior",
            "malicious intent is not confirmed",
            "malicious intent has not been confirmed",
            "malicious intent is unknown",

            "possible attack",
            "potential attack",
            "suspected attack",
            "attack is not confirmed",
            "attack has not been confirmed",

            # Investigation/search language does not assert that the
            # activity already exists.
            "any malicious activity",
            "check for malicious activity",
            "check for any malicious activity",
            "look for malicious activity",
            "look for any malicious activity",
            "determine if the activity is malicious",
            "determine whether the activity is malicious",
            "verify whether the activity is malicious",
        ]

        # Generic references to malicious patterns/techniques are
        # comparisons, not classifications of the current event.
        #
        # Example:
        #   "signals match known malicious macro patterns"
        # is allowed for SUSPICIOUS because it describes similarity.
        contextual_reference_markers = [
            "known malicious pattern",
            "known malicious patterns",
            "known malicious macro pattern",
            "known malicious macro patterns",
            "known malicious technique",
            "known malicious techniques",
            "known malicious tactic",
            "known malicious tactics",
            "known malicious behavior pattern",
            "known malicious behavior patterns",
            "matches malicious patterns",
            "match malicious patterns",
            "matches known malicious",
            "match known malicious",
            "similar to malicious",
            "resembles malicious",
            "associated with malicious",
            "commonly used by malicious",
            "often used by malicious",
            "characteristic of malicious",
        ]

        for statement in statements:
            if not any(
                phrase in statement
                for phrase in definitive_phrases
            ):
                continue

            if any(
                marker in statement
                for marker in qualifiers
            ):
                continue

            if any(
                marker in statement
                for marker in contextual_reference_markers
            ):
                continue

            raise ValueError(
                (
                    "User explanation upgraded "
                    f"{assessment or 'UNKNOWN'} into "
                    "confirmed malicious activity. "
                    f"Statement: {statement}"
                )
            )


    # ============================================================
    # EXECUTION VALIDATION
    # ============================================================

    def validate_execution_language(
        self,
        *,
        result: Dict,
        protection_policy: Dict,
    ) -> None:

        text = (
            self.collect_explanation_text(
                result
            )
        )


        protection_policy = (
            self.safe_dict(
                protection_policy
            )
        )


        real_executed = (
            protection_policy.get(
                "real_response_executed"
            )
            is True
        )


        if real_executed:

            return


        forbidden_completed_phrases = [

            "has been terminated",
            "was terminated",
            "is terminated",

            "has been quarantined",
            "was quarantined",
            "is quarantined",

            "has been blocked",
            "was blocked",
            "is blocked",

            "has been isolated",
            "was isolated",
            "is isolated",

            "persistence has been removed",
            "persistence was removed",
            "persistence is removed",

            "sentinel-x terminated",
            "sentinel-x quarantined",
            "sentinel-x blocked",
            "sentinel-x isolated",
            "sentinel-x removed",

            "sentinel-x has protected",
            "endpoint has been protected",
            "system has been protected",
            "device has been protected",
        ]


        for phrase in (
            forbidden_completed_phrases
        ):

            if phrase in text:

                raise ValueError(
                    (
                        "Explanation claims a real response "
                        "action was completed: "
                        f"{phrase}"
                    )
                )


        forbidden_future_execution = [

            "sentinel-x will terminate",
            "sentinel-x will quarantine",
            "sentinel-x will block",
            "sentinel-x will isolate",
            "sentinel-x will remove",
            "sentinel-x will execute",

            "the system will terminate",
            "the system will quarantine",
            "the system will block",
            "the system will isolate",
        ]


        for phrase in (
            forbidden_future_execution
        ):

            if phrase in text:

                raise ValueError(
                    (
                        "Explanation promises real execution "
                        "in a simulation-only build: "
                        f"{phrase}"
                    )
                )


    # ============================================================
    # SIMULATION SEMANTICS
    # ============================================================

    def validate_simulation_semantics(
        self,
        *,
        result: Dict,
    ) -> None:

        text = (
            self.collect_explanation_text(
                result
            )
        )


        forbidden_guarantees = [

            "guaranteed protection",
            "guarantees protection",
            "guaranteed safe",
            "completely safe",
            "zero real-world risk",
            "eliminates all real-world risk",
            "will eliminate all risk",
        ]


        for phrase in (
            forbidden_guarantees
        ):

            if phrase in text:

                raise ValueError(
                    (
                        "Digital Twin explanation contains "
                        "an unsupported guarantee: "
                        f"{phrase}"
                    )
                )


        probability_pattern = re.compile(
            (
                r"\b\d{1,3}(?:\.\d+)?\s*%\s*"
                r"(?:chance|probability|likely|likelihood)"
            )
        )


        if probability_pattern.search(
            text
        ):

            raise ValueError(
                (
                    "Explanation converted security score "
                    "into an attack probability."
                )
            )


    # ============================================================
    # OUTPUT VALIDATION
    # ============================================================

    def validate_output(
        self,
        *,
        result: Dict,
        risk_assessment: Dict,
        protection_policy: Dict,
    ) -> Dict:

        result = (
            self.safe_dict(
                result
            )
        )


        required_text_fields = [

            "headline",
            "plain_language_summary",
            "why_it_matters",
            "recommended_action_explanation",
            "uncertainty_note",
            "digital_twin_note",
        ]


        normalized = {}


        for field in (
            required_text_fields
        ):

            value = (
                self.safe_string(
                    result.get(
                        field
                    )
                )
            )


            if not value:

                raise ValueError(
                    f"{field} is empty."
                )


            normalized[
                field
            ] = value


        why_flagged = [

            self.safe_string(
                item
            )

            for item in self.safe_list(
                result.get(
                    "why_flagged"
                )
            )

            if self.safe_string(
                item
            )
        ]


        if not (
            1
            <=
            len(
                why_flagged
            )
            <=
            4
        ):

            raise ValueError(
                (
                    "why_flagged must contain "
                    "1 to 4 items."
                )
            )


        normalized[
            "why_flagged"
        ] = why_flagged


        self.validate_certainty(

            result=
                normalized,

            risk_assessment=
                risk_assessment,
        )


        self.validate_execution_language(

            result=
                normalized,

            protection_policy=
                protection_policy,
        )


        self.validate_simulation_semantics(

            result=
                normalized,
        )


        return normalized


    # ============================================================
    # DETERMINISTIC PLANNED ACTIONS
    # ============================================================

    def planned_actions(
        self,
        plan_selection: Dict,
    ) -> List[Dict]:

        compact = (
            self.compact_plan_selection(
                plan_selection
            )
        )


        selected_plan = (
            self.safe_dict(
                compact.get(
                    "selected_plan"
                )
            )
        )


        return deepcopy(
            self.safe_list(
                selected_plan.get(
                    "actions"
                )
            )
        )


    # ============================================================
    # DETERMINISTIC UI POLICY
    # ============================================================

    def ui_policy_fields(
        self,
        *,
        protection_policy: Dict,
        plan_selection: Dict,
    ) -> Dict:

        protection_policy = (
            self.safe_dict(
                protection_policy
            )
        )


        plan_selection = (
            self.safe_dict(
                plan_selection
            )
        )


        decision = (
            self.safe_string(
                protection_policy.get(
                    "policy_decision"
                )
            )
            .upper()
        )


        if (
            decision
            not in
            self.VALID_POLICY_DECISIONS
        ):

            raise ValueError(
                (
                    "Unsupported protection policy "
                    f"decision: {decision}"
                )
            )


        display_status = (
            self.DISPLAY_STATUS[
                decision
            ]
        )


        has_plan = bool(
            self.safe_dict(
                plan_selection.get(
                    "selected_plan"
                )
            )
        )


        if decision == "MONITOR":

            execution_message = (
                "Sentinel-X is monitoring this activity. "
                "No containment or remediation action "
                "has been executed."
            )


            user_prompt = None


        elif decision == "ASK_USER":

            execution_message = (
                "Sentinel-X is waiting for review or "
                "confirmation. No containment or "
                "remediation action has been executed."
            )


            if has_plan:

                user_prompt = (
                    "Review the simulated protection plan "
                    "and decide whether it should be "
                    "approved when an execution layer "
                    "is available."
                )

            else:

                user_prompt = (
                    "Review this security event. A final "
                    "simulated protection plan is not "
                    "currently available."
                )


        else:

            execution_message = (
                "Sentinel-X prepared a protection plan "
                "in simulation. No real containment or "
                "remediation action has been executed."
            )


            user_prompt = None


        return {

            "display_status":
                display_status,

            "requires_user_confirmation":
                bool(
                    protection_policy.get(
                        "requires_user_confirmation",
                        False,
                    )
                ),

            "user_prompt":
                user_prompt,

            "execution_message":
                execution_message,
        }


    # ============================================================
    # PROVIDER
    # ============================================================

    def call_provider(
        self,
        *,
        prompt: str,
        temperature: float = 0.1,
    ) -> Dict:

        return (
            self.provider_manager.generate(

                prompt=
                    prompt,

                system_instruction=
                    self.build_system_instruction(),

                json_mode=
                    True,

                temperature=
                    temperature,
            )
        )


    # ============================================================
    # UNAVAILABLE RESULT
    # ============================================================

    def unavailable_result(
        self,
        *,
        threat: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        plan_selection: Dict,
        protection_policy: Dict,
        provider_result: Dict,
        validation_error: Optional[str] = None,
        repair_attempted: bool = False,
    ) -> Dict:

        ui = (
            self.ui_policy_fields(

                protection_policy=
                    protection_policy,

                plan_selection=
                    plan_selection,
            )
        )


        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "agent":
                self.name,

            "agent_version":
                self.VERSION,

            "generated_at":
                self.now_iso(),

            "ai_available":
                False,

            "provider":
                provider_result.get(
                    "provider"
                ),

            "model":
                provider_result.get(
                    "model"
                ),

            "provider_error":
                provider_result.get(
                    "error"
                ),

            "output_validation_error":
                validation_error,

            "output_repair_attempted":
                repair_attempted,

            "security_id":
                threat.get(
                    "id"
                ),

            "event_id":
                threat.get(
                    "event_id"
                ),

            "incident_id":
                (
                    threat.get(
                        "incident_id"
                    )
                    or
                    protection_policy.get(
                        "incident_id"
                    )
                ),

            "risk_level":
                risk_assessment.get(
                    "risk_level"
                ),

            "threat_assessment":
                risk_assessment.get(
                    "threat_assessment"
                ),

            "protection_mode":
                protection_policy.get(
                    "protection_mode"
                ),

            "policy_decision":
                protection_policy.get(
                    "policy_decision"
                ),

            **ui,

            "headline":
                "Security explanation temporarily unavailable",

            "plain_language_summary":
                (
                    "Sentinel-X retained the grounded "
                    "security decision, but the AI "
                    "explanation service is currently "
                    "unavailable."
                ),

            "why_flagged":
                [],

            "why_it_matters":
                (
                    "The underlying security result "
                    "remains available for technical review."
                ),

            "planned_actions":
                self.planned_actions(
                    plan_selection
                ),

            "recommended_action_explanation":
                (
                    "Refer to the existing response and "
                    "Digital Twin decision until the user "
                    "explanation service is available."
                ),

            "uncertainty_note":
                (
                    "This is an explanation-service "
                    "availability issue, not a new security "
                    "classification."
                ),

            "digital_twin_note":
                (
                    "Any Digital Twin result remains "
                    "simulation-only."
                ),

            "technical_details_available":
                True,

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_executed":
                False,

            "next_stage":
                "USER_FACING_API",
        }


    # ============================================================
    # MAIN
    # ============================================================

    def explain(
        self,
        *,
        threat: Dict,
        risk_assessment: Dict,
        response_recommendation: Dict,
        plan_selection: Dict,
        protection_policy: Dict,
    ) -> Dict:

        for name, value in [

            (
                "threat",
                threat,
            ),

            (
                "risk_assessment",
                risk_assessment,
            ),

            (
                "response_recommendation",
                response_recommendation,
            ),

            (
                "plan_selection",
                plan_selection,
            ),

            (
                "protection_policy",
                protection_policy,
            ),

        ]:

            if not isinstance(
                value,
                dict,
            ):

                raise TypeError(
                    f"{name} must be a dictionary."
                )


        # ========================================================
        # HARD SAFETY
        # ========================================================

        if (
            protection_policy.get(
                "real_response_executed"
            )
            is True
        ):

            raise ValueError(
                (
                    "7D.8 expected a simulation-only "
                    "protection policy, but real response "
                    "execution was reported."
                )
            )


        if (
            protection_policy.get(
                "execution_allowed"
            )
            is True
        ):

            raise ValueError(
                (
                    "7D.8 cannot explain an upstream "
                    "state that permits real execution."
                )
            )


        payload = (
            self.build_reasoning_payload(

                threat=
                    threat,

                risk_assessment=
                    risk_assessment,

                response_recommendation=
                    response_recommendation,

                plan_selection=
                    plan_selection,

                protection_policy=
                    protection_policy,
            )
        )


        provider_result = (
            self.call_provider(

                prompt=
                    self.build_prompt(
                        payload
                    ),

                temperature=
                    0.1,
            )
        )


        if not provider_result.get(
            "success"
        ):

            return (
                self.unavailable_result(

                    threat=
                        threat,

                    risk_assessment=
                        risk_assessment,

                    response_recommendation=
                        response_recommendation,

                    plan_selection=
                        plan_selection,

                    protection_policy=
                        protection_policy,

                    provider_result=
                        provider_result,
                )
            )


        repair_used = False


        try:

            parsed = (
                self.parse_json_response(
                    provider_result[
                        "text"
                    ]
                )
            )


            validated = (
                self.validate_output(

                    result=
                        parsed,

                    risk_assessment=
                        risk_assessment,

                    protection_policy=
                        protection_policy,
                )
            )


        except Exception as first_error:

            repair_result = (
                self.call_provider(

                    prompt=
                        self.build_repair_prompt(

                            payload=
                                payload,

                            validation_error=
                                str(
                                    first_error
                                ),
                        ),

                    temperature=
                        0.0,
                )
            )


            if not repair_result.get(
                "success"
            ):

                return (
                    self.unavailable_result(

                        threat=
                            threat,

                        risk_assessment=
                            risk_assessment,

                        response_recommendation=
                            response_recommendation,

                        plan_selection=
                            plan_selection,

                        protection_policy=
                            protection_policy,

                        provider_result=
                            repair_result,

                        validation_error=
                            str(
                                first_error
                            ),

                        repair_attempted=
                            True,
                    )
                )


            try:

                repaired = (
                    self.parse_json_response(
                        repair_result[
                            "text"
                        ]
                    )
                )


                validated = (
                    self.validate_output(

                        result=
                            repaired,

                        risk_assessment=
                            risk_assessment,

                        protection_policy=
                            protection_policy,
                    )
                )


                provider_result = (
                    repair_result
                )


                repair_used = True


            except Exception as repair_error:

                return (
                    self.unavailable_result(

                        threat=
                            threat,

                        risk_assessment=
                            risk_assessment,

                        response_recommendation=
                            response_recommendation,

                        plan_selection=
                            plan_selection,

                        protection_policy=
                            protection_policy,

                        provider_result=
                            repair_result,

                        validation_error=
                            str(
                                repair_error
                            ),

                        repair_attempted=
                            True,
                    )
                )


        ui = (
            self.ui_policy_fields(

                protection_policy=
                    protection_policy,

                plan_selection=
                    plan_selection,
            )
        )


        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "agent":
                self.name,

            "agent_version":
                self.VERSION,

            "generated_at":
                self.now_iso(),

            "ai_available":
                True,

            "provider":
                provider_result.get(
                    "provider"
                ),

            "model":
                provider_result.get(
                    "model"
                ),

            "fallback_used":
                provider_result.get(
                    "fallback_used",
                    False,
                ),

            "output_repair_used":
                repair_used,

            "security_id":
                threat.get(
                    "id"
                ),

            "event_id":
                threat.get(
                    "event_id"
                ),

            "incident_id":
                (
                    threat.get(
                        "incident_id"
                    )
                    or
                    protection_policy.get(
                        "incident_id"
                    )
                ),

            "risk_level":
                risk_assessment.get(
                    "risk_level"
                ),

            "threat_assessment":
                risk_assessment.get(
                    "threat_assessment"
                ),

            "risk_confidence":
                risk_assessment.get(
                    "confidence"
                ),

            "protection_mode":
                protection_policy.get(
                    "protection_mode"
                ),

            "protection_mode_display":
                protection_policy.get(
                    "protection_mode_display"
                ),

            "policy_decision":
                protection_policy.get(
                    "policy_decision"
                ),

            "selected_plan_id":
                plan_selection.get(
                    "selected_plan_id"
                ),

            **ui,

            **validated,

            "planned_actions":
                self.planned_actions(
                    plan_selection
                ),

            "technical_details_available":
                True,

            "source_versions": {

                "risk":
                    risk_assessment.get(
                        "agent_version"
                    ),

                "response":
                    response_recommendation.get(
                        "agent_version"
                    ),

                "plan_selection":
                    plan_selection.get(
                        "agent_version"
                    ),

                "protection_policy":
                    protection_policy.get(
                        "policy_version"
                    ),
            },

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_executed":
                False,

            "next_stage":
                "USER_FACING_API",
        }


# ================================================================
# SHARED INSTANCE
# ================================================================


shared_ai_user_explanation_agent = (
    AIUserExplanationAgent()
)
