from __future__ import annotations

import json

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

from agents.evidence_context_builder import (
    EvidenceContextBuilder,
    shared_evidence_context_builder,
)

from agents.evidence_enrichment_agent import (
    EvidenceEnrichmentAgent,
)


# ================================================================
# SENTINEL-X AI PROTECTION DECISION AGENT
# ================================================================


class ProtectionDecisionAgent:
    """
    SENTINEL-X AI Protection Decision Agent.

    7D.2 integration:

        Canonical threat
                ↓
        EvidenceEnrichmentAgent
                ↓
        EvidenceContextBuilder
                ↓
        ProtectionDecisionAgent
                ↓
        AIProviderManager / Groq

    Security reasoning is separated from validation provenance.

    This agent NEVER executes real endpoint actions.
    """

    VERSION = "7D.2-integrated-v1"

    SCHEMA_VERSION = (
        "sentinelx.ai.protection-decision.v1"
    )


    # ============================================================
    # OUTPUT ENUMS
    # ============================================================

    VALID_DECISIONS = {
        "SAFE",
        "MONITOR",
        "ASK_USER",
        "PROTECT",
    }


    VALID_THREAT_ASSESSMENTS = {
        "BENIGN",
        "LOW_CONCERN",
        "UNCERTAIN",
        "SUSPICIOUS",
        "LIKELY_MALICIOUS",
        "MALICIOUS",
    }


    VALID_ACTIONS = {
        "NONE",
        "MONITOR",
        "INVESTIGATE",
        "TERMINATE_PROCESS",
        "QUARANTINE_FILE",
        "BLOCK_NETWORK",
        "REMOVE_PERSISTENCE",
        "ACCOUNT_PROTECTION",
        "DEVICE_ISOLATION",
    }


    CONTAINMENT_ACTIONS = {
        "TERMINATE_PROCESS",
        "QUARANTINE_FILE",
        "BLOCK_NETWORK",
        "REMOVE_PERSISTENCE",
        "ACCOUNT_PROTECTION",
        "DEVICE_ISOLATION",
    }


    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
        provider_manager=None,
        context_builder=None,
        enrichment_agent=None,
    ):

        self.name = (
            "ProtectionDecisionAgent"
        )


        self.provider_manager = (
            provider_manager
            if provider_manager is not None
            else shared_ai_provider_manager
        )


        self.context_builder = (
            context_builder
            if context_builder is not None
            else shared_evidence_context_builder
        )


        self.enrichment_agent = (
            enrichment_agent
            if enrichment_agent is not None
            else EvidenceEnrichmentAgent()
        )


    # ============================================================
    # BASIC HELPERS
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


    @staticmethod
    def safe_float(
        value: Any,
        default: float = 0.0,
    ) -> float:

        try:

            number = float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return default


        if number < 0:

            return 0.0


        if number > 1:

            return 1.0


        return number


    def clean_string_list(
        self,
        value: Any,
    ) -> List[str]:

        output = []


        for item in self.safe_list(
            value
        ):

            text = self.safe_string(
                item
            )


            if text:

                output.append(
                    text
                )


        return output


    # ============================================================
    # STATUS
    # ============================================================

    def status(
        self,
    ) -> Dict:

        context_status = (
            self.context_builder
            .status()
        )


        return {

            "agent":
                self.name,

            "version":
                self.VERSION,

            "schema_version":
                self.SCHEMA_VERSION,

            "provider_manager":
                self.provider_manager.status(),

            "evidence_context_builder":
                context_status,

            "evidence_enrichment_agent":
                self.enrichment_agent.name,

            "context_pipeline":

                (
                    "EvidenceEnrichmentAgent"
                    " -> "
                    "EvidenceContextBuilder"
                    " -> "
                    "ProtectionDecisionAgent"
                ),

            "simulation_only":
                True,

            "execution_allowed":
                False,
        }


    # ============================================================
    # OPTIONAL EVIDENCE ENRICHMENT
    #
    # If a full incident timeline exists, use the existing
    # EvidenceEnrichmentAgent.
    #
    # Canonical threat summary objects may not contain a timeline;
    # in that case no fake enrichment is generated.
    # ============================================================

    def resolve_enriched_evidence(
        self,
        *,
        incident: Optional[Dict],
        enriched_evidence: Optional[Dict],
    ) -> Dict:

        if isinstance(
            enriched_evidence,
            dict,
        ) and enriched_evidence:

            return enriched_evidence


        incident = self.safe_dict(
            incident
        )


        timeline = self.safe_list(
            incident.get(
                "timeline"
            )
        )


        if not timeline:

            return {}


        try:

            enriched = (
                self.enrichment_agent
                .enrich(
                    incident
                )
            )


            return self.safe_dict(
                enriched
            )


        except Exception:

            # Enrichment failure must not invent evidence.
            return {}


    # ============================================================
    # BUILD COMPLETE EVIDENCE CONTEXT
    # ============================================================

    def build_ai_context(
        self,
        *,
        threat: Dict,
        incident: Optional[Dict] = None,
        investigation: Optional[Dict] = None,
        enriched_evidence: Optional[Dict] = None,
        graph_rag_context: Optional[Any] = None,
        additional_context: Optional[Dict] = None,
    ) -> Dict:

        resolved_enrichment = (
            self.resolve_enriched_evidence(

                incident=
                    incident,

                enriched_evidence=
                    enriched_evidence,
            )
        )


        return (
            self.context_builder
            .build(

                threat=
                    threat,

                incident=
                    incident,

                investigation=
                    investigation,

                enriched_evidence=
                    resolved_enrichment,

                graph_rag_context=
                    graph_rag_context,

                additional_context=
                    additional_context,
            )
        )


    # ============================================================
    # SECURITY REASONING PAYLOAD
    #
    # IMPORTANT:
    #
    # provenance_context is intentionally NOT sent to the LLM.
    # safety_context is intentionally NOT used for maliciousness
    # reasoning.
    #
    # They remain available in the EvidenceContextBuilder result
    # for audit/runtime use.
    # ============================================================

    def build_reasoning_payload(
        self,
        context: Dict,
    ) -> Dict:

        context = self.safe_dict(
            context
        )


        return {

            "security_context":

                self.safe_dict(
                    context.get(
                        "security_context"
                    )
                ),

            "evidence_availability":

                self.safe_dict(
                    context.get(
                        "evidence_availability"
                    )
                ),

            "evidence_quality":

                self.safe_dict(
                    context.get(
                        "evidence_quality"
                    )
                ),

            "reasoning_policy":

                self.safe_dict(
                    context.get(
                        "reasoning_policy"
                    )
                ),
        }


    # ============================================================
    # SYSTEM INSTRUCTION
    # ============================================================

    def build_system_instruction(
        self,
    ) -> str:

        return """
You are the AI Protection Decision Agent inside SENTINEL-X.

Your responsibility is cybersecurity threat reasoning.

You receive a normalized security evidence package prepared by
the SENTINEL-X Evidence Context Builder.

Evaluate the represented cybersecurity behavior as though the
same behavior occurred on a real endpoint.

Do not infer benignity or maliciousness from:

- synthetic/test/validation provenance
- validation filenames
- validation usernames
- validation hostnames
- simulation mode
- disabled endpoint execution

Those properties concern system safety and testing only.

They are not security evidence.

Reason using:

- observed endpoint behavior
- detector evidence
- ML/DL model evidence
- temporal evidence
- incident correlation
- investigation findings
- enriched evidence
- verified relationships
- unverified/inferred relationships
- Graph-RAG context when present
- uncertainty and conflicting evidence

IMPORTANT EVIDENCE RULES:

Direct observations are stronger than inferred relationships.

Unverified identity links must not be treated as confirmed
attribution.

Graph-RAG knowledge is supporting context, not proof.

Detector risk scores are defensive scores, not probabilities.

Detector confidence is not automatically a calibrated probability.

A detector alert alone does not prove malicious intent.

Missing investigation data does not prove that activity is benign.

SAFE requires actual security evidence supporting a legitimate
or benign explanation.

When evidence is incomplete or contradictory, prefer uncertainty
over invented certainty.

Do not invent:

- processes
- files
- IP addresses
- users
- registry keys
- model outputs
- relationships
- threat intelligence
- attack activity

Allowed decisions:

SAFE
MONITOR
ASK_USER
PROTECT

Decision meaning:

SAFE:
Available security evidence supports a benign explanation.

MONITOR:
Activity remains concerning or incomplete but immediate protection
is not sufficiently justified.

ASK_USER:
User or administrator context is materially necessary.

PROTECT:
Security evidence justifies preparing a protective response.

PROTECT does not authorize real execution.

Allowed actions:

NONE
MONITOR
INVESTIGATE
TERMINATE_PROCESS
QUARANTINE_FILE
BLOCK_NETWORK
REMOVE_PERSISTENCE
ACCOUNT_PROTECTION
DEVICE_ISOLATION

Allowed threat assessments:

BENIGN
LOW_CONCERN
UNCERTAIN
SUSPICIOUS
LIKELY_MALICIOUS
MALICIOUS

Return JSON only.
""".strip()


    # ============================================================
    # PROMPT
    # ============================================================

    def build_prompt(
        self,
        context: Dict,
    ) -> str:

        reasoning_payload = (
            self.build_reasoning_payload(
                context
            )
        )


        evidence_json = (
            json.dumps(
                reasoning_payload,
                indent=2,
                default=str,
            )
        )


        return f"""
Analyze the following SENTINEL-X cybersecurity evidence.

Return exactly one JSON object using this schema:

{{
  "decision":
    "SAFE|MONITOR|ASK_USER|PROTECT",

  "confidence":
    0.0,

  "threat_assessment":
    "BENIGN|LOW_CONCERN|UNCERTAIN|SUSPICIOUS|LIKELY_MALICIOUS|MALICIOUS",

  "recommended_action":
    "NONE|MONITOR|INVESTIGATE|TERMINATE_PROCESS|QUARANTINE_FILE|BLOCK_NETWORK|REMOVE_PERSISTENCE|ACCOUNT_PROTECTION|DEVICE_ISOLATION",

  "reasoning_summary": [
    "evidence-grounded reason"
  ],

  "evidence_used": [
    "specific supplied security evidence"
  ],

  "corroborating_signals": [
    "independent supporting security signal"
  ],

  "uncertainties": [
    "remaining uncertainty"
  ],

  "why_not_more_aggressive":
    "security-grounded explanation",

  "why_not_less_aggressive":
    "security-grounded explanation",

  "digital_twin_required":
    true
}}

Requirements:

- confidence must be between 0 and 1

- use only supplied security evidence

- do not invent facts

- detector risk scores are not probabilities

- high detector score alone does not justify PROTECT

- low detector score alone does not justify SAFE

- missing evidence does not prove benignity

- SAFE requires affirmative benign evidence

- inferred relationships are not confirmed attribution

- prefer observed evidence over inferred evidence

- PROTECT requires a protective containment recommendation

- SAFE must recommend NONE

- MONITOR and ASK_USER cannot recommend containment actions

- evidence_used must not be empty

- reasoning_summary must not be empty

- why_not_more_aggressive must not be empty

- why_not_less_aggressive must not be empty

- return JSON only

- no markdown

SECURITY EVIDENCE:

{evidence_json}
""".strip()


    # ============================================================
    # REPAIR PROMPT
    # ============================================================

    def build_repair_prompt(
        self,
        *,
        context: Dict,
        validation_error: str,
    ) -> str:

        return f"""
{self.build_prompt(context)}

Your previous response failed Sentinel-X output validation.

Validation error:

{validation_error}

Generate the complete JSON object again.

Do not return a partial patch.

Ensure every required field is present and valid.

Return JSON only.
""".strip()


    # ============================================================
    # PARSE JSON
    # ============================================================

    def parse_json_response(
        self,
        raw_text: str,
    ) -> Dict:

        raw_text = self.safe_string(
            raw_text
        )


        if not raw_text:

            raise ValueError(
                "AI provider returned an empty response."
            )


        try:

            parsed = json.loads(
                raw_text
            )


            if isinstance(
                parsed,
                dict,
            ):

                return parsed


        except json.JSONDecodeError:

            pass


        start = raw_text.find(
            "{"
        )


        end = raw_text.rfind(
            "}"
        )


        if (
            start < 0
            or
            end < start
        ):

            raise ValueError(
                "AI response does not contain valid JSON."
            )


        parsed = json.loads(

            raw_text[
                start:
                end + 1
            ]
        )


        if not isinstance(
            parsed,
            dict,
        ):

            raise ValueError(
                "AI result must be a JSON object."
            )


        return parsed


    # ============================================================
    # VALIDATE AI OUTPUT
    # ============================================================

    def validate_ai_output(
        self,
        result: Dict,
    ) -> Dict:

        result = self.safe_dict(
            result
        )


        # --------------------------------------------------------
        # DECISION
        # --------------------------------------------------------

        decision = (
            self.safe_string(
                result.get(
                    "decision"
                )
            )
            .upper()
        )


        if (
            decision
            not in
            self.VALID_DECISIONS
        ):

            raise ValueError(
                f"Invalid AI decision: {decision}"
            )


        # --------------------------------------------------------
        # ASSESSMENT
        # --------------------------------------------------------

        assessment = (
            self.safe_string(
                result.get(
                    "threat_assessment"
                )
            )
            .upper()
        )


        if (
            assessment
            not in
            self.VALID_THREAT_ASSESSMENTS
        ):

            raise ValueError(
                (
                    "Invalid AI threat assessment: "
                    f"{assessment}"
                )
            )


        # --------------------------------------------------------
        # ACTION
        # --------------------------------------------------------

        action = (
            self.safe_string(
                result.get(
                    "recommended_action"
                )
            )
            .upper()
        )


        if (
            action
            not in
            self.VALID_ACTIONS
        ):

            raise ValueError(
                (
                    "Invalid AI recommended action: "
                    f"{action}"
                )
            )


        confidence = (
            self.safe_float(
                result.get(
                    "confidence"
                ),
                0.0,
            )
        )


        # --------------------------------------------------------
        # REQUIRED EXPLANATION
        # --------------------------------------------------------

        reasoning_summary = (
            self.clean_string_list(
                result.get(
                    "reasoning_summary"
                )
            )
        )


        evidence_used = (
            self.clean_string_list(
                result.get(
                    "evidence_used"
                )
            )
        )


        corroborating_signals = (
            self.clean_string_list(
                result.get(
                    "corroborating_signals"
                )
            )
        )


        uncertainties = (
            self.clean_string_list(
                result.get(
                    "uncertainties"
                )
            )
        )


        why_not_more_aggressive = (
            self.safe_string(
                result.get(
                    "why_not_more_aggressive"
                )
            )
        )


        why_not_less_aggressive = (
            self.safe_string(
                result.get(
                    "why_not_less_aggressive"
                )
            )
        )


        if not reasoning_summary:

            raise ValueError(
                "reasoning_summary is empty."
            )


        if not evidence_used:

            raise ValueError(
                "evidence_used is empty."
            )


        if not why_not_more_aggressive:

            raise ValueError(
                "why_not_more_aggressive is empty."
            )


        if not why_not_less_aggressive:

            raise ValueError(
                "why_not_less_aggressive is empty."
            )


        # --------------------------------------------------------
        # ACTION SAFETY
        # --------------------------------------------------------

        if (
            decision
            ==
            "SAFE"

            and

            action
            !=
            "NONE"
        ):

            raise ValueError(
                "SAFE must recommend NONE."
            )


        if (
            decision
            in {
                "MONITOR",
                "ASK_USER",
            }

            and

            action
            in
            self.CONTAINMENT_ACTIONS
        ):

            raise ValueError(
                (
                    f"{decision} cannot contain "
                    "a containment action."
                )
            )


        if (
            decision
            ==
            "PROTECT"

            and

            action
            not in
            self.CONTAINMENT_ACTIONS
        ):

            raise ValueError(
                (
                    "PROTECT must recommend "
                    "a containment action."
                )
            )


        # --------------------------------------------------------
        # ASSESSMENT CONSISTENCY
        # --------------------------------------------------------

        if (
            decision
            ==
            "SAFE"

            and

            assessment
            not in {
                "BENIGN",
                "LOW_CONCERN",
            }
        ):

            raise ValueError(
                (
                    "SAFE decision has incompatible "
                    f"assessment: {assessment}"
                )
            )


        if (
            decision
            ==
            "PROTECT"

            and

            assessment
            in {
                "BENIGN",
                "LOW_CONCERN",
            }
        ):

            raise ValueError(
                (
                    "PROTECT decision has incompatible "
                    f"assessment: {assessment}"
                )
            )


        # --------------------------------------------------------
        # DIGITAL TWIN IS DERIVED, NOT TRUSTED TO LLM
        # --------------------------------------------------------

        digital_twin_required = (
            decision
            ==
            "PROTECT"
        )


        return {

            "decision":
                decision,

            "confidence":
                confidence,

            "threat_assessment":
                assessment,

            "recommended_action":
                action,

            "reasoning_summary":
                reasoning_summary,

            "evidence_used":
                evidence_used,

            "corroborating_signals":
                corroborating_signals,

            "uncertainties":
                uncertainties,

            "why_not_more_aggressive":
                why_not_more_aggressive,

            "why_not_less_aggressive":
                why_not_less_aggressive,

            "digital_twin_required":
                digital_twin_required,
        }


    # ============================================================
    # PROVIDER CALL
    # ============================================================

    def call_provider(
        self,
        *,
        prompt: str,
        temperature: float = 0.1,
    ) -> Dict:

        return (
            self.provider_manager
            .generate(

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
    # AI UNAVAILABLE
    # ============================================================

    def build_ai_unavailable_result(
        self,
        *,
        threat: Dict,
        provider_result: Dict,
        context: Dict,
    ) -> Dict:

        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "agent":
                self.name,

            "agent_version":
                self.VERSION,

            "generated_at":
                self.now_iso(),

            "context_schema_version":
                context.get(
                    "schema_version"
                ),

            "context_builder_version":
                context.get(
                    "builder_version"
                ),

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

            "provider_error_type":
                provider_result.get(
                    "error_type"
                ),

            "provider_error":
                provider_result.get(
                    "error"
                ),

            "decision":
                "UNAVAILABLE",

            "confidence":
                None,

            "threat_assessment":
                "UNAVAILABLE",

            "recommended_action":
                "NONE",

            "reasoning_summary":
                [],

            "evidence_used":
                [],

            "corroborating_signals":
                [],

            "uncertainties": [
                (
                    "AI protection reasoning "
                    "is currently unavailable."
                )
            ],

            "security_id":
                threat.get(
                    "id"
                ),

            "detection_id":
                threat.get(
                    "detection_id"
                ),

            "event_id":
                threat.get(
                    "event_id"
                ),

            "incident_id":
                threat.get(
                    "incident_id"
                ),

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_executed":
                False,

            "next_stage":
                "NONE",
        }


    # ============================================================
    # OUTPUT VALIDATION FAILURE
    # ============================================================

    def build_validation_failure_result(
        self,
        *,
        threat: Dict,
        provider_result: Dict,
        context: Dict,
        error: Exception,
        repair_attempted: bool,
    ) -> Dict:

        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "agent":
                self.name,

            "agent_version":
                self.VERSION,

            "generated_at":
                self.now_iso(),

            "context_schema_version":
                context.get(
                    "schema_version"
                ),

            "context_builder_version":
                context.get(
                    "builder_version"
                ),

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

            "decision":
                "UNAVAILABLE",

            "confidence":
                None,

            "threat_assessment":
                "UNAVAILABLE",

            "recommended_action":
                "NONE",

            "reasoning_summary":
                [],

            "evidence_used":
                [],

            "corroborating_signals":
                [],

            "uncertainties": [
                (
                    "AI response failed Sentinel-X "
                    "output validation."
                )
            ],

            "security_id":
                threat.get(
                    "id"
                ),

            "detection_id":
                threat.get(
                    "detection_id"
                ),

            "event_id":
                threat.get(
                    "event_id"
                ),

            "incident_id":
                threat.get(
                    "incident_id"
                ),

            "output_validation_error":
                str(
                    error
                ),

            "output_repair_attempted":
                repair_attempted,

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_executed":
                False,

            "next_stage":
                "NONE",
        }


    # ============================================================
    # MAIN DECISION
    # ============================================================

    def decide(
        self,
        *,
        threat: Dict,
        incident: Optional[Dict] = None,
        investigation: Optional[Dict] = None,
        enriched_evidence: Optional[Dict] = None,
        graph_rag_context: Optional[Any] = None,
        additional_context: Optional[Dict] = None,
    ) -> Dict:

        if not isinstance(
            threat,
            dict,
        ):

            raise TypeError(
                "threat must be a dictionary."
            )


        # ========================================================
        # 1. BUILD NORMALIZED EVIDENCE CONTEXT
        # ========================================================

        context = (
            self.build_ai_context(

                threat=
                    threat,

                incident=
                    incident,

                investigation=
                    investigation,

                enriched_evidence=
                    enriched_evidence,

                graph_rag_context=
                    graph_rag_context,

                additional_context=
                    additional_context,
            )
        )


        # ========================================================
        # 2. CALL AI
        # ========================================================

        provider_result = (
            self.call_provider(

                prompt=
                    self.build_prompt(
                        context
                    ),

                temperature=
                    0.1,
            )
        )


        if not provider_result.get(
            "success"
        ):

            return (
                self.build_ai_unavailable_result(

                    threat=
                        threat,

                    provider_result=
                        provider_result,

                    context=
                        context,
                )
            )


        output_repair_used = False


        # ========================================================
        # 3. PARSE + VALIDATE
        # ========================================================

        try:

            parsed = (
                self.parse_json_response(

                    provider_result[
                        "text"
                    ]
                )
            )


            validated = (
                self.validate_ai_output(
                    parsed
                )
            )


        except Exception as first_error:

            # ====================================================
            # 4. ONE CONTROLLED REPAIR ATTEMPT
            # ====================================================

            repair_result = (
                self.call_provider(

                    prompt=
                        self.build_repair_prompt(

                            context=
                                context,

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
                    self.build_validation_failure_result(

                        threat=
                            threat,

                        provider_result=
                            provider_result,

                        context=
                            context,

                        error=
                            first_error,

                        repair_attempted=
                            True,
                    )
                )


            try:

                repaired_parsed = (
                    self.parse_json_response(

                        repair_result[
                            "text"
                        ]
                    )
                )


                validated = (
                    self.validate_ai_output(
                        repaired_parsed
                    )
                )


                provider_result = (
                    repair_result
                )


                output_repair_used = (
                    True
                )


            except Exception as repair_error:

                return (
                    self.build_validation_failure_result(

                        threat=
                            threat,

                        provider_result=
                            repair_result,

                        context=
                            context,

                        error=
                            repair_error,

                        repair_attempted=
                            True,
                    )
                )


        # ========================================================
        # 5. FINAL RESULT
        # ========================================================

        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "agent":
                self.name,

            "agent_version":
                self.VERSION,

            "generated_at":
                self.now_iso(),

            # ----------------------------------------------------
            # Evidence context audit
            # ----------------------------------------------------

            "context_schema_version":
                context.get(
                    "schema_version"
                ),

            "context_builder_version":
                context.get(
                    "builder_version"
                ),

            "evidence_availability":
                context.get(
                    "evidence_availability"
                ),

            "evidence_quality":
                context.get(
                    "evidence_quality"
                ),

            # ----------------------------------------------------
            # Provider
            # ----------------------------------------------------

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
                output_repair_used,

            # ----------------------------------------------------
            # Canonical IDs
            # ----------------------------------------------------

            "security_id":
                threat.get(
                    "id"
                ),

            "detection_id":
                threat.get(
                    "detection_id"
                ),

            "event_id":
                threat.get(
                    "event_id"
                ),

            "incident_id":
                threat.get(
                    "incident_id"
                ),

            # ----------------------------------------------------
            # Validated AI result
            # ----------------------------------------------------

            **validated,

            # ----------------------------------------------------
            # Hard execution boundary
            # ----------------------------------------------------

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_executed":
                False,

            "next_stage":
                (
                    "DIGITAL_TWIN"

                    if validated[
                        "digital_twin_required"
                    ]

                    else

                    "NONE"
                ),
        }


# ================================================================
# SHARED INSTANCE
# ================================================================

shared_protection_decision_agent = (
    ProtectionDecisionAgent()
)