from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ai_provider_manager import shared_ai_provider_manager
from agents.evidence_context_builder import shared_evidence_context_builder


# ================================================================
# SENTINEL-X AI RISK REASONING AGENT
# ================================================================


class AIRiskReasoningAgent:
    """
    SENTINEL-X 7D.4 AI Risk Reasoning Agent.

    Risk reasoning only.

    This agent:
        - assesses cybersecurity risk
        - reasons over available evidence
        - expresses uncertainty
        - produces a review-priority score

    This agent DOES NOT:
        - choose containment actions
        - execute endpoint actions
        - treat synthetic provenance as benign evidence
        - convert detector scores into probabilities
        - use fixed score thresholds for semantic decisions
    """

    VERSION = "7D.4-v3"
    SCHEMA_VERSION = "sentinelx.ai.risk-reasoning.v1"

    VALID_RISK_LEVELS = {
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    VALID_ASSESSMENTS = {
        "BENIGN",
        "LOW_CONCERN",
        "UNCERTAIN",
        "SUSPICIOUS",
        "LIKELY_MALICIOUS",
        "MALICIOUS",
    }

    VALID_EVIDENCE_STRENGTH = {
        "WEAK",
        "MODERATE",
        "STRONG",
        "VERY_STRONG",
    }

    # ============================================================
    # REASONING CONTENT THAT MUST NEVER BE USED AS RISK EVIDENCE
    # ============================================================

    FORBIDDEN_PROVENANCE_PHRASES = {
        "synthetic provenance",
        "synthetic validation",
        "synthetic source",
        "synthetic data",
        "synthetic environment",
        "validation source",
        "validation environment",
        "validation data",
        "test environment",
        "test data",
        "simulation mode",
        "simulation-only",
        "simulation only",
        "because it is synthetic",
        "because this is synthetic",
        "not production",
        "production environment",
        "real endpoint execution",
        "execution is disabled",
    }

    FORBIDDEN_THRESHOLD_PHRASES = {
        "exceeds the threshold",
        "exceed the threshold",
        "below the threshold",
        "above the threshold",
        "threshold for low",
        "threshold for medium",
        "threshold for high",
        "threshold for critical",
    }

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
        provider_manager=None,
        context_builder=None,
    ):
        self.name = "AIRiskReasoningAgent"

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
        return {
            "agent":
                self.name,

            "version":
                self.VERSION,

            "schema_version":
                self.SCHEMA_VERSION,

            "provider_manager":
                self.provider_manager.status(),

            "context_builder":
                self.context_builder.status(),

            "risk_score_semantics":
                "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",

            "provenance_used_for_risk":
                False,

            "fixed_threshold_reasoning":
                False,

            "action_selection":
                False,

            "simulation_only":
                True,

            "execution_allowed":
                False,
        }

    # ============================================================
    # BUILD EVIDENCE CONTEXT
    # ============================================================

    def build_context(
        self,
        *,
        threat: Dict,
        incident: Optional[Dict] = None,
        investigation: Optional[Dict] = None,
        enriched_evidence: Optional[Dict] = None,
        graph_rag_context: Optional[Any] = None,
        additional_context: Optional[Dict] = None,
    ) -> Dict:
        return (
            self.context_builder.build(
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

    # ============================================================
    # CLEAN VALIDATION-LIKE IDENTIFIERS
    # ============================================================

    def normalize_identifier_text(
        self,
        value: str,
    ) -> str:
        text = self.safe_string(
            value
        )

        if not text:
            return text

        text = re.sub(
            r"(?i)\bvalidation[._-]",
            "",
            text,
        )

        text = re.sub(
            r"(?i)\bsentinelx-validation-",
            "sentinelx-",
            text,
        )

        text = re.sub(
            r"(?i)\bsynthetic[._-]",
            "",
            text,
        )

        return text.strip()

    # ============================================================
    # REASONING SANITIZER
    # ============================================================

    def sanitize_reasoning_value(
        self,
        value: Any,
    ) -> Any:
        if isinstance(
            value,
            dict,
        ):
            output = {}

            for key, item in (
                value.items()
            ):
                cleaned = (
                    self.sanitize_reasoning_value(
                        item
                    )
                )

                if cleaned is None:
                    continue

                output[
                    key
                ] = cleaned

            return output

        if isinstance(
            value,
            list,
        ):
            output = []

            for item in value:
                cleaned = (
                    self.sanitize_reasoning_value(
                        item
                    )
                )

                if cleaned is not None:
                    output.append(
                        cleaned
                    )

            return output

        if isinstance(
            value,
            str,
        ):
            lower = (
                value.lower()
            )

            # Pure provenance statements are not security evidence.
            if (
                "synthetic validation metadata only"
                in lower
            ):
                return None

            if (
                "validation metadata only"
                in lower
            ):
                return None

            return (
                self.normalize_identifier_text(
                    value
                )
            )

        return value

    # ============================================================
    # REASONING PAYLOAD
    #
    # provenance_context and safety_context NEVER enter the LLM
    # risk assessment.
    # ============================================================

    def build_reasoning_payload(
        self,
        context: Dict,
    ) -> Dict:
        context = self.safe_dict(
            context
        )

        payload = {
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

        return (
            self.sanitize_reasoning_value(
                payload
            )
        )

    # ============================================================
    # SYSTEM INSTRUCTION
    # ============================================================

    def build_system_instruction(
        self,
    ) -> str:
        return """
You are the AI Risk Reasoning Agent inside SENTINEL-X.

Your only job is cybersecurity risk assessment.

You must assess the SECURITY BEHAVIOR represented by the supplied
evidence.

IMPORTANT PROVENANCE RULE:

Synthetic, test, validation and simulation provenance must NEVER:

- increase risk
- decrease risk
- appear as mitigating evidence
- appear as aggravating evidence
- justify a risk level
- justify why risk is not higher
- justify why risk is not lower
- change evidence strength
- change threat assessment

Treat supplied behavior as though the same security behavior had
been observed on a real endpoint.

Risk must be derived only from cybersecurity evidence.

Examples of valid mitigating evidence:

- successful authentication after failures
- trusted signature
- verified legitimate process path
- expected administrative workflow
- known legitimate parent process
- no successful authentication
- no follow-on activity
- no corroborating process/file/network behavior
- investigation disproves malicious behavior

Examples of INVALID mitigating evidence:

- synthetic data
- test environment
- validation account
- validation machine
- simulation mode
- real actions are disabled

You must NOT use fixed numerical thresholds.

Do not say:

- "above the threshold"
- "below the threshold"
- "exceeds the threshold"
- "risk score crosses the HIGH threshold"

Risk levels must come from holistic evidence reasoning.

risk_score is a 0-100 REVIEW PRIORITY score.

risk_score is NOT:

- probability of attack
- probability of compromise
- probability of malware
- calibrated statistical likelihood

Detector scores are not probabilities.

Detector confidence is not automatically a calibrated probability.

Incident correlation is supporting context, not proof.

Graph anomaly score is supporting model evidence, not probability.

Unverified graph relationships are not confirmed attribution.

Missing evidence does not prove benignity.

Absence of corroboration can reduce evidence strength, but does not
itself prove benign intent.

Do not invent:

- successful compromise
- malware
- credentials stolen
- lateral movement
- exfiltration
- threat intelligence
- user intent
- attribution

Allowed risk levels:

INFO
LOW
MEDIUM
HIGH
CRITICAL

Allowed threat assessments:

BENIGN
LOW_CONCERN
UNCERTAIN
SUSPICIOUS
LIKELY_MALICIOUS
MALICIOUS

Allowed evidence strengths:

WEAK
MODERATE
STRONG
VERY_STRONG

Do not recommend response actions.

Action selection belongs to a separate Sentinel-X agent.

GROUNDING RULES:

Every factual statement must be directly supported by the supplied
security evidence.

Missing or unavailable evidence is UNKNOWN.

Never convert missing evidence into mitigating evidence.

Examples:

"reputation data unavailable"
DOES NOT mean
"the destination has no malicious reputation"

"payload was not inspected"
DOES NOT mean
"payload inspection found no malicious content"

"no process telemetry was supplied"
DOES NOT mean
"no malicious process activity occurred"

"No successful authentication observed"
may be used only when the supplied authentication evidence actually
shows failures without a successful authentication.

Do not upgrade a generic external network connection into:

- command-and-control
- C2
- exfiltration
- malware delivery

unless supplied evidence explicitly supports that classification.

Potential impact may discuss those outcomes hypothetically, for
example:

"If malicious, this communication could potentially support
command-and-control."

But they must not be stated as observed facts.

Mitigating evidence must be AFFIRMATIVE security evidence that
actually reduces concern.

If no affirmative mitigating evidence exists, return:

"mitigating_evidence": []

Do not use absence of telemetry as affirmative mitigation.

Return JSON only.
""".strip()

    # ============================================================
    # PROMPT
    # ============================================================

    def build_prompt(
        self,
        context: Dict,
    ) -> str:
        payload = (
            self.build_reasoning_payload(
                context
            )
        )

        evidence_json = json.dumps(
            payload,
            indent=2,
            default=str,
        )

        return f"""
Assess the cybersecurity risk represented by this SENTINEL-X
security evidence.

Judge only the SECURITY BEHAVIOR.

Do not use synthetic/test/validation/simulation provenance as
either risk or mitigation.

Do not use fixed thresholds.

Return exactly one JSON object:

{{
  "risk_score": 0.0,

  "risk_level":
    "INFO|LOW|MEDIUM|HIGH|CRITICAL",

  "confidence": 0.0,

  "threat_assessment":
    "BENIGN|LOW_CONCERN|UNCERTAIN|SUSPICIOUS|LIKELY_MALICIOUS|MALICIOUS",

  "evidence_strength":
    "WEAK|MODERATE|STRONG|VERY_STRONG",

  "risk_summary": [
    "security-evidence-grounded explanation"
  ],

  "primary_risk_drivers": [
    "security evidence increasing concern"
  ],

  "corroborating_evidence": [
    "independent supplied evidence"
  ],

  "mitigating_evidence": [
    "real security evidence reducing concern"
  ],

  "uncertainties": [
    "unresolved security uncertainty"
  ],

  "potential_impact": [
    "potential impact justified by supplied behavior"
  ],

  "why_this_level":
    "evidence-based explanation",

  "why_not_higher":
    "security-evidence-based explanation",

  "why_not_lower":
    "security-evidence-based explanation"
}}

Requirements:

- unavailable evidence must remain UNKNOWN
- missing evidence must not become mitigating evidence
- do not call a connection C2 unless supplied evidence identifies it as C2
- do not claim reputation is benign when reputation data is unavailable
- do not claim payload content is benign when payload inspection was not performed
- mitigating_evidence must contain affirmative mitigating security evidence only
- risk_score must be 0 to 100
- risk_score is NOT probability
- confidence must be 0 to 1
- no numerical threshold reasoning
- no synthetic/test/validation reasoning
- use only supplied security evidence
- do not invent successful compromise
- do not invent attribution
- graph anomaly is not probability
- detector score is not probability
- correlation is not proof
- missing evidence is not benign evidence
- risk_summary must not be empty
- primary_risk_drivers must not be empty
- why_this_level must not be empty
- why_not_higher must not be empty
- why_not_lower must not be empty
- do not recommend containment actions
- JSON only
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

Your previous response failed Sentinel-X risk-output validation.

Validation error:

{validation_error}

Generate the COMPLETE JSON object again.

Correct the reasoning itself.

Do not merely remove one phrase.

Use cybersecurity evidence only.

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
                "AI provider returned empty response."
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
                "AI response contains no valid JSON."
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
                "AI response must be a JSON object."
            )

        return parsed

    # ============================================================
    # REASONING TEXT COLLECTION
    # ============================================================

    def collect_reasoning_text(
        self,
        result: Dict,
    ) -> str:
        parts = []

        for key in [
            "risk_summary",
            "primary_risk_drivers",
            "corroborating_evidence",
            "mitigating_evidence",
            "uncertainties",
            "potential_impact",
        ]:
            parts.extend(
                self.clean_string_list(
                    result.get(
                        key
                    )
                )
            )

        for key in [
            "why_this_level",
            "why_not_higher",
            "why_not_lower",
        ]:
            parts.append(
                self.safe_string(
                    result.get(
                        key
                    )
                )
            )

        return (
            " ".join(
                parts
            )
            .lower()
        )

    # ============================================================
    # SEMANTIC VALIDATION
    # ============================================================

    def validate_reasoning_semantics(
        self,
        result: Dict,
    ) -> None:
        text = (
            self.collect_reasoning_text(
                result
            )
        )

        for phrase in (
            self.FORBIDDEN_PROVENANCE_PHRASES
        ):
            if phrase in text:
                raise ValueError(
                    (
                        "Risk reasoning used validation "
                        "provenance as evidence: "
                        f"{phrase}"
                    )
                )

        for phrase in (
            self.FORBIDDEN_THRESHOLD_PHRASES
        ):
            if phrase in text:
                raise ValueError(
                    (
                        "Risk reasoning used fixed-threshold "
                        "language: "
                        f"{phrase}"
                    )
                )

        forbidden_actions = [
            "terminate_process",
            "terminate process",

            "quarantine_file",
            "quarantine file",

            "device_isolation",
            "device isolation",

            "block_network",
            "block network",

            "remove_persistence",
            "remove persistence",

            "account_protection",
            "account protection",
        ]

        for phrase in forbidden_actions:
            if phrase in text:
                raise ValueError(
                    (
                        "Risk agent selected or recommended "
                        "a response action: "
                        f"{phrase}"
                    )
                )

    # ============================================================
    # FACTUAL REASONING TEXT
    # ============================================================

    def collect_factual_reasoning_text(
        self,
        result: Dict,
    ) -> str:
        parts = []

        # Potential impact is deliberately excluded.
        # Hypothetical future consequences are allowed there.
        for key in [
            "risk_summary",
            "primary_risk_drivers",
            "corroborating_evidence",
            "mitigating_evidence",
            "uncertainties",
        ]:
            parts.extend(
                self.clean_string_list(
                    result.get(
                        key
                    )
                )
            )

        for key in [
            "why_this_level",
            "why_not_higher",
            "why_not_lower",
        ]:
            parts.append(
                self.safe_string(
                    result.get(
                        key
                    )
                )
            )

        return (
            " ".join(
                parts
            )
            .lower()
        )

    # ============================================================
    # EVIDENCE GROUNDING VALIDATION
    # ============================================================

    def validate_evidence_grounding(
        self,
        result: Dict,
        context: Dict,
    ) -> None:
        factual_text = (
            self.collect_factual_reasoning_text(
                result
            )
        )

        input_text = (
            json.dumps(
                self.build_reasoning_payload(
                    context
                ),
                default=str,
            )
            .lower()
        )

        # --------------------------------------------------------
        # MISSING DATA MUST NOT BECOME NEGATIVE / BENIGN EVIDENCE
        # --------------------------------------------------------

        unsupported_absence_claims = [
            "absence of known malicious reputation",
            "no known malicious reputation",
            "no malicious reputation",

            "payload inspection has not revealed",
            "payload inspection found no malicious",
            "no malicious content was found",
            "no malicious content found",
        ]

        for phrase in unsupported_absence_claims:
            if phrase in factual_text:
                raise ValueError(
                    (
                        "Missing/unavailable evidence was converted "
                        "into mitigating evidence: "
                        f"{phrase}"
                    )
                )

        # --------------------------------------------------------
        # HIGH-INFERENCE NETWORK CLAIMS
        #
        # These classifications may only be stated as observed
        # facts when the supplied evidence actually supports them.
        #
        # IMPORTANT:
        #
        # "data exfiltration occurred"
        #     -> factual classification
        #
        # "no direct evidence of data exfiltration"
        #     -> uncertainty / NOT a factual classification
        #
        # "preventing confirmation of data exfiltration"
        #     -> uncertainty / NOT a factual classification
        #
        # "could potentially support data exfiltration"
        #     -> hypothetical / NOT a factual classification
        # --------------------------------------------------------

        inferred_network_claims = {
            "command-and-control": [
                "command-and-control",
                "command and control",
                "c2",
            ],

            "exfiltration": [
                "exfiltration",
                "exfiltrate",
            ],
        }

        # --------------------------------------------------------
        # Work statement-by-statement rather than matching against
        # the complete combined output.
        #
        # This prevents a negative statement containing a sensitive
        # classification term from being mistaken for an assertion.
        # --------------------------------------------------------

        statements = [
            item.strip()

            for item in (
                factual_text
                .replace(
                    ";",
                    ".",
                )
                .replace(
                    "\n",
                    ".",
                )
                .split(
                    "."
                )
            )

            if item.strip()
        ]

        # --------------------------------------------------------
        # Wording that explicitly does NOT assert the classification
        # occurred.
        # --------------------------------------------------------

        non_assertive_markers = [
            # Explicit absence / lack of evidence.
            "no direct evidence of",
            "no evidence of",
            "no observed evidence of",
            "no supplied evidence of",
            "no confirmed evidence of",

            "without direct evidence of",
            "without evidence of",

            "lack of direct evidence",
            "lack of evidence",

            "absence of direct evidence",
            "absence of evidence",

            "insufficient evidence of",
            "insufficient evidence to confirm",

            "evidence does not establish",
            "evidence does not confirm",

            "not supported by",

            "not established",
            "not confirmed",
            "not verified",
            "not observed",
            "not demonstrated",

            "cannot confirm",
            "cannot establish",
            "cannot determine",

            "unable to confirm",
            "unable to establish",

            # ----------------------------------------------------
            # Covers the exact runtime phrase:
            #
            # "preventing confirmation of malicious payload
            # execution or data exfiltration"
            # ----------------------------------------------------

            "preventing confirmation of",
            "prevents confirmation of",
            "prevent confirmation of",

            # Hypothetical / conditional language.
            "if malicious",
            "if confirmed",

            "could ",
            "could potentially",

            "may ",
            "might ",

            "potential ",
            "potentially ",

            "possible ",
            "possibly ",

            "risk of",
        ]

        for (
            label,
            phrases,
        ) in inferred_network_claims.items():

            input_supports_claim = any(
                phrase in input_text
                for phrase in phrases
            )

            # Supplied evidence itself contains/supports the
            # classification.
            if input_supports_claim:
                continue

            for statement in statements:

                statement_has_claim = any(
                    phrase in statement
                    for phrase in phrases
                )

                if not statement_has_claim:
                    continue

                # Example:
                #
                # "There is no direct evidence of exfiltration."
                #
                # This mentions "exfiltration", but it is explicitly
                # saying that exfiltration is NOT established.
                non_assertive = any(
                    marker in statement
                    for marker in non_assertive_markers
                )

                if non_assertive:
                    continue

                # Anything remaining is an unsupported factual
                # classification.
                raise ValueError(
                    (
                        "AI upgraded supplied evidence into an "
                        "unsupported factual classification: "
                        f"{label}. "
                        f"Statement: {statement}"
                    )
                )

    # ============================================================
    # OUTPUT VALIDATION
    # ============================================================

    def validate_output(
        self,
        result: Dict,
        context: Optional[Dict] = None,
    ) -> Dict:
        result = self.safe_dict(
            result
        )

        try:
            risk_score = float(
                result.get(
                    "risk_score"
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            raise ValueError(
                "risk_score must be numeric."
            )

        if not (
            0.0
            <=
            risk_score
            <=
            100.0
        ):
            raise ValueError(
                "risk_score must be between 0 and 100."
            )

        risk_level = (
            self.safe_string(
                result.get(
                    "risk_level"
                )
            )
            .upper()
        )

        if (
            risk_level
            not in
            self.VALID_RISK_LEVELS
        ):
            raise ValueError(
                f"Invalid risk level: {risk_level}"
            )

        try:
            confidence = float(
                result.get(
                    "confidence"
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            raise ValueError(
                "confidence must be numeric."
            )

        if not (
            0.0
            <=
            confidence
            <=
            1.0
        ):
            raise ValueError(
                "confidence must be between 0 and 1."
            )

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
            self.VALID_ASSESSMENTS
        ):
            raise ValueError(
                (
                    "Invalid threat assessment: "
                    f"{assessment}"
                )
            )

        evidence_strength = (
            self.safe_string(
                result.get(
                    "evidence_strength"
                )
            )
            .upper()
        )

        if (
            evidence_strength
            not in
            self.VALID_EVIDENCE_STRENGTH
        ):
            raise ValueError(
                (
                    "Invalid evidence strength: "
                    f"{evidence_strength}"
                )
            )

        risk_summary = (
            self.clean_string_list(
                result.get(
                    "risk_summary"
                )
            )
        )

        primary_risk_drivers = (
            self.clean_string_list(
                result.get(
                    "primary_risk_drivers"
                )
            )
        )

        corroborating_evidence = (
            self.clean_string_list(
                result.get(
                    "corroborating_evidence"
                )
            )
        )

        mitigating_evidence = (
            self.clean_string_list(
                result.get(
                    "mitigating_evidence"
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

        potential_impact = (
            self.clean_string_list(
                result.get(
                    "potential_impact"
                )
            )
        )

        why_this_level = (
            self.safe_string(
                result.get(
                    "why_this_level"
                )
            )
        )

        why_not_higher = (
            self.safe_string(
                result.get(
                    "why_not_higher"
                )
            )
        )

        why_not_lower = (
            self.safe_string(
                result.get(
                    "why_not_lower"
                )
            )
        )

        if not risk_summary:
            raise ValueError(
                "risk_summary is empty."
            )

        if not primary_risk_drivers:
            raise ValueError(
                "primary_risk_drivers is empty."
            )

        if not why_this_level:
            raise ValueError(
                "why_this_level is empty."
            )

        if not why_not_higher:
            raise ValueError(
                "why_not_higher is empty."
            )

        if not why_not_lower:
            raise ValueError(
                "why_not_lower is empty."
            )

        validated = {
            "risk_score":
                round(
                    risk_score,
                    2,
                ),

            "risk_level":
                risk_level,

            "confidence":
                confidence,

            "threat_assessment":
                assessment,

            "evidence_strength":
                evidence_strength,

            "risk_summary":
                risk_summary,

            "primary_risk_drivers":
                primary_risk_drivers,

            "corroborating_evidence":
                corroborating_evidence,

            "mitigating_evidence":
                mitigating_evidence,

            "uncertainties":
                uncertainties,

            "potential_impact":
                potential_impact,

            "why_this_level":
                why_this_level,

            "why_not_higher":
                why_not_higher,

            "why_not_lower":
                why_not_lower,
        }

        self.validate_reasoning_semantics(
            validated
        )

        if context is not None:
            self.validate_evidence_grounding(
                validated,
                context,
            )

        return validated

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
        context: Dict,
        provider_result: Dict,
        validation_error: Optional[str] = None,
        repair_attempted: bool = False,
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

            "output_validation_error":
                validation_error,

            "output_repair_attempted":
                repair_attempted,

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

            "context_schema_version":
                context.get(
                    "schema_version"
                ),

            "risk_score":
                None,

            "risk_level":
                "UNAVAILABLE",

            "risk_score_semantics":
                "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",

            "action_selected":
                False,

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_executed":
                False,
        }

    # ============================================================
    # MAIN ASSESSMENT
    # ============================================================

    def assess(
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

        context = (
            self.build_context(
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
                self.unavailable_result(
                    threat=
                        threat,

                    context=
                        context,

                    provider_result=
                        provider_result,
                )
            )

        output_repair_used = False

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
                    parsed,
                    context=context,
                )
            )

        except Exception as first_error:
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
                    self.unavailable_result(
                        threat=
                            threat,

                        context=
                            context,

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
                        repaired,
                        context=context,
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
                    self.unavailable_result(
                        threat=
                            threat,

                        context=
                            context,

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
                output_repair_used,

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

            **validated,

            "risk_score_semantics":
                "AI_EVIDENCE_PRIORITY_SCORE_NOT_PROBABILITY",

            "action_selected":
                False,

            "simulation_only":
                True,

            "execution_allowed":
                False,

            "automatic_execution_allowed":
                False,

            "real_response_executed":
                False,
        }


# ================================================================
# SHARED INSTANCE
# ================================================================


shared_ai_risk_reasoning_agent = (
    AIRiskReasoningAgent()
)