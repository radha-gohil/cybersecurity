from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ai_provider_manager import shared_ai_provider_manager
from agents.evidence_context_builder import shared_evidence_context_builder


class AIResponseRecommendationAgent:
    """SENTINEL-X 7D.5 AI Response Recommendation Agent.

    The LLM chooses only a response *type* and target reference. Concrete
    targets are resolved deterministically from observed evidence. This agent
    never executes endpoint actions.
    """

    VERSION = "7D.5-v2"
    SCHEMA_VERSION = "sentinelx.ai.response-recommendation.v1"

    VALID_STRATEGIES = {
        "MONITOR",
        "INVESTIGATE",
        "TARGETED_RESPONSE",
        "CONTAINMENT_REVIEW",
    }

    VALID_PRIORITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    VALID_ACTIONS = {
        "MONITOR_INCIDENT",
        "INVESTIGATE_INCIDENT",
        "QUARANTINE_REVIEW",
        "PROCESS_TERMINATION_REVIEW",
        "NETWORK_BLOCK_REVIEW",
        "PERSISTENCE_REMEDIATION_REVIEW",
        "ENDPOINT_ISOLATION_REVIEW",
    }

    ACTION_TARGET_REFERENCE = {
        "MONITOR_INCIDENT": "NONE",
        "INVESTIGATE_INCIDENT": "NONE",
        "QUARANTINE_REVIEW": "FILE",
        "PROCESS_TERMINATION_REVIEW": "PROCESS",
        "NETWORK_BLOCK_REVIEW": "NETWORK",
        "PERSISTENCE_REMEDIATION_REVIEW": "PERSISTENCE",
        "ENDPOINT_ISOLATION_REVIEW": "ENDPOINT",
    }

    DIGITAL_TWIN_ACTIONS = {
        "QUARANTINE_REVIEW",
        "PROCESS_TERMINATION_REVIEW",
        "NETWORK_BLOCK_REVIEW",
        "PERSISTENCE_REMEDIATION_REVIEW",
        "ENDPOINT_ISOLATION_REVIEW",
    }

    NON_DISRUPTIVE_ACTIONS = {
        "MONITOR_INCIDENT",
        "INVESTIGATE_INCIDENT",
    }

    def __init__(self, provider_manager=None, context_builder=None):
        self.name = "AIResponseRecommendationAgent"
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
            "provider_manager": self.provider_manager.status(),
            "context_builder": self.context_builder.status(),
            "allowed_actions": sorted(self.VALID_ACTIONS),
            "target_resolution": "DETERMINISTIC_FROM_EVIDENCE",
            "certainty_preserved": True,
            "response_grounding": True,
            "action_execution": False,
            "digital_twin_required_for_response": True,
            "simulation_only": True,
            "execution_allowed": False,
        }

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
        return self.context_builder.build(
            threat=threat,
            incident=incident,
            investigation=investigation,
            enriched_evidence=enriched_evidence,
            graph_rag_context=graph_rag_context,
            additional_context=additional_context,
        )

    def compact_risk(self, risk_assessment: Dict) -> Dict:
        risk_assessment = self.safe_dict(risk_assessment)
        allowed = [
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
            key: risk_assessment.get(key)
            for key in allowed
            if key in risk_assessment
        }

    def build_reasoning_payload(
        self,
        *,
        context: Dict,
        risk_assessment: Dict,
    ) -> Dict:
        return {
            "security_context": self.safe_dict(context.get("security_context")),
            "evidence_availability": self.safe_dict(
                context.get("evidence_availability")
            ),
            "evidence_quality": self.safe_dict(context.get("evidence_quality")),
            "ai_risk_assessment": self.compact_risk(risk_assessment),
            "response_policy": {
                "choose_least_disruptive_effective_response": True,
                "risk_does_not_automatically_require_isolation": True,
                "unverified_relationships_are_not_targets": True,
                "targets_must_exist_in_observed_evidence": True,
                "preserve_risk_assessment_certainty": True,
                "all_disruptive_actions_require_digital_twin": True,
                "all_disruptive_actions_require_review": True,
                "real_execution_allowed": False,
            },
        }

    def build_system_instruction(self) -> str:
        return """
You are the AI Response Recommendation Agent inside SENTINEL-X.

You receive grounded cybersecurity evidence, an AI risk assessment,
investigation context, model evidence, and graph context when available.

Your task is RESPONSE RECOMMENDATION ONLY. You do not execute anything.
Choose the least-disruptive response that reasonably addresses the observed
security behavior.

A high or critical risk level does NOT automatically require endpoint
isolation. Response aggressiveness must depend on what was actually observed,
what asset is affected, whether a concrete response target exists, evidence
strength, uncertainty, likely operational impact, and whether a narrower
response can address the risk.

Do not invent process IDs, file paths, hashes, IP addresses, registry keys,
users, endpoint identities, attack attribution, or concrete target values.
Only specify a target_reference. SENTINEL-X resolves concrete targets
deterministically from observed evidence.

Allowed actions:
MONITOR_INCIDENT
INVESTIGATE_INCIDENT
QUARANTINE_REVIEW
PROCESS_TERMINATION_REVIEW
NETWORK_BLOCK_REVIEW
PERSISTENCE_REMEDIATION_REVIEW
ENDPOINT_ISOLATION_REVIEW

Allowed target references:
NONE
PROCESS
FILE
NETWORK
PERSISTENCE
ENDPOINT

Required mappings:
MONITOR_INCIDENT -> NONE
INVESTIGATE_INCIDENT -> NONE
QUARANTINE_REVIEW -> FILE
PROCESS_TERMINATION_REVIEW -> PROCESS
NETWORK_BLOCK_REVIEW -> NETWORK
PERSISTENCE_REMEDIATION_REVIEW -> PERSISTENCE
ENDPOINT_ISOLATION_REVIEW -> ENDPOINT

Response rules:
- BENIGN or LOW_CONCERN should normally use monitoring/investigation only.
- UNCERTAIN evidence should normally prefer investigation.
- SUSPICIOUS evidence may justify a narrow review only when grounded.
- LIKELY_MALICIOUS or MALICIOUS evidence may justify stronger targeted review.
- Endpoint isolation is the broadest option and should be used only when
  narrower controls may be insufficient.
- Unverified graph edges must not become response targets.
- Graph anomaly scores are supporting evidence, not target identity.
- Missing evidence is not proof of benignity.
- Risk scores are review-priority scores, not attack probabilities.
- All disruptive actions remain REVIEW candidates.
- Digital Twin simulation occurs later.

GROUNDING RULES:
Do not upgrade a generic external connection into command-and-control, C2, or
exfiltration unless supplied evidence explicitly supports that classification.
Do not call an observed file a malicious artifact, malicious file, or malicious
payload unless supplied evidence explicitly supports that classification.
Use lower-inference descriptions such as "observed outbound external
connection", "observed file artifact", "observed executable", and "observed
persistence artifact".

For SUSPICIOUS evidence with WEAK or MODERATE evidence strength:
- prefer MONITOR_INCIDENT or INVESTIGATE_INCIDENT
- do not recommend NETWORK_BLOCK_REVIEW
- do not recommend PROCESS_TERMINATION_REVIEW
- do not recommend PERSISTENCE_REMEDIATION_REVIEW
- never recommend ENDPOINT_ISOLATION_REVIEW
QUARANTINE_REVIEW may still be proposed for a concrete observed file because it
is narrow and preserves the artifact for analysis.

THREAT CERTAINTY RULE:
Preserve the exact uncertainty represented by the AI risk assessment.
If threat_assessment is LIKELY_MALICIOUS, do not state "malicious activity",
"malicious component", "malicious file", or "malicious payload" as confirmed
facts. Use "likely malicious activity", "suspicious process", "observed file
artifact", or "suspicious persistence behavior" instead.
Only threat_assessment = MALICIOUS may be described as confirmed malicious
without qualification.

Return JSON only.
""".strip()

    def build_prompt(self, *, context: Dict, risk_assessment: Dict) -> str:
        payload = self.build_reasoning_payload(
            context=context,
            risk_assessment=risk_assessment,
        )
        return f"""
Recommend the appropriate SENTINEL-X response posture.

Return exactly one JSON object:
{{
  "response_strategy": "MONITOR|INVESTIGATE|TARGETED_RESPONSE|CONTAINMENT_REVIEW",
  "confidence": 0.0,
  "response_summary": ["concise evidence-grounded response explanation"],
  "recommendations": [
    {{
      "action": "MONITOR_INCIDENT|INVESTIGATE_INCIDENT|QUARANTINE_REVIEW|PROCESS_TERMINATION_REVIEW|NETWORK_BLOCK_REVIEW|PERSISTENCE_REMEDIATION_REVIEW|ENDPOINT_ISOLATION_REVIEW",
      "priority": "LOW|MEDIUM|HIGH|CRITICAL",
      "target_reference": "NONE|PROCESS|FILE|NETWORK|PERSISTENCE|ENDPOINT",
      "reason": "why this response is appropriate"
    }}
  ],
  "why_this_response": "why this response strategy fits the evidence",
  "why_not_more_aggressive": "why broader containment is not justified",
  "why_not_less_aggressive": "why a weaker response is not sufficient"
}}

Requirements:
- ambiguous SUSPICIOUS network evidence must be investigated before blocking
- unsupported C2 or exfiltration claims are forbidden
- observed files must not be called malicious unless evidence establishes it
- preserve LIKELY_MALICIOUS versus MALICIOUS certainty
- rewrite unsupported high-inference labels into directly observed facts
- return 1 to 5 unique recommendations
- do not return concrete target values
- do not invent evidence or target identities
- use only allowed actions and exact target_reference mappings
- prefer the least-disruptive effective response
- do not automatically isolate because risk is HIGH or CRITICAL
- unverified graph relationships cannot establish target identity
- no action is executed here
- Digital Twin simulation happens later
- JSON only; no markdown

INPUT:
{json.dumps(payload, indent=2, default=str)}
""".strip()

    def build_repair_prompt(
        self,
        *,
        context: Dict,
        risk_assessment: Dict,
        validation_error: str,
    ) -> str:
        return f"""
{self.build_prompt(context=context, risk_assessment=risk_assessment)}

Your previous response failed SENTINEL-X response validation.

VALIDATION ERROR:
{validation_error}

Repair the COMPLETE JSON object.

If a disruptive recommendation is rejected because evidence is only SUSPICIOUS
with MODERATE or WEAK strength, replace it with INVESTIGATE_INCIDENT or
MONITOR_INCIDENT.

If wording such as C2, exfiltration, or malicious payload is unsupported,
rewrite it using directly observed evidence.

Examples:
"outbound C2 connection" -> "observed outbound external connection"
"malicious payload file" -> "observed file artifact"

If the risk assessment is LIKELY_MALICIOUS, do not rewrite it as confirmed
malicious activity.
"malicious activity" -> "likely malicious activity"
"malicious component" -> "observed suspicious component"
"malicious payload" -> "observed file artifact"

Negative or uncertainty wording is allowed when it accurately preserves
uncertainty. For example:
"no confirmed malicious activity"
"malicious intent has not been confirmed"
"no evidence confirming data exfiltration"
"likely part of malicious activity"

Do not turn missing evidence into a benign conclusion.
Do not remove valid observations merely because one interpretation was too
strong. Do not invent targets. Choose only allowed review actions.

Return JSON only.
""".strip()

    def parse_json_response(self, raw_text: str) -> Dict:
        raw_text = self.safe_string(raw_text)
        if not raw_text:
            raise ValueError("AI provider returned empty response.")
        try:
            result = json.loads(raw_text)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start < 0 or end < start:
            raise ValueError("No JSON object found.")
        result = json.loads(raw_text[start : end + 1])
        if not isinstance(result, dict):
            raise ValueError("Response must be a JSON object.")
        return result

    def normalize_canonical_observed_evidence(
        self,
        threat: Dict,
    ) -> Dict:
        """
        Convert directly observed canonical threat evidence into the
        normalized target shape used by deterministic response targeting.

        Nothing is inferred. Values are copied only from:
            threat["evidence"]["observed"][*]["data"]
        """
        normalized = {
            "processes": [],
            "files": [],
            "network_connections": [],
            "registry_artifacts": [],
        }

        evidence = self.safe_dict(
            self.safe_dict(threat).get("evidence")
        )

        for item in self.safe_list(evidence.get("observed")):
            item = self.safe_dict(item)
            evidence_type = self.safe_string(
                item.get("type")
            ).upper()
            data = self.safe_dict(item.get("data"))

            if evidence_type == "PROCESS":
                pid = data.get("pid")
                if pid is None:
                    continue

                process_name = (
                    data.get("name")
                    or data.get("process_name")
                )

                normalized["processes"].append(
                    {
                        "pid": pid,
                        "name": process_name,
                        "process_name": process_name,
                        "exe": data.get("exe"),
                    }
                )

            elif evidence_type == "FILE":
                path = data.get("path")
                if not path:
                    continue

                normalized["files"].append(
                    {
                        "path": path,
                        "sha256": data.get("sha256"),
                        "name": data.get("name"),
                    }
                )

            elif evidence_type == "NETWORK":
                remote_ip = (
                    data.get("remote_ip")
                    or data.get("destination_ip")
                    or data.get("dst_ip")
                )

                if not remote_ip:
                    continue

                normalized["network_connections"].append(
                    {
                        "remote_ip": remote_ip,
                        "remote_port": (
                            data.get("remote_port")
                            or data.get("destination_port")
                            or data.get("dst_port")
                        ),
                        "pid": data.get("pid"),
                        "process_name": (
                            data.get("process_name")
                            or data.get("name")
                        ),
                    }
                )

            elif evidence_type == "REGISTRY":
                key = (
                    data.get("key")
                    or data.get("registry_key")
                    or data.get("path")
                )

                if not key:
                    continue

                normalized["registry_artifacts"].append(
                    {
                        "key": key,
                        "value_name": (
                            data.get("value_name")
                            or data.get("value")
                        ),
                        "data": data.get("data"),
                    }
                )

        return normalized

    def merge_target_evidence(
        self,
        *sources: Dict,
    ) -> Dict:
        """
        Merge only observed target evidence and remove duplicates.
        """
        merged = {
            "processes": [],
            "files": [],
            "network_connections": [],
            "registry_artifacts": [],
        }

        seen = {
            "processes": set(),
            "files": set(),
            "network_connections": set(),
            "registry_artifacts": set(),
        }

        for source in sources:
            source = self.safe_dict(source)

            for item in self.safe_list(source.get("processes")):
                item = self.safe_dict(item)
                pid = item.get("pid")
                if pid is None:
                    continue
                marker = str(pid)
                if marker in seen["processes"]:
                    continue
                seen["processes"].add(marker)
                merged["processes"].append(item)

            for item in self.safe_list(source.get("files")):
                item = self.safe_dict(item)
                path = self.safe_string(item.get("path"))
                if not path:
                    continue
                marker = path.lower()
                if marker in seen["files"]:
                    continue
                seen["files"].add(marker)
                merged["files"].append(item)

            network_items = source.get("network_connections")
            if not isinstance(network_items, list):
                network_items = source.get("network")

            for item in self.safe_list(network_items):
                item = self.safe_dict(item)
                remote_ip = self.safe_string(item.get("remote_ip"))
                if not remote_ip:
                    continue
                marker = (
                    remote_ip,
                    item.get("remote_port"),
                    item.get("pid"),
                )
                if marker in seen["network_connections"]:
                    continue
                seen["network_connections"].add(marker)
                merged["network_connections"].append(item)

            for item in self.safe_list(source.get("registry_artifacts")):
                item = self.safe_dict(item)
                key = self.safe_string(item.get("key"))
                if not key:
                    continue
                marker = (
                    key.lower(),
                    self.safe_string(
                        item.get("value_name")
                        or item.get("value")
                    ).lower(),
                )
                if marker in seen["registry_artifacts"]:
                    continue
                seen["registry_artifacts"].add(marker)
                merged["registry_artifacts"].append(item)

        return merged

    def resolve_enrichment(
        self,
        *,
        context: Dict,
        enriched_evidence: Optional[Dict],
        threat: Optional[Dict] = None,
    ) -> Dict:
        """
        Resolve concrete target evidence from explicit enrichment first,
        EvidenceContextBuilder enrichment second, and canonical observed
        evidence as a deterministic fallback.
        """
        direct = self.safe_dict(enriched_evidence)

        security_context = self.safe_dict(
            self.safe_dict(context).get("security_context")
        )

        contextual = self.safe_dict(
            security_context.get("enrichment")
        )

        canonical = self.normalize_canonical_observed_evidence(
            self.safe_dict(threat)
        )

        return self.merge_target_evidence(
            direct,
            contextual,
            canonical,
        )

    def build_process_target(self, evidence: Dict) -> Dict:
        items = []
        for process in self.safe_list(evidence.get("processes")):
            if not isinstance(process, dict):
                continue
            pid = process.get("pid")
            if pid is None:
                continue
            items.append(
                {
                    "pid": pid,
                    "name": process.get("name") or process.get("process_name"),
                    "exe": process.get("exe"),
                }
            )
        return {"processes": items}

    def build_file_target(self, evidence: Dict) -> Dict:
        items = []
        for file_item in self.safe_list(evidence.get("files")):
            if not isinstance(file_item, dict):
                continue
            path = file_item.get("path")
            if not path:
                continue
            items.append({"path": path, "sha256": file_item.get("sha256")})
        return {"files": items}

    def build_network_target(self, evidence: Dict) -> Dict:
        items = []
        connections = evidence.get("network_connections")
        if not isinstance(connections, list):
            connections = evidence.get("network")
        for connection in self.safe_list(connections):
            if not isinstance(connection, dict):
                continue
            remote_ip = connection.get("remote_ip")
            if not remote_ip:
                continue
            items.append(
                {
                    "remote_ip": remote_ip,
                    "remote_port": connection.get("remote_port"),
                    "pid": connection.get("pid"),
                    "process_name": connection.get("process_name"),
                }
            )
        return {"connections": items}

    def build_persistence_target(self, evidence: Dict) -> Dict:
        items = []
        for artifact in self.safe_list(evidence.get("registry_artifacts")):
            if not isinstance(artifact, dict):
                continue
            key = artifact.get("key")
            if not key:
                continue
            items.append(
                {
                    "key": key,
                    "value_name": artifact.get("value_name")
                    or artifact.get("value"),
                    "data": artifact.get("data"),
                }
            )
        return {"registry_artifacts": items}

    def build_endpoint_target(self, threat: Dict) -> Dict:
        device_id = threat.get("device_id")
        return {"device_id": device_id} if device_id else {}

    def build_target(
        self,
        *,
        target_reference: str,
        threat: Dict,
        enrichment: Dict,
    ) -> Dict:
        if target_reference == "NONE":
            return {}
        if target_reference == "PROCESS":
            return self.build_process_target(enrichment)
        if target_reference == "FILE":
            return self.build_file_target(enrichment)
        if target_reference == "NETWORK":
            return self.build_network_target(enrichment)
        if target_reference == "PERSISTENCE":
            return self.build_persistence_target(enrichment)
        if target_reference == "ENDPOINT":
            return self.build_endpoint_target(threat)
        return {}

    def target_is_available(self, *, target_reference: str, target: Dict) -> bool:
        if target_reference == "NONE":
            return True
        if target_reference == "ENDPOINT":
            return bool(target.get("device_id"))
        expected_keys = {
            "PROCESS": "processes",
            "FILE": "files",
            "NETWORK": "connections",
            "PERSISTENCE": "registry_artifacts",
        }
        key = expected_keys.get(target_reference)
        return bool(key and self.safe_list(target.get(key)))

    def validate_action_for_assessment(
        self,
        *,
        action: str,
        risk_assessment: Dict,
    ) -> None:
        assessment = self.safe_string(
            risk_assessment.get("threat_assessment")
        ).upper()
        evidence_strength = self.safe_string(
            risk_assessment.get("evidence_strength")
        ).upper()

        if assessment in {"BENIGN", "LOW_CONCERN", "UNCERTAIN"}:
            if action not in self.NON_DISRUPTIVE_ACTIONS:
                raise ValueError(
                    f"Disruptive response is not permitted for assessment "
                    f"{assessment}: {action}"
                )

        if assessment == "SUSPICIOUS":
            if action == "ENDPOINT_ISOLATION_REVIEW":
                raise ValueError(
                    "Endpoint isolation is too broad for a SUSPICIOUS-only assessment."
                )
            if (
                evidence_strength in {"WEAK", "MODERATE", ""}
                and action
                in {
                    "PROCESS_TERMINATION_REVIEW",
                    "NETWORK_BLOCK_REVIEW",
                    "PERSISTENCE_REMEDIATION_REVIEW",
                }
            ):
                raise ValueError(
                    f"{action} requires stronger corroboration for a SUSPICIOUS "
                    f"assessment. Current evidence strength: "
                    f"{evidence_strength or 'UNKNOWN'}."
                )

    def collect_response_reasoning_text(self, result: Dict) -> str:
        parts = []
        for item in self.safe_list(result.get("response_summary")):
            text = self.safe_string(item)
            if text:
                parts.append(text)
        for recommendation in self.safe_list(result.get("recommendations")):
            recommendation = self.safe_dict(recommendation)
            reason = self.safe_string(recommendation.get("reason"))
            if reason:
                parts.append(reason)
        for key in (
            "why_this_response",
            "why_not_more_aggressive",
            "why_not_less_aggressive",
        ):
            text = self.safe_string(result.get(key))
            if text:
                parts.append(text)
        return " ".join(parts).lower()

    @staticmethod
    def split_statements(text: str) -> List[str]:
        return [
            item.strip()
            for item in text.replace(";", ".").replace("\n", ".").split(".")
            if item.strip()
        ]

    def validate_response_grounding(
        self,
        *,
        result: Dict,
        context: Dict,
        risk_assessment: Dict,
    ) -> None:
        """
        Preserve 7D.4 certainty and reject unsupported factual upgrades,
        while allowing explicitly negative, uncertain, and hypothetical
        wording.
        """
        output_text = self.collect_response_reasoning_text(result)

        # Potential impact and uncertainty fields are intentionally excluded
        # from factual support. A hypothetical impact must not authorize a
        # factual response claim.
        factual_risk_keys = (
            "risk_summary",
            "primary_risk_drivers",
            "corroborating_evidence",
            "mitigating_evidence",
            "why_this_level",
        )

        factual_risk = {
            key: risk_assessment.get(key)
            for key in factual_risk_keys
            if key in risk_assessment
        }

        input_payload = {
            "security_context": self.safe_dict(
                context.get("security_context")
            ),
            "risk_assessment": factual_risk,
        }

        input_text = json.dumps(
            input_payload,
            default=str,
        ).lower()

        statements = self.split_statements(output_text)

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
                "no supplied evidence of",
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
                "not supported by",
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
                "prevent confirmation of",

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

            # Example:
            # "no malicious payload or confirmed malicious process evidence"
            if re.search(
                r"\bno\b.{0,120}\b(evidence|confirmation|indication|proof)\b",
                statement,
            ):
                return True

            # Example:
            # "no execution or confirmed malicious activity has been observed"
            if re.search(
                r"\bno\b.{0,120}\b(has|have|was|were)\s+"
                r"(?:not\s+)?(?:been\s+)?observed\b",
                statement,
            ):
                return True

            return False

        # Preserve LIKELY_MALICIOUS vs MALICIOUS certainty.
        assessment = self.safe_string(
            risk_assessment.get("threat_assessment")
        ).upper()

        if assessment != "MALICIOUS":
            definitive_malicious_phrases = (
                "malicious activity",
                "malicious behavior",
                "malicious component",
                "malicious components",
                "malicious artifact",
                "malicious file",
                "malicious payload",
                "confirmed malicious",
                "known malicious",
            )

            for statement in statements:
                if not any(
                    phrase in statement
                    for phrase in definitive_malicious_phrases
                ):
                    continue

                if is_non_assertive(statement):
                    continue

                raise ValueError(
                    "Response reasoning upgraded "
                    f"{assessment or 'UNKNOWN'} into confirmed malicious "
                    f"activity. Statement: {statement}"
                )

        claim_groups = {
            "command-and-control": (
                "command-and-control",
                "command and control",
                "c2 connection",
                "c2 traffic",
                "c2 channel",
            ),
            "exfiltration": (
                "data exfiltration",
                "exfiltration",
                "exfiltrate",
                "exfiltrating data",
            ),
            "malicious-file-classification": (
                "malicious artifact",
                "malicious file",
                "malicious payload",
            ),
        }

        for label, phrases in claim_groups.items():
            input_supports = any(
                phrase in input_text
                for phrase in phrases
            )

            if input_supports:
                continue

            for statement in statements:
                if not any(
                    phrase in statement
                    for phrase in phrases
                ):
                    continue

                if is_non_assertive(statement):
                    continue

                raise ValueError(
                    "Response reasoning upgraded evidence into an "
                    f"unsupported factual claim: {label}. "
                    f"Statement: {statement}"
                )

    def validate_output(
        self,
        *,
        result: Dict,
        threat: Dict,
        context: Dict,
        risk_assessment: Dict,
        enriched_evidence: Optional[Dict],
    ) -> Dict:
        result = self.safe_dict(result)

        strategy = self.safe_string(result.get("response_strategy")).upper()
        if strategy not in self.VALID_STRATEGIES:
            raise ValueError(f"Invalid response_strategy: {strategy}")

        try:
            confidence = float(result.get("confidence"))
        except (TypeError, ValueError):
            raise ValueError("confidence must be numeric.")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1.")

        response_summary = [
            self.safe_string(item)
            for item in self.safe_list(result.get("response_summary"))
            if self.safe_string(item)
        ]
        if not response_summary:
            raise ValueError("response_summary is empty.")

        recommendations = self.safe_list(result.get("recommendations"))
        if not 1 <= len(recommendations) <= 5:
            raise ValueError("recommendations must contain 1 to 5 items.")

        enrichment = self.resolve_enrichment(
            context=context,
            enriched_evidence=enriched_evidence,
            threat=threat,
        )

        normalized = []
        seen_actions = set()

        for recommendation in recommendations:
            recommendation = self.safe_dict(recommendation)
            action = self.safe_string(recommendation.get("action")).upper()
            if action not in self.VALID_ACTIONS:
                raise ValueError(f"Unsupported response action: {action}")
            if action in seen_actions:
                raise ValueError(f"Duplicate response action: {action}")
            seen_actions.add(action)

            self.validate_action_for_assessment(
                action=action,
                risk_assessment=risk_assessment,
            )

            priority = self.safe_string(recommendation.get("priority")).upper()
            if priority not in self.VALID_PRIORITIES:
                raise ValueError(f"Invalid recommendation priority: {priority}")

            target_reference = self.safe_string(
                recommendation.get("target_reference")
            ).upper()
            expected_reference = self.ACTION_TARGET_REFERENCE[action]
            if target_reference != expected_reference:
                raise ValueError(
                    f"{action} must use target_reference {expected_reference}, "
                    f"not {target_reference}."
                )

            reason = self.safe_string(recommendation.get("reason"))
            if not reason:
                raise ValueError(f"{action} recommendation has no reason.")

            # Important: ignore any target supplied by the LLM.
            target = self.build_target(
                target_reference=target_reference,
                threat=threat,
                enrichment=enrichment,
            )
            if not self.target_is_available(
                target_reference=target_reference,
                target=target,
            ):
                raise ValueError(
                    f"{action} was recommended but no observed "
                    f"{target_reference} target is available."
                )

            normalized.append(
                {
                    "action": action,
                    "priority": priority,
                    "reason": reason,
                    "target_reference": target_reference,
                    "target": target,
                    "requires_approval": action in self.DIGITAL_TWIN_ACTIONS,
                    "digital_twin_candidate": action in self.DIGITAL_TWIN_ACTIONS,
                    "execution_allowed": False,
                }
            )

        why_this_response = self.safe_string(result.get("why_this_response"))
        why_not_more_aggressive = self.safe_string(
            result.get("why_not_more_aggressive")
        )
        why_not_less_aggressive = self.safe_string(
            result.get("why_not_less_aggressive")
        )

        if not why_this_response:
            raise ValueError("why_this_response is empty.")
        if not why_not_more_aggressive:
            raise ValueError("why_not_more_aggressive is empty.")
        if not why_not_less_aggressive:
            raise ValueError("why_not_less_aggressive is empty.")

        validated = {
            "response_strategy": strategy,
            "confidence": confidence,
            "response_summary": response_summary,
            "recommendations": normalized,
            "why_this_response": why_this_response,
            "why_not_more_aggressive": why_not_more_aggressive,
            "why_not_less_aggressive": why_not_less_aggressive,
        }

        self.validate_response_grounding(
            result=validated,
            context=context,
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

    def unavailable_result(
        self,
        *,
        threat: Dict,
        context: Dict,
        risk_assessment: Dict,
        provider_result: Dict,
        validation_error=None,
        repair_attempted=False,
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
            "security_id": threat.get("id"),
            "event_id": threat.get("event_id"),
            "incident_id": threat.get("incident_id"),
            "risk_level": risk_assessment.get("risk_level"),
            "threat_assessment": risk_assessment.get("threat_assessment"),
            "recommendations": [],
            "recommendation_count": 0,
            "digital_twin_required": False,
            "simulation_only": True,
            "execution_allowed": False,
            "automatic_execution_allowed": False,
            "real_response_executed": False,
        }

    def recommend(
        self,
        *,
        threat: Dict,
        risk_assessment: Dict,
        incident: Optional[Dict] = None,
        investigation: Optional[Dict] = None,
        enriched_evidence: Optional[Dict] = None,
        graph_rag_context: Optional[Any] = None,
        additional_context: Optional[Dict] = None,
    ) -> Dict:
        if not isinstance(threat, dict):
            raise TypeError("threat must be a dictionary.")
        if not isinstance(risk_assessment, dict):
            raise TypeError("risk_assessment must be a dictionary.")

        context = self.build_context(
            threat=threat,
            incident=incident,
            investigation=investigation,
            enriched_evidence=enriched_evidence,
            graph_rag_context=graph_rag_context,
            additional_context=additional_context,
        )

        provider_result = self.call_provider(
            prompt=self.build_prompt(
                context=context,
                risk_assessment=risk_assessment,
            ),
            temperature=0.1,
        )

        if not provider_result.get("success"):
            return self.unavailable_result(
                threat=threat,
                context=context,
                risk_assessment=risk_assessment,
                provider_result=provider_result,
            )

        repair_used = False
        try:
            parsed = self.parse_json_response(provider_result["text"])
            validated = self.validate_output(
                result=parsed,
                threat=threat,
                context=context,
                risk_assessment=risk_assessment,
                enriched_evidence=enriched_evidence,
            )
        except Exception as first_error:
            repair_result = self.call_provider(
                prompt=self.build_repair_prompt(
                    context=context,
                    risk_assessment=risk_assessment,
                    validation_error=str(first_error),
                ),
                temperature=0.0,
            )
            if not repair_result.get("success"):
                return self.unavailable_result(
                    threat=threat,
                    context=context,
                    risk_assessment=risk_assessment,
                    provider_result=repair_result,
                    validation_error=str(first_error),
                    repair_attempted=True,
                )
            try:
                repaired = self.parse_json_response(repair_result["text"])
                validated = self.validate_output(
                    result=repaired,
                    threat=threat,
                    context=context,
                    risk_assessment=risk_assessment,
                    enriched_evidence=enriched_evidence,
                )
                provider_result = repair_result
                repair_used = True
            except Exception as repair_error:
                return self.unavailable_result(
                    threat=threat,
                    context=context,
                    risk_assessment=risk_assessment,
                    provider_result=repair_result,
                    validation_error=str(repair_error),
                    repair_attempted=True,
                )

        digital_twin_required = any(
            item.get("digital_twin_candidate") is True
            for item in validated["recommendations"]
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
            "security_id": threat.get("id"),
            "detection_id": threat.get("detection_id"),
            "event_id": threat.get("event_id"),
            "incident_id": threat.get("incident_id"),
            "risk_agent": risk_assessment.get("agent"),
            "risk_agent_version": risk_assessment.get("agent_version"),
            "risk_level": risk_assessment.get("risk_level"),
            "threat_assessment": risk_assessment.get("threat_assessment"),
            **validated,
            "recommendation_count": len(validated["recommendations"]),
            "digital_twin_required": digital_twin_required,
            "next_stage": (
                "DIGITAL_TWIN"
                if digital_twin_required
                else "MONITOR_OR_INVESTIGATE"
            ),
            "simulation_only": True,
            "execution_allowed": False,
            "automatic_execution_allowed": False,
            "real_response_executed": False,
        }


shared_ai_response_recommendation_agent = AIResponseRecommendationAgent()
