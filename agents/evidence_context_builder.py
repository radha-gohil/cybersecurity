from __future__ import annotations

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


# ================================================================
# SENTINEL-X AI EVIDENCE CONTEXT BUILDER
# ================================================================


class EvidenceContextBuilder:
    """
    SENTINEL-X 7D.2 Evidence Context Builder.

    Purpose
    -------

    Convert canonical Sentinel-X threat / incident /
    investigation / enrichment evidence into one stable context
    consumed by later AI reasoning agents.

    Important architectural rule:

        SECURITY EVIDENCE
            !=
        VALIDATION / EXECUTION PROVENANCE

    Synthetic / validation metadata is preserved separately for
    auditability and runtime safety, but must not determine whether
    the represented behavior is benign or malicious.

    This component performs NO AI inference.
    """

    VERSION = "7D.2-v1"

    SCHEMA_VERSION = (
        "sentinelx.ai.evidence-context.v1"
    )


    # ============================================================
    # PROVENANCE-ONLY KEYS
    # ============================================================

    PROVENANCE_KEYS = {

        "synthetic",
        "synthetic_validation",
        "synthetic_demo",

        "simulation_mode",

        "validation_only",
        "production_eligible",

        "internal_regression",
        "user_visible",

        "contract_validation",

        "dataset",
    }


    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
    ):

        self.name = (
            "EvidenceContextBuilder"
        )


    # ============================================================
    # TIME
    # ============================================================

    @staticmethod
    def now_iso() -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # SAFE TYPES
    # ============================================================

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
    # REMOVE PROVENANCE FROM SECURITY REASONING DATA
    # ============================================================

    def sanitize_security_value(
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

                normalized_key = (
                    str(
                        key
                    )
                    .strip()
                    .lower()
                )


                if (
                    normalized_key
                    in
                    self.PROVENANCE_KEYS
                ):

                    continue


                cleaned = (
                    self.sanitize_security_value(
                        item
                    )
                )


                if cleaned is None:

                    continue


                if (
                    isinstance(
                        cleaned,
                        dict,
                    )
                    and
                    not cleaned
                ):

                    continue


                if (
                    isinstance(
                        cleaned,
                        list,
                    )
                    and
                    not cleaned
                ):

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
                    self.sanitize_security_value(
                        item
                    )
                )


                if cleaned is None:

                    continue


                if (
                    isinstance(
                        cleaned,
                        dict,
                    )
                    and
                    not cleaned
                ):

                    continue


                if (
                    isinstance(
                        cleaned,
                        list,
                    )
                    and
                    not cleaned
                ):

                    continue


                output.append(
                    cleaned
                )


            return output


        return deepcopy(
            value
        )


    # ============================================================
    # REMOVE PROVENANCE-ONLY DETECTOR REASONS
    # ============================================================

    def sanitize_detector_reasons(
        self,
        value: Any,
    ) -> List:

        result = []


        for item in self.safe_list(
            value
        ):

            text = self.safe_string(
                item
            )


            if not text:

                continue


            lower = (
                text.lower()
            )


            if (
                "synthetic validation metadata only"
                in lower
            ):

                continue


            if (
                "validation metadata only"
                in lower
            ):

                continue


            result.append(
                text
            )


        return result


    # ============================================================
    # STATUS
    # ============================================================

    def status(
        self,
    ) -> Dict:

        return {

            "builder":
                self.name,

            "version":
                self.VERSION,

            "schema_version":
                self.SCHEMA_VERSION,

            "ai_inference":
                False,

            "provenance_separated":
                True,

            "simulation_only":
                True,

            "execution_allowed":
                False,
        }


    # ============================================================
    # IDENTITY
    # ============================================================

    def build_identity(
        self,
        threat: Dict,
    ) -> Dict:

        threat = self.safe_dict(
            threat
        )


        return {

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

            "device_id":
                threat.get(
                    "device_id"
                ),
        }


    # ============================================================
    # DETECTOR CONTEXT
    # ============================================================

    def build_detector_context(
        self,
        threat: Dict,
    ) -> Dict:

        threat = self.safe_dict(
            threat
        )


        risk = self.safe_dict(
            threat.get(
                "risk"
            )
        )


        detection_risk = self.safe_dict(
            risk.get(
                "detection"
            )
        )


        model_evidence = self.safe_dict(
            threat.get(
                "model_evidence"
            )
        )


        detector = self.safe_dict(
            model_evidence.get(
                "detector"
            )
        )


        detector_copy = deepcopy(
            detector
        )


        if (
            "reason"
            in detector_copy
        ):

            detector_copy[
                "reason"
            ] = (
                self.sanitize_detector_reasons(

                    detector_copy.get(
                        "reason"
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

            "engine":
                threat.get(
                    "engine"
                ),

            "severity":
                threat.get(
                    "severity"
                ),

            "verdict":
                threat.get(
                    "verdict"
                ),

            "confidence":
                threat.get(
                    "confidence"
                ),

            "confidence_semantics":
                threat.get(
                    "confidence_semantics"
                ),

            "risk": {

                "score":
                    detection_risk.get(
                        "score"
                    ),

                "semantics":
                    detection_risk.get(
                        "semantics"
                    ),

                "source":
                    detection_risk.get(
                        "source"
                    ),
            },

            "detector_details":
                self.sanitize_security_value(
                    detector_copy
                ),
        }


    # ============================================================
    # OBSERVED EVIDENCE
    # ============================================================

    def build_observed_evidence(
        self,
        threat: Dict,
    ) -> Dict:

        evidence = self.safe_dict(

            self.safe_dict(
                threat
            ).get(
                "evidence"
            )
        )


        return (
            self.sanitize_security_value(
                evidence
            )
        )


    # ============================================================
    # MODEL EVIDENCE
    # ============================================================

    def build_model_context(
        self,
        threat: Dict,
    ) -> Dict:

        model_evidence = self.safe_dict(

            self.safe_dict(
                threat
            ).get(
                "model_evidence"
            )
        )


        model_copy = deepcopy(
            model_evidence
        )


        detector = self.safe_dict(
            model_copy.get(
                "detector"
            )
        )


        if detector:

            detector[
                "reason"
            ] = (
                self.sanitize_detector_reasons(

                    detector.get(
                        "reason"
                    )
                )
            )


            model_copy[
                "detector"
            ] = detector


        return (
            self.sanitize_security_value(
                model_copy
            )
        )


    # ============================================================
    # INCIDENT CONTEXT
    # ============================================================

    def build_incident_context(
        self,
        incident: Optional[Dict],
    ) -> Dict:

        incident = self.safe_dict(
            incident
        )


        if not incident:

            return {}


        context = {

            "severity":
                incident.get(
                    "severity"
                ),

            "correlation_score":
                incident.get(
                    "correlation_score"
                ),

            "event_count":
                incident.get(
                    "event_count"
                ),

            "categories":
                incident.get(
                    "categories"
                ),

            "related_incident_count":
                incident.get(
                    "related_incident_count"
                ),

            "status":
                incident.get(
                    "status"
                ),

            "requires_investigation":
                incident.get(
                    "requires_investigation"
                ),

            "timeline":
                incident.get(
                    "timeline"
                ),

            "detections":
                incident.get(
                    "detections"
                ),
        }


        return (
            self.sanitize_security_value(
                context
            )
        )


    # ============================================================
    # INVESTIGATION CONTEXT
    # ============================================================

    def build_investigation_context(
        self,
        investigation: Optional[Dict],
    ) -> Dict:

        return (
            self.sanitize_security_value(

                self.safe_dict(
                    investigation
                )
            )
        )


    # ============================================================
    # ENRICHED EVIDENCE CONTEXT
    #
    # Compatible with current EvidenceEnrichmentAgent output.
    # ============================================================

    def build_enrichment_context(
        self,
        enriched_evidence: Optional[Dict],
    ) -> Dict:

        enriched = self.safe_dict(
            enriched_evidence
        )


        if not enriched:

            return {}


        context = {

            "processes":
                enriched.get(
                    "processes"
                ),

            "files":
                enriched.get(
                    "files"
                ),

            "network_connections":
                enriched.get(
                    "network_connections"
                ),

            "registry_artifacts":
                enriched.get(
                    "registry_artifacts"
                ),

            "indicators":
                enriched.get(
                    "indicators"
                ),

            "iocs":
                enriched.get(
                    "iocs"
                ),

            "relationships":
                enriched.get(
                    "relationships"
                ),

            "identity_links":
                enriched.get(
                    "identity_links"
                ),

            "detections":
                enriched.get(
                    "detections"
                ),

            "detection_summary":
                enriched.get(
                    "detection_summary"
                ),

            "summary":
                enriched.get(
                    "summary"
                ),
        }


        return (
            self.sanitize_security_value(
                context
            )
        )


    # ============================================================
    # PROVENANCE CONTEXT
    #
    # Audit-only.
    #
    # This section must not be used to lower or raise threat
    # assessment.
    # ============================================================

    def build_provenance_context(
        self,
        threat: Dict,
        enriched_evidence: Optional[Dict],
    ) -> Dict:

        threat = self.safe_dict(
            threat
        )


        visibility = self.safe_dict(
            threat.get(
                "visibility"
            )
        )


        contract = self.safe_dict(
            threat.get(
                "contract_validation"
            )
        )


        source_reference = self.safe_dict(
            threat.get(
                "source_reference"
            )
        )


        enriched = self.safe_dict(
            enriched_evidence
        )


        return {

            "reasoning_use":
                "AUDIT_ONLY_NOT_SECURITY_EVIDENCE",

            "synthetic":
                bool(
                    visibility.get(
                        "synthetic",
                        False,
                    )
                ),

            "internal_regression":
                bool(
                    visibility.get(
                        "internal_regression",
                        False,
                    )
                ),

            "user_visible":
                visibility.get(
                    "user_visible"
                ),

            "source":
                source_reference.get(
                    "source"
                ),

            "contract_valid":
                contract.get(
                    "valid"
                ),

            "contract_errors":
                contract.get(
                    "errors"
                )
                or [],

            "validation_only":
                enriched.get(
                    "validation_only"
                ),

            "production_eligible":
                enriched.get(
                    "production_eligible"
                ),
        }


    # ============================================================
    # SAFETY CONTEXT
    # ============================================================

    @staticmethod
    def build_safety_context() -> Dict:

        return {

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
    # AVAILABLE EVIDENCE CHANNELS
    # ============================================================

    def build_evidence_availability(
        self,
        *,
        observed: Dict,
        model: Dict,
        incident: Dict,
        investigation: Dict,
        enrichment: Dict,
        graph_rag_context: Any,
    ) -> Dict:

        processes = self.safe_list(
            enrichment.get(
                "processes"
            )
        )


        files = self.safe_list(
            enrichment.get(
                "files"
            )
        )


        network = self.safe_list(
            enrichment.get(
                "network_connections"
            )
        )


        registry = self.safe_list(
            enrichment.get(
                "registry_artifacts"
            )
        )


        relationships = self.safe_list(
            enrichment.get(
                "relationships"
            )
        )


        identity_links = self.safe_list(
            enrichment.get(
                "identity_links"
            )
        )


        return {

            "observed_evidence":
                bool(
                    observed
                ),

            "model_evidence":
                bool(
                    model
                ),

            "incident_context":
                bool(
                    incident
                ),

            "investigation_context":
                bool(
                    investigation
                ),

            "enrichment_context":
                bool(
                    enrichment
                ),

            "graph_rag_context":
                graph_rag_context
                is not None,

            "process_count":
                len(
                    processes
                ),

            "file_count":
                len(
                    files
                ),

            "network_count":
                len(
                    network
                ),

            "registry_count":
                len(
                    registry
                ),

            "relationship_count":
                len(
                    relationships
                ),

            "identity_link_count":
                len(
                    identity_links
                ),
        }


    # ============================================================
    # INFERRED / UNVERIFIED EVIDENCE
    # ============================================================

    def build_evidence_quality(
        self,
        enrichment: Dict,
    ) -> Dict:

        relationships = self.safe_list(
            enrichment.get(
                "relationships"
            )
        )


        identity_links = self.safe_list(
            enrichment.get(
                "identity_links"
            )
        )


        inferred_relationships = 0
        verified_relationships = 0


        for item in relationships:

            item = self.safe_dict(
                item
            )


            if (
                item.get(
                    "verified"
                )
                is True
            ):

                verified_relationships += 1

            else:

                inferred_relationships += 1


        verified_identity_links = 0
        unverified_identity_links = 0


        for item in identity_links:

            item = self.safe_dict(
                item
            )


            if (
                item.get(
                    "verified"
                )
                is True
            ):

                verified_identity_links += 1

            else:

                unverified_identity_links += 1


        return {

            "relationship_evidence": {

                "verified":
                    verified_relationships,

                "inferred_or_unverified":
                    inferred_relationships,
            },

            "identity_link_evidence": {

                "verified":
                    verified_identity_links,

                "unverified":
                    unverified_identity_links,
            },

            "rule":
                (
                    "Inferred relationships and "
                    "unverified identity links are "
                    "supporting context, not confirmed "
                    "attribution."
                ),
        }


    # ============================================================
    # FINAL BUILD
    # ============================================================

    def build(
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


        identity = (
            self.build_identity(
                threat
            )
        )


        detector = (
            self.build_detector_context(
                threat
            )
        )


        observed = (
            self.build_observed_evidence(
                threat
            )
        )


        model = (
            self.build_model_context(
                threat
            )
        )


        incident_context = (
            self.build_incident_context(
                incident
            )
        )


        investigation_context = (
            self.build_investigation_context(
                investigation
            )
        )


        enrichment_context = (
            self.build_enrichment_context(
                enriched_evidence
            )
        )


        additional = (
            self.sanitize_security_value(

                self.safe_dict(
                    additional_context
                )
            )
        )


        graph_context = (

            self.sanitize_security_value(
                graph_rag_context
            )

            if graph_rag_context
            is not None

            else None
        )


        evidence_availability = (
            self.build_evidence_availability(

                observed=
                    observed,

                model=
                    model,

                incident=
                    incident_context,

                investigation=
                    investigation_context,

                enrichment=
                    enrichment_context,

                graph_rag_context=
                    graph_context,
            )
        )


        evidence_quality = (
            self.build_evidence_quality(
                enrichment_context
            )
        )


        provenance = (
            self.build_provenance_context(

                threat,

                enriched_evidence,
            )
        )


        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "builder":
                self.name,

            "builder_version":
                self.VERSION,

            "built_at":
                self.now_iso(),

            # ====================================================
            # ORIGINAL IDs
            # ====================================================

            "identity":
                identity,

            # ====================================================
            # CONTENT ALLOWED FOR AI SECURITY REASONING
            # ====================================================

            "security_context": {

                "detector":
                    detector,

                "observed_evidence":
                    observed,

                "model_evidence":
                    model,

                "incident":
                    incident_context,

                "investigation":
                    investigation_context,

                "enrichment":
                    enrichment_context,

                "graph_rag":
                    graph_context,

                "additional_context":
                    additional,
            },

            # ====================================================
            # META ABOUT WHAT EVIDENCE EXISTS
            # ====================================================

            "evidence_availability":
                evidence_availability,

            "evidence_quality":
                evidence_quality,

            # ====================================================
            # NOT SECURITY EVIDENCE
            # ====================================================

            "provenance_context":
                provenance,

            # ====================================================
            # HARD RUNTIME SAFETY
            # ====================================================

            "safety_context":
                self.build_safety_context(),

            # ====================================================
            # INTERPRETATION RULES
            # ====================================================

            "reasoning_policy": {

                "evaluate_behavior_as_real":
                    True,

                "synthetic_provenance_is_not_benign_evidence":
                    True,

                "detector_risk_is_not_probability":
                    True,

                "detector_alert_is_not_proof":
                    True,

                "missing_evidence_is_not_benign_evidence":
                    True,

                "prefer_observed_over_inferred":
                    True,

                "unverified_relationships_are_not_attribution":
                    True,
            },
        }


# ================================================================
# SHARED INSTANCE
# ================================================================

shared_evidence_context_builder = (
    EvidenceContextBuilder()
)