"""
SENTINEL-X Canonical User Security Contract
===========================================

Phase 7C.2

Purpose
-------
Provide one stable user-facing security representation for:

- detections
- incidents
- AI investigation
- Digital Twin / protection preview
- frontend pages
- future real telemetry

IMPORTANT
---------
This module does NOT:

- change detector logic
- change correlation
- change investigation
- execute protection
- modify the endpoint
- convert heuristic scores into probabilities
- declare uncertain evidence as confirmed malicious activity

It only NORMALIZES already-recorded Sentinel-X evidence.

Contract version:
    sentinelx.security.v1
"""

from __future__ import annotations

from copy import deepcopy
from datetime import (
    datetime,
    timezone,
)
from enum import Enum
from typing import (
    Any,
    Dict,
    List,
    Optional,
)


# ================================================================
# CONTRACT VERSION
# ================================================================

SECURITY_CONTRACT_VERSION = (
    "sentinelx.security.v1"
)


# ================================================================
# SECURITY CATEGORY
# ================================================================

class SecurityCategory(
    str,
    Enum,
):

    PROCESS = "PROCESS"

    FILE = "FILE"

    NETWORK = "NETWORK"

    REGISTRY = "REGISTRY"

    AUTHENTICATION = "AUTHENTICATION"

    SYSTEM = "SYSTEM"

    STARTUP = "STARTUP"

    OTHER = "OTHER"


# ================================================================
# SECURITY VERDICT
#
# Verdict answers:
#
#     "What does Sentinel-X currently think this activity is?"
#
# It is intentionally separate from severity.
# ================================================================

class SecurityVerdict(
    str,
    Enum,
):

    SAFE = "SAFE"

    BENIGN = "BENIGN"

    SUSPICIOUS = "SUSPICIOUS"

    LIKELY_THREAT = "LIKELY_THREAT"

    CONFIRMED_THREAT = "CONFIRMED_THREAT"

    UNKNOWN = "UNKNOWN"


# ================================================================
# USER SECURITY STATE
#
# State answers:
#
#     "What does this mean for the user right now?"
# ================================================================

class UserSecurityState(
    str,
    Enum,
):

    SAFE = "SAFE"

    MONITORING = "MONITORING"

    SUSPICIOUS = "SUSPICIOUS"

    UNKNOWN = "UNKNOWN"

    THREAT = "THREAT"

    NEEDS_ATTENTION = "NEEDS_ATTENTION"

    PROTECTION_RECOMMENDED = (
        "PROTECTION_RECOMMENDED"
    )

    PROTECTED = "PROTECTED"

    USER_ACTION_REQUIRED = (
        "USER_ACTION_REQUIRED"
    )

    ALLOWED = "ALLOWED"

    QUARANTINED = "QUARANTINED"

    RESOLVED = "RESOLVED"

    PROTECTION_FAILED = (
        "PROTECTION_FAILED"
    )

    VERIFIED_SAFE = "VERIFIED_SAFE"


# ================================================================
# PROTECTION POLICY
# ================================================================

class ProtectionPolicyDecision(
    str,
    Enum,
):

    AUTO_PROTECT = "AUTO_PROTECT"

    ASK_USER = "ASK_USER"

    MONITOR_ONLY = "MONITOR_ONLY"


class ProtectionMode(
    str,
    Enum,
):

    RECOMMENDED = "RECOMMENDED"

    STRICT = "STRICT"

    ASK_ME = "ASK_ME"

    MONITOR_ONLY = "MONITOR_ONLY"


# ================================================================
# RISK SEMANTICS
# ================================================================

class RiskSemantics(
    str,
    Enum,
):

    DETECTION = (
        "DETECTOR_RISK_SCORE_NOT_PROBABILITY"
    )

    INVESTIGATION = (
        "INVESTIGATION_REVIEW_SCORE_NOT_PROBABILITY"
    )

    SIMULATION = (
        "MODELED_HEURISTIC_ENDPOINT_STATE_NOT_PROBABILITY"
    )


# ================================================================
# BASIC HELPERS
# ================================================================

def now_iso() -> str:

    return (
        datetime.now(
            timezone.utc
        ).isoformat()
    )


def obj(
    value,
) -> dict:

    return (
        value
        if isinstance(
            value,
            dict,
        )
        else {}
    )


def items(
    value,
) -> list:

    return (
        [
            item
            for item in value
            if isinstance(
                item,
                dict,
            )
        ]
        if isinstance(
            value,
            list,
        )
        else []
    )


def strings(
    value,
) -> List[str]:

    if value is None:

        return []

    if isinstance(
        value,
        list,
    ):

        result = []

        for item in value:

            if item is None:

                continue

            text = str(
                item
            ).strip()

            if text:

                result.append(
                    text
                )

        return result

    text = str(
        value
    ).strip()

    return (
        [text]
        if text
        else []
    )


def safe_float(
    value,
) -> Optional[float]:

    if (
        value is None
        or value == ""
    ):

        return None

    try:

        return float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        return None


def bounded_score(
    value,
) -> Optional[float]:

    number = safe_float(
        value
    )

    if number is None:

        return None

    return max(
        0.0,
        min(
            number,
            100.0,
        ),
    )


def normalize_confidence(
    value,
) -> Optional[float]:
    """
    Canonical confidence range:

        0.0 -> 1.0

    This does NOT imply universal statistical calibration.
    """

    number = safe_float(
        value
    )

    if number is None:

        return None

    if number > 1:

        number = (
            number / 100.0
        )

    return max(
        0.0,
        min(
            number,
            1.0,
        ),
    )


def normalize_severity(
    value,
) -> str:

    severity = str(
        value
        or
        "UNKNOWN"
    ).upper()

    allowed = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
        "UNKNOWN",
    }

    if severity not in allowed:

        return "UNKNOWN"

    return severity


def title_case_identifier(
    value,
) -> str:

    text = str(
        value
        or
        "Security Detection"
    )

    return (
        text
        .replace(
            "_",
            " ",
        )
        .strip()
        .title()
    )


# ================================================================
# CATEGORY NORMALIZATION
# ================================================================

def normalize_category(
    detection: dict,
) -> str:

    detection = obj(
        detection
    )

    event_type = str(
        detection.get(
            "event_type"
        )
        or ""
    ).lower()

    raw_category = str(
        detection.get(
            "category"
        )
        or
        obj(
            detection.get(
                "model_scores"
            )
        ).get(
            "event_category"
        )
        or ""
    ).upper()

    # ------------------------------------------------------------
    # EVENT TYPE IS MORE SPECIFIC FOR SECURITY EVENTS
    # ------------------------------------------------------------

    if event_type.startswith(
        "security_auth"
    ):

        return (
            SecurityCategory
            .AUTHENTICATION
            .value
        )

    if event_type.startswith(
        "security_privilege"
    ):

        return (
            SecurityCategory
            .SYSTEM
            .value
        )

    if event_type.startswith(
        "process"
    ):

        return (
            SecurityCategory
            .PROCESS
            .value
        )

    if event_type.startswith(
        "file"
    ):

        return (
            SecurityCategory
            .FILE
            .value
        )

    if event_type.startswith(
        "network"
    ):

        return (
            SecurityCategory
            .NETWORK
            .value
        )

    if event_type.startswith(
        "registry"
    ):

        return (
            SecurityCategory
            .REGISTRY
            .value
        )

    if event_type.startswith(
        "startup"
    ):

        return (
            SecurityCategory
            .STARTUP
            .value
        )

    if event_type.startswith(
        "system"
    ):

        return (
            SecurityCategory
            .SYSTEM
            .value
        )

    # ------------------------------------------------------------
    # RAW CATEGORY FALLBACK
    # ------------------------------------------------------------

    mapping = {

        "PROCESS":
            SecurityCategory.PROCESS.value,

        "FILE":
            SecurityCategory.FILE.value,

        "NETWORK":
            SecurityCategory.NETWORK.value,

        "REGISTRY":
            SecurityCategory.REGISTRY.value,

        "AUTH":
            SecurityCategory.AUTHENTICATION.value,

        "AUTHENTICATION":
            SecurityCategory.AUTHENTICATION.value,

        "SECURITY":
            SecurityCategory.SYSTEM.value,

        "SYSTEM":
            SecurityCategory.SYSTEM.value,

        "STARTUP":
            SecurityCategory.STARTUP.value,
    }

    return mapping.get(
        raw_category,
        SecurityCategory.OTHER.value,
    )


# ================================================================
# INTERNAL REGRESSION DETECTION
# ================================================================

def is_internal_regression(
    detection=None,
    incident=None,
) -> bool:

    detection = obj(
        detection
    )

    incident = obj(
        incident
    )

    engine = str(
        detection.get(
            "engine"
        )
        or ""
    ).upper()

    threat_type = str(
        detection.get(
            "threat_type"
        )
        or ""
    ).upper()

    event_id = str(
        detection.get(
            "event_id"
        )
        or ""
    ).upper()

    incident_id = str(
        incident.get(
            "incident_id"
        )
        or
        detection.get(
            "incident_id"
        )
        or ""
    ).upper()

    source = str(
        incident.get(
            "source"
        )
        or ""
    ).upper()

    if (
        engine
        ==
        "SYNTHETIC_SOC_VALIDATION"
    ):

        return True

    if threat_type.startswith(
        "SOC_"
    ):

        return True

    if event_id.startswith(
        "SYNTH-INC-SOC-"
    ):

        return True

    if incident_id.startswith(
        "SYNTH-INC-SOC-"
    ):

        return True

    if (
        source
        ==
        "SYNTHETIC_SOC_VALIDATION"
    ):

        return True

    return False


# ================================================================
# SYNTHETIC MARKER
# ================================================================

def is_synthetic_record(
    detection=None,
    incident=None,
) -> bool:

    detection = obj(
        detection
    )

    incident = obj(
        incident
    )

    metadata = obj(
        detection.get(
            "event_metadata"
        )
    )

    if metadata.get(
        "synthetic"
    ) is True:

        return True

    for key in (
        "process_evidence",
        "file_evidence",
        "network_evidence",
        "registry_evidence",
    ):

        evidence = obj(
            detection.get(
                key
            )
        )

        if evidence.get(
            "synthetic"
        ) is True:

            return True

    event_id = str(
        detection.get(
            "event_id"
        )
        or ""
    ).upper()

    incident_id = str(
        incident.get(
            "incident_id"
        )
        or
        detection.get(
            "incident_id"
        )
        or ""
    ).upper()

    source = str(
        incident.get(
            "source"
        )
        or ""
    ).upper()

    if event_id.startswith(
        "SYNTH-"
    ):

        return True

    if incident_id.startswith(
        "SYNTH-"
    ):

        return True

    if "SYNTHETIC" in source:

        return True

    return False


# ================================================================
# VERDICT
# ================================================================

def derive_verdict(
    detection: dict,
) -> str:
    """
    Conservative verdict derivation.

    CONFIRMED_THREAT is never inferred solely from HIGH/CRITICAL
    severity or a high risk score.

    It requires an explicit confirmed marker.
    """

    detection = obj(
        detection
    )

    metadata = obj(
        detection.get(
            "event_metadata"
        )
    )

    explicit = str(
        detection.get(
            "verdict"
        )
        or metadata.get(
            "verdict"
        )
        or ""
    ).upper()

    allowed = {
        item.value
        for item
        in SecurityVerdict
    }

    if explicit in allowed:

        return explicit

    detected = detection.get(
        "detected"
    )

    threat_type = str(
        detection.get(
            "threat_type"
        )
        or ""
    ).upper()

    severity = normalize_severity(
        detection.get(
            "severity"
        )
    )

    risk = bounded_score(
        detection.get(
            "risk_score"
        )
    )

    confidence = normalize_confidence(
        detection.get(
            "confidence"
        )
    )

    if metadata.get(
        "confirmed_threat"
    ) is True:

        return (
            SecurityVerdict
            .CONFIRMED_THREAT
            .value
        )

    if (
        detected is False
        or
        threat_type.startswith(
            "BENIGN_"
        )
    ):

        return (
            SecurityVerdict
            .BENIGN
            .value
        )

    if threat_type.startswith(
        "NORMAL_"
    ):

        return (
            SecurityVerdict
            .SAFE
            .value
        )

    if (
        "ISOLATED_AUTH_FAILURE"
        in threat_type
    ):

        return (
            SecurityVerdict
            .SAFE
            .value
        )

    # ------------------------------------------------------------
    # STRONG BUT NOT "CONFIRMED"
    # ------------------------------------------------------------

    strong_type = any(
        marker in threat_type
        for marker in (
            "MALWARE",
            "RANSOMWARE",
            "EXFILTRATION",
            "BRUTE_FORCE",
            "PERSISTENCE",
        )
    )

    strong_score = (
        risk is not None
        and risk >= 85
    )

    strong_confidence = (
        confidence is not None
        and confidence >= 0.85
    )

    if (
        strong_type
        and
        strong_score
        and
        severity
        in (
            "HIGH",
            "CRITICAL",
        )
    ):

        return (
            SecurityVerdict
            .LIKELY_THREAT
            .value
        )

    if (
        strong_score
        and
        strong_confidence
        and
        severity
        in (
            "HIGH",
            "CRITICAL",
        )
    ):

        return (
            SecurityVerdict
            .LIKELY_THREAT
            .value
        )

    if detected is True:

        return (
            SecurityVerdict
            .SUSPICIOUS
            .value
        )

    return (
        SecurityVerdict
        .UNKNOWN
        .value
    )


# ================================================================
# USER STATE
# ================================================================

def derive_user_state(
    detection: dict,
    *,
    verdict: str,
    protection=None,
) -> str:

    detection = obj(
        detection
    )

    protection = obj(
        protection
    )

    explicit_state = str(
        detection.get(
            "user_state"
        )
        or ""
    ).upper()

    allowed = {
        item.value
        for item
        in UserSecurityState
    }

    if explicit_state in allowed:

        return explicit_state

    # ------------------------------------------------------------
    # EXPLICIT PROTECTION OUTCOMES
    # ------------------------------------------------------------

    protection_status = str(
        protection.get(
            "status"
        )
        or ""
    ).upper()

    if protection_status in (
        "QUARANTINED",
    ):

        return (
            UserSecurityState
            .QUARANTINED
            .value
        )

    if protection_status in (
        "PROTECTED",
        "AUTO_PROTECTED",
    ):

        return (
            UserSecurityState
            .PROTECTED
            .value
        )

    if protection_status in (
        "RESOLVED",
        "MITIGATION_VERIFIED",
        "VERIFIED",
    ):

        return (
            UserSecurityState
            .RESOLVED
            .value
        )

    if protection_status in (
        "FAILED",
        "PROTECTION_FAILED",
    ):

        return (
            UserSecurityState
            .PROTECTION_FAILED
            .value
        )

    # ------------------------------------------------------------
    # VERDICT → USER STATE
    # ------------------------------------------------------------

    if verdict in (
        SecurityVerdict.SAFE.value,
        SecurityVerdict.BENIGN.value,
    ):

        return (
            UserSecurityState
            .SAFE
            .value
        )

    if (
        verdict
        ==
        SecurityVerdict
        .CONFIRMED_THREAT
        .value
    ):

        return (
            UserSecurityState
            .PROTECTION_RECOMMENDED
            .value
        )

    if (
        verdict
        ==
        SecurityVerdict
        .LIKELY_THREAT
        .value
    ):

        return (
            UserSecurityState
            .PROTECTION_RECOMMENDED
            .value
        )

    if (
        verdict
        ==
        SecurityVerdict
        .SUSPICIOUS
        .value
    ):

        return (
            UserSecurityState
            .NEEDS_ATTENTION
            .value
        )

    return (
        UserSecurityState
        .UNKNOWN
        .value
    )


# ================================================================
# RISK CONTRACT
# ================================================================

def extract_investigation_score(
    investigation,
) -> Optional[float]:

    investigation = obj(
        investigation
    )

    direct = bounded_score(
        investigation.get(
            "risk_score"
        )
    )

    if direct is not None:

        return direct

    direct = bounded_score(
        investigation.get(
            "investigation_risk_score"
        )
    )

    if direct is not None:

        return direct

    coordinated = obj(
        investigation.get(
            "coordinated_analysis"
        )
    )

    risk_assessment = obj(
        coordinated.get(
            "risk_assessment"
        )
    )

    return bounded_score(
        risk_assessment.get(
            "risk_score"
        )
    )


def extract_simulation_score(
    protection_preview,
) -> Optional[float]:

    protection_preview = obj(
        protection_preview
    )

    return bounded_score(
        protection_preview.get(
            "initial_risk_score"
        )
    )


def build_risk_contract(
    detection,
    investigation=None,
    protection_preview=None,
) -> dict:

    detection = obj(
        detection
    )

    detection_score = bounded_score(
        detection.get(
            "risk_score"
        )
    )

    investigation_score = (
        extract_investigation_score(
            investigation
        )
    )

    simulation_score = (
        extract_simulation_score(
            protection_preview
        )
    )

    return {

        "detection": {

            "score":
                detection_score,

            "semantics":
                RiskSemantics
                .DETECTION
                .value,

            "source":
                detection.get(
                    "engine"
                ),

        },

        "investigation": {

            "score":
                investigation_score,

            "semantics":
                RiskSemantics
                .INVESTIGATION
                .value,

        },

        "simulation": {

            "score":
                simulation_score,

            "semantics":
                RiskSemantics
                .SIMULATION
                .value,

            "model_type":
                obj(
                    protection_preview
                ).get(
                    "model_type"
                ),

        },
    }

# ================================================================
# SUBSTANTIVE EVIDENCE CHECK
# ================================================================

def has_substantive_evidence(
    value,
) -> bool:
    """
    Return True only when an evidence object contains at least
    one meaningful recorded value.

    Empty dictionaries or placeholder dictionaries containing
    only None / empty-string / empty-list / empty-dict values
    must NOT become canonical evidence.
    """

    if value is None:

        return False

    if isinstance(
        value,
        dict,
    ):

        for item in value.values():

            if has_substantive_evidence(
                item
            ):

                return True

        return False

    if isinstance(
        value,
        (
            list,
            tuple,
            set,
        ),
    ):

        return any(
            has_substantive_evidence(
                item
            )
            for item in value
        )

    if isinstance(
        value,
        str,
    ):

        return bool(
            value.strip()
        )

    # Numeric zero and False can be meaningful recorded values.
    if isinstance(
        value,
        (
            int,
            float,
            bool,
        ),
    ):

        return True

    return True
# ================================================================
# OBSERVED EVIDENCE
# ================================================================

def build_observed_evidence(
    detection,
) -> List[dict]:

    detection = obj(
        detection
    )

    event_id = detection.get(
        "event_id"
    )

    category = normalize_category(
        detection
    )

    evidence = []

    mappings = (

        (
            SecurityCategory
            .PROCESS
            .value,
            "process_evidence",
        ),

        (
            SecurityCategory
            .FILE
            .value,
            "file_evidence",
        ),

        (
            SecurityCategory
            .NETWORK
            .value,
            "network_evidence",
        ),

        (
            SecurityCategory
            .REGISTRY
            .value,
            "registry_evidence",
        ),
    )

    for (
        evidence_type,
        field_name,
    ) in mappings:

        payload = obj(
            detection.get(
                field_name
            )
        )

        if not has_substantive_evidence(
            payload
        ):

            continue

        evidence.append(
            {

                "type":
                    evidence_type,

                "event_id":
                    event_id,

                "data":
                    deepcopy(
                        payload
                    ),
            }
        )

    metadata = obj(
        detection.get(
            "event_metadata"
        )
    )

    # ------------------------------------------------------------
    # AUTH / SYSTEM / STARTUP OFTEN STORE EVIDENCE IN METADATA
    # ------------------------------------------------------------

    if (
        category
        in (
            SecurityCategory
            .AUTHENTICATION
            .value,

            SecurityCategory
            .SYSTEM
            .value,

            SecurityCategory
            .STARTUP
            .value,
        )
        and metadata
    ):

        evidence.append(
            {

                "type":
                    category,

                "event_id":
                    event_id,

                "data":
                    deepcopy(
                        metadata
                    ),
            }
        )

    return evidence


# ================================================================
# EVIDENCE BOUNDARIES
# ================================================================

def build_evidence_boundaries(
    detection,
    investigation=None,
) -> dict:
    """
    Raw detections contribute OBSERVED evidence only.

    INFERRED and UNKNOWN should come from investigation/reasoning
    layers when explicitly available.

    We never invent them here.
    """

    investigation = obj(
        investigation
    )

    explicit = obj(
        investigation.get(
            "evidence_boundaries"
        )
    )

    inferred = (
        deepcopy(
            explicit.get(
                "inferred"
            )
        )
        if isinstance(
            explicit.get(
                "inferred"
            ),
            list,
        )
        else []
    )

    unknown = (
        deepcopy(
            explicit.get(
                "unknown"
            )
        )
        if isinstance(
            explicit.get(
                "unknown"
            ),
            list,
        )
        else []
    )

    return {

        "observed":
            build_observed_evidence(
                detection
            ),

        "inferred":
            inferred,

        "unknown":
            unknown,
    }


# ================================================================
# MODEL EVIDENCE CONTRACT
# ================================================================

def build_model_evidence(
    detection,
) -> dict:

    detection = obj(
        detection
    )

    process = obj(
        detection.get(
            "process_evidence"
        )
    )

    file_evidence = obj(
        detection.get(
            "file_evidence"
        )
    )

    model_scores = obj(
        detection.get(
            "model_scores"
        )
    )

    engine = str(
        detection.get(
            "engine"
        )
        or ""
    )

    engine_lower = (
        engine.lower()
    )

    category = normalize_category(
        detection
    )

    # ============================================================
    # PROCESS FUSION-V3
    # ============================================================

    if (
        engine_lower
        ==
        "process_threat_fusion_v3"
        or
        process.get(
            "fusion_version"
        )
    ):

        isolation = obj(
            process.get(
                "isolation_forest"
            )
        )

        autoencoder = obj(
            process.get(
                "autoencoder"
            )
        )

        temporal = obj(
            process.get(
                "temporal_ai"
            )
            or
            process.get(
                "temporal"
            )
        )

        return {

            "type":
                "PROCESS_FUSION_V3",

            "applicable_models": [
                "RULES",
                "ISOLATION_FOREST",
                "AUTOENCODER",
                "TEMPORAL_AI",
                "FUSION_V3",
            ],

            "rules": {

                "score":
                    (
                        model_scores.get(
                            "rule_score"
                        )
                        or
                        process.get(
                            "rule_score"
                        )
                        or
                        process.get(
                            "behavior_score"
                        )
                    ),

                "indicators":
                    deepcopy(
                        process.get(
                            "behavior_indicators"
                        )
                        or []
                    ),

                "reasons":
                    deepcopy(
                        process.get(
                            "behavior_reasons"
                        )
                        or []
                    ),
            },

            "isolation_forest":
                deepcopy(
                    isolation
                ),

            "autoencoder":
                deepcopy(
                    autoencoder
                ),

            "temporal_ai":
                deepcopy(
                    temporal
                ),

            "fusion": {

                "version":
                    process.get(
                        "fusion_version"
                    ),

                "score":
                    (
                        process.get(
                            "fusion_score"
                        )
                        or
                        model_scores.get(
                            "fusion_score"
                        )
                    ),

                "severity":
                    process.get(
                        "fusion_severity"
                    ),

                "confidence":
                    normalize_confidence(
                        process.get(
                            "fusion_confidence"
                        )
                    ),

                "reasons":
                    deepcopy(
                        process.get(
                            "fusion_reasons"
                        )
                        or []
                    ),
            },

            "consensus": {

                "score":
                    (
                        process.get(
                            "ai_consensus_score"
                        )
                        or
                        model_scores.get(
                            "ai_consensus_score"
                        )
                    ),

                "label":
                    process.get(
                        "ai_consensus"
                    ),

                "context":
                    deepcopy(
                        process.get(
                            "ai_behavior_context"
                        )
                        or {}
                    ),
            },
        }

    # ============================================================
    # STATIC MALWARE CLASSIFIER
    # ============================================================

    if (
        "ember"
        in engine_lower
        or
        "malware"
        in engine_lower
    ):

        return {

            "type":
                "MALWARE_CLASSIFIER",

            "applicable_models": [
                "MALWARE_CLASSIFIER",
            ],

            "classifier": {

                "engine":
                    engine,

                "risk_score":
                    bounded_score(
                        detection.get(
                            "risk_score"
                        )
                    ),

                "confidence":
                    normalize_confidence(
                        detection.get(
                            "confidence"
                        )
                    ),

                "severity":
                    normalize_severity(
                        detection.get(
                            "severity"
                        )
                    ),

                "file_evidence":
                    deepcopy(
                        file_evidence
                    ),
            },
        }

    # ============================================================
    # RANSOMWARE
    # ============================================================

    if (
        "ransomware"
        in engine_lower
    ):

        return {

            "type":
                "RANSOMWARE_BEHAVIOR",

            "applicable_models": [
                "RANSOMWARE_BEHAVIOR",
            ],

            "behavior": {

                "engine":
                    engine,

                "risk_score":
                    bounded_score(
                        detection.get(
                            "risk_score"
                        )
                    ),

                "confidence":
                    normalize_confidence(
                        detection.get(
                            "confidence"
                        )
                    ),

                "severity":
                    normalize_severity(
                        detection.get(
                            "severity"
                        )
                    ),

                "file_evidence":
                    deepcopy(
                        file_evidence
                    ),
            },
        }

    # ============================================================
    # BEHAVIOR / RULE DETECTOR
    # ============================================================

    return {

        "type":
            (
                f"{category}_DETECTOR"
            ),

        "applicable_models": [
            engine
        ] if engine else [],

        "detector": {

            "engine":
                engine,

            "risk_score":
                bounded_score(
                    detection.get(
                        "risk_score"
                    )
                ),

            "confidence":
                normalize_confidence(
                    detection.get(
                        "confidence"
                    )
                ),

            "severity":
                normalize_severity(
                    detection.get(
                        "severity"
                    )
                ),

            "reason":
                strings(
                    detection.get(
                        "detection_reason"
                    )
                    or
                    detection.get(
                        "reason"
                    )
                ),
        },
    }


# ================================================================
# PROTECTION CONTRACT
# ================================================================

def build_protection_contract(
    protection_preview=None,
) -> dict:

    preview = obj(
        protection_preview
    )

    preview_available = bool(
        preview
    )

    best_plan = obj(
        preview.get(
            "best_plan"
        )
    )

    recommended_actions = []

    for action in items(
        best_plan.get(
            "actions"
        )
    ):

        action_type = action.get(
            "action_type"
        )

        if action_type:

            recommended_actions.append(
                str(
                    action_type
                )
            )

    return {

        "available":
            preview_available,

        # Policy engine is not implemented yet.
        "policy_decision":
            None,

        "protection_mode":
            None,

        "recommended_actions":
            recommended_actions,

        "best_plan_id":
            best_plan.get(
                "plan_id"
            ),

        "best_plan_name":
            best_plan.get(
                "plan_name"
            ),

        "simulation_only":
            (
                preview.get(
                    "simulation_mode"
                )
                is True
            )
            if preview_available
            else None,

        "response_authorized":
            (
                preview.get(
                    "response_authorized"
                )
                is True
            )
            if preview_available
            else None,

        "real_endpoint_modified":
            (
                preview.get(
                    "real_endpoint_modified"
                )
                is True
            )
            if preview_available
            else None,

        "production_eligible":
            (
                obj(
                    preview.get(
                        "evidence_validation"
                    )
                ).get(
                    "production_eligible"
                )
                if preview_available
                else None
            ),
    }
# ================================================================
# VISIBILITY CONTRACT
# ================================================================

def build_visibility_contract(
    detection=None,
    incident=None,
) -> dict:

    detection = obj(
        detection
    )

    internal = (
        is_internal_regression(
            detection,
            incident,
        )
    )

    explicit_visible = (
        detection.get(
            "user_visible"
        )
    )

    if explicit_visible is False:

        visible = False

    else:

        visible = (
            not internal
        )

    return {

        "user_visible":
            visible,

        "internal_regression":
            internal,

        "synthetic":
            is_synthetic_record(
                detection,
                incident,
            ),
    }


# ================================================================
# CANONICAL TITLE
# ================================================================

def build_title(
    detection,
) -> str:

    detection = obj(
        detection
    )

    explicit = detection.get(
        "display_title"
    )

    if explicit:

        return str(
            explicit
        )

    threat_type = (
        detection.get(
            "threat_type"
        )
        or
        "SECURITY_DETECTION"
    )

    return title_case_identifier(
        threat_type
    )


# ================================================================
# CANONICAL ID
# ================================================================

def build_security_id(
    detection,
) -> str:

    detection = obj(
        detection
    )

    detection_id = detection.get(
        "detection_id"
    )

    if detection_id is not None:

        return (
            f"detection-{detection_id}"
        )

    event_id = detection.get(
        "event_id"
    )

    if event_id:

        return (
            f"event-{event_id}"
        )

    return (
        "security-object-unknown"
    )


# ================================================================
# CANONICAL SECURITY OBJECT
# ================================================================

def build_canonical_security_object(
    detection,
    *,
    incident=None,
    investigation=None,
    protection_preview=None,
) -> dict:
    """
    Convert existing SENTINEL-X objects into the canonical
    user-facing security contract.

    The source objects remain unchanged.
    """

    detection = obj(
        detection
    )

    incident = obj(
        incident
    )

    investigation = obj(
        investigation
    )

    protection_preview = obj(
        protection_preview
    )

    category = normalize_category(
        detection
    )

    verdict = derive_verdict(
        detection
    )

    protection = (
        build_protection_contract(
            protection_preview
        )
    )

    user_state = (
        derive_user_state(
            detection,
            verdict=verdict,
            protection=protection,
        )
    )

    visibility = (
        build_visibility_contract(
            detection,
            incident,
        )
    )

    incident_id = (
        incident.get(
            "incident_id"
        )
        or
        detection.get(
            "incident_id"
        )
    )

    confidence = (
        normalize_confidence(
            detection.get(
                "confidence"
            )
        )
    )

    return {

        # ========================================================
        # CONTRACT
        # ========================================================

        "schema_version":
            SECURITY_CONTRACT_VERSION,

        "generated_at":
            now_iso(),

        # ========================================================
        # IDENTITY
        # ========================================================

        "id":
            build_security_id(
                detection
            ),

        "detection_id":
            detection.get(
                "detection_id"
            ),

        "event_id":
            detection.get(
                "event_id"
            ),

        "incident_id":
            incident_id,

        "device_id":
            (
                detection.get(
                    "device_id"
                )
                or
                incident.get(
                    "device_id"
                )
            ),

        # ========================================================
        # DISPLAY
        # ========================================================

        "title":
            build_title(
                detection
            ),

        "category":
            category,

        "event_type":
            detection.get(
                "event_type"
            ),

        "threat_type":
            detection.get(
                "threat_type"
            ),

        "engine":
            detection.get(
                "engine"
            ),

        "timestamp":
            (
                detection.get(
                    "timestamp"
                )
                or
                incident.get(
                    "updated_at"
                )
            ),

        # ========================================================
        # USER SECURITY MEANING
        # ========================================================

        "verdict":
            verdict,

        "severity":
            normalize_severity(
                detection.get(
                    "severity"
                )
            ),

        "confidence":
            confidence,

        "confidence_semantics":
            (
                "RECORDED_DETECTOR_CONFIDENCE_"
                "NOT_UNIVERSALLY_CALIBRATED"
            ),

        "user_state":
            user_state,

        # ========================================================
        # SCORES
        # ========================================================

        "risk":
            build_risk_contract(
                detection,
                investigation,
                protection_preview,
            ),

        # ========================================================
        # EVIDENCE
        # ========================================================

        "evidence":
            build_evidence_boundaries(
                detection,
                investigation,
            ),

        "model_evidence":
            build_model_evidence(
                detection
            ),

        # ========================================================
        # INCIDENT
        # ========================================================

        "incident": {

            "incident_id":
                incident_id,

            "title":
                incident.get(
                    "title"
                ),

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
                deepcopy(
                    incident.get(
                        "categories"
                    )
                    or []
                ),
            "related_incident_ids":
                deepcopy(
                    incident.get(
                        "related_incident_ids"
                    )
                    or (
                        [incident_id]
                        if incident_id
                        else []
                    )
                ),

            "related_incident_count":
                len(
                    incident.get(
                        "related_incident_ids"
                    )
                    or (
                        [incident_id]
                        if incident_id
                        else []
                    )
                ),
        },
        
        # ========================================================
        # INVESTIGATION
        # ========================================================

        "investigation": {

            "available":
                bool(
                    investigation
                ),

            "status":
                (
                    investigation.get(
                        "status"
                    )
                    or
                    investigation.get(
                        "investigation_status"
                    )
                ),

            "risk_score":
                extract_investigation_score(
                    investigation
                ),
        },

        # ========================================================
        # PROTECTION
        # ========================================================

        "protection":
            protection,

        # ========================================================
        # VISIBILITY / DATA ORIGIN
        # ========================================================

        "visibility":
            visibility,

        # ========================================================
        # RAW REFERENCE FIELDS
        #
        # Useful during migration.
        # We can remove these later after all pages consume
        # canonical evidence.
        # ========================================================

        "source_reference": {

            "source":
                detection.get(
                    "source"
                ),

            "detection_reason":
                deepcopy(
                    detection.get(
                        "detection_reason"
                    )
                    or
                    detection.get(
                        "reason"
                    )
                ),

            "event_evidence_available":
                detection.get(
                    "event_evidence_available"
                ),
        },
    }


# ================================================================
# CONTRACT VALIDATION
# ================================================================

def validate_canonical_security_object(
    payload,
) -> dict:

    payload = obj(
        payload
    )

    errors = []

    # ------------------------------------------------------------
    # REQUIRED STRUCTURE
    # ------------------------------------------------------------

    required = (
        "schema_version",
        "id",
        "category",
        "verdict",
        "severity",
        "user_state",
        "risk",
        "evidence",
        "visibility",
    )

    for key in required:

        if key not in payload:

            errors.append(
                f"Missing required field: {key}"
            )

    # ------------------------------------------------------------
    # ENUM VALIDATION
    # ------------------------------------------------------------

    categories = {
        item.value
        for item
        in SecurityCategory
    }

    verdicts = {
        item.value
        for item
        in SecurityVerdict
    }

    states = {
        item.value
        for item
        in UserSecurityState
    }

    if (
        payload.get(
            "category"
        )
        not in categories
    ):

        errors.append(
            "Invalid category."
        )

    if (
        payload.get(
            "verdict"
        )
        not in verdicts
    ):

        errors.append(
            "Invalid verdict."
        )

    if (
        payload.get(
            "user_state"
        )
        not in states
    ):

        errors.append(
            "Invalid user_state."
        )

    # ------------------------------------------------------------
    # CONFIDENCE
    # ------------------------------------------------------------

    confidence = payload.get(
        "confidence"
    )

    if confidence is not None:

        try:

            confidence_number = float(
                confidence
            )

            if not (
                0
                <=
                confidence_number
                <=
                1
            ):

                errors.append(
                    "Confidence must be between 0 and 1."
                )

        except (
            TypeError,
            ValueError,
        ):

            errors.append(
                "Confidence must be numeric or null."
            )

    # ------------------------------------------------------------
    # RISK SCORE RANGE
    # ------------------------------------------------------------

    risk = obj(
        payload.get(
            "risk"
        )
    )

    for key in (
        "detection",
        "investigation",
        "simulation",
    ):

        score = obj(
            risk.get(
                key
            )
        ).get(
            "score"
        )

        if score is None:

            continue

        try:

            score_number = float(
                score
            )

            if not (
                0
                <=
                score_number
                <=
                100
            ):

                errors.append(
                    (
                        f"{key} risk score "
                        "must be between 0 and 100."
                    )
                )

        except (
            TypeError,
            ValueError,
        ):

            errors.append(
                f"{key} risk score is invalid."
            )

    return {

        "valid":
            len(
                errors
            )
            ==
            0,

        "errors":
            errors,
    }

# ================================================================
# CANONICAL INCIDENT HELPERS
# ================================================================

def _first_nonempty_dict(
    *values,
) -> dict:

    for value in values:

        candidate = obj(
            value
        )

        if candidate:

            return candidate

    return {}


def _safe_list(
    value,
) -> list:

    return (
        value
        if isinstance(
            value,
            list,
        )
        else []
    )


def _clean_incident_title(
    value,
) -> str:

    text = str(
        value
        or
        "Security Incident"
    ).strip()

    prefix = (
        "[SYNTHETIC]"
    )

    if text.upper().startswith(
        prefix
    ):

        text = text[
            len(prefix):
        ].strip()

    return (
        text
        or
        "Security Incident"
    )


def _incident_categories(
    incident,
) -> List[str]:

    incident = obj(
        incident
    )

    result = []

    # ------------------------------------------------------------
    # STORED CATEGORY LIST FIRST
    # ------------------------------------------------------------

    for category in _safe_list(
        incident.get(
            "categories"
        )
    ):

        value = str(
            category
            or
            ""
        ).upper()

        if (
            value
            and
            value not in result
        ):

            result.append(
                value
            )

    # ------------------------------------------------------------
    # TIMELINE FALLBACK
    # ------------------------------------------------------------

    for event in items(
        incident.get(
            "timeline"
        )
    ):

        metadata = obj(
            event.get(
                "metadata"
            )
        )

        category = str(
            event.get(
                "event_category"
            )
            or
            metadata.get(
                "event_category"
            )
            or
            ""
        ).upper()

        event_type = str(
            event.get(
                "event_type"
            )
            or
            ""
        ).lower()

        if (
            category
            ==
            "SECURITY"
        ):

            category = (
                "AUTHENTICATION"
                if "auth" in event_type
                else "SYSTEM"
            )

        if not category:

            if event_type.startswith(
                "process"
            ):

                category = "PROCESS"

            elif event_type.startswith(
                "file"
            ):

                category = "FILE"

            elif event_type.startswith(
                "network"
            ):

                category = "NETWORK"

            elif event_type.startswith(
                "registry"
            ):

                category = "REGISTRY"

            elif event_type.startswith(
                "startup"
            ):

                category = "STARTUP"

            elif event_type.startswith(
                "security_auth"
            ):

                category = (
                    "AUTHENTICATION"
                )

            elif event_type.startswith(
                "security"
            ):

                category = "SYSTEM"

        if (
            category
            and
            category not in result
        ):

            result.append(
                category
            )

    # ------------------------------------------------------------
    # NORMALIZE LEGACY SECURITY CATEGORY
    # ------------------------------------------------------------

    normalized = []

    for category in result:

        value = str(
            category
            or ""
        ).upper()

        if value == "AUTH":

            value = "AUTHENTICATION"

        if (
            value
            and
            value not in normalized
        ):

            normalized.append(
                value
            )

    # Legacy correlation records sometimes store SECURITY while
    # the hydrated event resolves it more specifically.
    if (
        "AUTHENTICATION" in normalized
        and
        "SECURITY" in normalized
    ):

        normalized.remove(
            "SECURITY"
        )

    if (
        "SYSTEM" in normalized
        and
        "SECURITY" in normalized
    ):

        normalized.remove(
            "SECURITY"
        )

    return normalized


# ================================================================
# CANONICAL INCIDENT SUMMARY
# ================================================================

def build_canonical_incident_summary(
    incident,
) -> dict:

    incident = obj(
        incident
    )

    incident_id = (
        incident.get(
            "incident_id"
        )
    )

    internal = (
        is_internal_regression(
            incident=incident
        )
    )

    synthetic = (
        is_synthetic_record(
            incident=incident
        )
    )

    event_count = (
        incident.get(
            "event_count"
        )
    )

    if event_count is None:

        event_count = len(
            _safe_list(
                incident.get(
                    "event_ids"
                )
            )
        )

    return {

        "schema_version":
            SECURITY_CONTRACT_VERSION,

        "object_type":
            "SECURITY_INCIDENT",

        "generated_at":
            now_iso(),

        "incident_id":
            incident_id,

        "title":
            incident.get(
                "title"
            ),

        "display_title":
            _clean_incident_title(
                incident.get(
                    "title"
                )
            ),

        "severity":
            normalize_severity(
                incident.get(
                    "severity"
                )
            ),

        "status":
            incident.get(
                "status"
            ),

        "correlation_score":
            bounded_score(
                incident.get(
                    "correlation_score"
                )
            ),

        "event_count":
            event_count,

        "categories":
            _incident_categories(
                incident
            ),

        "device_id":
            incident.get(
                "device_id"
            ),

        "created_at":
            incident.get(
                "created_at"
            ),

        "updated_at":
            incident.get(
                "updated_at"
            ),

        "visibility": {

            "user_visible":
                not internal,

            "internal_regression":
                internal,

            "synthetic":
                synthetic,
        },
    }


# ================================================================
# CANONICAL INVESTIGATION CONTRACT
# ================================================================

def build_canonical_investigation_contract(
    incident,
    intelligence,
) -> dict:
    """
    Convert the existing multi-agent read-only investigation
    result into the canonical SENTINEL-X user product contract.

    IMPORTANT:

    - does not rerun detectors
    - does not execute protection
    - does not promote an incident
    - does not convert risk into probability
    - does not treat COMPLETED as confirmed compromise
    """

    incident = obj(
        incident
    )

    intelligence = obj(
        intelligence
    )

    coordinated = obj(
        intelligence.get(
            "coordinated_analysis"
        )
    )

    agent_outputs = obj(
        coordinated.get(
            "agent_outputs"
        )
    )

    # ============================================================
    # ANALYTICAL PRODUCTS
    # ============================================================

    risk = _first_nonempty_dict(

        coordinated.get(
            "risk"
        ),

        agent_outputs.get(
            "RiskAssessmentAgent"
        ),
    )

    investigation = (
        _first_nonempty_dict(

            coordinated.get(
                "investigation"
            ),

            agent_outputs.get(
                "InvestigationAgent"
            ),
        )
    )

    evidence = (
        _first_nonempty_dict(

            coordinated.get(
                "evidence"
            ),

            agent_outputs.get(
                "EvidenceEnrichmentAgent"
            ),
        )
    )

    graph = (
        _first_nonempty_dict(

            coordinated.get(
                "attack_graph"
            ),

            agent_outputs.get(
                "AttackGraphAgent"
            ),
        )
    )

    report = (
        _first_nonempty_dict(

            coordinated.get(
                "report"
            ),

            agent_outputs.get(
                "InvestigationReportAgent"
            ),
        )
    )

    consensus = obj(
        intelligence.get(
            "consensus"
        )
    )

    response = obj(
        intelligence.get(
            "response"
        )
    )

    validation = obj(
        intelligence.get(
            "evidence_validation"
        )
    )

    # ============================================================
    # INVESTIGATION SCORE
    # ============================================================

    investigation_score = (
        bounded_score(
            intelligence.get(
                "risk_score"
            )
        )
    )

    if (
        investigation_score
        is None
    ):

        investigation_score = (
            bounded_score(
                risk.get(
                    "risk_score"
                )
            )
        )

    risk_level = (
        intelligence.get(
            "risk_level"
        )
        or
        risk.get(
            "risk_level"
        )
        or
        "INFO"
    )

    # ============================================================
    # FINDINGS
    # ============================================================

    findings = _safe_list(
        investigation.get(
            "findings"
        )
    )

    if not findings:

        findings = _safe_list(
            report.get(
                "key_findings"
            )
        )

    # ============================================================
    # EXPLICIT UNKNOWNS ONLY
    #
    # Never invent uncertainty statements.
    # ============================================================

    unknown = []

    for source in (
        investigation,
        report,
    ):

        for field in (
            "unknown",
            "unknowns",
            "uncertainties",
        ):

            for item in _safe_list(
                source.get(
                    field
                )
            ):

                if (
                    item
                    not in unknown
                ):

                    unknown.append(
                        deepcopy(
                            item
                        )
                    )

    # ============================================================
    # ADVISORY RECOMMENDATIONS
    # ============================================================

    recommendations = (
        deepcopy(
            _safe_list(
                response.get(
                    "recommendations"
                )
            )
        )
    )

    # ============================================================
    # TIMELINE + DETECTION SUMMARY
    # ============================================================

    timeline = deepcopy(
        items(
            incident.get(
                "timeline"
            )
        )
    )

    detections = []

    for detection in items(
        incident.get(
            "detections"
        )
    ):

        detections.append(
            {

                "detection_id":
                    detection.get(
                        "detection_id"
                    ),

                "event_id":
                    detection.get(
                        "event_id"
                    ),

                "engine":
                    detection.get(
                        "engine"
                    ),

                "threat_type":
                    detection.get(
                        "threat_type"
                    ),

                "severity":
                    normalize_severity(
                        detection.get(
                            "severity"
                        )
                    ),

                "risk_score":
                    bounded_score(
                        detection.get(
                            "risk_score"
                        )
                    ),

                "confidence":
                    normalize_confidence(
                        detection.get(
                            "confidence"
                        )
                    ),
            }
        )

    # ============================================================
    # ENTITY COUNTS
    # ============================================================

    evidence_summary = obj(
        risk.get(
            "evidence_summary"
        )
    )

    entity_summary = obj(
        evidence.get(
            "summary"
        )
    )

    graph_summary = obj(
        graph.get(
            "summary"
        )
    )

    # ============================================================
    # QUALIFYING EVENT TERMINOLOGY
    #
    # The existing validation engine calls these
    # "authoritative_event_count".
    #
    # In synthetic validation mode we expose them as
    # qualifying validation events instead of implying
    # production-authoritative telemetry.
    # ============================================================

    qualifying_event_count = (
        validation.get(
            "authoritative_event_count"
        )
    )

    # ============================================================
    # RESULT
    # ============================================================

    return {

        "schema_version":
            SECURITY_CONTRACT_VERSION,

        "object_type":
            "SECURITY_INCIDENT_INVESTIGATION",

        "generated_at":
            now_iso(),

        # ========================================================
        # INCIDENT
        # ========================================================

        "incident":
            build_canonical_incident_summary(
                incident
            ),

        # ========================================================
        # INVESTIGATION
        # ========================================================

        "investigation": {

            "available":
                True,

            "status":
                intelligence.get(
                    "status"
                )
                or
                "UNKNOWN",

            "security_state":
                intelligence.get(
                    "security_state"
                ),

            "final_decision":
                intelligence.get(
                    "final_decision"
                )
                or
                consensus.get(
                    "final_decision"
                ),

            "risk": {

                "score":
                    investigation_score,

                "level":
                    normalize_severity(
                        risk_level
                    ),

                "semantics":
                    RiskSemantics
                    .INVESTIGATION
                    .value,
            },

            "confidence_calibrated":
                bool(
                    consensus.get(
                        "confidence_calibrated",
                        False,
                    )
                ),

            "processed_at":
                intelligence.get(
                    "processed_at"
                ),
        },

        # ========================================================
        # EVIDENCE VALIDATION
        # ========================================================

        "evidence_validation": {

            "passed":
                (
                    validation.get(
                        "passed"
                    )
                    is True
                ),

            "qualifying_event_count":
                qualifying_event_count,

            "stored_detection_count":
                validation.get(
                    "stored_detection_count"
                ),

            "strong_detection_count":
                validation.get(
                    "strong_detection_count"
                ),

            "cross_category_corroboration":
                validation.get(
                    "cross_category_corroboration"
                ),

            "rejected_event_count":
                validation.get(
                    "rejected_event_count"
                ),

            "rejected_reasons":
                deepcopy(
                    _safe_list(
                        validation.get(
                            "rejected_reasons"
                        )
                    )
                ),

            "validation_only":
                bool(
                    validation.get(
                        "validation_only",
                        False,
                    )
                ),

            "production_eligible":
                (
                    validation.get(
                        "production_eligible"
                    )
                    is True
                ),

            "validation_policy":
                validation.get(
                    "validation_policy"
                ),
        },

        # ========================================================
        # EVIDENCE BOUNDARIES
        # ========================================================

        "evidence_boundaries": {

            "observed": {

                "timeline_event_count":
                    len(
                        timeline
                    ),

                "stored_detection_count":
                    len(
                        detections
                    ),

                "qualifying_event_count":
                    qualifying_event_count,

                "categories":
                    _incident_categories(
                        incident
                    ),

                "entity_summary":
                    deepcopy(
                        entity_summary
                    ),

                "evidence_summary":
                    deepcopy(
                        evidence_summary
                    ),
            },

            "inferred":
                deepcopy(
                    findings
                ),

            "unknown":
                deepcopy(
                    unknown
                ),
        },

        # ========================================================
        # FINDINGS
        # ========================================================

        "findings":
            deepcopy(
                findings
            ),

        # ========================================================
        # ADVISORY RESPONSE
        # ========================================================

        "recommendations": {

            "available":
                len(
                    recommendations
                )
                >
                0,

            "advisory_only":
                True,

            "items":
                recommendations,
        },

        # ========================================================
        # CONSENSUS
        # ========================================================

        "consensus": {

            "final_decision":
                consensus.get(
                    "final_decision"
                ),

            "confidence":
                consensus.get(
                    "confidence"
                ),

            "confidence_calibrated":
                bool(
                    consensus.get(
                        "confidence_calibrated",
                        False,
                    )
                ),
        },

        # ========================================================
        # RECORDED DATA
        # ========================================================

        "detections":
            detections,

        "timeline":
            timeline,

        # ========================================================
        # TECHNICAL DETAIL
        # ========================================================

        "technical": {

            "pipeline":
                intelligence.get(
                    "pipeline"
                ),

            "autonomy_level":
                intelligence.get(
                    "autonomy_level"
                ),

            "autonomy_mode":
                intelligence.get(
                    "autonomy_mode"
                ),

            "agent_decisions":
                deepcopy(
                    _safe_list(
                        intelligence.get(
                            "agent_decisions"
                        )
                    )
                ),

            "agent_output_names":
                sorted(
                    agent_outputs.keys()
                ),

            # Retained for Advanced Technical Details.
            "agent_outputs":
                deepcopy(
                    agent_outputs
                ),

            "attack_graph_summary":
                deepcopy(
                    graph_summary
                ),

            "report_summary":
                {

                    "executive_summary":
                        report.get(
                            "executive_summary"
                        ),

                    "decision":
                        deepcopy(
                            obj(
                                report.get(
                                    "decision"
                                )
                            )
                        ),

                    "attack":
                        deepcopy(
                            obj(
                                report.get(
                                    "attack"
                                )
                            )
                        ),
                },
        },

        # ========================================================
        # SAFETY CONTRACT
        # ========================================================

        "safety": {

            "read_only":
                True,

            "preview_only":
                True,

            "execution_enabled":
                False,

            "response_authorized":
                False,

            "real_response_executed":
                False,

            "production_eligible":
                (
                    validation.get(
                        "production_eligible"
                    )
                    is True
                ),
        },
    }
    

# ================================================================
# CANONICAL PROTECTION PREVIEW HELPERS
# ================================================================

def _first_present(
    record,
    *keys,
):
    record = obj(
        record
    )

    for key in keys:

        value = record.get(
            key
        )

        if (
            value is not None
            and
            value != ""
        ):

            return value

    return None


def _protection_action_label(
    action_type,
) -> str:

    key = str(
        action_type
        or ""
    ).upper()

    mapping = {

        "TERMINATE_PROCESS":
            "Stop suspicious process",

        "QUARANTINE_FILE":
            "Quarantine suspicious file",

        "BLOCK_NETWORK":
            "Block suspicious network connection",

        "REMEDIATE_PERSISTENCE":
            "Remove persistence mechanism",

        "ISOLATE_ENDPOINT":
            "Isolate device",
    }

    return mapping.get(
        key,
        title_case_identifier(
            action_type
            or
            "Protection Action"
        ),
    )


def _protection_plan_label(
    plan_name,
) -> str:

    key = str(
        plan_name
        or ""
    ).strip()

    mapping = {

        "Minimal Targeted Response":
            "Minimal Protection",

        "Targeted Containment":
            "Balanced Protection",

        "Targeted Full Remediation":
            "Comprehensive Protection",

        "Full Endpoint Containment":
            "Full Device Isolation",
    }

    return mapping.get(
        key,
        key
        or
        "Virtual Protection Plan",
    )


def _canonical_virtual_action(
    action,
) -> dict:

    action = obj(
        action
    )

    action_type = str(
        action.get(
            "action_type"
        )
        or ""
    ).upper()

    target = deepcopy(
        obj(
            action.get(
                "target"
            )
        )
    )

    evidence_reference = (
        action.get(
            "evidence_reference"
        )
    )

    scenario_basis = (
        action.get(
            "scenario_basis"
        )
    )

    target_provenance = deepcopy(
        obj(
            action.get(
                "target_provenance"
            )
        )
    )

    # ------------------------------------------------------------
    # DIGITAL TWIN CURRENTLY STORES PROVENANCE AS:
    #
    # evidence_reference
    # scenario_basis
    #
    # Canonical contract exposes both directly and also provides
    # a normalized provenance object.
    # ------------------------------------------------------------

    if not target_provenance:

        target_provenance = {}

        if evidence_reference:

            target_provenance[
                "event_id"
            ] = evidence_reference

        if scenario_basis:

            target_provenance[
                "basis"
            ] = scenario_basis

    return {

        "action_type":
            action_type,

        "display_name":
            _protection_action_label(
                action_type
            ),

        "target":
            target,

        "evidence_reference":
            evidence_reference,

        "scenario_basis":
            scenario_basis,

        "target_provenance":
            target_provenance,

        "reason":
            (
                action.get(
                    "reason"
                )
                or
                scenario_basis
            ),

        "source":
            action.get(
                "source"
            ),

        "scenario_only":
            (
                action.get(
                    "scenario_only"
                )
                is True
            ),

        "hypothetical":
            True,

        "virtual_only":
            True,

        "response_authorized":
            False,
    }
    
def _canonical_playback_frame(
    frame,
) -> dict:

    frame = obj(
        frame
    )

    return {

        "step":
            frame.get(
                "step"
            ),

        "action_type":
            frame.get(
                "action_type"
            ),

        "display_name":
            (
                _protection_action_label(
                    frame.get(
                        "action_type"
                    )
                )
                if frame.get(
                    "action_type"
                )
                else "Initial Virtual State"
            ),

        "status":
            frame.get(
                "status"
            ),

        "success":
            (
                frame.get(
                    "success"
                )
                is True
            ),

        "risk_score":
            bounded_score(
                frame.get(
                    "risk_score"
                )
            ),

        "risk_components":
            deepcopy(
                obj(
                    frame.get(
                        "risk_components"
                    )
                )
            ),

        "state":
            deepcopy(
                obj(
                    frame.get(
                        "state"
                    )
                )
            ),

        "virtual_only":
            True,
    }


def _canonical_virtual_plan(
    plan,
) -> dict:

    plan = obj(
        plan
    )

    if not plan:

        return {}

    # ============================================================
    # ACTIONS
    # ============================================================

    actions = [

        _canonical_virtual_action(
            action
        )

        for action
        in items(
            plan.get(
                "actions"
            )
        )
    ]

    # ============================================================
    # PLAYBACK
    # ============================================================

    playback = [

        _canonical_playback_frame(
            frame
        )

        for frame
        in items(
            plan.get(
                "playback"
            )
        )
    ]

    # ============================================================
    # INITIAL RISK
    #
    # Ranked plans may not duplicate initial_risk_score because
    # the baseline belongs to the Digital Twin itself.
    # Playback step 0 is therefore a safe recorded fallback.
    # ============================================================

    initial_risk = bounded_score(
        _first_present(
            plan,
            "initial_risk",
            "initial_risk_score",
            "baseline_risk",
        )
    )

    if (
        initial_risk is None
        and
        playback
    ):

        initial_risk = bounded_score(
            playback[0].get(
                "risk_score"
            )
        )

    # ============================================================
    # RESIDUAL RISK
    # ============================================================

    residual_risk = bounded_score(
        _first_present(
            plan,
            "predicted_residual_risk",
            "residual_risk",
            "residual_risk_score",
            "final_risk_score",
        )
    )

    # ============================================================
    # RANKING SCORE
    #
    # Current Digital Twin planner uses plan_score.
    # ============================================================

    ranking_score = bounded_score(
        _first_present(
            plan,
            "plan_score",
            "ranking_score",
            "score",
        )
    )

    # ============================================================
    # REDUCTION
    # ============================================================

    risk_reduction = safe_float(
        _first_present(
            plan,
            "risk_reduction",
            "absolute_risk_reduction",
        )
    )

    risk_reduction_percentage = safe_float(
        _first_present(
            plan,
            "risk_reduction_percentage",
            "risk_reduction_percent",
        )
    )

    # ============================================================
    # LIMITATIONS
    # ============================================================

    limitations = [

        _clean_protection_limitation(
            item
        )

        for item
        in _safe_list(
            plan.get(
                "limitations"
            )
        )

        if item
    ]

    return {

        "plan_id":
            plan.get(
                "plan_id"
            ),

        "technical_name":
            plan.get(
                "plan_name"
            ),

        "display_name":
            _protection_plan_label(
                plan.get(
                    "plan_name"
                )
            ),

        "description":
            plan.get(
                "description"
            ),

        "actions":
            actions,

        "action_count":
            len(
                actions
            ),

        # ========================================================
        # RISK
        # ========================================================

        "initial_risk_score":
            initial_risk,

        "residual_risk_score":
            residual_risk,

        "risk_reduction":
            risk_reduction,

        "risk_reduction_percentage":
            risk_reduction_percentage,

        # ========================================================
        # RANKING
        # ========================================================

        "ranking_score":
            ranking_score,

        "ranking_semantics":
            (
                plan.get(
                    "score_type"
                )
                or
                "HEURISTIC_RANKING_SCORE"
            ),

        "reduction_semantics":
            (
                plan.get(
                    "reduction_semantics"
                )
                or
                "REDUCTION_OF_MODELED_COMPONENTS"
            ),

        # ========================================================
        # SIMULATION RESULT
        # ========================================================

        "simulation_valid":
            (
                plan.get(
                    "simulation_valid"
                )
                is True
            ),

        "simulation_status":
            plan.get(
                "simulation_status"
            ),

        "response_effectiveness":
            plan.get(
                "response_effectiveness"
            ),

        "recommended_decision":
            plan.get(
                "recommended_decision"
            ),

        # ========================================================
        # DISRUPTION
        # ========================================================

        "modeled_disruption":
            deepcopy(
                obj(
                    _first_present(
                        plan,
                        "operational_impact",
                        "modeled_disruption",
                        "disruption",
                    )
                )
            ),

        # ========================================================
        # COMPONENTS
        # ========================================================

        "baseline_components":
            deepcopy(
                obj(
                    plan.get(
                        "baseline_components"
                    )
                )
            ),

        "residual_components":
            deepcopy(
                obj(
                    plan.get(
                        "residual_components"
                    )
                )
            ),

        # ========================================================
        # PLAYBACK
        # ========================================================

        "playback":
            playback,

        "virtual_action_failures":
            deepcopy(
                _safe_list(
                    plan.get(
                        "virtual_action_failures"
                    )
                )
            ),

        "limitations":
            limitations,

        # ========================================================
        # SAFETY
        # ========================================================

        "hypothetical":
            True,

        "virtual_only":
            True,

        "approval_eligible":
            False,

        "response_authorized":
            False,

        "real_endpoint_modified":
            False,
    }
def _clean_protection_limitation(
    value,
) -> str:

    text = str(
        value
        or ""
    )

    replacements = {

        "A virtual success is not real containment.":
            (
                "A virtual success is not verified "
                "real-world protection."
            ),

        "No SOC case or real response created.":
            (
                "No persistent protection workflow or "
                "real endpoint action was created."
            ),

        "No action is executed, approved, persisted or promoted to SOC.":
            (
                "No real action is executed, authorized "
                "or persisted by this preview."
            ),

        "No real containment performed.":
            (
                "No real endpoint protection action "
                "was performed."
            ),
    }

    return replacements.get(
        text,
        text,
    )


# ================================================================
# CANONICAL PROTECTION PREVIEW CONTRACT
# ================================================================

def build_canonical_protection_preview_contract(
    incident,
    preview,
) -> dict:
    """
    Normalize the existing read-only Digital Twin response into
    the canonical Sentinel-X user product contract.

    This function does not simulate anything itself.
    It only normalizes the already-generated preview.
    """

    incident = obj(
        incident
    )

    preview = obj(
        preview
    )

    validation = obj(
        preview.get(
            "evidence_validation"
        )
    )

    baseline_components = deepcopy(
        obj(
            preview.get(
                "baseline_risk_components"
            )
        )
    )

    baseline_explanation = deepcopy(
        obj(
            preview.get(
                "baseline_risk_explanation"
            )
        )
    )

    candidate_actions = [
        _canonical_virtual_action(
            action
        )
        for action
        in items(
            preview.get(
                "candidate_actions"
            )
        )
    ]

    plans = [
        _canonical_virtual_plan(
            plan
        )
        for plan
        in items(
            preview.get(
                "ranked_plans"
            )
        )
    ]

    best_plan = (
        _canonical_virtual_plan(
            preview.get(
                "best_plan"
            )
        )
        if obj(
            preview.get(
                "best_plan"
            )
        )
        else None
    )

    qualifying_event_count = (
        validation.get(
            "authoritative_event_count"
        )
    )

    limitations = [
        _clean_protection_limitation(
            item
        )
        for item
        in _safe_list(
            preview.get(
                "limitations"
            )
        )
        if item
    ]

    return {

        "schema_version":
            SECURITY_CONTRACT_VERSION,

        "object_type":
            "SECURITY_PROTECTION_PREVIEW",

        "generated_at":
            now_iso(),

        # ========================================================
        # INCIDENT
        # ========================================================

        "incident":
            build_canonical_incident_summary(
                incident
            ),

        # ========================================================
        # RISK
        # ========================================================

        "risk": {

            "investigation": {

                "score":
                    bounded_score(
                        preview.get(
                            "investigation_risk_score"
                        )
                    ),

                "semantics":
                    RiskSemantics
                    .INVESTIGATION
                    .value,
            },

            "simulation": {

                "score":
                    bounded_score(
                        preview.get(
                            "initial_risk_score"
                        )
                    ),

                "semantics":
                    RiskSemantics
                    .SIMULATION
                    .value,

                "model_type":
                    preview.get(
                        "model_type"
                    ),

                "components":
                    baseline_components,

                "component_explanation":
                    baseline_explanation,

                "score_note":
                    preview.get(
                        "score_note"
                    ),
            },
        },

        # ========================================================
        # INVESTIGATION GATE
        # ========================================================

        "investigation": {

            "status":
                preview.get(
                    "investigation_status"
                ),
        },

        # ========================================================
        # EVIDENCE VALIDATION
        # ========================================================

        "evidence_validation": {

            "passed":
                (
                    validation.get(
                        "passed"
                    )
                    is True
                ),

            "qualifying_event_count":
                qualifying_event_count,

            "stored_detection_count":
                validation.get(
                    "stored_detection_count"
                ),

            "strong_detection_count":
                validation.get(
                    "strong_detection_count"
                ),

            "cross_category_corroboration":
                validation.get(
                    "cross_category_corroboration"
                ),

            "rejected_event_count":
                validation.get(
                    "rejected_event_count"
                ),

            "rejected_reasons":
                deepcopy(
                    _safe_list(
                        validation.get(
                            "rejected_reasons"
                        )
                    )
                ),

            "validation_only":
                bool(
                    validation.get(
                        "validation_only",
                        False,
                    )
                ),

            "production_eligible":
                (
                    validation.get(
                        "production_eligible"
                    )
                    is True
                ),

            "validation_policy":
                validation.get(
                    "validation_policy"
                ),
        },

        # ========================================================
        # RECORDED VIRTUAL EVIDENCE COUNTS
        # ========================================================

        "evidence_counts":
            deepcopy(
                obj(
                    preview.get(
                        "evidence_counts"
                    )
                )
            ),

        # ========================================================
        # VIRTUAL PROTECTION
        # ========================================================

        "protection": {

            "available":
                True,

            "mode":
                "HYPOTHETICAL_READ_ONLY",

            "decision":
                preview.get(
                    "decision"
                ),

            "plan_evaluation_eligible":
                (
                    preview.get(
                        "plan_evaluation_eligible"
                    )
                    is True
                ),

            "candidate_action_count":
                len(
                    candidate_actions
                ),

            "candidate_actions":
                candidate_actions,

            "plans_evaluated":
                len(
                    plans
                ),

            "plans":
                plans,

            "best_plan":
                best_plan,
        },

        # ========================================================
        # LIMITATIONS
        # ========================================================

        "limitations":
            limitations,

        # ========================================================
        # SAFETY
        # ========================================================

        "safety": {

            "read_only":
                True,

            "preview_only":
                True,

            "simulation_mode":
                True,

            "workflow_created":
                False,

            "approval_eligible":
                False,

            "response_authorized":
                False,

            "real_endpoint_modified":
                False,

            "production_eligible":
                (
                    validation.get(
                        "production_eligible"
                    )
                    is True
                ),
        },
    }
    
# ================================================================
# SIMPLE MODULE SELF-CHECK
# ================================================================

if __name__ == "__main__":

    sample = {

        "detection_id":
            1,

        "event_id":
            "SAMPLE-EVENT",

        "event_type":
            "process_security_detection",

        "engine":
            "process_behavior",

        "threat_type":
            "SUSPICIOUS_PROCESS_BEHAVIOR",

        "severity":
            "HIGH",

        "confidence":
            0.90,

        "risk_score":
            80,

        "detected":
            True,

        "process_evidence": {

            "pid":
                1234,

            "name":
                "sample.exe",
        },

        "event_metadata": {

            "synthetic":
                True,
        },
    }

    canonical = (
        build_canonical_security_object(
            sample
        )
    )

    validation = (
        validate_canonical_security_object(
            canonical
        )
    )

    print(
        "SENTINEL-X SECURITY CONTRACT"
    )

    print(
        "Schema:",
        canonical[
            "schema_version"
        ],
    )

    print(
        "Category:",
        canonical[
            "category"
        ],
    )

    print(
        "Verdict:",
        canonical[
            "verdict"
        ],
    )

    print(
        "User State:",
        canonical[
            "user_state"
        ],
    )

    print(
        "Contract Valid:",
        validation[
            "valid"
        ],
    )

    if validation[
        "errors"
    ]:

        print(
            "Errors:",
            validation[
                "errors"
            ],
        )