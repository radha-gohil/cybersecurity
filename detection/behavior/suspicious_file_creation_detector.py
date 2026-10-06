from __future__ import annotations

from typing import Dict, Optional


class SuspiciousFileCreationDetector:
    """
    SENTINEL-X suspicious executable creation detector.

    This detector consumes static-analysis output. It never executes,
    opens, or modifies the analyzed file.

    Current F1 policy:
      - event must be file_create/file_created
      - file must be recognized as a PE file
      - static risk must be >= 30

    This is a suspicious-file heuristic, NOT malware classification.
    Malware classification remains the separate M1 supervised model.
    """

    def __init__(
        self,
        static_risk_threshold: int = 30,
    ):
        self.static_risk_threshold = int(
            static_risk_threshold
        )

    def analyze(
        self,
        event_type: str,
        file_path: str,
        static_analysis: Dict,
    ) -> Optional[Dict]:
        event_type = str(
            event_type or ""
        ).lower().strip()

        if event_type not in {
            "file_create",
            "file_created",
        }:
            return None

        if not isinstance(
            static_analysis,
            dict,
        ):
            return None

        if not static_analysis.get(
            "is_pe"
        ):
            return None

        risk_score = int(
            static_analysis.get(
                "risk_score",
                0,
            )
            or 0
        )

        if (
            risk_score
            < self.static_risk_threshold
        ):
            return None

        severity = str(
            static_analysis.get(
                "severity",
                "MEDIUM",
            )
            or "MEDIUM"
        ).upper()

        if severity in {
            "INFO",
            "LOW",
        }:
            severity = "MEDIUM"

        reasons = [
            str(item)
            for item in (
                static_analysis.get(
                    "reasons",
                    []
                )
                or []
            )
            if item
        ]

        if not reasons:
            reasons = [
                "PE file exceeded the suspicious static-risk threshold"
            ]

        return {
            "engine":
                "file_static_behavior",

            "detection_type":
                "SUSPICIOUS_EXECUTABLE_CREATION",

            "threat_type":
                "SUSPICIOUS_EXECUTABLE_CREATION",

            "severity":
                severity,

            "risk":
                risk_score,

            "risk_score":
                risk_score,

            # Static risk is heuristic evidence, not a calibrated
            # probability, so confidence is intentionally omitted.
            "confidence":
                None,

            "file_path":
                file_path,

            "sha256":
                static_analysis.get(
                    "sha256"
                ),

            "entropy":
                static_analysis.get(
                    "entropy"
                ),

            "extension":
                static_analysis.get(
                    "extension"
                ),

            "is_pe":
                True,

            "static_reasons":
                reasons,

            "reason":
                "; ".join(
                    reasons
                ),

            "detection_method":
                "STATIC_FILE_HEURISTIC",

            "interpretation":
                (
                    "The newly created PE file has suspicious static "
                    "characteristics. This does not establish that the "
                    "file is malware."
                ),
        }
