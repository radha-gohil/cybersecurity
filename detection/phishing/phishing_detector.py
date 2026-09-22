import ipaddress
import re

from email.utils import parseaddr
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse


class PhishingDetector:
    """
    SENTINEL-X Phishing Behavior Detector.

    This detector performs metadata/text analysis only.

    It DOES NOT:

        - send emails
        - open URLs
        - download files
        - execute attachments
        - contact external domains

    Current signals:

        1. SUSPICIOUS_SENDER_DOMAIN
        2. DISPLAY_NAME_DOMAIN_MISMATCH
        3. SUSPICIOUS_URL
        4. URGENCY_LANGUAGE
        5. SUSPICIOUS_ATTACHMENT
        6. PHISHING_SUSPICION
    """

    def __init__(
        self,
        phishing_score_threshold: int = 60,
        protected_brand_domains: Optional[
            Dict[str, Set[str]]
        ] = None,
    ):

        self.phishing_score_threshold = (
            phishing_score_threshold
        )

        # ========================================================
        # PROTECTED BRAND / DOMAIN MAP
        #
        # Example:
        #
        # {
        #     "examplecorp": {
        #         "examplecorp.test"
        #     }
        # }
        #
        # If a display name contains "ExampleCorp" but the sender
        # domain is not one of the approved domains, it can be
        # treated as a mismatch signal.
        # ========================================================

        self.protected_brand_domains = {}

        protected_brand_domains = (
            protected_brand_domains
            or {}
        )

        for (
            brand,
            domains,
        ) in protected_brand_domains.items():

            self.protected_brand_domains[
                str(
                    brand
                ).strip().lower()
            ] = {

                self.normalize_domain(
                    domain
                )

                for domain
                in domains
            }

        # ========================================================
        # URGENCY / SOCIAL ENGINEERING TERMS
        # ========================================================

        self.urgency_terms = {

            "urgent",
            "immediately",
            "immediate action",
            "verify now",
            "verify your account",
            "account suspended",
            "account will be suspended",
            "within 24 hours",
            "limited time",
            "final warning",
            "action required",
            "security alert",
            "confirm immediately",
        }

        # ========================================================
        # HIGH-RISK ATTACHMENT EXTENSIONS
        #
        # These extensions are not automatically malicious.
        # They are simply higher-risk attachment types.
        # ========================================================

        self.suspicious_extensions = {

            ".exe",
            ".scr",
            ".js",
            ".jse",
            ".vbs",
            ".vbe",
            ".ps1",
            ".bat",
            ".cmd",
            ".hta",
            ".lnk",
            ".msi",
            ".iso",
            ".img",
            ".com",
        }

    # ============================================================
    # BASIC NORMALIZATION
    # ============================================================

    def normalize_text(
        self,
        value,
    ) -> str:

        if value is None:
            return ""

        return str(
            value
        ).strip()

    def normalize_domain(
        self,
        value,
    ) -> str:

        value = (
            self.normalize_text(
                value
            )
            .lower()
            .strip(".")
        )

        return value

    # ============================================================
    # EMAIL ADDRESS
    # ============================================================

    def extract_email_address(
        self,
        value,
    ) -> str:

        value = (
            self.normalize_text(
                value
            )
        )

        if not value:
            return ""

        _, address = (
            parseaddr(
                value
            )
        )

        return (
            address
            or value
        ).strip().lower()

    def extract_domain_from_email(
        self,
        value,
    ) -> str:

        address = (
            self.extract_email_address(
                value
            )
        )

        if (
            "@"
            not in address
        ):

            return ""

        return (
            self.normalize_domain(
                address.rsplit(
                    "@",
                    1,
                )[1]
            )
        )

    # ============================================================
    # URL EXTRACTION
    # ============================================================

    def get_urls(
        self,
        email_event: Dict,
    ) -> List[str]:

        urls = []

        explicit_urls = (
            email_event.get(
                "urls"
            )
        )

        if isinstance(
            explicit_urls,
            str,
        ):

            explicit_urls = [
                explicit_urls
            ]

        if isinstance(
            explicit_urls,
            list,
        ):

            for url in explicit_urls:

                normalized = (
                    self.normalize_text(
                        url
                    )
                )

                if normalized:

                    urls.append(
                        normalized
                    )

        # --------------------------------------------------------
        # Also scan email body for URL-like strings.
        # --------------------------------------------------------

        body = self.normalize_text(
            email_event.get(
                "body"
            )
        )

        if body:

            found = re.findall(
                r"https?://[^\s<>\"]+",
                body,
                flags=re.IGNORECASE,
            )

            urls.extend(
                found
            )

        # --------------------------------------------------------
        # Deduplicate while preserving order.
        # --------------------------------------------------------

        unique_urls = []

        seen = set()

        for url in urls:

            if url in seen:
                continue

            seen.add(
                url
            )

            unique_urls.append(
                url
            )

        return unique_urls

    # ============================================================
    # ATTACHMENT EXTRACTION
    # ============================================================

    def get_attachments(
        self,
        email_event: Dict,
    ) -> List[str]:

        attachments = (
            email_event.get(
                "attachments"
            )
        )

        if attachments is None:

            attachment = (
                email_event.get(
                    "attachment"
                )
            )

            if attachment:

                attachments = [
                    attachment
                ]

        if isinstance(
            attachments,
            str,
        ):

            attachments = [
                attachments
            ]

        if not isinstance(
            attachments,
            list,
        ):

            return []

        normalized = []

        for attachment in attachments:

            if isinstance(
                attachment,
                dict,
            ):

                name = (

                    attachment.get(
                        "filename"
                    )

                    or attachment.get(
                        "name"
                    )
                )

            else:

                name = (
                    attachment
                )

            name = (
                self.normalize_text(
                    name
                )
            )

            if name:

                normalized.append(
                    name
                )

        return normalized

    # ============================================================
    # DOMAIN CHARACTERISTICS
    # ============================================================

    def analyze_sender_domain(
        self,
        sender_domain: str,
    ) -> List[str]:

        reasons = []

        sender_domain = (
            self.normalize_domain(
                sender_domain
            )
        )

        if not sender_domain:

            return reasons

        # --------------------------------------------------------
        # Internationalized/punycode domains can be legitimate,
        # but they are useful as one phishing heuristic.
        # --------------------------------------------------------

        if (
            "xn--"
            in sender_domain
        ):

            reasons.append(
                "Sender domain contains punycode notation"
            )

        # --------------------------------------------------------
        # Excessive hyphenation can resemble impersonation domains.
        # --------------------------------------------------------

        if (
            sender_domain.count(
                "-"
            )
            >= 3
        ):

            reasons.append(
                "Sender domain contains excessive hyphenation"
            )

        # --------------------------------------------------------
        # Common social-engineering wording inside domains.
        # --------------------------------------------------------

        suspicious_domain_terms = {

            "secure-login",
            "account-verify",
            "account-update",
            "verification-center",
            "security-check",
            "login-verify",
        }

        for term in suspicious_domain_terms:

            if term in sender_domain:

                reasons.append(
                    (
                        "Sender domain contains "
                        f"suspicious term: {term}"
                    )
                )

        return reasons

    # ============================================================
    # DISPLAY NAME / DOMAIN MISMATCH
    # ============================================================

    def analyze_display_name_mismatch(
        self,
        display_name: str,
        sender_domain: str,
    ) -> List[str]:

        reasons = []

        display_name_lower = (
            self.normalize_text(
                display_name
            ).lower()
        )

        sender_domain = (
            self.normalize_domain(
                sender_domain
            )
        )

        if (
            not display_name_lower
            or not sender_domain
        ):

            return reasons

        for (
            brand,
            approved_domains,
        ) in self.protected_brand_domains.items():

            if (
                brand
                not in display_name_lower
            ):

                continue

            if (
                sender_domain
                not in approved_domains
            ):

                reasons.append(
                    (
                        f"Display name references protected "
                        f"brand '{brand}' but sender domain "
                        f"is '{sender_domain}'"
                    )
                )

        return reasons

    # ============================================================
    # URL ANALYSIS
    # ============================================================

    def is_ip_address(
        self,
        hostname: str,
    ) -> bool:

        if not hostname:

            return False

        try:

            ipaddress.ip_address(
                hostname
            )

            return True

        except ValueError:

            return False

    def analyze_url(
        self,
        url: str,
    ) -> List[str]:

        reasons = []

        try:

            parsed = (
                urlparse(
                    url
                )
            )

        except Exception:

            return [
                "URL could not be parsed normally"
            ]

        hostname = (
            parsed.hostname
            or ""
        ).lower()

        # --------------------------------------------------------
        # Plain HTTP
        # --------------------------------------------------------

        if (
            parsed.scheme.lower()
            ==
            "http"
        ):

            reasons.append(
                "URL uses unencrypted HTTP"
            )

        # --------------------------------------------------------
        # Raw IP destination
        # --------------------------------------------------------

        if self.is_ip_address(
            hostname
        ):

            reasons.append(
                "URL uses a raw IP address instead of a domain"
            )

        # --------------------------------------------------------
        # URL user-info trick:
        #
        # http://trusted-looking-name@actual-host/
        # --------------------------------------------------------

        if (
            parsed.username
            is not None
        ):

            reasons.append(
                "URL contains user-info before the hostname"
            )

        # --------------------------------------------------------
        # Punycode URL
        # --------------------------------------------------------

        if (
            "xn--"
            in hostname
        ):

            reasons.append(
                "URL hostname contains punycode notation"
            )

        # --------------------------------------------------------
        # Excessive subdomains
        # --------------------------------------------------------

        if (
            hostname.count(
                "."
            )
            >= 4
        ):

            reasons.append(
                "URL contains an unusually deep subdomain chain"
            )

        # --------------------------------------------------------
        # Suspicious login terminology
        # --------------------------------------------------------

        url_lower = (
            url.lower()
        )

        suspicious_terms = {

            "verify-account",
            "secure-login",
            "confirm-login",
            "account-update",
            "password-reset",
            "security-check",
        }

        for term in suspicious_terms:

            if term in url_lower:

                reasons.append(
                    (
                        "URL contains suspicious "
                        f"authentication term: {term}"
                    )
                )

        return reasons

    # ============================================================
    # URGENCY LANGUAGE
    # ============================================================

    def analyze_urgency(
        self,
        subject: str,
        body: str,
    ) -> List[str]:

        combined = (
            f"{subject} {body}"
        ).lower()

        matched_terms = []

        for term in self.urgency_terms:

            if term in combined:

                matched_terms.append(
                    term
                )

        # --------------------------------------------------------
        # Require at least two social-engineering terms to reduce
        # false positives from ordinary business email.
        # --------------------------------------------------------

        if len(
            matched_terms
        ) < 2:

            return []

        return [
            (
                "Multiple urgency/social-engineering terms "
                "were observed: "
                + ", ".join(
                    sorted(
                        matched_terms
                    )
                )
            )
        ]

    # ============================================================
    # ATTACHMENTS
    # ============================================================

    def analyze_attachments(
        self,
        attachments: List[str],
    ) -> List[str]:

        reasons = []

        for attachment in attachments:

            extension = (

                Path(
                    attachment
                )
                .suffix
                .lower()
            )

            if (
                extension
                in self.suspicious_extensions
            ):

                reasons.append(
                    (
                        "Higher-risk attachment extension "
                        f"observed: {attachment}"
                    )
                )

        return reasons

    # ============================================================
    # DETECTION BUILDER
    # ============================================================

    def build_detection(
        self,
        detection_type: str,
        severity: str,
        risk_score: int,
        reasons: List[str],
        sender_domain: str,
        indicators: Optional[List[str]] = None,
    ) -> Dict:

        return {

            "engine":
                "phishing_behavior",

            "detection_type":
                detection_type,

            "severity":
                severity,

            "risk":
                risk_score,

            "risk_score":
                risk_score,

            # ----------------------------------------------------
            # Heuristic score only.
            # It is NOT a calibrated phishing probability.
            # ----------------------------------------------------

            "confidence":
                round(
                    risk_score
                    / 100.0,
                    4,
                ),

            "sender_domain":
                sender_domain,

            "indicators":
                indicators
                or [],

            "reasons":
                reasons,

            "reason":
                "; ".join(
                    reasons
                ),

            "detection_method":
                "RULE_BASED_EMAIL_BEHAVIOR",
        }

    # ============================================================
    # MAIN ANALYSIS
    # ============================================================

    def analyze(
        self,
        email_event: Dict,
    ) -> List[Dict]:

        detections = []

        # ========================================================
        # BASIC EMAIL FIELDS
        # ========================================================

        sender = (

            email_event.get(
                "sender"
            )

            or email_event.get(
                "from"
            )

            or email_event.get(
                "from_address"
            )

            or ""
        )

        display_name = (

            email_event.get(
                "display_name"
            )

            or parseaddr(
                self.normalize_text(
                    sender
                )
            )[0]

            or ""
        )

        sender_domain = (
            self.extract_domain_from_email(
                sender
            )
        )

        subject = (
            self.normalize_text(
                email_event.get(
                    "subject"
                )
            )
        )

        body = (
            self.normalize_text(
                email_event.get(
                    "body"
                )
            )
        )

        urls = (
            self.get_urls(
                email_event
            )
        )

        attachments = (
            self.get_attachments(
                email_event
            )
        )

        # ========================================================
        # SIGNAL 1 — SUSPICIOUS SENDER DOMAIN
        # ========================================================

        sender_reasons = (
            self.analyze_sender_domain(
                sender_domain
            )
        )

        sender_domain_active = (
            bool(
                sender_reasons
            )
        )

        if sender_domain_active:

            detections.append(

                self.build_detection(

                    detection_type=
                        "SUSPICIOUS_SENDER_DOMAIN",

                    severity=
                        "MEDIUM",

                    risk_score=
                        50,

                    reasons=
                        sender_reasons,

                    sender_domain=
                        sender_domain,

                    indicators=[
                        "sender_domain"
                    ],
                )
            )

        # ========================================================
        # SIGNAL 2 — DISPLAY NAME / DOMAIN MISMATCH
        # ========================================================

        display_reasons = (
            self.analyze_display_name_mismatch(

                display_name,

                sender_domain,
            )
        )

        display_mismatch_active = (
            bool(
                display_reasons
            )
        )

        if display_mismatch_active:

            detections.append(

                self.build_detection(

                    detection_type=
                        "DISPLAY_NAME_DOMAIN_MISMATCH",

                    severity=
                        "HIGH",

                    risk_score=
                        70,

                    reasons=
                        display_reasons,

                    sender_domain=
                        sender_domain,

                    indicators=[
                        "display_name",
                        "sender_domain",
                    ],
                )
            )

        # ========================================================
        # SIGNAL 3 — SUSPICIOUS URL
        # ========================================================

        url_reasons = []

        suspicious_urls = []

        for url in urls:

            reasons = (
                self.analyze_url(
                    url
                )
            )

            if reasons:

                suspicious_urls.append(
                    url
                )

                url_reasons.extend(
                    reasons
                )

        suspicious_url_active = (
            bool(
                url_reasons
            )
        )

        if suspicious_url_active:

            detection = (
                self.build_detection(

                    detection_type=
                        "SUSPICIOUS_URL",

                    severity=
                        "HIGH",

                    risk_score=
                        75,

                    reasons=
                        url_reasons,

                    sender_domain=
                        sender_domain,

                    indicators=[
                        "url"
                    ],
                )
            )

            detection[
                "suspicious_urls"
            ] = suspicious_urls

            detections.append(
                detection
            )

        # ========================================================
        # SIGNAL 4 — URGENCY LANGUAGE
        # ========================================================

        urgency_reasons = (
            self.analyze_urgency(

                subject,

                body,
            )
        )

        urgency_active = (
            bool(
                urgency_reasons
            )
        )

        if urgency_active:

            detections.append(

                self.build_detection(

                    detection_type=
                        "URGENCY_LANGUAGE",

                    severity=
                        "MEDIUM",

                    risk_score=
                        45,

                    reasons=
                        urgency_reasons,

                    sender_domain=
                        sender_domain,

                    indicators=[
                        "subject",
                        "body",
                    ],
                )
            )

        # ========================================================
        # SIGNAL 5 — SUSPICIOUS ATTACHMENT
        # ========================================================

        attachment_reasons = (
            self.analyze_attachments(
                attachments
            )
        )

        suspicious_attachment_active = (
            bool(
                attachment_reasons
            )
        )

        if suspicious_attachment_active:

            detection = (
                self.build_detection(

                    detection_type=
                        "SUSPICIOUS_ATTACHMENT",

                    severity=
                        "HIGH",

                    risk_score=
                        75,

                    reasons=
                        attachment_reasons,

                    sender_domain=
                        sender_domain,

                    indicators=[
                        "attachment"
                    ],
                )
            )

            detection[
                "attachments"
            ] = attachments

            detections.append(
                detection
            )

        # ========================================================
        # COMBINED PHISHING SCORE
        # ========================================================

        combined_score = 0

        signals = []

        if sender_domain_active:

            combined_score += 20

            signals.append(
                "SUSPICIOUS_SENDER_DOMAIN"
            )

        if display_mismatch_active:

            combined_score += 25

            signals.append(
                "DISPLAY_NAME_DOMAIN_MISMATCH"
            )

        if suspicious_url_active:

            combined_score += 25

            signals.append(
                "SUSPICIOUS_URL"
            )

        if urgency_active:

            combined_score += 15

            signals.append(
                "URGENCY_LANGUAGE"
            )

        if suspicious_attachment_active:

            combined_score += 25

            signals.append(
                "SUSPICIOUS_ATTACHMENT"
            )

        combined_score = min(
            combined_score,
            100,
        )

        # ========================================================
        # COMBINED PHISHING-LIKE BEHAVIOR
        # ========================================================

        if (
            combined_score
            >= self.phishing_score_threshold
        ):

            severity = (

                "CRITICAL"

                if combined_score >= 90

                else "HIGH"
            )

            reasons = [

                (
                    "Email contains multiple phishing-like "
                    "signals: "
                    + ", ".join(
                        signals
                    )
                )
            ]

            detection = (
                self.build_detection(

                    detection_type=
                        "PHISHING_SUSPICION",

                    severity=
                        severity,

                    risk_score=
                        combined_score,

                    reasons=
                        reasons,

                    sender_domain=
                        sender_domain,

                    indicators=
                        signals,
                )
            )

            detection[
                "signals"
            ] = signals

            detection[
                "detection_method"
            ] = (
                "MULTI_SIGNAL_PHISHING_HEURISTIC"
            )

            detection[
                "interpretation"
            ] = (
                "The email resembles a phishing attempt based "
                "on several metadata/content signals. "
                "This heuristic does not prove malicious intent."
            )

            detections.append(
                detection
            )

        return detections