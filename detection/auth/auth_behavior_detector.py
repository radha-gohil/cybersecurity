from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


class AuthBehaviorDetector:
    """
    SENTINEL-X authentication behavior detector.

    This detector does NOT perform authentication attempts.

    It analyzes authentication-event metadata supplied to it.

    Current detections:

        1. REPEATED_LOGIN_FAILURES
        2. MULTI_ACCOUNT_LOGIN_FAILURES
        3. AUTH_BRUTE_FORCE_BEHAVIOR

    These are heuristic behavioral detections and do not prove
    that a brute-force attack is occurring.
    """

    def __init__(
        self,
        failure_window_seconds: int = 60,
        repeated_failure_threshold: int = 5,
        multi_account_threshold: int = 3,
        brute_force_score_threshold: int = 70,
        alert_cooldown_seconds: int = 30,
    ):

        # ========================================================
        # SETTINGS
        # ========================================================

        self.failure_window_seconds = (
            failure_window_seconds
        )

        self.repeated_failure_threshold = (
            repeated_failure_threshold
        )

        self.multi_account_threshold = (
            multi_account_threshold
        )

        self.brute_force_score_threshold = (
            brute_force_score_threshold
        )

        self.alert_cooldown_seconds = (
            alert_cooldown_seconds
        )

        # ========================================================
        # FAILURE HISTORY
        #
        # key:
        #
        #     source_ip
        #
        # value:
        #
        #     deque[
        #         (
        #             timestamp,
        #             username,
        #         )
        #     ]
        # ========================================================

        self.failure_history = defaultdict(
            deque
        )

        # ========================================================
        # ALERT COOLDOWN
        # ========================================================

        self.last_alert_time = {}

    # ============================================================
    # TIME
    # ============================================================

    def now_timestamp(
        self,
    ) -> float:

        return datetime.now(
            timezone.utc
        ).timestamp()

    def iso_from_timestamp(
        self,
        timestamp: float,
    ) -> str:

        return datetime.fromtimestamp(
            timestamp,
            timezone.utc,
        ).isoformat()

    # ============================================================
    # NORMALIZATION
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

    def get_source_ip(
        self,
        event: Dict,
    ) -> str:

        return self.normalize_text(

            event.get(
                "source_ip"
            )

            or event.get(
                "src_ip"
            )

            or event.get(
                "remote_ip"
            )

            or event.get(
                "ip_address"
            )
        )

    def get_username(
        self,
        event: Dict,
    ) -> str:

        return self.normalize_text(

            event.get(
                "username"
            )

            or event.get(
                "user"
            )

            or event.get(
                "account"
            )

            or event.get(
                "account_name"
            )
        ).lower()

    # ============================================================
    # FAILED AUTHENTICATION CHECK
    # ============================================================

    def is_failed_auth_event(
        self,
        event: Dict,
    ) -> bool:

        event_type = self.normalize_text(
            event.get(
                "event_type"
            )
        ).lower()

        failure_event_types = {

            "login_failure",

            "failed_login",

            "auth_failure",

            "authentication_failure",

            "logon_failure",

            "failed_logon",
        }

        if (
            event_type
            in failure_event_types
        ):

            return True

        # --------------------------------------------------------
        # Some log sources represent the result separately.
        # --------------------------------------------------------

        result = self.normalize_text(

            event.get(
                "result"
            )

            or event.get(
                "status"
            )

            or event.get(
                "outcome"
            )
        ).lower()

        failure_results = {

            "failed",

            "failure",

            "denied",

            "rejected",

            "invalid_password",
        }

        return (
            result
            in failure_results
        )

    # ============================================================
    # CLEAN HISTORY
    # ============================================================

    def cleanup_history(
        self,
        history: deque,
        cutoff: float,
    ):

        while (
            history
            and history[0][0] < cutoff
        ):

            history.popleft()

    # ============================================================
    # ALERT COOLDOWN
    # ============================================================

    def should_emit_alert(
        self,
        alert_key: Tuple,
        current_time: float,
    ) -> bool:

        previous_time = (
            self.last_alert_time.get(
                alert_key
            )
        )

        if previous_time is None:

            self.last_alert_time[
                alert_key
            ] = current_time

            return True

        elapsed = (
            current_time
            - previous_time
        )

        if (
            elapsed
            >= self.alert_cooldown_seconds
        ):

            self.last_alert_time[
                alert_key
            ] = current_time

            return True

        return False

    # ============================================================
    # HEURISTIC CONFIDENCE
    # ============================================================

    def calculate_confidence(
        self,
        observed: int,
        threshold: int,
    ) -> float:

        if threshold <= 0:

            return 0.0

        score = (
            observed
            / (
                threshold
                * 2
            )
        )

        return round(
            min(
                1.0,
                max(
                    0.0,
                    score,
                ),
            ),
            4,
        )

    # ============================================================
    # MAIN ANALYSIS
    # ============================================================

    def analyze(
        self,
        event: Dict,
        current_time: Optional[float] = None,
    ) -> List[Dict]:

        detections = []

        # --------------------------------------------------------
        # IGNORE SUCCESSFUL / UNRELATED EVENTS
        # --------------------------------------------------------

        if not self.is_failed_auth_event(
            event
        ):

            return detections

        source_ip = (
            self.get_source_ip(
                event
            )
        )

        username = (
            self.get_username(
                event
            )
        )

        # --------------------------------------------------------
        # Initial detector requires both fields.
        # --------------------------------------------------------

        if (
            not source_ip
            or not username
        ):

            return detections

        if current_time is None:

            current_time = (
                self.now_timestamp()
            )

        # ========================================================
        # UPDATE SOURCE FAILURE HISTORY
        # ========================================================

        history = (
            self.failure_history[
                source_ip
            ]
        )

        history.append(
            (
                current_time,
                username,
            )
        )

        cutoff = (
            current_time
            - self.failure_window_seconds
        )

        self.cleanup_history(
            history,
            cutoff,
        )

        # ========================================================
        # CURRENT SOURCE STATE
        # ========================================================

        failure_count = len(
            history
        )

        unique_accounts = {

            account

            for _, account
            in history
        }

        unique_account_count = len(
            unique_accounts
        )

        # ========================================================
        # SIGNAL 1:
        # REPEATED LOGIN FAILURES
        # ========================================================

        repeated_failure_active = (

            failure_count
            >= self.repeated_failure_threshold
        )

        if repeated_failure_active:

            alert_key = (

                "REPEATED_LOGIN_FAILURES",

                source_ip,
            )

            if self.should_emit_alert(
                alert_key,
                current_time,
            ):

                detections.append(
                    {

                        "engine":
                            "auth_behavior",

                        "detection_type":
                            "REPEATED_LOGIN_FAILURES",

                        "severity":
                            "MEDIUM",

                        "risk":
                            60,

                        "risk_score":
                            60,

                        "confidence":
                            self.calculate_confidence(
                                failure_count,
                                self.repeated_failure_threshold,
                            ),

                        "source_ip":
                            source_ip,

                        "username":
                            username,

                        "failure_count":
                            failure_count,

                        "unique_account_count":
                            unique_account_count,

                        "time_window_seconds":
                            self.failure_window_seconds,

                        "reason":
                            (
                                f"{failure_count} failed authentication "
                                f"attempts were observed from "
                                f"{source_ip} within "
                                f"{self.failure_window_seconds} seconds"
                            ),

                        "detected_at":
                            self.iso_from_timestamp(
                                current_time
                            ),

                        "detection_method":
                            "RULE_BASED_AUTH_BEHAVIOR",

                        "interpretation":
                            (
                                "Repeated authentication failures "
                                "were observed from one source. "
                                "This may be legitimate user error "
                                "or automated password guessing."
                            ),
                    }
                )

        # ========================================================
        # SIGNAL 2:
        # MULTIPLE ACCOUNTS FROM SAME SOURCE
        # ========================================================

        multi_account_active = (

            unique_account_count
            >= self.multi_account_threshold
        )

        if multi_account_active:

            alert_key = (

                "MULTI_ACCOUNT_LOGIN_FAILURES",

                source_ip,
            )

            if self.should_emit_alert(
                alert_key,
                current_time,
            ):

                detections.append(
                    {

                        "engine":
                            "auth_behavior",

                        "detection_type":
                            "MULTI_ACCOUNT_LOGIN_FAILURES",

                        "severity":
                            "HIGH",

                        "risk":
                            70,

                        "risk_score":
                            70,

                        "confidence":
                            self.calculate_confidence(
                                unique_account_count,
                                self.multi_account_threshold,
                            ),

                        "source_ip":
                            source_ip,

                        "username":
                            username,

                        "failure_count":
                            failure_count,

                        "unique_accounts":
                            sorted(
                                unique_accounts
                            ),

                        "unique_account_count":
                            unique_account_count,

                        "time_window_seconds":
                            self.failure_window_seconds,

                        "reason":
                            (
                                f"Failed authentication attempts "
                                f"from {source_ip} targeted "
                                f"{unique_account_count} different "
                                f"accounts within "
                                f"{self.failure_window_seconds} seconds"
                            ),

                        "detected_at":
                            self.iso_from_timestamp(
                                current_time
                            ),

                        "detection_method":
                            "RULE_BASED_AUTH_BEHAVIOR",

                        "interpretation":
                            (
                                "One source generated authentication "
                                "failures against multiple accounts. "
                                "This can resemble password spraying "
                                "or brute-force behavior."
                            ),
                    }
                )

        # ========================================================
        # COMBINED AUTHENTICATION THREAT SCORE
        # ========================================================

        score = 0

        signals = []

        if repeated_failure_active:

            score += 40

            signals.append(
                "REPEATED_LOGIN_FAILURES"
            )

        if multi_account_active:

            score += 45

            signals.append(
                "MULTI_ACCOUNT_LOGIN_FAILURES"
            )

        # --------------------------------------------------------
        # Extra support for a substantially larger failure burst.
        # --------------------------------------------------------

        if (
            failure_count
            >= (
                self.repeated_failure_threshold
                * 2
            )
        ):

            score += 10

        score = min(
            score,
            100,
        )

        # ========================================================
        # COMBINED BRUTE-FORCE-LIKE BEHAVIOR
        # ========================================================

        if (
            score
            >= self.brute_force_score_threshold
        ):

            alert_key = (

                "AUTH_BRUTE_FORCE_BEHAVIOR",

                source_ip,
            )

            if self.should_emit_alert(
                alert_key,
                current_time,
            ):

                severity = (

                    "CRITICAL"

                    if score >= 90

                    else "HIGH"
                )

                detections.append(
                    {

                        "engine":
                            "auth_behavior",

                        "detection_type":
                            "AUTH_BRUTE_FORCE_BEHAVIOR",

                        "severity":
                            severity,

                        "risk":
                            score,

                        "risk_score":
                            score,

                        # ----------------------------------------
                        # Heuristic score, not a probability.
                        # ----------------------------------------

                        "confidence":
                            round(
                                score
                                / 100.0,
                                4,
                            ),

                        "source_ip":
                            source_ip,

                        "username":
                            username,

                        "failure_count":
                            failure_count,

                        "unique_accounts":
                            sorted(
                                unique_accounts
                            ),

                        "unique_account_count":
                            unique_account_count,

                        "signals":
                            signals,

                        "time_window_seconds":
                            self.failure_window_seconds,

                        "reason":
                            (
                                "Authentication failures show "
                                "multiple brute-force-like signals: "
                                + ", ".join(
                                    signals
                                )
                            ),

                        "detected_at":
                            self.iso_from_timestamp(
                                current_time
                            ),

                        "detection_method":
                            "MULTI_SIGNAL_AUTH_HEURISTIC",

                        "interpretation":
                            (
                                "Authentication activity resembles "
                                "automated credential guessing or "
                                "password spraying. This heuristic "
                                "does not prove account compromise."
                            ),
                    }
                )

        return detections