from __future__ import annotations

from typing import Dict, Optional


class SystemAbuseDetector:
    """
    Deterministic SENTINEL-X detector for privilege/persistence/system-abuse
    evidence from normalized Windows security-event metadata.

    This detector consumes event metadata only. It never changes users,
    groups, tasks, audit policy, privileges, or event logs.
    """

    SYSTEM_ACCOUNTS = {
        "system",
        "local service",
        "network service",
        "anonymous logon",
    }

    SENSITIVE_PRIVILEGES = {
        "sedebugprivilege",
        "setcbprivilege",
        "seimpersonateprivilege",
        "setakeownershipprivilege",
        "seloaddriverprivilege",
        "serestoreprivilege",
        "sebackupprivilege",
    }

    PRIVILEGED_GROUP_MARKERS = (
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "account operators",
        "backup operators",
        "server operators",
    )

    SUSPICIOUS_TASK_MARKERS = (
        "powershell",
        "pwsh",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "-encodedcommand",
        "-enc ",
        "invoke-expression",
        "downloadstring",
        "http://",
        "https://",
        "\\appdata\\",
        "\\temp\\",
        "\\users\\public\\",
        "\\downloads\\",
    )


    @staticmethod
    def _text(value) -> str:
        return str(
            value
            if value is not None
            else ""
        ).strip()


    @classmethod
    def _lower(cls, value) -> str:
        return cls._text(
            value
        ).lower()


    @staticmethod
    def _finding(
        detection_type: str,
        severity: str,
        risk_score: int,
        confidence: float,
        reason: str,
        event: Dict,
        evidence=None,
    ) -> Dict:

        return {
            "engine":
                "system_abuse",

            "detected":
                True,

            "detection_type":
                detection_type,

            "threat_type":
                detection_type,

            "severity":
                severity,

            "risk":
                risk_score,

            "risk_score":
                risk_score,

            "confidence":
                confidence,

            "reason":
                reason,

            "windows_event_id":
                event.get(
                    "windows_event_id",
                    event.get(
                        "event_id"
                    ),
                ),

            "username":
                event.get(
                    "username",
                    event.get(
                        "subject_username"
                    ),
                ),

            "evidence":
                list(
                    evidence
                    or []
                ),
        }


    # ============================================================
    # S1-A — SPECIAL PRIVILEGE ASSIGNMENT (4672)
    # ============================================================

    def detect_special_privileges(
        self,
        event: Dict,
    ) -> Optional[Dict]:

        event_id = event.get(
            "windows_event_id",
            event.get(
                "event_id"
            ),
        )

        if str(
            event_id
        ) != "4672":

            return None


        username = self._lower(
            event.get(
                "username",
                event.get(
                    "subject_username"
                ),
            )
        )


        if (
            not username
            or username
            in self.SYSTEM_ACCOUNTS
        ):

            return None


        raw_privileges = (
            event.get(
                "privileges"
            )
            or event.get(
                "privilege_list"
            )
            or []
        )


        if isinstance(
            raw_privileges,
            str,
        ):

            privilege_items = (
                raw_privileges
                .replace(
                    ",",
                    " ",
                )
                .split()
            )

        elif isinstance(
            raw_privileges,
            (
                list,
                tuple,
                set,
            ),
        ):

            privilege_items = list(
                raw_privileges
            )

        else:

            privilege_items = []


        normalized = {
            self._lower(
                item
            )
            for item
            in privilege_items
            if self._text(
                item
            )
        }


        sensitive = sorted(
            normalized
            & self.SENSITIVE_PRIVILEGES
        )


        if not sensitive:

            return None


        return self._finding(
            detection_type=
                "SENSITIVE_PRIVILEGE_ASSIGNMENT",

            severity=
                "MEDIUM",

            risk_score=
                62,

            confidence=
                0.68,

            reason=(
                "A non-system account received one or more "
                "security-sensitive Windows privileges."
            ),

            event=
                event,

            evidence=[
                "WINDOWS_EVENT_4672",
                *sensitive,
            ],
        )


    # ============================================================
    # S1-B — LOCAL ACCOUNT CREATION (4720)
    # ============================================================

    def detect_account_creation(
        self,
        event: Dict,
    ) -> Optional[Dict]:

        event_id = event.get(
            "windows_event_id",
            event.get(
                "event_id"
            ),
        )

        if str(
            event_id
        ) != "4720":

            return None


        target_user = self._text(
            event.get(
                "target_username",
                event.get(
                    "account_name"
                ),
            )
        )


        if not target_user:

            return None


        return self._finding(
            detection_type=
                "LOCAL_ACCOUNT_CREATED",

            severity=
                "MEDIUM",

            risk_score=
                58,

            confidence=
                0.72,

            reason=(
                "A Windows user account was created. "
                "Account creation is persistence-capable activity "
                "and requires administrative context."
            ),

            event=
                event,

            evidence=[
                "WINDOWS_EVENT_4720",
                f"TARGET_ACCOUNT:{target_user}",
            ],
        )


    # ============================================================
    # S1-C — PRIVILEGED GROUP MEMBERSHIP (4728 / 4732)
    # ============================================================

    def detect_privileged_group_change(
        self,
        event: Dict,
    ) -> Optional[Dict]:

        event_id = str(
            event.get(
                "windows_event_id",
                event.get(
                    "event_id"
                ),
            )
        )


        if event_id not in {
            "4728",
            "4732",
        }:

            return None


        group_name = self._lower(
            event.get(
                "group_name",
                event.get(
                    "target_group"
                ),
            )
        )


        member_name = self._text(
            event.get(
                "member_name",
                event.get(
                    "target_username"
                ),
            )
        )


        if (
            not group_name
            or not member_name
        ):

            return None


        privileged = any(
            marker in group_name
            for marker
            in self.PRIVILEGED_GROUP_MARKERS
        )


        if not privileged:

            return None


        return self._finding(
            detection_type=
                "PRIVILEGED_GROUP_MEMBERSHIP_CHANGE",

            severity=
                "HIGH",

            risk_score=
                86,

            confidence=
                0.90,

            reason=(
                "An account was added to a privileged Windows group."
            ),

            event=
                event,

            evidence=[
                f"WINDOWS_EVENT_{event_id}",
                f"GROUP:{group_name}",
                f"MEMBER:{member_name}",
            ],
        )


    # ============================================================
    # S1-D — SCHEDULED TASK CREATION (4698)
    # ============================================================

    def detect_scheduled_task(
        self,
        event: Dict,
    ) -> Optional[Dict]:

        event_id = str(
            event.get(
                "windows_event_id",
                event.get(
                    "event_id"
                ),
            )
        )


        if event_id != "4698":

            return None


        task_name = self._text(
            event.get(
                "task_name"
            )
        )


        task_content = " ".join(
            self._lower(
                value
            )
            for value
            in [
                event.get(
                    "task_command"
                ),
                event.get(
                    "task_content"
                ),
                event.get(
                    "command"
                ),
            ]
            if value is not None
        )


        if (
            not task_name
            and not task_content
        ):

            return None


        suspicious = any(
            marker in task_content
            for marker
            in self.SUSPICIOUS_TASK_MARKERS
        )


        return self._finding(
            detection_type=(
                "SUSPICIOUS_SCHEDULED_TASK_PERSISTENCE"
                if suspicious
                else "SCHEDULED_TASK_PERSISTENCE"
            ),

            severity=(
                "HIGH"
                if suspicious
                else "MEDIUM"
            ),

            risk_score=(
                84
                if suspicious
                else 60
            ),

            confidence=(
                0.88
                if suspicious
                else 0.67
            ),

            reason=(
                "A scheduled task was created"
                + (
                    " with a suspicious command or user-writable path."
                    if suspicious
                    else ". Scheduled task creation is persistence-capable activity."
                )
            ),

            event=
                event,

            evidence=[
                "WINDOWS_EVENT_4698",
                f"TASK:{task_name or 'UNKNOWN'}",
            ]
            + (
                [
                    "SUSPICIOUS_TASK_CONTENT"
                ]
                if suspicious
                else []
            ),
        )


    # ============================================================
    # S1-E — SECURITY LOG CLEARED (1102)
    # ============================================================

    def detect_security_log_clear(
        self,
        event: Dict,
    ) -> Optional[Dict]:

        event_id = str(
            event.get(
                "windows_event_id",
                event.get(
                    "event_id"
                ),
            )
        )


        if event_id != "1102":

            return None


        return self._finding(
            detection_type=
                "SECURITY_LOG_CLEARED",

            severity=
                "CRITICAL",

            risk_score=
                96,

            confidence=
                0.97,

            reason=(
                "The Windows Security audit log was cleared."
            ),

            event=
                event,

            evidence=[
                "WINDOWS_EVENT_1102",
                "AUDIT_EVIDENCE_REMOVAL",
            ],
        )


    # ============================================================
    # S1-F — AUDIT POLICY CHANGE (4719)
    # ============================================================

    def detect_audit_policy_change(
        self,
        event: Dict,
    ) -> Optional[Dict]:

        event_id = str(
            event.get(
                "windows_event_id",
                event.get(
                    "event_id"
                ),
            )
        )


        if event_id != "4719":

            return None


        return self._finding(
            detection_type=
                "AUDIT_POLICY_CHANGE",

            severity=
                "HIGH",

            risk_score=
                80,

            confidence=
                0.82,

            reason=(
                "Windows system audit policy was changed."
            ),

            event=
                event,

            evidence=[
                "WINDOWS_EVENT_4719",
                "AUDIT_CONFIGURATION_CHANGE",
            ],
        )


    # ============================================================
    # MAIN
    # ============================================================

    def analyze(
        self,
        event: Dict,
    ) -> list[Dict]:

        if not isinstance(
            event,
            dict,
        ):

            return []


        findings = []


        for detector in (
            self.detect_special_privileges,
            self.detect_account_creation,
            self.detect_privileged_group_change,
            self.detect_scheduled_task,
            self.detect_security_log_clear,
            self.detect_audit_policy_change,
        ):

            finding = detector(
                event
            )


            if finding:

                findings.append(
                    finding
                )


        return findings
