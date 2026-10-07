from __future__ import annotations

from typing import Dict, Optional


class RegistryBehaviorDetector:
    """
    Rule-based registry behavior detector for SENTINEL-X validation.

    The detector consumes normalized registry-change metadata only.
    It never reads or modifies the Windows registry itself.
    """

    SUSPICIOUS_COMMAND_MARKERS = (
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
        "-enc",
        "-encodedcommand",
        "invoke-expression",
        "downloadstring",
        "http://",
        "https://",
    )

    SUSPICIOUS_PATH_MARKERS = (
        "\\appdata\\",
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
        "\\users\\public\\",
    )

    RUN_KEY_MARKERS = (
        "\\software\\microsoft\\windows\\currentversion\\run",
        "\\software\\microsoft\\windows\\currentversion\\runonce",
    )

    SERVICE_MARKER = (
        "\\system\\currentcontrolset\\services\\"
    )

    WINLOGON_MARKER = (
        "\\software\\microsoft\\windows nt\\currentversion\\winlogon"
    )

    DEFENDER_MARKERS = (
        "\\software\\microsoft\\windows defender",
        "\\software\\policies\\microsoft\\windows defender",
    )

    SECURITY_POLICY_MARKERS = (
        "\\system\\currentcontrolset\\control\\lsa",
        "\\software\\microsoft\\windows\\currentversion\\policies\\system",
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


    @classmethod
    def _full_path(
        cls,
        event: Dict,
    ) -> str:

        registry_path = cls._text(
            event.get(
                "registry_path"
            )
        )

        name = cls._text(
            event.get(
                "name"
            )
        )

        if name:

            return (
                f"{registry_path}\\{name}"
            ).lower()

        return registry_path.lower()


    @classmethod
    def _value_text(
        cls,
        event: Dict,
    ) -> str:

        candidates = [
            event.get(
                "value"
            ),
            event.get(
                "new_value"
            ),
            event.get(
                "data"
            ),
        ]

        return " ".join(
            cls._lower(
                value
            )
            for value in candidates
            if value is not None
        )


    @classmethod
    def _has_suspicious_payload(
        cls,
        event: Dict,
    ) -> bool:

        value_text = (
            cls._value_text(
                event
            )
        )

        return any(
            marker in value_text
            for marker
            in (
                cls.SUSPICIOUS_COMMAND_MARKERS
                + cls.SUSPICIOUS_PATH_MARKERS
            )
        )


    @staticmethod
    def _finding(
        detection_type: str,
        severity: str,
        risk: int,
        confidence: float,
        reason: str,
        event: Dict,
        evidence: Optional[list] = None,
    ) -> Dict:

        return {
            "engine":
                "registry_behavior",

            "detected":
                True,

            "detection_type":
                detection_type,

            "threat_type":
                detection_type,

            "severity":
                severity,

            "risk":
                risk,

            "risk_score":
                risk,

            "confidence":
                confidence,

            "reason":
                reason,

            "registry_path":
                event.get(
                    "registry_path"
                ),

            "name":
                event.get(
                    "name"
                ),

            "value":
                event.get(
                    "value",
                    event.get(
                        "new_value"
                    ),
                ),

            "action":
                event.get(
                    "action",
                    event.get(
                        "event_type"
                    ),
                ),

            "evidence":
                list(
                    evidence
                    or []
                ),
        }


    # ============================================================
    # R1 — RUN / RUNONCE PERSISTENCE
    # ============================================================

    def detect_run_persistence(
        self,
        event: Dict,
    ) -> Optional[Dict]:

        path = (
            self._full_path(
                event
            )
        )

        event_type = (
            self._lower(
                event.get(
                    "event_type",
                    event.get(
                        "action"
                    ),
                )
            )
        )

        if not any(
            marker in path
            for marker
            in self.RUN_KEY_MARKERS
        ):

            return None


        if (
            "delete"
            in event_type
        ):

            return None


        suspicious_payload = (
            self._has_suspicious_payload(
                event
            )
        )


        if suspicious_payload:

            return self._finding(
                detection_type=
                    "SUSPICIOUS_RUN_KEY_PERSISTENCE",

                severity=
                    "HIGH",

                risk=
                    78,

                confidence=
                    0.82,

                reason=(
                    "A Run/RunOnce autorun value was created or modified "
                    "with a suspicious command or user-writable path."
                ),

                event=
                    event,

                evidence=[
                    "RUN_OR_RUNONCE",
                    "SUSPICIOUS_PAYLOAD",
                ],
            )


        return self._finding(
            detection_type=
                "REGISTRY_AUTORUN_PERSISTENCE",

            severity=
                "MEDIUM",

            risk=
                55,

            confidence=
                0.60,

            reason=(
                "A Run/RunOnce autorun value was created or modified. "
                "This is persistence-capable behavior and requires context."
            ),

            event=
                event,

            evidence=[
                "RUN_OR_RUNONCE",
            ],
        )


    # ============================================================
    # R2 — SERVICE / WINLOGON PERSISTENCE
    # ============================================================

    def detect_service_or_autorun(
        self,
        event: Dict,
    ) -> Optional[Dict]:

        path = (
            self._full_path(
                event
            )
        )

        name = (
            self._lower(
                event.get(
                    "name"
                )
            )
        )

        event_type = (
            self._lower(
                event.get(
                    "event_type",
                    event.get(
                        "action"
                    ),
                )
            )
        )

        if (
            "delete"
            in event_type
        ):

            return None


        # --------------------------------------------------------
        # SERVICE IMAGEPATH / SERVICE DLL
        # --------------------------------------------------------

        if (
            self.SERVICE_MARKER
            in path
            and name
            in {
                "imagepath",
                "servicedll",
            }
        ):

            suspicious_payload = (
                self._has_suspicious_payload(
                    event
                )
            )

            return self._finding(
                detection_type=(
                    "SUSPICIOUS_SERVICE_PERSISTENCE"
                    if suspicious_payload
                    else "SERVICE_PERSISTENCE_CHANGE"
                ),

                severity=(
                    "HIGH"
                    if suspicious_payload
                    else "MEDIUM"
                ),

                risk=(
                    80
                    if suspicious_payload
                    else 58
                ),

                confidence=(
                    0.84
                    if suspicious_payload
                    else 0.62
                ),

                reason=(
                    "A Windows service execution value was changed"
                    + (
                        " to a suspicious command or user-writable path."
                        if suspicious_payload
                        else ". This is persistence-capable behavior."
                    )
                ),

                event=
                    event,

                evidence=[
                    "SERVICE_EXECUTION_VALUE",
                ]
                + (
                    [
                        "SUSPICIOUS_PAYLOAD"
                    ]
                    if suspicious_payload
                    else []
                ),
            )


        # --------------------------------------------------------
        # WINLOGON SHELL / USERINIT
        # --------------------------------------------------------

        if (
            self.WINLOGON_MARKER
            in path
            and name
            in {
                "shell",
                "userinit",
            }
        ):

            value_text = (
                self._value_text(
                    event
                )
            )

            normal_shell = (
                name == "shell"
                and value_text.strip()
                == "explorer.exe"
            )

            normal_userinit = (
                name == "userinit"
                and "userinit.exe"
                in value_text
                and "," in value_text
                and not self._has_suspicious_payload(
                    event
                )
            )


            if (
                normal_shell
                or normal_userinit
            ):

                return None


            return self._finding(
                detection_type=
                    "WINLOGON_PERSISTENCE_CHANGE",

                severity=
                    "HIGH",

                risk=
                    82,

                confidence=
                    0.86,

                reason=(
                    "A Winlogon Shell/Userinit value deviated from the "
                    "standard Windows startup configuration."
                ),

                event=
                    event,

                evidence=[
                    "WINLOGON_AUTOSTART",
                    "NONSTANDARD_VALUE",
                ],
            )


        return None


    # ============================================================
    # R3 — DEFENDER / SECURITY TAMPERING
    # ============================================================

    def detect_security_tampering(
        self,
        event: Dict,
    ) -> Optional[Dict]:

        path = (
            self._full_path(
                event
            )
        )

        name = (
            self._lower(
                event.get(
                    "name"
                )
            )
        )

        value = (
            self._lower(
                event.get(
                    "value",
                    event.get(
                        "new_value"
                    ),
                )
            )
        )

        event_type = (
            self._lower(
                event.get(
                    "event_type",
                    event.get(
                        "action"
                    ),
                )
            )
        )

        if (
            "delete"
            in event_type
        ):

            return None


        # --------------------------------------------------------
        # WINDOWS DEFENDER POLICY / PREFERENCE DISABLE SIGNALS
        # --------------------------------------------------------

        if any(
            marker in path
            for marker
            in self.DEFENDER_MARKERS
        ):

            disable_names = {
                "disableantispyware",
                "disableantivirus",
                "disablerealtimemonitoring",
                "disablebehaviormonitoring",
                "disableioavprotection",
                "disableonaccessprotection",
                "disableintrusionpreventionsystem",
            }


            if (
                name
                in disable_names
                and value
                in {
                    "1",
                    "true",
                }
            ):

                return self._finding(
                    detection_type=
                        "SECURITY_DEFENDER_TAMPERING",

                    severity=
                        "CRITICAL",

                    risk=
                        92,

                    confidence=
                        0.95,

                    reason=(
                        "A Windows Defender protection setting was changed "
                        "to a disabling value."
                    ),

                    event=
                        event,

                    evidence=[
                        "DEFENDER_CONFIGURATION",
                        "PROTECTION_DISABLED",
                    ],
                )


        # --------------------------------------------------------
        # SECURITY POLICY VALUES
        # --------------------------------------------------------

        if any(
            marker in path
            for marker
            in self.SECURITY_POLICY_MARKERS
        ):

            high_risk_names = {
                "runasppl",
                "enablelua",
                "consentpromptbehavioradmin",
            }


            if (
                name
                in high_risk_names
            ):

                return self._finding(
                    detection_type=
                        "SECURITY_POLICY_TAMPERING",

                    severity=
                        "HIGH",

                    risk=
                        76,

                    confidence=
                        0.78,

                    reason=(
                        "A security-sensitive Windows policy value was modified."
                    ),

                    event=
                        event,

                    evidence=[
                        "SECURITY_POLICY_CHANGE",
                    ],
                )


        return None


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
            self.detect_run_persistence,
            self.detect_service_or_autorun,
            self.detect_security_tampering,
        ):

            finding = (
                detector(
                    event
                )
            )


            if finding:

                findings.append(
                    finding
                )


        return findings
