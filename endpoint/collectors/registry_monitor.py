"""Read-only Windows registry telemetry + SHADOW detection for SENTINEL-X.

Coverage:
- Run / RunOnce autoruns
- Service ImagePath / ServiceDll persistence
- Winlogon Shell / Userinit
- Defender policy / real-time protection settings
- Selected Windows security policy values

The collector never modifies the registry.

During VALIDATION mode, real registry observations remain live-only and
registry detection is forced to SHADOW so live machine activity cannot
pollute the synthetic validation store.
"""
from __future__ import annotations

import time
from typing import Dict, Optional

import winreg

from config import IS_VALIDATION_MODE

from detection.registry.registry_behavior_detector import (
    RegistryBehaviorDetector,
)

from endpoint.agent.telemetry_manager import (
    shared_telemetry_manager,
)

from endpoint.storage.database import (
    save_detection,
)

from endpoint.utils.logger import (
    get_logger,
)


logger = get_logger(__name__)


class RegistryMonitor:

    VALID_DETECTION_MODES = {
        "OFF",
        "SHADOW",
        "EMIT",
    }


    def __init__(
        self,
        polling_interval: float = 10.0,
        registry_detection_mode: str = "SHADOW",
    ):

        self.polling_interval = float(
            polling_interval
        )

        if self.polling_interval <= 0:

            raise ValueError(
                "polling_interval must be positive"
            )


        requested_mode = str(
            registry_detection_mode
        ).upper().strip()


        if requested_mode not in self.VALID_DETECTION_MODES:

            raise ValueError(
                "registry_detection_mode must be "
                "OFF, SHADOW, or EMIT"
            )


        # Real endpoint telemetry must never create synthetic SOC
        # detections while the application is in VALIDATION mode.
        if (
            IS_VALIDATION_MODE
            and requested_mode == "EMIT"
        ):

            logger.warning(
                "Registry EMIT requested during VALIDATION mode. "
                "Forcing registry detector to SHADOW."
            )

            requested_mode = "SHADOW"


        self.registry_detection_mode = (
            requested_mode
        )

        self.running = False

        self.telemetry = (
            shared_telemetry_manager
        )

        self.detector = (
            RegistryBehaviorDetector()
        )


        # One baseline per registry scope.  A temporary read failure in
        # one scope must never make values from another scope appear deleted.
        self.known_scope_values: Dict[
            str,
            Dict[str, Dict],
        ] = {}

        self.baseline_ready_scopes = set()


        self.registry_scopes = [
            # ----------------------------------------------------
            # R1 — Run / RunOnce
            # ----------------------------------------------------
            {
                "id": "hkcu_run",
                "kind": "key",
                "root": winreg.HKEY_CURRENT_USER,
                "root_name": "HKEY_CURRENT_USER",
                "path": (
                    r"Software\Microsoft\Windows"
                    r"\CurrentVersion\Run"
                ),
                "allowed_names": None,
            },
            {
                "id": "hkcu_runonce",
                "kind": "key",
                "root": winreg.HKEY_CURRENT_USER,
                "root_name": "HKEY_CURRENT_USER",
                "path": (
                    r"Software\Microsoft\Windows"
                    r"\CurrentVersion\RunOnce"
                ),
                "allowed_names": None,
            },
            {
                "id": "hklm_run",
                "kind": "key",
                "root": winreg.HKEY_LOCAL_MACHINE,
                "root_name": "HKEY_LOCAL_MACHINE",
                "path": (
                    r"Software\Microsoft\Windows"
                    r"\CurrentVersion\Run"
                ),
                "allowed_names": None,
            },
            {
                "id": "hklm_runonce",
                "kind": "key",
                "root": winreg.HKEY_LOCAL_MACHINE,
                "root_name": "HKEY_LOCAL_MACHINE",
                "path": (
                    r"Software\Microsoft\Windows"
                    r"\CurrentVersion\RunOnce"
                ),
                "allowed_names": None,
            },

            # ----------------------------------------------------
            # R2 — Services + Winlogon
            # ----------------------------------------------------
            {
                "id": "services",
                "kind": "services",
            },
            {
                "id": "winlogon",
                "kind": "key",
                "root": winreg.HKEY_LOCAL_MACHINE,
                "root_name": "HKEY_LOCAL_MACHINE",
                "path": (
                    r"Software\Microsoft\Windows NT"
                    r"\CurrentVersion\Winlogon"
                ),
                "allowed_names": {
                    "shell",
                    "userinit",
                },
            },

            # ----------------------------------------------------
            # R3 — Defender / security policy
            # ----------------------------------------------------
            {
                "id": "defender_policy",
                "kind": "key",
                "root": winreg.HKEY_LOCAL_MACHINE,
                "root_name": "HKEY_LOCAL_MACHINE",
                "path": (
                    r"Software\Policies\Microsoft"
                    r"\Windows Defender"
                ),
                "allowed_names": {
                    "disableantispyware",
                    "disableantivirus",
                },
            },
            {
                "id": "defender_realtime_policy",
                "kind": "key",
                "root": winreg.HKEY_LOCAL_MACHINE,
                "root_name": "HKEY_LOCAL_MACHINE",
                "path": (
                    r"Software\Policies\Microsoft"
                    r"\Windows Defender\Real-Time Protection"
                ),
                "allowed_names": {
                    "disablerealtimemonitoring",
                    "disablebehaviormonitoring",
                    "disableioavprotection",
                    "disableonaccessprotection",
                    "disableintrusionpreventionsystem",
                },
            },
            {
                "id": "lsa_policy",
                "kind": "key",
                "root": winreg.HKEY_LOCAL_MACHINE,
                "root_name": "HKEY_LOCAL_MACHINE",
                "path": (
                    r"SYSTEM\CurrentControlSet"
                    r"\Control\Lsa"
                ),
                "allowed_names": {
                    "runasppl",
                },
            },
            {
                "id": "uac_policy",
                "kind": "key",
                "root": winreg.HKEY_LOCAL_MACHINE,
                "root_name": "HKEY_LOCAL_MACHINE",
                "path": (
                    r"Software\Microsoft\Windows"
                    r"\CurrentVersion\Policies\System"
                ),
                "allowed_names": {
                    "enablelua",
                    "consentpromptbehavioradmin",
                },
            },
        ]


    # ============================================================
    # WINDOWS REGISTRY HELPERS
    # ============================================================

    @staticmethod
    def _is_missing_key(
        error: OSError,
    ) -> bool:

        return (
            isinstance(
                error,
                FileNotFoundError,
            )
            or getattr(
                error,
                "winerror",
                None,
            )
            == 2
        )


    @staticmethod
    def _end_of_values(
        error: OSError,
    ) -> bool:

        return (
            getattr(
                error,
                "winerror",
                None,
            )
            == 259
        )


    @staticmethod
    def _read_access_flags():

        return (
            winreg.KEY_READ
            | getattr(
                winreg,
                "KEY_WOW64_64KEY",
                0,
            )
        )


    def read_registry_key(
        self,
        root,
        root_name: str,
        path: str,
        allowed_names=None,
    ) -> Optional[dict]:

        values = {}

        normalized_allowed = (
            {
                str(
                    name
                ).lower()
                for name in allowed_names
            }
            if allowed_names
            else None
        )


        try:

            with winreg.OpenKey(
                root,
                path,
                0,
                self._read_access_flags(),
            ) as key:

                index = 0

                while True:

                    try:

                        (
                            name,
                            value,
                            value_type,
                        ) = (
                            winreg.EnumValue(
                                key,
                                index,
                            )
                        )

                    except OSError as error:

                        if self._end_of_values(
                            error
                        ):

                            break

                        logger.warning(
                            "Registry enumeration failed at %s\\%s: %s",
                            root_name,
                            path,
                            error,
                        )

                        return None


                    index += 1


                    if (
                        normalized_allowed
                        is not None
                        and str(
                            name
                        ).lower()
                        not in normalized_allowed
                    ):

                        continue


                    full_name = (
                        f"{root_name}\\{path}\\{name}"
                    )


                    values[
                        full_name
                    ] = {
                        "name":
                            name,

                        "value":
                            str(
                                value
                            ),

                        "type":
                            value_type,

                        "registry_path":
                            f"{root_name}\\{path}",
                    }


        except OSError as error:

            if self._is_missing_key(
                error
            ):

                return {}

            logger.warning(
                "Unable to read registry path %s\\%s: %s",
                root_name,
                path,
                error,
            )

            return None


        return values


    # ============================================================
    # SERVICE PERSISTENCE SNAPSHOT
    # ============================================================

    def read_services_scope(
        self,
    ) -> Optional[dict]:

        root = (
            winreg.HKEY_LOCAL_MACHINE
        )

        root_name = (
            "HKEY_LOCAL_MACHINE"
        )

        services_path = (
            r"SYSTEM\CurrentControlSet\Services"
        )

        values = {}


        try:

            with winreg.OpenKey(
                root,
                services_path,
                0,
                self._read_access_flags(),
            ) as services_key:

                index = 0

                while True:

                    try:

                        service_name = (
                            winreg.EnumKey(
                                services_key,
                                index,
                            )
                        )

                    except OSError as error:

                        if self._end_of_values(
                            error
                        ):

                            break

                        logger.warning(
                            "Service registry enumeration failed: %s",
                            error,
                        )

                        return None


                    index += 1

                    service_path = (
                        f"{services_path}\\{service_name}"
                    )


                    # --------------------------------------------
                    # ImagePath
                    # --------------------------------------------

                    try:

                        with winreg.OpenKey(
                            root,
                            service_path,
                            0,
                            self._read_access_flags(),
                        ) as service_key:

                            try:

                                (
                                    image_path,
                                    image_type,
                                ) = (
                                    winreg.QueryValueEx(
                                        service_key,
                                        "ImagePath",
                                    )
                                )

                            except OSError:

                                image_path = None
                                image_type = None


                            if image_path is not None:

                                full_name = (
                                    f"{root_name}\\"
                                    f"{service_path}\\ImagePath"
                                )

                                values[
                                    full_name
                                ] = {
                                    "name":
                                        "ImagePath",

                                    "value":
                                        str(
                                            image_path
                                        ),

                                    "type":
                                        image_type,

                                    "registry_path":
                                        f"{root_name}\\{service_path}",
                                }


                    except OSError:

                        # Some protected services may not be readable.
                        # One unreadable service must not invalidate all
                        # service telemetry.
                        pass


                    # --------------------------------------------
                    # Parameters\ServiceDll
                    # --------------------------------------------

                    parameters_path = (
                        f"{service_path}\\Parameters"
                    )

                    try:

                        with winreg.OpenKey(
                            root,
                            parameters_path,
                            0,
                            self._read_access_flags(),
                        ) as parameters_key:

                            try:

                                (
                                    service_dll,
                                    service_dll_type,
                                ) = (
                                    winreg.QueryValueEx(
                                        parameters_key,
                                        "ServiceDll",
                                    )
                                )

                            except OSError:

                                service_dll = None
                                service_dll_type = None


                            if service_dll is not None:

                                full_name = (
                                    f"{root_name}\\"
                                    f"{parameters_path}\\ServiceDll"
                                )

                                values[
                                    full_name
                                ] = {
                                    "name":
                                        "ServiceDll",

                                    "value":
                                        str(
                                            service_dll
                                        ),

                                    "type":
                                        service_dll_type,

                                    "registry_path":
                                        f"{root_name}\\{parameters_path}",
                                }


                    except OSError:

                        pass


        except OSError as error:

            if self._is_missing_key(
                error
            ):

                return {}

            logger.warning(
                "Unable to read Windows service registry root: %s",
                error,
            )

            return None


        return values


    # ============================================================
    # SCOPE COLLECTION
    # ============================================================

    def read_scope(
        self,
        scope: dict,
    ) -> Optional[dict]:

        if (
            scope.get(
                "kind"
            )
            == "services"
        ):

            return (
                self.read_services_scope()
            )


        return self.read_registry_key(
            root=
                scope[
                    "root"
                ],

            root_name=
                scope[
                    "root_name"
                ],

            path=
                scope[
                    "path"
                ],

            allowed_names=
                scope.get(
                    "allowed_names"
                ),
        )


    def get_current_snapshot(
        self,
    ) -> Optional[dict]:
        """
        Compatibility helper returning all currently readable scopes.

        A scope read failure is omitted rather than being interpreted as an
        empty scope. check_changes() preserves that scope's previous baseline.
        """

        snapshot = {}

        successful_scopes = 0


        for scope in self.registry_scopes:

            values = (
                self.read_scope(
                    scope
                )
            )


            if values is None:

                continue


            successful_scopes += 1

            snapshot.update(
                values
            )


        if successful_scopes == 0:

            return None


        return snapshot


    # ============================================================
    # DETECTOR
    # ============================================================

    def analyze_registry_change(
        self,
        registry_event: dict,
    ) -> list[dict]:

        if (
            self.registry_detection_mode
            == "OFF"
        ):

            return []


        try:

            findings = (
                self.detector.analyze(
                    registry_event
                )
            )

        except Exception:

            logger.exception(
                "Registry detector failure"
            )

            return []


        if (
            findings
            and self.registry_detection_mode
            == "SHADOW"
        ):

            for finding in findings:

                logger.warning(
                    "REGISTRY SHADOW DETECTION | "
                    "Type=%s | Severity=%s | Risk=%s | "
                    "Path=%s | Name=%s | Reason=%s",
                    finding.get(
                        "detection_type"
                    ),
                    finding.get(
                        "severity"
                    ),
                    finding.get(
                        "risk_score"
                    ),
                    registry_event.get(
                        "registry_path"
                    ),
                    registry_event.get(
                        "name"
                    ),
                    finding.get(
                        "reason"
                    ),
                )


        return findings


    # ============================================================
    # EVENT / DETECTION PERSISTENCE
    # ============================================================

    @staticmethod
    def _max_finding_severity(
        findings: list[dict],
    ) -> str:

        ranking = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        maximum = "INFO"


        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    "INFO",
                )
            ).upper()


            if (
                ranking.get(
                    severity,
                    0,
                )
                > ranking[
                    maximum
                ]
            ):

                maximum = severity


        return maximum


    def persist_registry_detection(
        self,
        event_id: str,
        finding: dict,
    ) -> bool:

        detection = dict(
            finding
        )

        detection.update(
            {
                "engine":
                    "registry_behavior",

                "detected":
                    True,

                "threat_type":
                    finding.get(
                        "threat_type",
                        finding.get(
                            "detection_type"
                        ),
                    ),

                "risk":
                    finding.get(
                        "risk_score",
                        finding.get(
                            "risk",
                            0,
                        ),
                    ),

                "risk_score":
                    finding.get(
                        "risk_score",
                        finding.get(
                            "risk",
                            0,
                        ),
                    ),
            }
        )


        try:

            save_detection(
                event_id,
                detection,
            )

            logger.warning(
                "REGISTRY DETECTION SAVED | "
                "EventID=%s | Type=%s | Severity=%s | Risk=%s",
                event_id,
                detection.get(
                    "detection_type"
                ),
                detection.get(
                    "severity"
                ),
                detection.get(
                    "risk_score"
                ),
            )

            return True


        except Exception:

            logger.exception(
                "Unable to save registry detection | "
                "EventID=%s | Type=%s",
                event_id,
                detection.get(
                    "detection_type"
                ),
            )

            return False


    def emit_registry_event(
        self,
        event_type: str,
        registry_data: dict,
        metadata: dict = None,
    ):

        normalized = dict(
            registry_data
        )

        normalized[
            "event_type"
        ] = event_type


        if metadata:

            normalized.update(
                {
                    "previous_value":
                        metadata.get(
                            "previous_value"
                        ),

                    "new_value":
                        metadata.get(
                            "new_value"
                        ),
                }
            )


        findings = (
            self.analyze_registry_change(
                normalized
            )
        )


        # Raw/live telemetry remains informational in SHADOW.
        severity = "INFO"

        if (
            self.registry_detection_mode
            == "EMIT"
            and not IS_VALIDATION_MODE
            and findings
        ):

            severity = (
                self._max_finding_severity(
                    findings
                )
            )


        event_metadata = {
            "collector":
                "RegistryMonitor",

            "attribution_status":
                "UNKNOWN",

            "registry_detection_mode":
                self.registry_detection_mode,

            "shadow_detection_count":
                (
                    len(
                        findings
                    )
                    if self.registry_detection_mode
                    == "SHADOW"
                    else 0
                ),

            **(
                metadata
                or {}
            ),
        }


        event = (
            self.telemetry.emit(
                event_type=
                    event_type,

                source=
                    "registry_monitor",

                severity=
                    severity,

                registry=
                    registry_data,

                metadata=
                    event_metadata,
            )
        )


        # EMIT is never allowed to persist live registry activity into
        # the synthetic validation store.
        if (
            self.registry_detection_mode
            == "EMIT"
            and not IS_VALIDATION_MODE
        ):

            for finding in findings:

                self.persist_registry_detection(
                    event.event_id,
                    finding,
                )


        logger.info(
            "%s | %s | %s | Findings=%s | Mode=%s",
            event_type.upper(),
            registry_data.get(
                "registry_path"
            ),
            registry_data.get(
                "name"
            ),
            len(
                findings
            ),
            self.registry_detection_mode,
        )


        return event


    # ============================================================
    # BASELINE + CHANGE DETECTION
    # ============================================================

    def build_initial_snapshot(
        self,
    ):

        logger.info(
            "Building initial registry snapshot..."
        )

        ready = 0
        unavailable = 0
        total_values = 0


        for scope in self.registry_scopes:

            scope_id = (
                scope[
                    "id"
                ]
            )

            values = (
                self.read_scope(
                    scope
                )
            )


            if values is None:

                unavailable += 1

                logger.warning(
                    "Registry scope unavailable during baseline | %s",
                    scope_id,
                )

                continue


            self.known_scope_values[
                scope_id
            ] = values

            self.baseline_ready_scopes.add(
                scope_id
            )

            ready += 1

            total_values += len(
                values
            )


        logger.info(
            "Initial registry snapshot complete | "
            "ScopesReady=%s | ScopesUnavailable=%s | Values=%s | "
            "DetectionMode=%s",
            ready,
            unavailable,
            total_values,
            self.registry_detection_mode,
        )


        return (
            ready > 0
        )


    def _compare_scope(
        self,
        scope_id: str,
        old_values: dict,
        current_values: dict,
    ):

        old_keys = set(
            old_values
        )

        current_keys = set(
            current_values
        )


        for key in sorted(
            current_keys
            - old_keys
        ):

            self.emit_registry_event(
                "registry_create",
                current_values[
                    key
                ],
            )


        for key in sorted(
            old_keys
            - current_keys
        ):

            self.emit_registry_event(
                "registry_delete",
                old_values[
                    key
                ],
            )


        for key in sorted(
            old_keys
            & current_keys
        ):

            old_data = (
                old_values[
                    key
                ]
            )

            new_data = (
                current_values[
                    key
                ]
            )


            if (
                old_data.get(
                    "value"
                ),
                old_data.get(
                    "type"
                ),
            ) != (
                new_data.get(
                    "value"
                ),
                new_data.get(
                    "type"
                ),
            ):

                self.emit_registry_event(
                    "registry_modify",
                    new_data,
                    metadata={
                        "scope":
                            scope_id,

                        "previous_value":
                            old_data.get(
                                "value"
                            ),

                        "new_value":
                            new_data.get(
                                "value"
                            ),

                        "previous_type":
                            old_data.get(
                                "type"
                            ),

                        "new_type":
                            new_data.get(
                                "type"
                            ),
                    },
                )


    def check_changes(
        self,
    ):

        successful_scopes = 0


        for scope in self.registry_scopes:

            scope_id = (
                scope[
                    "id"
                ]
            )

            current_values = (
                self.read_scope(
                    scope
                )
            )


            if current_values is None:

                logger.warning(
                    "Registry scope unavailable; preserving previous "
                    "baseline | %s",
                    scope_id,
                )

                continue


            successful_scopes += 1


            if (
                scope_id
                not in self.baseline_ready_scopes
            ):

                # First reliable observation becomes the baseline.
                # Existing values are not change events.
                self.known_scope_values[
                    scope_id
                ] = current_values

                self.baseline_ready_scopes.add(
                    scope_id
                )

                continue


            old_values = (
                self.known_scope_values.get(
                    scope_id,
                    {},
                )
            )


            self._compare_scope(
                scope_id,
                old_values,
                current_values,
            )


            self.known_scope_values[
                scope_id
            ] = current_values


        return (
            successful_scopes > 0
        )


    # ============================================================
    # LIFECYCLE
    # ============================================================

    def start(
        self,
    ):

        logger.info(
            "Starting SENTINEL-X Registry Monitor..."
        )

        logger.info(
            "Polling interval: %ss",
            self.polling_interval,
        )

        logger.info(
            "Registry detection mode: %s",
            self.registry_detection_mode,
        )

        self.running = True

        self.build_initial_snapshot()


        try:

            while self.running:

                self.check_changes()

                time.sleep(
                    self.polling_interval
                )


        except KeyboardInterrupt:

            logger.info(
                "Registry monitor interrupted"
            )


        finally:

            self.stop()


    def stop(
        self,
    ):

        self.running = False

        logger.info(
            "SENTINEL-X Registry Monitor stopped"
        )


if __name__ == "__main__":

    RegistryMonitor().start()
