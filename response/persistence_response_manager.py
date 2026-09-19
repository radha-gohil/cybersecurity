from datetime import datetime, timezone


class PersistenceResponseManager:

    def __init__(
        self,
        simulation_mode=True,
    ):

        self.name = "PersistenceResponseManager"

        self.simulation_mode = bool(
            simulation_mode
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(
        self,
    ) -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # SAFE STRING
    # ============================================================

    def safe_string(
        self,
        value,
    ) -> str:

        if value is None:

            return ""

        return str(
            value
        ).strip()


    # ============================================================
    # DETECT PERSISTENCE CATEGORY
    # ============================================================

    def detect_persistence_type(
        self,
        key: str,
        value_name: str,
        value_data: str,
    ) -> str:

        text = (
            " ".join(
                [
                    self.safe_string(
                        key
                    ),

                    self.safe_string(
                        value_name
                    ),

                    self.safe_string(
                        value_data
                    ),
                ]
            )
            .lower()
        )


        if "\\runonce" in text:

            return "RUNONCE_KEY"


        if "\\run" in text:

            return "RUN_KEY"


        if "winlogon" in text:

            return "WINLOGON"


        if "services" in text:

            return "SERVICE"


        if "startup" in text:

            return "STARTUP"


        return "OTHER_REGISTRY_ACTIVITY"


    # ============================================================
    # VALIDATE PERSISTENCE TARGET
    # ============================================================

    def validate_target(
        self,
        target: dict,
    ) -> dict:

        if not isinstance(
            target,
            dict,
        ):

            return {

                "valid":
                    False,

                "issues": [
                    "Persistence target must be a dictionary."
                ],
            }


        key = (
            self.safe_string(
                target.get(
                    "key"
                )
            )
        )


        value_name = (
            self.safe_string(
                target.get(
                    "value_name"
                )
            )
        )


        value_data = (
            self.safe_string(
                target.get(
                    "value_data"
                )
            )
        )


        issues = []


        if not key:

            issues.append(
                "Missing registry key."
            )


        if not value_name:

            issues.append(
                "Missing registry value name."
            )


        persistence_type = (
            self.detect_persistence_type(
                key,
                value_name,
                value_data,
            )
        )


        return {

            "valid":
                len(
                    issues
                )
                == 0,

            "issues":
                issues,

            "key":
                key,

            "value_name":
                value_name,

            "value_data":
                value_data,

            "persistence_type":
                persistence_type,
        }


    # ============================================================
    # SIMULATE REMEDIATION
    # ============================================================

    def simulate_remediation(
        self,
        incident_id: str,
        action_id: str,
        persistence_target: dict,
        reason: str,
    ) -> dict:

        validation = (
            self.validate_target(
                persistence_target
            )
        )


        if not validation[
            "valid"
        ]:

            return {

                "success":
                    False,

                "status":
                    "INVALID_TARGET",

                "issues":
                    validation[
                        "issues"
                    ],

                "registry_modified":
                    False,

                "artifact_removed":
                    False,
            }


        return {

            "success":
                True,

            "status":
                "SIMULATED",

            "manager":
                self.name,

            "incident_id":
                incident_id,

            "action_id":
                action_id,

            "registry_key":
                validation[
                    "key"
                ],

            "value_name":
                validation[
                    "value_name"
                ],

            "value_data":
                validation[
                    "value_data"
                ],

            "persistence_type":
                validation[
                    "persistence_type"
                ],

            "reason":
                reason,

            "simulation_mode":
                self.simulation_mode,

            "registry_modified":
                False,

            "artifact_removed":
                False,

            "created_at":
                self.now_iso(),

            "message":
                (
                    "Persistence remediation was simulated only. "
                    "No registry key or startup artifact was changed or removed."
                ),
        }


    # ============================================================
    # PROCESS MULTIPLE TARGETS
    # ============================================================

    def process_targets(
        self,
        incident_id: str,
        action_id: str,
        registry_artifacts: list,
        reason: str,
    ) -> dict:

        if not isinstance(
            registry_artifacts,
            list,
        ):

            registry_artifacts = []


        results = []


        for target in registry_artifacts:

            result = (
                self.simulate_remediation(

                    incident_id=
                        incident_id,

                    action_id=
                        action_id,

                    persistence_target=
                        target,

                    reason=
                        reason,
                )
            )


            results.append(
                result
            )


        successful = sum(

            1
            for item in results

            if item.get(
                "success",
                False,
            )
        )


        failed = (
            len(
                results
            )
            - successful
        )


        return {

            "manager":
                self.name,

            "incident_id":
                incident_id,

            "action_id":
                action_id,

            "simulation_mode":
                self.simulation_mode,

            "target_count":
                len(
                    registry_artifacts
                ),

            "successful_simulations":
                successful,

            "failed_simulations":
                failed,

            "results":
                results,

            "real_registry_modification_performed":
                False,
        }