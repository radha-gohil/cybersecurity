from datetime import datetime, timezone


class ProcessResponseManager:

    def __init__(
        self,
        simulation_mode=True,
    ):

        self.name = "ProcessResponseManager"

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
    # SAFE HELPERS
    # ============================================================

    def safe_int(
        self,
        value,
        default=None,
    ):

        try:

            return int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return default


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
    # VALIDATE PROCESS TARGET
    # ============================================================

    def validate_process_target(
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
                    "Process target must be a dictionary."
                ],
            }


        pid = (
            self.safe_int(
                target.get(
                    "pid"
                )
            )
        )


        name = (
            self.safe_string(
                target.get(
                    "name"
                )
            )
        )


        exe = (
            self.safe_string(
                target.get(
                    "exe"
                )
            )
        )


        threat_score = (
            self.safe_int(
                target.get(
                    "threat_score"
                ),
                0,
            )
        )


        issues = []


        if pid is None:

            issues.append(
                "Missing or invalid PID."
            )


        elif pid <= 0:

            issues.append(
                "PID must be greater than zero."
            )


        if not name:

            issues.append(
                "Missing process name."
            )


        return {

            "valid":
                len(
                    issues
                )
                == 0,

            "issues":
                issues,

            "pid":
                pid,

            "name":
                name,

            "exe":
                exe,

            "threat_score":
                threat_score,
        }


    # ============================================================
    # SIMULATE PROCESS TERMINATION
    # ============================================================

    def simulate_termination(
        self,
        incident_id: str,
        action_id: str,
        process_target: dict,
        reason: str,
    ) -> dict:

        validation = (
            self.validate_process_target(
                process_target
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

                "process_terminated":
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

            "pid":
                validation[
                    "pid"
                ],

            "process_name":
                validation[
                    "name"
                ],

            "executable":
                validation[
                    "exe"
                ],

            "threat_score":
                validation[
                    "threat_score"
                ],

            "reason":
                reason,

            "simulation_mode":
                self.simulation_mode,

            "process_terminated":
                False,

            "created_at":
                self.now_iso(),

            "message":
                (
                    "Process termination was simulated only. "
                    "No process was stopped or modified."
                ),
        }


    # ============================================================
    # PROCESS MULTIPLE TARGETS
    # ============================================================

    def process_targets(
        self,
        incident_id: str,
        action_id: str,
        processes: list,
        reason: str,
    ) -> dict:

        if not isinstance(
            processes,
            list,
        ):

            processes = []


        results = []


        for process_target in processes:

            result = (
                self.simulate_termination(

                    incident_id=
                        incident_id,

                    action_id=
                        action_id,

                    process_target=
                        process_target,

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
                    processes
                ),

            "successful_simulations":
                successful,

            "failed_simulations":
                failed,

            "results":
                results,

            "real_process_termination_performed":
                False,
        }