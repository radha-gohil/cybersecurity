from datetime import datetime, timezone
import ipaddress


class NetworkResponseManager:

    def __init__(
        self,
        simulation_mode=True,
    ):

        self.name = "NetworkResponseManager"
        self.simulation_mode = bool(
            simulation_mode
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(self) -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_int(
        self,
        value,
        default=None,
    ):

        try:
            return int(value)

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

        return str(value).strip()


    # ============================================================
    # VALIDATE IP
    # ============================================================

    def is_valid_ip(
        self,
        value,
    ) -> bool:

        try:
            ipaddress.ip_address(
                value
            )
            return True

        except ValueError:
            return False


    # ============================================================
    # VALIDATE NETWORK TARGET
    # ============================================================

    def validate_network_target(
        self,
        target: dict,
    ) -> dict:

        if not isinstance(
            target,
            dict,
        ):

            return {
                "valid": False,
                "issues": [
                    "Network target must be a dictionary."
                ],
            }


        remote_ip = (
            self.safe_string(
                target.get(
                    "remote_ip"
                )
            )
        )


        remote_port = (
            self.safe_int(
                target.get(
                    "remote_port"
                )
            )
        )


        pid = (
            self.safe_int(
                target.get(
                    "pid"
                )
            )
        )


        process_name = (
            self.safe_string(
                target.get(
                    "process_name"
                )
            )
        )


        issues = []


        if not remote_ip:

            issues.append(
                "Missing remote IP."
            )

        elif not self.is_valid_ip(
            remote_ip
        ):

            issues.append(
                "Invalid remote IP."
            )


        if remote_port is not None:

            if not (
                1
                <= remote_port
                <= 65535
            ):

                issues.append(
                    "Remote port must be between 1 and 65535."
                )


        return {
            "valid":
                len(
                    issues
                )
                == 0,

            "issues":
                issues,

            "remote_ip":
                remote_ip,

            "remote_port":
                remote_port,

            "pid":
                pid,

            "process_name":
                process_name,
        }


    # ============================================================
    # SIMULATE NETWORK BLOCK
    # ============================================================

    def simulate_block(
        self,
        incident_id: str,
        action_id: str,
        network_target: dict,
        reason: str,
    ) -> dict:

        validation = (
            self.validate_network_target(
                network_target
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

                "network_block_performed":
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

            "remote_ip":
                validation[
                    "remote_ip"
                ],

            "remote_port":
                validation[
                    "remote_port"
                ],

            "pid":
                validation[
                    "pid"
                ],

            "process_name":
                validation[
                    "process_name"
                ],

            "reason":
                reason,

            "simulation_mode":
                self.simulation_mode,

            "network_block_performed":
                False,

            "firewall_modified":
                False,

            "connection_terminated":
                False,

            "created_at":
                self.now_iso(),

            "message":
                (
                    "Network block was simulated only. "
                    "No firewall rule was created and no "
                    "connection was terminated."
                ),
        }


    # ============================================================
    # PROCESS MULTIPLE NETWORK TARGETS
    # ============================================================

    def process_targets(
        self,
        incident_id: str,
        action_id: str,
        connections: list,
        reason: str,
    ) -> dict:

        if not isinstance(
            connections,
            list,
        ):

            connections = []


        results = []


        for network_target in connections:

            result = (
                self.simulate_block(

                    incident_id=
                        incident_id,

                    action_id=
                        action_id,

                    network_target=
                        network_target,

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
                    connections
                ),

            "successful_simulations":
                successful,

            "failed_simulations":
                failed,

            "results":
                results,

            "real_network_block_performed":
                False,
        }