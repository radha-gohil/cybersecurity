from copy import deepcopy

from response.endpoint_digital_twin import (
    EndpointDigitalTwin,
)


class DigitalTwinSimulator:

    def __init__(
        self,
    ):

        self.name = "DigitalTwinSimulator"


    # ============================================================
    # VALIDATE TWIN
    # ============================================================

    def validate_twin(
        self,
        twin,
    ):

        if not isinstance(
            twin,
            EndpointDigitalTwin,
        ):

            raise TypeError(
                "twin must be an EndpointDigitalTwin."
            )


    # ============================================================
    # SIMULATE PROCESS TERMINATION
    # ============================================================

    def terminate_process(
        self,
        twin,
        target,
    ) -> dict:

        pid = (
            target.get(
                "pid"
            )
            if isinstance(
                target,
                dict,
            )
            else None
        )


        process = (
            twin.find_process(
                pid
            )
        )


        if process is None:

            return {
                "success":
                    False,

                "status":
                    "TARGET_NOT_FOUND",
            }


        process[
            "terminated_in_twin"
        ] = True

        process[
            "twin_status"
        ] = "TERMINATED"


        # --------------------------------------------------------
        # Associated network connections become inactive
        # --------------------------------------------------------

        for connection in (
            twin.network_connections
        ):

            if (
                connection.get(
                    "pid"
                )
                == process.get(
                    "pid"
                )
            ):

                connection[
                    "blocked_in_twin"
                ] = True

                connection[
                    "twin_status"
                ] = "DISCONNECTED_AFTER_PROCESS_TERMINATION"


        twin.add_history(

            "TERMINATE_PROCESS",

            {
                "pid":
                    process.get(
                        "pid"
                    ),

                "name":
                    process.get(
                        "name"
                    ),
            },
        )


        return {
            "success":
                True,

            "status":
                "SIMULATED",

            "pid":
                process.get(
                    "pid"
                ),

            "process_terminated_in_twin":
                True,

            "real_process_terminated":
                False,
        }


    # ============================================================
    # SIMULATE FILE QUARANTINE
    # ============================================================

    def quarantine_file(
        self,
        twin,
        target,
    ) -> dict:

        path = (
            target.get(
                "path"
            )
            if isinstance(
                target,
                dict,
            )
            else None
        )


        sha256 = (
            target.get(
                "sha256"
            )
            if isinstance(
                target,
                dict,
            )
            else None
        )


        file_item = (
            twin.find_file(
                path=path,
                sha256=sha256,
            )
        )


        if file_item is None:

            return {
                "success":
                    False,

                "status":
                    "TARGET_NOT_FOUND",
            }


        file_item[
            "quarantined_in_twin"
        ] = True

        file_item[
            "twin_status"
        ] = "QUARANTINED"


        twin.add_history(

            "QUARANTINE_FILE",

            {
                "path":
                    file_item.get(
                        "path"
                    ),

                "sha256":
                    file_item.get(
                        "sha256"
                    ),
            },
        )


        return {
            "success":
                True,

            "status":
                "SIMULATED",

            "path":
                file_item.get(
                    "path"
                ),

            "file_quarantined_in_twin":
                True,

            "real_file_modified":
                False,
        }


    # ============================================================
    # SIMULATE NETWORK BLOCK
    # ============================================================

    def block_network(
        self,
        twin,
        target,
    ) -> dict:

        remote_ip = (
            target.get(
                "remote_ip"
            )
            if isinstance(
                target,
                dict,
            )
            else None
        )


        remote_port = (
            target.get(
                "remote_port"
            )
            if isinstance(
                target,
                dict,
            )
            else None
        )


        connection = (
            twin.find_network_connection(
                remote_ip,
                remote_port,
            )
        )


        if connection is None:

            return {
                "success":
                    False,

                "status":
                    "TARGET_NOT_FOUND",
            }


        connection[
            "blocked_in_twin"
        ] = True

        connection[
            "twin_status"
        ] = "BLOCKED"


        twin.add_history(

            "BLOCK_NETWORK",

            {
                "remote_ip":
                    connection.get(
                        "remote_ip"
                    ),

                "remote_port":
                    connection.get(
                        "remote_port"
                    ),
            },
        )


        return {
            "success":
                True,

            "status":
                "SIMULATED",

            "remote_ip":
                connection.get(
                    "remote_ip"
                ),

            "network_blocked_in_twin":
                True,

            "real_network_modified":
                False,
        }


    # ============================================================
    # SIMULATE PERSISTENCE REMOVAL
    # ============================================================

    def remediate_persistence(
        self,
        twin,
        target,
    ) -> dict:

        key = (
            target.get(
                "key"
            )
            if isinstance(
                target,
                dict,
            )
            else None
        )


        value_name = (
            target.get(
                "value_name"
            )
            if isinstance(
                target,
                dict,
            )
            else None
        )


        artifact = (
            twin.find_persistence_artifact(
                key,
                value_name,
            )
        )


        if artifact is None:

            return {
                "success":
                    False,

                "status":
                    "TARGET_NOT_FOUND",
            }


        artifact[
            "removed_in_twin"
        ] = True

        artifact[
            "twin_status"
        ] = "REMOVED"


        twin.add_history(

            "REMEDIATE_PERSISTENCE",

            {
                "key":
                    artifact.get(
                        "key"
                    ),

                "value_name":
                    artifact.get(
                        "value_name"
                    ),
            },
        )


        return {
            "success":
                True,

            "status":
                "SIMULATED",

            "registry_key":
                artifact.get(
                    "key"
                ),

            "persistence_removed_in_twin":
                True,

            "real_registry_modified":
                False,
        }


    # ============================================================
    # SIMULATE ENDPOINT ISOLATION
    # ============================================================

    def isolate_endpoint(
        self,
        twin,
    ) -> dict:

        twin.endpoint_state[
            "isolated"
        ] = True

        twin.endpoint_state[
            "management_connectivity_preserved"
        ] = True


        for connection in (
            twin.network_connections
        ):

            connection[
                "blocked_in_twin"
            ] = True

            connection[
                "twin_status"
            ] = "BLOCKED_BY_ENDPOINT_ISOLATION"


        twin.add_history(

            "ISOLATE_ENDPOINT",

            {
                "management_connectivity_preserved":
                    True,
            },
        )


        return {
            "success":
                True,

            "status":
                "SIMULATED",

            "endpoint_isolated_in_twin":
                True,

            "real_endpoint_isolated":
                False,
        }


    # ============================================================
    # SIMULATE RESPONSE ACTION
    # ============================================================

    def simulate_action(
        self,
        twin,
        action_type: str,
        target: dict = None,
    ) -> dict:

        self.validate_twin(
            twin
        )


        action_type = str(
            action_type
        ).upper()


        target = (
            deepcopy(
                target
            )
            if isinstance(
                target,
                dict,
            )
            else {}
        )


        if action_type == "TERMINATE_PROCESS":

            return self.terminate_process(
                twin,
                target,
            )


        if action_type == "QUARANTINE_FILE":

            return self.quarantine_file(
                twin,
                target,
            )


        if action_type == "BLOCK_NETWORK":

            return self.block_network(
                twin,
                target,
            )


        if action_type == "REMEDIATE_PERSISTENCE":

            return self.remediate_persistence(
                twin,
                target,
            )


        if action_type == "ISOLATE_ENDPOINT":

            return self.isolate_endpoint(
                twin
            )


        return {
            "success":
                False,

            "status":
                "UNSUPPORTED_ACTION",

            "action_type":
                action_type,
        }