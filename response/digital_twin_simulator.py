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
    # SAFE HELPERS
    # ============================================================

    def safe_dict(
        self,
        value,
    ) -> dict:

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )


    def safe_list(
        self,
        value,
    ) -> list:

        return (
            value
            if isinstance(
                value,
                list,
            )
            else []
        )


    def safe_int(
        self,
        value,
        default=None,
    ):

        try:

            if (
                value is None
                or isinstance(
                    value,
                    bool,
                )
            ):

                return default


            return int(
                value
            )

        except (
            TypeError,
            ValueError,
            OverflowError,
        ):

            return default


    def grouped_targets(
        self,
        target,
        key,
    ) -> list:

        target = self.safe_dict(
            target
        )


        grouped = target.get(
            key
        )


        if isinstance(
            grouped,
            list,
        ):

            return [
                deepcopy(
                    item
                )

                for item
                in grouped

                if isinstance(
                    item,
                    dict,
                )
            ]


        if target:

            return [
                deepcopy(
                    target
                )
            ]


        return []


    def aggregate_results(
        self,
        results,
    ) -> dict:

        results = [
            result

            for result
            in self.safe_list(
                results
            )

            if isinstance(
                result,
                dict,
            )
        ]


        success_count = sum(

            1

            for result
            in results

            if result.get(
                "success"
            ) is True
        )


        failure_count = (
            len(
                results
            )
            - success_count
        )


        if (
            success_count > 0
            and failure_count == 0
        ):

            status = "SIMULATED"

        elif (
            success_count > 0
            and failure_count > 0
        ):

            status = "PARTIAL_SIMULATION"

        elif results:

            status = str(
                results[
                    0
                ].get(
                    "status",
                    "TARGET_NOT_FOUND",
                )
            )

        else:

            status = "TARGET_NOT_FOUND"


        return {
            "success":
                (
                    success_count > 0
                    and failure_count == 0
                ),

            "partial_success":
                (
                    success_count > 0
                    and failure_count > 0
                ),

            "status":
                status,

            "target_count":
                len(
                    results
                ),

            "successful_simulations":
                success_count,

            "failed_simulations":
                failure_count,

            "results":
                results,

            "real_endpoint_modified":
                False,
        }


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

        targets = self.grouped_targets(
            target,
            "processes",
        )


        results = []

        seen_pids = set()


        for item in targets:

            pid = self.safe_int(
                item.get(
                    "pid"
                )
            )


            if (
                pid is None
                or pid <= 0
            ):

                results.append(
                    {
                        "success":
                            False,

                        "status":
                            "INVALID_TARGET",

                        "reason":
                            "Missing or invalid PID.",
                    }
                )

                continue


            if pid in seen_pids:
                continue


            seen_pids.add(
                pid
            )


            matching_processes = []


            for process in twin.processes:

                process_pid = self.safe_int(
                    process.get(
                        "pid"
                    )
                )


                if process_pid == pid:

                    matching_processes.append(
                        process
                    )


            if not matching_processes:

                results.append(
                    {
                        "success":
                            False,

                        "status":
                            "TARGET_NOT_FOUND",

                        "pid":
                            pid,
                    }
                )

                continue


            # A process may appear more than once in enriched
            # evidence. Mark every representation of the same PID
            # so duplicate evidence cannot keep virtual risk alive.
            for process in matching_processes:

                process[
                    "terminated_in_twin"
                ] = True

                process[
                    "twin_status"
                ] = "TERMINATED"


            # Associated network connections become inactive.
            for connection in (
                twin.network_connections
            ):

                if (
                    self.safe_int(
                        connection.get(
                            "pid"
                        )
                    )
                    == pid
                ):

                    connection[
                        "blocked_in_twin"
                    ] = True

                    connection[
                        "twin_status"
                    ] = (
                        "DISCONNECTED_AFTER_"
                        "PROCESS_TERMINATION"
                    )


            representative = (
                matching_processes[
                    0
                ]
            )


            twin.add_history(

                "TERMINATE_PROCESS",

                {
                    "pid":
                        pid,

                    "name":
                        (
                            item.get(
                                "name"
                            )
                            or representative.get(
                                "name"
                            )
                        ),

                    "threat_type":
                        item.get(
                            "threat_type"
                        ),
                },
            )


            results.append(
                {
                    "success":
                        True,

                    "status":
                        "SIMULATED",

                    "pid":
                        pid,

                    "process_name":
                        (
                            item.get(
                                "name"
                            )
                            or representative.get(
                                "name"
                            )
                        ),

                    "process_terminated_in_twin":
                        True,

                    "matching_twin_records":
                        len(
                            matching_processes
                        ),

                    "real_process_terminated":
                        False,
                }
            )


        return self.aggregate_results(
            results
        )


    # ============================================================
    # SIMULATE FILE QUARANTINE
    # ============================================================

    def quarantine_file(
        self,
        twin,
        target,
    ) -> dict:

        targets = self.grouped_targets(
            target,
            "files",
        )


        results = []

        seen = set()


        for item in targets:

            path = item.get(
                "path"
            )

            sha256 = item.get(
                "sha256"
            )


            signature = (
                str(
                    path
                    or ""
                ).lower(),

                str(
                    sha256
                    or ""
                ).lower(),
            )


            if signature in seen:
                continue


            seen.add(
                signature
            )


            file_item = twin.find_file(
                path=path,
                sha256=sha256,
            )


            if file_item is None:

                results.append(
                    {
                        "success":
                            False,

                        "status":
                            "TARGET_NOT_FOUND",

                        "path":
                            path,

                        "sha256":
                            sha256,
                    }
                )

                continue


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


            results.append(
                {
                    "success":
                        True,

                    "status":
                        "SIMULATED",

                    "path":
                        file_item.get(
                            "path"
                        ),

                    "sha256":
                        file_item.get(
                            "sha256"
                        ),

                    "file_quarantined_in_twin":
                        True,

                    "real_file_modified":
                        False,
                }
            )


        return self.aggregate_results(
            results
        )


    # ============================================================
    # SIMULATE NETWORK BLOCK
    # ============================================================

    def block_network(
        self,
        twin,
        target,
    ) -> dict:

        targets = self.grouped_targets(
            target,
            "connections",
        )


        results = []

        seen = set()


        for item in targets:

            remote_ip = item.get(
                "remote_ip"
            )

            remote_port = item.get(
                "remote_port"
            )


            signature = (
                str(
                    remote_ip
                    or ""
                ),

                str(
                    remote_port
                    or ""
                ),
            )


            if signature in seen:
                continue


            seen.add(
                signature
            )


            connection = (
                twin.find_network_connection(
                    remote_ip,
                    remote_port,
                )
            )


            if connection is None:

                results.append(
                    {
                        "success":
                            False,

                        "status":
                            "TARGET_NOT_FOUND",

                        "remote_ip":
                            remote_ip,

                        "remote_port":
                            remote_port,
                    }
                )

                continue


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


            results.append(
                {
                    "success":
                        True,

                    "status":
                        "SIMULATED",

                    "remote_ip":
                        connection.get(
                            "remote_ip"
                        ),

                    "remote_port":
                        connection.get(
                            "remote_port"
                        ),

                    "network_blocked_in_twin":
                        True,

                    "real_network_modified":
                        False,
                }
            )


        return self.aggregate_results(
            results
        )


    # ============================================================
    # SIMULATE PERSISTENCE REMOVAL
    # ============================================================

    def remediate_persistence(
        self,
        twin,
        target,
    ) -> dict:

        targets = self.grouped_targets(
            target,
            "registry_artifacts",
        )


        results = []

        seen = set()


        for item in targets:

            key = item.get(
                "key"
            )

            value_name = item.get(
                "value_name"
            )


            signature = (
                str(
                    key
                    or ""
                ).lower(),

                str(
                    value_name
                    or ""
                ).lower(),
            )


            if signature in seen:
                continue


            seen.add(
                signature
            )


            artifact = (
                twin.find_persistence_artifact(
                    key,
                    value_name,
                )
            )


            if artifact is None:

                results.append(
                    {
                        "success":
                            False,

                        "status":
                            "TARGET_NOT_FOUND",

                        "key":
                            key,

                        "value_name":
                            value_name,
                    }
                )

                continue


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


            results.append(
                {
                    "success":
                        True,

                    "status":
                        "SIMULATED",

                    "registry_key":
                        artifact.get(
                            "key"
                        ),

                    "value_name":
                        artifact.get(
                            "value_name"
                        ),

                    "persistence_removed_in_twin":
                        True,

                    "real_registry_modified":
                        False,
                }
            )


        return self.aggregate_results(
            results
        )


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
            ] = (
                "BLOCKED_BY_ENDPOINT_ISOLATION"
            )


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

            "real_endpoint_modified":
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

            "real_endpoint_modified":
                False,
        }
