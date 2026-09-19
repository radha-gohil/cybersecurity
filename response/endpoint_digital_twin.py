from copy import deepcopy
from datetime import datetime, timezone
import uuid


class EndpointDigitalTwin:

    def __init__(
        self,
        incident_id: str,
        initial_risk_score: int = 0,
        initial_risk_level: str = "INFO",
    ):

        self.twin_id = (
            "TWIN-"
            + uuid.uuid4().hex[
                :12
            ].upper()
        )

        self.incident_id = (
            incident_id
        )

        self.created_at = (
            self.now_iso()
        )

        self.updated_at = (
            self.created_at
        )

        self.initial_risk_score = (
            self.normalize_score(
                initial_risk_score
            )
        )

        self.initial_risk_level = str(
            initial_risk_level
        ).upper()

        self.current_risk_score = (
            self.initial_risk_score
        )

        self.current_risk_level = (
            self.initial_risk_level
        )

        # ========================================================
        # VIRTUAL ENDPOINT STATE
        # ========================================================

        self.processes = []

        self.files = []

        self.network_connections = []

        self.persistence_artifacts = []

        self.endpoint_state = {
            "isolated": False,
            "management_connectivity_preserved": True,
        }

        # ========================================================
        # DIGITAL TWIN HISTORY
        # ========================================================

        self.simulation_history = []


    # ============================================================
    # TIME
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
    # NORMALIZE SCORE
    # ============================================================

    def normalize_score(
        self,
        value,
    ) -> int:

        try:

            value = int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            value = 0


        return max(
            0,
            min(
                value,
                100,
            ),
        )


    # ============================================================
    # RISK LEVEL
    # ============================================================

    def score_to_level(
        self,
        score,
    ) -> str:

        score = (
            self.normalize_score(
                score
            )
        )


        if score >= 80:

            return "CRITICAL"


        if score >= 60:

            return "HIGH"


        if score >= 35:

            return "MEDIUM"


        if score >= 15:

            return "LOW"


        return "INFO"


    # ============================================================
    # LOAD FROM INCIDENT EVIDENCE
    # ============================================================

    def load_evidence(
        self,
        evidence: dict,
    ):

        if not isinstance(
            evidence,
            dict,
        ):

            evidence = {}


        # --------------------------------------------------------
        # PROCESSES
        # --------------------------------------------------------

        self.processes = deepcopy(
            evidence.get(
                "processes",
                [],
            )
            if isinstance(
                evidence.get(
                    "processes"
                ),
                list,
            )
            else []
        )


        for process in self.processes:

            process.setdefault(
                "twin_status",
                "RUNNING",
            )

            process.setdefault(
                "terminated_in_twin",
                False,
            )


        # --------------------------------------------------------
        # FILES
        # --------------------------------------------------------

        self.files = deepcopy(
            evidence.get(
                "files",
                [],
            )
            if isinstance(
                evidence.get(
                    "files"
                ),
                list,
            )
            else []
        )


        for file_item in self.files:

            file_item.setdefault(
                "twin_status",
                "ACTIVE",
            )

            file_item.setdefault(
                "quarantined_in_twin",
                False,
            )


        # --------------------------------------------------------
        # NETWORK
        # --------------------------------------------------------

        self.network_connections = deepcopy(
            evidence.get(
                "network_connections",
                [],
            )
            if isinstance(
                evidence.get(
                    "network_connections"
                ),
                list,
            )
            else []
        )


        for connection in self.network_connections:

            connection.setdefault(
                "twin_status",
                "CONNECTED",
            )

            connection.setdefault(
                "blocked_in_twin",
                False,
            )


        # --------------------------------------------------------
        # PERSISTENCE
        # --------------------------------------------------------

        self.persistence_artifacts = deepcopy(
            evidence.get(
                "registry_artifacts",
                [],
            )
            if isinstance(
                evidence.get(
                    "registry_artifacts"
                ),
                list,
            )
            else []
        )


        for artifact in self.persistence_artifacts:

            artifact.setdefault(
                "twin_status",
                "ACTIVE",
            )

            artifact.setdefault(
                "removed_in_twin",
                False,
            )


        self.updated_at = (
            self.now_iso()
        )


    # ============================================================
    # FIND PROCESS
    # ============================================================

    def find_process(
        self,
        pid,
    ):

        try:

            pid = int(
                pid
            )

        except (
            TypeError,
            ValueError,
        ):

            return None


        for process in self.processes:

            try:

                process_pid = int(
                    process.get(
                        "pid"
                    )
                )

            except (
                TypeError,
                ValueError,
            ):

                continue


            if process_pid == pid:

                return process


        return None


    # ============================================================
    # FIND FILE
    # ============================================================

    def find_file(
        self,
        path=None,
        sha256=None,
    ):

        normalized_path = (
            str(
                path
            ).lower()
            if path
            else None
        )


        normalized_hash = (
            str(
                sha256
            ).lower()
            if sha256
            else None
        )


        for file_item in self.files:

            item_path = (
                str(
                    file_item.get(
                        "path",
                        ""
                    )
                ).lower()
            )


            item_hash = (
                str(
                    file_item.get(
                        "sha256",
                        ""
                    )
                ).lower()
            )


            if (
                normalized_hash
                and item_hash
                == normalized_hash
            ):

                return file_item


            if (
                normalized_path
                and item_path
                == normalized_path
            ):

                return file_item


        return None


    # ============================================================
    # FIND NETWORK CONNECTION
    # ============================================================

    def find_network_connection(
        self,
        remote_ip,
        remote_port=None,
    ):

        remote_ip = str(
            remote_ip
        )


        for connection in (
            self.network_connections
        ):

            if (
                str(
                    connection.get(
                        "remote_ip"
                    )
                )
                != remote_ip
            ):

                continue


            if remote_port is None:

                return connection


            try:

                existing_port = int(
                    connection.get(
                        "remote_port"
                    )
                )

                requested_port = int(
                    remote_port
                )

            except (
                TypeError,
                ValueError,
            ):

                continue


            if (
                existing_port
                == requested_port
            ):

                return connection


        return None


    # ============================================================
    # FIND PERSISTENCE ARTIFACT
    # ============================================================

    def find_persistence_artifact(
        self,
        key,
        value_name=None,
    ):

        normalized_key = str(
            key
        ).lower()


        normalized_name = (
            str(
                value_name
            ).lower()
            if value_name
            else None
        )


        for artifact in (
            self.persistence_artifacts
        ):

            artifact_key = str(
                artifact.get(
                    "key",
                    ""
                )
            ).lower()


            artifact_name = str(
                artifact.get(
                    "value_name",
                    ""
                )
            ).lower()


            if artifact_key != normalized_key:

                continue


            if (
                normalized_name is None
                or artifact_name
                == normalized_name
            ):

                return artifact


        return None


    # ============================================================
    # ADD HISTORY EVENT
    # ============================================================

    def add_history(
        self,
        action_type: str,
        details: dict,
    ):

        self.simulation_history.append(
            {
                "timestamp":
                    self.now_iso(),

                "action_type":
                    action_type,

                "details":
                    deepcopy(
                        details
                        if isinstance(
                            details,
                            dict,
                        )
                        else {}
                    ),
            }
        )


        self.updated_at = (
            self.now_iso()
        )


    # ============================================================
    # CALCULATE STATE SUMMARY
    # ============================================================

    def get_state_summary(
        self,
    ) -> dict:

        active_processes = sum(

            1

            for process in self.processes

            if not process.get(
                "terminated_in_twin",
                False,
            )
        )


        active_files = sum(

            1

            for file_item in self.files

            if not file_item.get(
                "quarantined_in_twin",
                False,
            )
        )


        active_network = sum(

            1

            for connection
            in self.network_connections

            if not connection.get(
                "blocked_in_twin",
                False,
            )
        )


        active_persistence = sum(

            1

            for artifact
            in self.persistence_artifacts

            if not artifact.get(
                "removed_in_twin",
                False,
            )
        )


        return {
            "total_processes":
                len(
                    self.processes
                ),

            "active_processes":
                active_processes,

            "total_files":
                len(
                    self.files
                ),

            "active_files":
                active_files,

            "total_network_connections":
                len(
                    self.network_connections
                ),

            "active_network_connections":
                active_network,

            "total_persistence_artifacts":
                len(
                    self.persistence_artifacts
                ),

            "active_persistence_artifacts":
                active_persistence,

            "endpoint_isolated":
                self.endpoint_state.get(
                    "isolated",
                    False,
                ),
        }


    # ============================================================
    # SET CURRENT RISK
    # ============================================================

    def update_risk(
        self,
        new_score,
    ):

        self.current_risk_score = (
            self.normalize_score(
                new_score
            )
        )


        self.current_risk_level = (
            self.score_to_level(
                self.current_risk_score
            )
        )


        self.updated_at = (
            self.now_iso()
        )


    # ============================================================
    # EXPORT TWIN
    # ============================================================

    def to_dict(
        self,
    ) -> dict:

        return {
            "twin_id":
                self.twin_id,

            "incident_id":
                self.incident_id,

            "created_at":
                self.created_at,

            "updated_at":
                self.updated_at,

            "initial_risk_score":
                self.initial_risk_score,

            "initial_risk_level":
                self.initial_risk_level,

            "current_risk_score":
                self.current_risk_score,

            "current_risk_level":
                self.current_risk_level,

            "processes":
                deepcopy(
                    self.processes
                ),

            "files":
                deepcopy(
                    self.files
                ),

            "network_connections":
                deepcopy(
                    self.network_connections
                ),

            "persistence_artifacts":
                deepcopy(
                    self.persistence_artifacts
                ),

            "endpoint_state":
                deepcopy(
                    self.endpoint_state
                ),

            "state_summary":
                self.get_state_summary(),

            "simulation_history":
                deepcopy(
                    self.simulation_history
                ),

            "real_endpoint_modified":
                False,
        }