from datetime import datetime, timezone


class AttackTimelineAgent:

    def __init__(self):

        self.name = "AttackTimelineAgent"


    # ============================================================
    # SAFE DICT
    # ============================================================

    def safe_dict(
        self,
        value,
    ) -> dict:

        if isinstance(
            value,
            dict,
        ):

            return value

        return {}


    # ============================================================
    # SAFE LIST
    # ============================================================

    def safe_list(
        self,
        value,
    ) -> list:

        if isinstance(
            value,
            list,
        ):

            return value

        return []


    # ============================================================
    # CURRENT UTC TIME
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
    # NORMALIZE TIMESTAMP
    # ============================================================

    def get_timestamp_value(
        self,
        event: dict,
    ) -> float:

        value = (
            event.get(
                "timestamp_unix"
            )
        )


        if value is not None:

            try:

                return float(
                    value
                )

            except (
                TypeError,
                ValueError,
            ):

                pass


        timestamp = (
            event.get(
                "timestamp"
            )
        )


        if timestamp:

            try:

                parsed = datetime.fromisoformat(
                    str(
                        timestamp
                    ).replace(
                        "Z",
                        "+00:00",
                    )
                )

                return parsed.timestamp()

            except (
                ValueError,
                TypeError,
            ):

                pass


        return 0.0


    # ============================================================
    # FORMAT TIMESTAMP
    # ============================================================

    def format_timestamp(
        self,
        event: dict,
    ) -> str:

        timestamp = (
            event.get(
                "timestamp"
            )
        )


        if timestamp:

            return str(
                timestamp
            )


        timestamp_unix = (
            event.get(
                "timestamp_unix"
            )
        )


        if timestamp_unix is not None:

            try:

                dt = datetime.fromtimestamp(
                    float(
                        timestamp_unix
                    ),
                    tz=timezone.utc,
                )

                return dt.isoformat()

            except (
                TypeError,
                ValueError,
                OSError,
            ):

                pass


        return "UNKNOWN"


    # ============================================================
    # EVENT CATEGORY
    # ============================================================

    def get_category(
        self,
        event: dict,
    ) -> str:

        event_type = str(
            event.get(
                "event_type",
                ""
            )
        ).lower()


        if event_type.startswith(
            "process"
        ):

            return "PROCESS"


        if event_type.startswith(
            "file"
        ):

            return "FILE"


        if event_type.startswith(
            "network"
        ):

            return "NETWORK"


        if (
            event_type.startswith(
                "registry"
            )
            or event_type.startswith(
                "startup"
            )
        ):

            return "REGISTRY"


        return "OTHER"


    # ============================================================
    # BUILD PROCESS DESCRIPTION
    # ============================================================

    def describe_process(
        self,
        event: dict,
    ) -> str:

        process = (
            self.safe_dict(
                event.get(
                    "process"
                )
            )
        )


        name = (
            process.get(
                "name"
            )
            or "Unknown process"
        )


        pid = (
            process.get(
                "pid"
            )
        )


        event_type = str(
            event.get(
                "event_type",
                ""
            )
        ).lower()


        if event_type == "process_start":

            action = (
                "Process started"
            )


        elif event_type == "process_stop":

            action = (
                "Process stopped"
            )


        else:

            action = (
                "Process activity observed"
            )


        if pid is not None:

            return (
                f"{action}: "
                f"{name} "
                f"(PID {pid})"
            )


        return (
            f"{action}: {name}"
        )


    # ============================================================
    # BUILD FILE DESCRIPTION
    # ============================================================

    def describe_file(
        self,
        event: dict,
    ) -> str:

        file_data = (
            self.safe_dict(
                event.get(
                    "file"
                )
            )
        )


        path = (
            file_data.get(
                "path"
            )
            or file_data.get(
                "name"
            )
            or "Unknown file"
        )


        event_type = str(
            event.get(
                "event_type",
                ""
            )
        ).lower()


        if event_type == "file_create":

            action = (
                "File created"
            )


        elif event_type == "file_modify":

            action = (
                "File modified"
            )


        elif event_type == "file_delete":

            action = (
                "File deleted"
            )


        elif event_type == "file_move":

            action = (
                "File moved"
            )


        else:

            action = (
                "File activity observed"
            )


        description = (
            f"{action}: {path}"
        )


        malware_probability = (
            file_data.get(
                "malware_probability"
            )
        )


        if malware_probability is not None:

            try:

                probability = float(
                    malware_probability
                )


                if probability >= 0.70:

                    description += (
                        f" | Elevated malware probability "
                        f"{probability:.2f}"
                    )

            except (
                TypeError,
                ValueError,
            ):

                pass


        return description


    # ============================================================
    # BUILD NETWORK DESCRIPTION
    # ============================================================

    def describe_network(
        self,
        event: dict,
    ) -> str:

        network = (
            self.safe_dict(
                event.get(
                    "network"
                )
            )
        )


        process_name = (
            network.get(
                "process_name"
            )
            or "Unknown process"
        )


        pid = (
            network.get(
                "pid"
            )
        )


        remote_ip = (
            network.get(
                "remote_ip"
            )
            or "Unknown IP"
        )


        remote_port = (
            network.get(
                "remote_port"
            )
        )


        if remote_port is not None:

            destination = (
                f"{remote_ip}:{remote_port}"
            )

        else:

            destination = (
                str(
                    remote_ip
                )
            )


        if pid is not None:

            return (
                f"Network connection: "
                f"{process_name} "
                f"(PID {pid}) "
                f"connected to {destination}"
            )


        return (
            f"Network connection: "
            f"{process_name} "
            f"connected to {destination}"
        )


    # ============================================================
    # BUILD REGISTRY DESCRIPTION
    # ============================================================

    def describe_registry(
        self,
        event: dict,
    ) -> str:

        registry = (
            self.safe_dict(
                event.get(
                    "registry"
                )
            )
        )


        key = (
            registry.get(
                "key"
            )
            or registry.get(
                "registry_key"
            )
            or registry.get(
                "path"
            )
            or "Unknown registry key"
        )


        value_name = (
            registry.get(
                "value_name"
            )
        )


        value_data = (
            registry.get(
                "value_data"
            )
            or registry.get(
                "data"
            )
            or registry.get(
                "value"
            )
        )


        description = (
            f"Registry activity: {key}"
        )


        if value_name:

            description += (
                f" | Value={value_name}"
            )


        if value_data:

            description += (
                f" | Data={value_data}"
            )


        return description


    # ============================================================
    # EVENT DESCRIPTION
    # ============================================================

    def describe_event(
        self,
        event: dict,
    ) -> str:

        category = (
            self.get_category(
                event
            )
        )


        if category == "PROCESS":

            return (
                self.describe_process(
                    event
                )
            )


        if category == "FILE":

            return (
                self.describe_file(
                    event
                )
            )


        if category == "NETWORK":

            return (
                self.describe_network(
                    event
                )
            )


        if category == "REGISTRY":

            return (
                self.describe_registry(
                    event
                )
            )


        return (
            f"Security event observed: "
            f"{event.get('event_type', 'unknown')}"
        )


    # ============================================================
    # DETERMINE EVENT SIGNIFICANCE
    # ============================================================

    def significance(
        self,
        event: dict,
    ) -> str:

        severity = str(
            event.get(
                "severity",
                "INFO",
            )
        ).upper()


        mapping = {

            "CRITICAL":
                "CRITICAL",

            "HIGH":
                "HIGH",

            "MEDIUM":
                "MEDIUM",

            "LOW":
                "LOW",

            "INFO":
                "INFORMATIONAL",
        }


        return mapping.get(
            severity,
            "INFORMATIONAL",
        )


    # ============================================================
    # BUILD TIMELINE ENTRY
    # ============================================================

    def build_entry(
        self,
        event: dict,
        sequence_number: int,
    ) -> dict:

        return {

            "sequence":
                sequence_number,

            "event_id":
                event.get(
                    "event_id"
                ),

            "timestamp":
                self.format_timestamp(
                    event
                ),

            "timestamp_unix":
                self.get_timestamp_value(
                    event
                ),

            "category":
                self.get_category(
                    event
                ),

            "event_type":
                event.get(
                    "event_type"
                ),

            "source":
                event.get(
                    "source"
                ),

            "severity":
                event.get(
                    "severity",
                    "INFO",
                ),

            "significance":
                self.significance(
                    event
                ),

            "description":
                self.describe_event(
                    event
                ),
        }


    # ============================================================
    # ATTACK STAGE ESTIMATION
    # ============================================================

    def estimate_attack_stage(
        self,
        entry: dict,
    ) -> str:

        category = (
            entry.get(
                "category"
            )
        )


        event_type = str(
            entry.get(
                "event_type",
                ""
            )
        ).lower()


        description = str(
            entry.get(
                "description",
                ""
            )
        ).lower()


        if (
            category == "PROCESS"
            and event_type == "process_start"
        ):

            return "EXECUTION"


        if category == "FILE":

            return "FILE_ACTIVITY"


        if category == "NETWORK":

            return "COMMAND_OR_NETWORK_ACTIVITY"


        if category == "REGISTRY":

            if any(
                keyword in description

                for keyword in [

                    "\\run",

                    "\\runonce",

                    "startup",

                    "winlogon",

                    "services",
                ]
            ):

                return "PERSISTENCE"

            return "REGISTRY_ACTIVITY"


        return "OBSERVED_ACTIVITY"


    # ============================================================
    # RECONSTRUCT TIMELINE
    # ============================================================

    def reconstruct(
        self,
        incident: dict,
    ) -> dict:

        incident = (
            self.safe_dict(
                incident
            )
        )


        events = (
            self.safe_list(
                incident.get(
                    "timeline"
                )
            )
        )


        # --------------------------------------------------------
        # Sort events chronologically
        # --------------------------------------------------------

        events = sorted(

            events,

            key=lambda event:
                self.get_timestamp_value(
                    event
                ),
        )


        timeline = []


        for index, event in enumerate(
            events,
            start=1,
        ):

            entry = (
                self.build_entry(
                    event,
                    index,
                )
            )


            entry[
                "attack_stage"
            ] = (
                self.estimate_attack_stage(
                    entry
                )
            )


            timeline.append(
                entry
            )


        # --------------------------------------------------------
        # Unique attack stages
        # --------------------------------------------------------

        attack_stages = []


        for entry in timeline:

            stage = (
                entry.get(
                    "attack_stage"
                )
            )


            if (
                stage
                and stage not in attack_stages
            ):

                attack_stages.append(
                    stage
                )


        # --------------------------------------------------------
        # Human-readable story
        # --------------------------------------------------------

        story = []


        for entry in timeline:

            story.append(

                f"{entry['sequence']}. "
                f"[{entry['category']}] "
                f"{entry['description']}"
            )


        return {

            "incident_id":
                incident.get(
                    "incident_id"
                ),

            "agent":
                self.name,

            "reconstructed_at":
                self.now_iso(),

            "event_count":
                len(
                    timeline
                ),

            "attack_stages":
                attack_stages,

            "timeline":
                timeline,

            "attack_story":
                story,
        }