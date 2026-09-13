from collections import Counter
from datetime import datetime, timezone


class InvestigationAgent:

    def __init__(self):

        self.name = "InvestigationAgent"


    # ============================================================
    # SAFE LIST HELPER
    # ============================================================

    def safe_list(
        self,
        value,
    ):

        if isinstance(
            value,
            list,
        ):

            return value

        return []


    # ============================================================
    # SAFE DICT HELPER
    # ============================================================

    def safe_dict(
        self,
        value,
    ):

        if isinstance(
            value,
            dict,
        ):

            return value

        return {}


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
    # EXTRACT CATEGORY
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
    # COLLECT PROCESSES
    # ============================================================

    def collect_processes(
        self,
        events: list,
    ) -> list:

        processes = {}


        for event in events:

            process = (
                self.safe_dict(
                    event.get(
                        "process"
                    )
                )
            )

            network = (
                self.safe_dict(
                    event.get(
                        "network"
                    )
                )
            )


            pid = (
                process.get(
                    "pid"
                )
                or network.get(
                    "pid"
                )
            )


            name = (
                process.get(
                    "name"
                )
                or network.get(
                    "process_name"
                )
            )


            exe = (
                process.get(
                    "exe"
                )
            )


            if (
                pid is None
                and not name
            ):

                continue


            key = (
                pid,
                str(
                    name
                ).lower()
                if name
                else None,
            )


            if key not in processes:

                processes[
                    key
                ] = {

                    "pid":
                        pid,

                    "name":
                        name,

                    "exe":
                        exe,
                }


        return list(
            processes.values()
        )


    # ============================================================
    # COLLECT FILES
    # ============================================================

    def collect_files(
        self,
        events: list,
    ) -> list:

        files = {}


        for event in events:

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
            )


            if not path:

                continue


            key = str(
                path
            ).lower()


            files[
                key
            ] = {

                "name":
                    file_data.get(
                        "name"
                    ),

                "path":
                    path,

                "sha256":
                    file_data.get(
                        "sha256"
                    ),

                "is_pe":
                    file_data.get(
                        "is_pe"
                    ),

                "static_risk_score":
                    file_data.get(
                        "static_risk_score"
                    ),

                "malware_probability":
                    file_data.get(
                        "malware_probability"
                    ),
            }


        return list(
            files.values()
        )


    # ============================================================
    # COLLECT NETWORK CONNECTIONS
    # ============================================================

    def collect_network(
        self,
        events: list,
    ) -> list:

        connections = []


        for event in events:

            network = (
                self.safe_dict(
                    event.get(
                        "network"
                    )
                )
            )


            remote_ip = (
                network.get(
                    "remote_ip"
                )
            )


            if not remote_ip:

                continue


            item = {

                "pid":
                    network.get(
                        "pid"
                    ),

                "process_name":
                    network.get(
                        "process_name"
                    ),

                "protocol":
                    network.get(
                        "protocol"
                    ),

                "remote_ip":
                    remote_ip,

                "remote_port":
                    network.get(
                        "remote_port"
                    ),

                "status":
                    network.get(
                        "status"
                    ),
            }


            if item not in connections:

                connections.append(
                    item
                )


        return connections


    # ============================================================
    # COLLECT REGISTRY
    # ============================================================

    def collect_registry(
        self,
        events: list,
    ) -> list:

        registry_items = []


        for event in events:

            registry = (
                self.safe_dict(
                    event.get(
                        "registry"
                    )
                )
            )


            if not registry:

                continue


            item = {

                "key":
                    registry.get(
                        "key"
                    )
                    or registry.get(
                        "registry_key"
                    )
                    or registry.get(
                        "path"
                    ),

                "value_name":
                    registry.get(
                        "value_name"
                    ),

                "value_data":
                    registry.get(
                        "value_data"
                    )
                    or registry.get(
                        "data"
                    )
                    or registry.get(
                        "value"
                    ),
            }


            if item not in registry_items:

                registry_items.append(
                    item
                )


        return registry_items


    # ============================================================
    # COLLECT INDICATORS
    # ============================================================

    def collect_indicators(
        self,
        events: list,
    ) -> list:

        indicators = []


        for event in events:

            process = (
                self.safe_dict(
                    event.get(
                        "process"
                    )
                )
            )

            file_data = (
                self.safe_dict(
                    event.get(
                        "file"
                    )
                )
            )

            metadata = (
                self.safe_dict(
                    event.get(
                        "metadata"
                    )
                )
            )


            for key in [
                "behavior_indicators",
                "anomaly_indicators",
            ]:

                values = (
                    process.get(
                        key
                    )
                )


                if isinstance(
                    values,
                    list,
                ):

                    indicators.extend(
                        values
                    )


            static_reasons = (
                file_data.get(
                    "static_reasons"
                )
            )


            if isinstance(
                static_reasons,
                list,
            ):

                indicators.extend(
                    static_reasons
                )


            for key in [
                "behavior_indicators",
                "anomaly_indicators",
            ]:

                values = (
                    metadata.get(
                        key
                    )
                )


                if isinstance(
                    values,
                    list,
                ):

                    indicators.extend(
                        values
                    )


        # Remove duplicates while preserving order
        unique = []

        seen = set()


        for indicator in indicators:

            value = str(
                indicator
            ).strip()


            if not value:

                continue


            normalized = (
                value.lower()
            )


            if normalized in seen:

                continue


            seen.add(
                normalized
            )

            unique.append(
                value
            )


        return unique


    # ============================================================
    # BUILD TIMELINE
    # ============================================================

    def build_timeline(
        self,
        events: list,
    ) -> list:

        timeline = []


        for event in events:

            timeline.append(
                {

                    "event_id":
                        event.get(
                            "event_id"
                        ),

                    "timestamp":
                        event.get(
                            "timestamp"
                        )
                        or event.get(
                            "timestamp_unix"
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
                            "severity"
                        ),

                    "category":
                        self.get_category(
                            event
                        ),
                }
            )


        return timeline


    # ============================================================
    # DETERMINE INVESTIGATION PRIORITY
    # ============================================================

    def determine_priority(
        self,
        incident: dict,
    ) -> str:

        score = int(
            incident.get(
                "correlation_score",
                0,
            )
            or 0
        )


        severity = str(
            incident.get(
                "severity",
                "INFO",
            )
        ).upper()


        if (
            severity == "CRITICAL"
            or score >= 80
        ):

            return "IMMEDIATE"


        if (
            severity == "HIGH"
            or score >= 60
        ):

            return "HIGH"


        if (
            severity == "MEDIUM"
            or score >= 35
        ):

            return "NORMAL"


        return "LOW"


    # ============================================================
    # GENERATE FINDINGS
    # ============================================================

    def generate_findings(
        self,
        incident: dict,
        events: list,
        processes: list,
        files: list,
        network: list,
        registry: list,
        indicators: list,
    ) -> list:

        findings = []


        categories = set(
            self.get_category(
                event
            )
            for event in events
        )


        if len(
            categories
        ) >= 2:

            findings.append(
                f"Activity spans {len(categories)} telemetry categories: "
                + ", ".join(
                    sorted(
                        categories
                    )
                )
            )


        if processes:

            findings.append(
                f"{len(processes)} process entity/entities involved."
            )


        if files:

            findings.append(
                f"{len(files)} file entity/entities involved."
            )


        if network:

            findings.append(
                f"{len(network)} network connection(s) observed."
            )


        if registry:

            findings.append(
                f"{len(registry)} registry-related artifact(s) observed."
            )


        high_probability_files = []


        for file_item in files:

            probability = (
                file_item.get(
                    "malware_probability"
                )
            )


            try:

                probability = float(
                    probability
                )

            except (
                TypeError,
                ValueError,
            ):

                continue


            if probability >= 0.70:

                high_probability_files.append(
                    file_item
                )


        if high_probability_files:

            findings.append(
                f"{len(high_probability_files)} file(s) have elevated malware probability."
            )


        if indicators:

            findings.append(
                f"{len(indicators)} behavioral/static indicator(s) identified."
            )


        if not findings:

            findings.append(
                "No strong investigation finding was derived from the available telemetry."
            )


        return findings


    # ============================================================
    # INVESTIGATE INCIDENT
    # ============================================================

    def investigate(
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


        processes = (
            self.collect_processes(
                events
            )
        )


        files = (
            self.collect_files(
                events
            )
        )


        network = (
            self.collect_network(
                events
            )
        )


        registry = (
            self.collect_registry(
                events
            )
        )


        indicators = (
            self.collect_indicators(
                events
            )
        )


        timeline = (
            self.build_timeline(
                events
            )
        )


        category_counts = Counter(

            self.get_category(
                event
            )

            for event in events
        )


        findings = (
            self.generate_findings(
                incident,
                events,
                processes,
                files,
                network,
                registry,
                indicators,
            )
        )


        result = {

            "incident_id":
                incident.get(
                    "incident_id"
                ),

            "agent":
                self.name,

            "investigated_at":
                self.now_iso(),

            "priority":
                self.determine_priority(
                    incident
                ),

            "incident_score":
                incident.get(
                    "correlation_score",
                    0,
                ),

            "incident_severity":
                incident.get(
                    "severity",
                    "INFO",
                ),

            "event_count":
                len(
                    events
                ),

            "category_counts":
                dict(
                    category_counts
                ),

            "processes":
                processes,

            "files":
                files,

            "network_connections":
                network,

            "registry_artifacts":
                registry,

            "indicators":
                indicators,

            "findings":
                findings,

            "timeline":
                timeline,

            "requires_response":
                (
                    self.determine_priority(
                        incident
                    )
                    in [
                        "IMMEDIATE",
                        "HIGH",
                    ]
                ),
        }


        return result