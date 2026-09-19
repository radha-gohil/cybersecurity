from datetime import datetime, timezone


class EvidenceEnrichmentAgent:

    def __init__(self):

        self.name = "EvidenceEnrichmentAgent"


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
    # ADD UNIQUE
    # ============================================================

    def add_unique(
        self,
        collection: list,
        item: dict,
    ):

        if item not in collection:

            collection.append(
                item
            )


    # ============================================================
    # EXTRACT PROCESS EVIDENCE
    # ============================================================

    def extract_processes(
        self,
        events: list,
    ) -> list:

        processes = []


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
                and not exe
            ):

                continue


            item = {

                "pid":
                    pid,

                "ppid":
                    process.get(
                        "ppid"
                    ),

                "name":
                    name,

                "exe":
                    exe,

                "cmdline":
                    process.get(
                        "cmdline"
                    ),

                "parent_name":
                    process.get(
                        "parent_name"
                    ),

                "behavior_score":
                    process.get(
                        "behavior_score"
                    ),

                "anomaly_score":
                    process.get(
                        "anomaly_score"
                    ),

                "combined_threat_score":
                    process.get(
                        "combined_threat_score"
                    ),
            }


            self.add_unique(
                processes,
                item,
            )


        return processes


    # ============================================================
    # EXTRACT FILE EVIDENCE
    # ============================================================

    def extract_files(
        self,
        events: list,
    ) -> list:

        files = []


        for event in events:

            file_data = (
                self.safe_dict(
                    event.get(
                        "file"
                    )
                )
            )


            if not file_data:

                continue


            if not (
                file_data.get(
                    "path"
                )
                or file_data.get(
                    "sha256"
                )
            ):

                continue


            item = {

                "name":
                    file_data.get(
                        "name"
                    ),

                "path":
                    file_data.get(
                        "path"
                    ),

                "extension":
                    file_data.get(
                        "extension"
                    ),

                "size":
                    file_data.get(
                        "size"
                    ),

                "md5":
                    file_data.get(
                        "md5"
                    ),

                "sha1":
                    file_data.get(
                        "sha1"
                    ),

                "sha256":
                    file_data.get(
                        "sha256"
                    ),

                "entropy":
                    file_data.get(
                        "entropy"
                    ),

                "is_pe":
                    file_data.get(
                        "is_pe"
                    ),

                "static_risk_score":
                    file_data.get(
                        "static_risk_score"
                    ),

                "static_severity":
                    file_data.get(
                        "static_severity"
                    ),

                "ml_prediction":
                    file_data.get(
                        "ml_prediction"
                    ),

                "malware_probability":
                    file_data.get(
                        "malware_probability"
                    ),

                "ml_confidence":
                    file_data.get(
                        "ml_confidence"
                    ),
            }


            self.add_unique(
                files,
                item,
            )


        return files


    # ============================================================
    # EXTRACT NETWORK EVIDENCE
    # ============================================================

    def extract_network(
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


            if not network:

                continue


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

                "local_ip":
                    network.get(
                        "local_ip"
                    ),

                "local_port":
                    network.get(
                        "local_port"
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


            self.add_unique(
                connections,
                item,
            )


        return connections


    # ============================================================
    # EXTRACT REGISTRY EVIDENCE
    # ============================================================

    def extract_registry(
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


            self.add_unique(
                registry_items,
                item,
            )


        return registry_items


    # ============================================================
    # EXTRACT INDICATORS
    # ============================================================

    def extract_indicators(
        self,
        events: list,
    ) -> list:

        indicators = []

        seen = set()


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


            candidates = []


            for key in [

                "behavior_indicators",

                "anomaly_indicators",

                "behavior_reasons",

                "anomaly_reasons",
            ]:

                value = (
                    process.get(
                        key
                    )
                )


                if isinstance(
                    value,
                    list,
                ):

                    candidates.extend(
                        value
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

                candidates.extend(
                    static_reasons
                )


            for key in [

                "behavior_indicators",

                "anomaly_indicators",
            ]:

                value = (
                    metadata.get(
                        key
                    )
                )


                if isinstance(
                    value,
                    list,
                ):

                    candidates.extend(
                        value
                    )


            for indicator in candidates:

                indicator = str(
                    indicator
                ).strip()


                if not indicator:

                    continue


                key = (
                    indicator.lower()
                )


                if key in seen:

                    continue


                seen.add(
                    key
                )


                indicators.append(
                    indicator
                )


        return indicators


    # ============================================================
    # BUILD IOC COLLECTION
    # ============================================================

    def build_iocs(
        self,
        files: list,
        network: list,
        registry: list,
    ) -> dict:

        hashes = []

        file_paths = []

        ips = []

        registry_keys = []


        # --------------------------------------------------------
        # FILE IOCS
        # --------------------------------------------------------

        for item in files:

            for key in [

                "md5",

                "sha1",

                "sha256",
            ]:

                value = (
                    item.get(
                        key
                    )
                )


                if (
                    value
                    and value not in hashes
                ):

                    hashes.append(
                        value
                    )


            path = (
                item.get(
                    "path"
                )
            )


            if (
                path
                and path not in file_paths
            ):

                file_paths.append(
                    path
                )


        # --------------------------------------------------------
        # NETWORK IOCS
        # --------------------------------------------------------

        for item in network:

            remote_ip = (
                item.get(
                    "remote_ip"
                )
            )


            if (
                remote_ip
                and remote_ip not in ips
            ):

                ips.append(
                    remote_ip
                )


        # --------------------------------------------------------
        # REGISTRY IOCS
        # --------------------------------------------------------

        for item in registry:

            key = (
                item.get(
                    "key"
                )
            )


            if (
                key
                and key not in registry_keys
            ):

                registry_keys.append(
                    key
                )


        return {

            "hashes":
                hashes,

            "file_paths":
                file_paths,

            "remote_ips":
                ips,

            "registry_keys":
                registry_keys,
        }


    # ============================================================
    # BUILD RELATIONSHIPS
    # ============================================================

    def build_relationships(
        self,
        processes: list,
        files: list,
        network: list,
        registry: list,
    ) -> list:

        relationships = []


        # ========================================================
        # PROCESS -> FILE
        # ========================================================

        for process in processes:

            process_exe = str(
                process.get(
                    "exe"
                )
                or ""
            ).lower()


            process_name = str(
                process.get(
                    "name"
                )
                or ""
            ).lower()


            for file_item in files:

                file_path = str(
                    file_item.get(
                        "path"
                    )
                    or ""
                ).lower()


                file_name = str(
                    file_item.get(
                        "name"
                    )
                    or ""
                ).lower()


                if (
                    process_exe
                    and file_path
                    and process_exe == file_path
                ):

                    relationships.append(
                        {

                            "source_type":
                                "PROCESS",

                            "source":
                                process.get(
                                    "name"
                                ),

                            "relationship":
                                "EXECUTABLE_FILE",

                            "target_type":
                                "FILE",

                            "target":
                                file_item.get(
                                    "path"
                                ),

                            "confidence":
                                100,
                        }
                    )


                elif (
                    process_name
                    and file_name
                    and process_name == file_name
                ):

                    relationships.append(
                        {

                            "source_type":
                                "PROCESS",

                            "source":
                                process.get(
                                    "name"
                                ),

                            "relationship":
                                "NAME_MATCH",

                            "target_type":
                                "FILE",

                            "target":
                                file_item.get(
                                    "path"
                                ),

                            "confidence":
                                30,
                        }
                    )


        # ========================================================
        # PROCESS -> NETWORK
        # ========================================================

        for process in processes:

            pid = (
                process.get(
                    "pid"
                )
            )


            for connection in network:

                network_pid = (
                    connection.get(
                        "pid"
                    )
                )


                if (
                    pid is not None
                    and network_pid is not None
                    and pid == network_pid
                ):

                    relationships.append(
                        {

                            "source_type":
                                "PROCESS",

                            "source":
                                process.get(
                                    "name"
                                ),

                            "relationship":
                                "CONNECTED_TO",

                            "target_type":
                                "NETWORK",

                            "target":
                                connection.get(
                                    "remote_ip"
                                ),

                            "confidence":
                                100,
                        }
                    )


        # ========================================================
        # REGISTRY REFERENCES FILE/PROCESS
        # ========================================================

        for registry_item in registry:

            value_data = str(
                registry_item.get(
                    "value_data"
                )
                or ""
            ).lower()


            if not value_data:

                continue


            for file_item in files:

                path = str(
                    file_item.get(
                        "path"
                    )
                    or ""
                ).lower()


                if (
                    path
                    and path in value_data
                ):

                    relationships.append(
                        {

                            "source_type":
                                "REGISTRY",

                            "source":
                                registry_item.get(
                                    "key"
                                ),

                            "relationship":
                                "REFERENCES",

                            "target_type":
                                "FILE",

                            "target":
                                file_item.get(
                                    "path"
                                ),

                            "confidence":
                                100,
                        }
                    )


            for process in processes:

                exe = str(
                    process.get(
                        "exe"
                    )
                    or ""
                ).lower()


                if (
                    exe
                    and exe in value_data
                ):

                    relationships.append(
                        {

                            "source_type":
                                "REGISTRY",

                            "source":
                                registry_item.get(
                                    "key"
                                ),

                            "relationship":
                                "PERSISTENCE_REFERENCE",

                            "target_type":
                                "PROCESS",

                            "target":
                                process.get(
                                    "name"
                                ),

                            "confidence":
                                90,
                        }
                    )


        # --------------------------------------------------------
        # REMOVE DUPLICATES
        # --------------------------------------------------------

        unique = []


        for item in relationships:

            if item not in unique:

                unique.append(
                    item
                )


        return unique


    # ============================================================
    # ENRICH INCIDENT
    # ============================================================

    def enrich(
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
            self.extract_processes(
                events
            )
        )


        files = (
            self.extract_files(
                events
            )
        )


        network = (
            self.extract_network(
                events
            )
        )


        registry = (
            self.extract_registry(
                events
            )
        )


        indicators = (
            self.extract_indicators(
                events
            )
        )


        iocs = (
            self.build_iocs(
                files,
                network,
                registry,
            )
        )


        relationships = (
            self.build_relationships(
                processes,
                files,
                network,
                registry,
            )
        )


        return {

            "incident_id":
                incident.get(
                    "incident_id"
                ),

            "agent":
                self.name,

            "enriched_at":
                self.now_iso(),

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

            "iocs":
                iocs,

            "relationships":
                relationships,

            "summary": {

                "process_count":
                    len(
                        processes
                    ),

                "file_count":
                    len(
                        files
                    ),

                "network_count":
                    len(
                        network
                    ),

                "registry_count":
                    len(
                        registry
                    ),

                "indicator_count":
                    len(
                        indicators
                    ),

                "relationship_count":
                    len(
                        relationships
                    ),
            },
        }