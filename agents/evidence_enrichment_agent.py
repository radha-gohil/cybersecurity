
from datetime import datetime, timezone
import math


class EvidenceEnrichmentAgent:

    def __init__(self):
        self.name = "EvidenceEnrichmentAgent"

    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ============================================================
    # SAFE DICT
    # ============================================================

    def safe_dict(self, value) -> dict:
        return value if isinstance(value, dict) else {}

    # ============================================================
    # SAFE LIST
    # ============================================================

    def safe_list(self, value) -> list:
        return value if isinstance(value, list) else []

    # ============================================================
    # ADD UNIQUE
    # ============================================================

    def add_unique(
        self,
        collection: list,
        item: dict,
    ):
        if item not in collection:
            collection.append(item)

    # ============================================================
    # EXTRACT PROCESS EVIDENCE
    # ============================================================

    def extract_processes(self, events: list) -> list:
        processes = []

        for event in events:
            if not isinstance(event, dict):
                continue

            process = self.safe_dict(
                event.get("process")
            )
            network = self.safe_dict(
                event.get("network")
            )

            pid = (
                process.get("pid")
                if process.get("pid") is not None
                else network.get("pid")
            )

            name = (
                process.get("name")
                or network.get("process_name")
            )

            exe = process.get("exe")

            if pid is None and not name and not exe:
                continue

            item = {
                "pid": pid,
                "ppid": process.get("ppid"),
                "name": name,
                "exe": exe,
                "cmdline": process.get("cmdline"),
                "parent_name":
                    process.get("parent_name"),
                "behavior_score":
                    process.get("behavior_score"),
                "anomaly_score":
                    process.get("anomaly_score"),
                "combined_threat_score":
                    process.get("combined_threat_score"),
            }

            self.add_unique(processes, item)

        return processes

    # ============================================================
    # EXTRACT FILE EVIDENCE
    # ============================================================

    def extract_files(self, events: list) -> list:
        files = []

        for event in events:
            if not isinstance(event, dict):
                continue

            file_data = self.safe_dict(
                event.get("file")
            )

            if not file_data:
                continue

            if not (
                file_data.get("path")
                or file_data.get("sha256")
            ):
                continue

            item = {
                "name": file_data.get("name"),
                "path": file_data.get("path"),
                "extension":
                    file_data.get("extension"),
                "size": file_data.get("size"),
                "md5": file_data.get("md5"),
                "sha1": file_data.get("sha1"),
                "sha256": file_data.get("sha256"),
                "entropy": file_data.get("entropy"),
                "is_pe": file_data.get("is_pe"),
                "static_risk_score":
                    file_data.get("static_risk_score"),
                "static_severity":
                    file_data.get("static_severity"),

                # These values are preserved for historical
                # context only. Malware inference is OFF.
                "ml_prediction":
                    file_data.get("ml_prediction"),
                "malware_probability":
                    file_data.get("malware_probability"),
                "ml_confidence":
                    file_data.get("ml_confidence"),
            }

            self.add_unique(files, item)

        return files

    # ============================================================
    # EXTRACT NETWORK EVIDENCE
    # ============================================================

    def extract_network(self, events: list) -> list:
        connections = []

        for event in events:
            if not isinstance(event, dict):
                continue

            network = self.safe_dict(
                event.get("network")
            )

            if not network:
                continue

            remote_ip = network.get("remote_ip")

            if not remote_ip:
                continue

            item = {
                "pid": network.get("pid"),
                "process_name":
                    network.get("process_name"),
                "protocol": network.get("protocol"),
                "local_ip": network.get("local_ip"),
                "local_port":
                    network.get("local_port"),
                "remote_ip": remote_ip,
                "remote_port":
                    network.get("remote_port"),
                "status": network.get("status"),
            }

            self.add_unique(connections, item)

        return connections

    # ============================================================
    # EXTRACT REGISTRY EVIDENCE
    # ============================================================

    def extract_registry(self, events: list) -> list:
        registry_items = []

        for event in events:
            if not isinstance(event, dict):
                continue

            registry = self.safe_dict(
                event.get("registry")
            )

            if not registry:
                continue

            item = {
                "key": (
                    registry.get("key")
                    or registry.get("registry_key")
                    or registry.get("path")
                ),
                "value_name":
                    registry.get("value_name"),
                "value_data": (
                    registry.get("value_data")
                    or registry.get("data")
                    or registry.get("value")
                ),
            }

            self.add_unique(registry_items, item)

        return registry_items

    # ============================================================
    # EXTRACT INDICATORS
    # ============================================================

    def extract_indicators(self, events: list) -> list:
        indicators = []
        seen = set()

        for event in events:
            if not isinstance(event, dict):
                continue

            process = self.safe_dict(
                event.get("process")
            )
            file_data = self.safe_dict(
                event.get("file")
            )
            metadata = self.safe_dict(
                event.get("metadata")
            )

            candidates = []

            for key in [
                "behavior_indicators",
                "anomaly_indicators",
                "behavior_reasons",
                "anomaly_reasons",
            ]:
                values = process.get(key)

                if isinstance(values, list):
                    candidates.extend(values)

            static_reasons = file_data.get(
                "static_reasons"
            )

            if isinstance(static_reasons, list):
                candidates.extend(static_reasons)

            for key in [
                "behavior_indicators",
                "anomaly_indicators",
            ]:
                values = metadata.get(key)

                if isinstance(values, list):
                    candidates.extend(values)

            for indicator in candidates:
                indicator = str(indicator).strip()

                if not indicator:
                    continue

                key = indicator.lower()

                if key in seen:
                    continue

                seen.add(key)
                indicators.append(indicator)

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
            for key in ["md5", "sha1", "sha256"]:
                value = item.get(key)

                if value and value not in hashes:
                    hashes.append(value)

            path = item.get("path")

            if path and path not in file_paths:
                file_paths.append(path)

        # --------------------------------------------------------
        # NETWORK IOCS
        # --------------------------------------------------------

        for item in network:
            remote_ip = item.get("remote_ip")

            if remote_ip and remote_ip not in ips:
                ips.append(remote_ip)

        # --------------------------------------------------------
        # REGISTRY IOCS
        # --------------------------------------------------------

        for item in registry:
            key = item.get("key")

            if key and key not in registry_keys:
                registry_keys.append(key)

        return {
            "hashes": hashes,
            "file_paths": file_paths,
            "remote_ips": ips,
            "registry_keys": registry_keys,
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
                process.get("exe") or ""
            ).lower()

            process_name = str(
                process.get("name") or ""
            ).lower()

            for file_item in files:
                file_path = str(
                    file_item.get("path") or ""
                ).lower()

                file_name = str(
                    file_item.get("name") or ""
                ).lower()

                if (
                    process_exe
                    and file_path
                    and process_exe == file_path
                ):
                    relationships.append({
                        "source_type": "PROCESS",
                        "source": process.get("name"),
                        "relationship":
                            "EXECUTABLE_FILE",
                        "target_type": "FILE",
                        "target": file_item.get("path"),
                        "confidence": 100,
                    })

                elif (
                    process_name
                    and file_name
                    and process_name == file_name
                ):
                    relationships.append({
                        "source_type": "PROCESS",
                        "source": process.get("name"),
                        "relationship": "NAME_MATCH",
                        "target_type": "FILE",
                        "target": file_item.get("path"),
                        "confidence": 30,
                    })

        # ========================================================
        # PROCESS -> NETWORK
        # ========================================================

        for process in processes:
            pid = process.get("pid")

            for connection in network:
                network_pid = connection.get("pid")

                if (
                    pid is not None
                    and network_pid is not None
                    and pid == network_pid
                ):
                    # Original PID matching remains
                    # visible as an inferred relationship.
                    # It does not establish attribution.
                    relationships.append({
                        "source_type": "PROCESS",
                        "source": process.get("name"),
                        "relationship": "CONNECTED_TO",
                        "target_type": "NETWORK",
                        "target":
                            connection.get("remote_ip"),
                        "confidence": 100,
                    })

        # ========================================================
        # REGISTRY REFERENCES FILE / PROCESS
        # ========================================================

        for registry_item in registry:
            value_data = str(
                registry_item.get("value_data") or ""
            ).lower()

            if not value_data:
                continue

            for file_item in files:
                path = str(
                    file_item.get("path") or ""
                ).lower()

                if path and path in value_data:
                    relationships.append({
                        "source_type": "REGISTRY",
                        "source": registry_item.get(
                            "key"
                        ),
                        "relationship": "REFERENCES",
                        "target_type": "FILE",
                        "target": file_item.get(
                            "path"
                        ),
                        "confidence": 100,
                    })

            for process in processes:
                exe = str(
                    process.get("exe") or ""
                ).lower()

                if exe and exe in value_data:
                    relationships.append({
                        "source_type": "REGISTRY",
                        "source": registry_item.get(
                            "key"
                        ),
                        "relationship":
                            "PERSISTENCE_REFERENCE",
                        "target_type": "PROCESS",
                        "target": process.get("name"),
                        "confidence": 90,
                    })

        # --------------------------------------------------------
        # REMOVE DUPLICATES
        # --------------------------------------------------------

        unique = []

        for item in relationships:
            if item not in unique:
                unique.append(item)

        return unique

    # ============================================================
    # NEW: EVIDENCE-LINKED PROCESS / NETWORK MATCHING
    # ============================================================

    def build_identity_links(self, events: list) -> list:
        """
        Build candidate relationships from raw telemetry.

        Required:
            - Explicit matching device ID
            - Valid matching PID
            - Matching nonempty process creation time
            - Distinct event IDs
            - Timezone-aware event timestamps
            - Process observation before network observation
            - Observation gap from 0 to 300 seconds

        Important:
            A matching tuple is not authenticated evidence.
            These records remain UNVERIFIED.

        No mutations, database access, or risk scoring.
        """

        # --------------------------------------------------------
        # SAFE PID NORMALIZATION
        # --------------------------------------------------------

        def safe_pid(value):
            if value is None or isinstance(value, bool):
                return None

            try:
                numeric = float(value)

                if not math.isfinite(numeric):
                    return None

                if not numeric.is_integer():
                    return None

                pid = int(numeric)

                if pid <= 0 or pid == 4:
                    return None

                return pid

            except (TypeError, ValueError, OverflowError):
                return None

        # --------------------------------------------------------
        # PROCESS CREATION TIME
        # --------------------------------------------------------

        def normalize_creation_time(value):
            if value is None or isinstance(value, bool):
                return None

            text = str(value).strip()

            if text.lower() in {
                "", "0", "0.0", "none",
                "unknown", "nan", "null"
            }:
                return None

            # Numeric epoch timestamps can be normalized
            # consistently even when one event provides
            # a string and another provides a number.
            try:
                number = float(text)

                if math.isfinite(number) and number > 0:
                    return f"epoch:{number:.6f}"

            except (TypeError, ValueError, OverflowError):
                pass

            # Accept timezone-aware ISO timestamps.
            try:
                parsed = datetime.fromisoformat(
                    text.replace("Z", "+00:00")
                )

                if parsed.tzinfo is None:
                    return None

                normalized = parsed.astimezone(
                    timezone.utc
                )

                return normalized.isoformat()

            except ValueError:
                return None

        # --------------------------------------------------------
        # OBSERVATION TIMESTAMP
        # --------------------------------------------------------

        def parse_timestamp(value):
            if not isinstance(value, str):
                return None

            try:
                parsed = datetime.fromisoformat(
                    value.strip().replace(
                        "Z", "+00:00"
                    )
                )

                if parsed.tzinfo is None:
                    return None

                return parsed.astimezone(
                    timezone.utc
                )

            except ValueError:
                return None

        # --------------------------------------------------------
        # SOURCE MODE FILTER
        # --------------------------------------------------------

        def eligible(event):
            metadata = self.safe_dict(
                event.get("metadata")
            )

            mode_values = [
                event.get("detection_mode"),
                event.get("mode"),
                metadata.get("detection_mode"),
                metadata.get("operating_mode"),
                metadata.get("mode"),
            ]

            for value in mode_values:
                mode = str(value or "").upper()

                if (
                    "SHADOW" in mode
                    or mode in {
                        "OFF", "DISABLED", "SIMULATION"
                    }
                ):
                    return False

            if (
                event.get("simulation_mode") is True
                or event.get("synthetic") is True
                or metadata.get("simulation_mode") is True
                or metadata.get("synthetic") is True
            ):
                return False

            return True

        # --------------------------------------------------------
        # EXTRACT VALID PROCESS / NETWORK OBSERVATIONS
        # --------------------------------------------------------

        processes = []
        connections = []
        seen_event_ids = set()

        for event in self.safe_list(events):
            if not isinstance(event, dict):
                continue

            event_id = str(
                event.get("event_id") or ""
            ).strip()

            if not event_id:
                continue

            if event_id in seen_event_ids:
                continue

            seen_event_ids.add(event_id)

            if not eligible(event):
                continue

            metadata = self.safe_dict(
                event.get("metadata")
            )

            device_id = str(
                event.get("device_id")
                or metadata.get("device_id")
                or ""
            ).strip()

            if not device_id:
                continue

            timestamp = parse_timestamp(
                event.get("timestamp")
            )

            if timestamp is None:
                continue

            category = str(
                event.get("event_category")
                or metadata.get("event_category")
                or ""
            ).upper()

            if not category:
                event_type = str(
                    event.get("event_type") or ""
                ).lower()

                if event_type.startswith("process"):
                    category = "PROCESS"

                elif event_type.startswith("network"):
                    category = "NETWORK"

            if category not in {
                "PROCESS",
                "NETWORK",
            }:
                continue

            detail = self.safe_dict(
                event.get(category.lower())
            )

            pid = safe_pid(
                detail.get("pid")
            )

            creation_value = (
                detail.get("create_time")
                if detail.get("create_time") is not None
                else detail.get("process_create_time")
            )

            create_time = normalize_creation_time(
                creation_value
            )

            if pid is None or create_time is None:
                continue

            common = {
                "event_id": event_id,
                "device_id": device_id,
                "pid": pid,
                "create_time": create_time,
                "timestamp": timestamp,
            }

            if category == "PROCESS":
                common["name"] = detail.get(
                    "name"
                )
                processes.append(common)

            elif category == "NETWORK":
                remote_ip = detail.get(
                    "remote_ip"
                )

                if not remote_ip:
                    continue

                common["remote_ip"] = remote_ip
                common["remote_port"] = detail.get(
                    "remote_port"
                )
                connections.append(common)

        # --------------------------------------------------------
        # GENERATE CANDIDATE LINKS
        # --------------------------------------------------------

        identity_links = []
        seen_links = set()

        for process in processes:
            for connection in connections:

                if (
                    process["device_id"]
                    != connection["device_id"]
                ):
                    continue

                if (
                    process["pid"]
                    != connection["pid"]
                ):
                    continue

                if (
                    process["create_time"]
                    != connection["create_time"]
                ):
                    continue

                if (
                    process["event_id"]
                    == connection["event_id"]
                ):
                    continue

                gap = (
                    connection["timestamp"]
                    - process["timestamp"]
                ).total_seconds()

                if gap < 0 or gap > 300:
                    continue

                identity = (
                    process["event_id"],
                    connection["event_id"],
                )

                if identity in seen_links:
                    continue

                seen_links.add(identity)

                identity_links.append({
                    "source_type": "PROCESS",
                    "target_type": "NETWORK",
                    "relationship":
                        "OBSERVED_CONNECTION",

                    "source_event_id":
                        process["event_id"],
                    "target_event_id":
                        connection["event_id"],

                    "device_id":
                        process["device_id"],
                    "pid": process["pid"],
                    "process_create_time":
                        process["create_time"],

                    "process_name":
                        process.get("name"),
                    "remote_ip":
                        connection["remote_ip"],
                    "remote_port":
                        connection["remote_port"],

                    "observation_gap_seconds":
                        gap,

                    "identity_match": True,

                    # Important: matching values are
                    # not authenticated attribution.
                    "verified": False,
                    "confidence_calibrated": False,
                    "confidence": 0,
                    "requires_validation": True,
                    "provenance_status":
                        "MATCHED_IDENTIFIERS_UNVERIFIED",
                    "evidence_source":
                        "RAW_TELEMETRY",
                })

        return identity_links

    # ============================================================
    # ENRICH INCIDENT
    # ============================================================

    def enrich(self, incident: dict) -> dict:
        incident = self.safe_dict(incident)

        events = self.safe_list(
            incident.get("timeline")
        )

        # ========================================================
        # EXISTING EVIDENCE EXTRACTION
        # ========================================================

        processes = self.extract_processes(
            events
        )

        files = self.extract_files(
            events
        )

        network = self.extract_network(
            events
        )

        registry = self.extract_registry(
            events
        )

        indicators = self.extract_indicators(
            events
        )

        iocs = self.build_iocs(
            files,
            network,
            registry,
        )

        # ========================================================
        # EXISTING RELATIONSHIPS
        # ========================================================

        relationships = self.build_relationships(
            processes,
            files,
            network,
            registry,
        )

        # Preserve original heuristic matching values
        # without representing them as verified confidence.
        for relationship in relationships:
            original_score = relationship.get(
                "confidence", 0
            )

            relationship["match_score"] = original_score
            relationship["confidence"] = 0
            relationship["verified"] = False
            relationship["provenance_status"] = "INFERRED"
            relationship["requires_validation"] = True

        # ========================================================
        # NEW: RAW-TELEMETRY IDENTITY LINKS
        # ========================================================

        identity_links = self.build_identity_links(
            events
        )

        # ========================================================
        # FINAL ENRICHED EVIDENCE
        # ========================================================

        return {
            "incident_id": incident.get(
                "incident_id"
            ),
            "agent": self.name,
            "enriched_at": self.now_iso(),

            # Original result fields retained.
            "processes": processes,
            "files": files,
            "network_connections": network,
            "registry_artifacts": registry,
            "indicators": indicators,
            "iocs": iocs,
            "relationships": relationships,

            # Supplemental candidate links.
            "identity_links": identity_links,

            "summary": {
                "process_count": len(processes),
                "file_count": len(files),
                "network_count": len(network),
                "registry_count": len(registry),
                "indicator_count": len(indicators),
                "relationship_count":
                    len(relationships),

                # New summary field.
                "identity_link_count":
                    len(identity_links),
            },
        }
