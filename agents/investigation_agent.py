
from collections import Counter
from datetime import datetime, timezone


class InvestigationAgent:
    """
    Evidence-grounded investigation.

    Historical severity and correlation are retained for
    context, not treated as confirmed attack evidence.
    """

    VALID_CATEGORIES = {
        "PROCESS", "FILE", "NETWORK", "REGISTRY"
    }

    VALID_SEVERITIES = {
        "MEDIUM", "HIGH", "CRITICAL"
    }

    def __init__(self):
        self.name = "InvestigationAgent"

    def safe_list(self, value):
        return value if isinstance(value, list) else []

    def safe_dict(self, value):
        return value if isinstance(value, dict) else {}

    def now_iso(self):
        return datetime.now(timezone.utc).isoformat()

    def get_category(self, event: dict) -> str:
        metadata = self.safe_dict(event.get("metadata"))

        category = str(
            event.get("event_category")
            or metadata.get("event_category")
            or ""
        ).upper()

        if category in self.VALID_CATEGORIES:
            return category

        event_type = str(
            event.get("event_type") or ""
        ).lower()

        if event_type.startswith("process"):
            return "PROCESS"
        if event_type.startswith("file"):
            return "FILE"
        if event_type.startswith("network"):
            return "NETWORK"
        if event_type.startswith(("registry", "startup")):
            return "REGISTRY"

        return "OTHER"

    @staticmethod
    def valid_pid(value):
        try:
            if value is None or isinstance(value, bool):
                return False

            pid = int(value)
            return pid > 0 and pid != 4
        except (TypeError, ValueError, OverflowError):
            return False

    def is_validation_incident(self, incident: dict) -> bool:
        context = self.safe_dict(
            self.safe_dict(incident).get("analysis_context")
        )
        return bool(context.get("validation_mode", False))

    def get_stored_detections(self, incident: dict) -> list:
        return [
            item
            for item in self.safe_list(
                self.safe_dict(incident).get("detections")
            )
            if isinstance(item, dict)
            and item.get("detected") is not False
            and item.get("stored_detection_record") is True
        ]

    def get_strong_detections(self, incident: dict) -> list:
        result = []

        for detection in self.get_stored_detections(incident):
            try:
                score = float(
                    detection.get("risk_score")
                    or detection.get("fusion_score")
                    or 0
                )
            except (TypeError, ValueError, OverflowError):
                score = 0.0

            severity = str(
                detection.get("severity") or "INFO"
            ).upper()

            try:
                signal_count = int(
                    detection.get("independent_signal_count")
                    or 0
                )
            except (TypeError, ValueError, OverflowError):
                signal_count = 0

            if (
                score >= 60
                and severity in {"HIGH", "CRITICAL"}
                and signal_count >= 2
            ):
                result.append(detection)

        return result

    def get_qualifying_events(self, incident: dict) -> list:
        incident = self.safe_dict(incident)
        validation_mode = self.is_validation_incident(incident)

        events = self.safe_list(
            incident.get("timeline")
        )

        result = []
        seen = set()

        for event in events:
            if not isinstance(event, dict):
                continue

            event_id = str(
                event.get("event_id") or ""
            ).strip()

            if not event_id or event_id in seen:
                continue

            seen.add(event_id)

            severity = str(
                event.get("severity") or "INFO"
            ).upper()

            if severity not in self.VALID_SEVERITIES:
                continue

            metadata = self.safe_dict(
                event.get("metadata")
            )

            mode = str(
                event.get("detection_mode")
                or event.get("mode")
                or metadata.get("detection_mode")
                or metadata.get("operating_mode")
                or metadata.get("mode")
                or ""
            ).upper()

            if not validation_mode:
                if (
                    "SHADOW" in mode
                    or mode in {
                        "OFF", "DISABLED", "SIMULATION"
                    }
                ):
                    continue

                if (
                    event.get("simulation_mode") is True
                    or metadata.get("simulation_mode") is True
                    or metadata.get("synthetic") is True
                ):
                    continue

            device_id = str(
                event.get("device_id")
                or metadata.get("device_id")
                or ""
            ).strip()

            if not device_id:
                continue

            category = self.get_category(event)

            if category not in self.VALID_CATEGORIES:
                continue

            if category in {"PROCESS", "NETWORK"}:
                data = self.safe_dict(
                    event.get(
                        "process"
                        if category == "PROCESS"
                        else "network"
                    )
                )

                if not self.valid_pid(data.get("pid")):
                    continue

            result.append(event)

        return result

    def collect_processes(self, events: list) -> list:
        processes = {}

        for event in events:
            if not isinstance(event, dict):
                continue

            process = self.safe_dict(
                event.get("process")
            )
            metadata = self.safe_dict(
                event.get("metadata")
            )

            if not self.valid_pid(process.get("pid")):
                continue

            pid = int(process["pid"])
            name = process.get("name")
            device = str(
                event.get("device_id")
                or metadata.get("device_id")
                or ""
            ).strip()

            create_time = (
                process.get("create_time")
                if process.get("create_time") is not None
                else process.get("process_create_time")
            )

            try:
                normalized_create_time = (
                    round(float(create_time), 6)
                    if create_time is not None
                    else None
                )
            except (TypeError, ValueError, OverflowError):
                normalized_create_time = (
                    str(create_time).strip()
                    if create_time is not None
                    else None
                )

            key = (
                device,
                pid,
                normalized_create_time,
            )

            if normalized_create_time is None:
                key = (
                    device,
                    pid,
                    str(name or "").lower(),
                    str(process.get("exe") or "").lower(),
                )

            item = processes.get(key)

            if item is None:
                item = {
                    "pid": pid,
                    "name": name,
                    "exe": process.get("exe"),
                    "device_id": device or None,
                    "process_create_time": normalized_create_time,
                    "identity_complete": bool(
                        device
                        and normalized_create_time is not None
                    ),
                    "identity_verified": False,
                    "observation_count": 0,
                    "event_ids": [],
                }
                processes[key] = item

            item["observation_count"] += 1

            event_id = event.get("event_id")
            if (
                event_id
                and event_id not in item["event_ids"]
            ):
                item["event_ids"].append(event_id)

            if name:
                item["name"] = name

            if process.get("exe"):
                item["exe"] = process.get("exe")

        return list(processes.values())

    # ============================================================
    # COLLECT FILES
    # ============================================================

    def collect_files(self, events: list) -> list:
        files = {}

        for event in events:
            if not isinstance(event, dict):
                continue

            file_data = self.safe_dict(
                event.get("file")
            )

            path = file_data.get("path")

            if not path:
                continue

            device = str(
                event.get("device_id") or ""
            )

            key = (device, str(path).lower())

            files[key] = {
                "name": file_data.get("name"),
                "path": path,
                "sha256": file_data.get("sha256"),
                "is_pe": file_data.get("is_pe"),
                "static_risk_score":
                    file_data.get("static_risk_score"),
                "malware_probability": None,
                "device_id": device,
            }

        return list(files.values())

    # ============================================================
    # COLLECT NETWORK CONNECTIONS
    # ============================================================

    def collect_network(self, events: list) -> list:
        connections = []
        seen = set()

        for event in events:
            if not isinstance(event, dict):
                continue

            network = self.safe_dict(
                event.get("network")
            )

            if not self.valid_pid(network.get("pid")):
                continue

            remote_ip = network.get("remote_ip")

            if not remote_ip:
                continue

            item = {
                "pid": int(network["pid"]),
                "process_name":
                    network.get("process_name"),
                "protocol": network.get("protocol"),
                "remote_ip": remote_ip,
                "remote_port":
                    network.get("remote_port"),
                "status": network.get("status"),
                "device_id": event.get("device_id"),
            }

            key = (
                str(item["device_id"]),
                item["pid"],
                str(item["remote_ip"]),
                str(item["remote_port"]),
                str(item["protocol"]),
            )

            if key not in seen:
                seen.add(key)
                connections.append(item)

        return connections

    # ============================================================
    # COLLECT REGISTRY
    # ============================================================

    def collect_registry(self, events: list) -> list:
        registry_items = []
        seen = set()

        for event in events:
            if not isinstance(event, dict):
                continue

            registry = self.safe_dict(
                event.get("registry")
            )

            if not registry:
                continue

            key = (
                registry.get("key")
                or registry.get("registry_key")
                or registry.get("path")
            )

            if not key:
                continue

            device = str(
                event.get("device_id") or ""
            )

            value_name = registry.get("value_name")

            identity = (
                device,
                str(key).lower(),
                str(value_name or "").lower(),
            )

            if identity in seen:
                continue

            seen.add(identity)

            registry_items.append({
                "key": key,
                "value_name": value_name,
                "value_data": (
                    registry.get("value_data")
                    or registry.get("data")
                    or registry.get("value")
                ),
                "device_id": device,
            })

        return registry_items

    # ============================================================
    # COLLECT INDICATORS
    # ============================================================

    def collect_indicators(self, events: list) -> list:
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

            groups = (
                process.get("behavior_indicators"),
                process.get("anomaly_indicators"),
                file_data.get("static_reasons"),
                metadata.get("behavior_indicators"),
                metadata.get("anomaly_indicators"),
            )

            for group in groups:
                if not isinstance(group, list):
                    continue

                for item in group:
                    value = str(item).strip()

                    if not value:
                        continue

                    normalized = value.lower()

                    if normalized not in seen:
                        seen.add(normalized)
                        indicators.append(value)

        return indicators

    # ============================================================
    # BUILD TIMELINE
    # ============================================================

    def build_timeline(self, events: list) -> list:
        timeline = []

        for event in events:
            if not isinstance(event, dict):
                continue

            timeline.append({
                "event_id": event.get("event_id"),
                "timestamp": (
                    event.get("timestamp")
                    if event.get("timestamp") is not None
                    else event.get("timestamp_unix")
                ),
                "event_type": event.get("event_type"),
                "source": event.get("source"),
                "severity": event.get("severity"),
                "category": self.get_category(event),
            })

        return timeline

    # ============================================================
    # EVIDENCE ASSESSMENT
    # ============================================================

    def evidence_assessment(self, incident: dict) -> dict:
        incident = self.safe_dict(incident)
        validation_mode = self.is_validation_incident(incident)

        qualifying = self.get_qualifying_events(
            incident
        )

        by_device = {}

        for event in qualifying:
            metadata = self.safe_dict(
                event.get("metadata")
            )

            device = str(
                event.get("device_id")
                or metadata.get("device_id")
                or ""
            )

            by_device.setdefault(
                device, set()
            ).add(self.get_category(event))

        diversity = max(
            (
                len(categories)
                for categories in by_device.values()
            ),
            default=0,
        )

        cross_category_corroboration = (
            len(qualifying) >= 2
            and diversity >= 2
        )

        indicator_event_ids = set()

        for event in qualifying:
            if self.collect_indicators([event]):
                indicator_event_ids.add(
                    str(event.get("event_id"))
                )

        strong_detections = self.get_strong_detections(
            incident
        )

        max_detection_risk = 0.0
        max_signal_count = 0

        for detection in strong_detections:
            try:
                max_detection_risk = max(
                    max_detection_risk,
                    float(
                        detection.get("risk_score")
                        or detection.get("fusion_score")
                        or 0
                    ),
                )
            except (TypeError, ValueError, OverflowError):
                pass

            try:
                max_signal_count = max(
                    max_signal_count,
                    int(
                        detection.get("independent_signal_count")
                        or 0
                    ),
                )
            except (TypeError, ValueError, OverflowError):
                pass

        detection_signal_corroboration = bool(
            strong_detections
            and max_signal_count >= 2
        )

        basic_corroboration = (
            cross_category_corroboration
            or (
                validation_mode
                and detection_signal_corroboration
            )
        )

        return {
            "qualifying_event_count": len(qualifying),
            "qualifying_category_count": diversity,
            "categories_by_device": {
                device: sorted(categories)
                for device, categories in by_device.items()
            },
            "indicator_event_count": len(indicator_event_ids),
            "stored_detection_count": len(
                self.get_stored_detections(incident)
            ),
            "strong_detection_count": len(strong_detections),
            "max_detection_risk": round(max_detection_risk, 4),
            "max_detection_signal_count": max_signal_count,
            "cross_category_corroboration": (
                cross_category_corroboration
            ),
            "detection_signal_corroboration": (
                detection_signal_corroboration
            ),
            "basic_corroboration": basic_corroboration,
            "causal_relationship_verified": False,
            "attack_confirmed": False,
            "validation_only": validation_mode,
            "production_eligible": not validation_mode,
            "policy": (
                "VALIDATION_DETECTION_EVIDENCE_V1"
                if validation_mode
                else "INVESTIGATION_EVIDENCE_V2"
            ),
        }

    def determine_priority(self, incident: dict) -> str:
        assessment = self.evidence_assessment(
            incident
        )

        detection_risk = float(
            assessment.get("max_detection_risk") or 0
        )

        if detection_risk >= 80:
            return "IMMEDIATE"

        if detection_risk >= 60:
            return "HIGH"

        if not assessment["basic_corroboration"]:
            return "LOW"

        if assessment["indicator_event_count"] >= 2:
            return "NORMAL"

        return "LOW"

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

        assessment = self.evidence_assessment(
            incident
        )

        findings.append(
            f"{len(events)} recorded events were reviewed. "
            f"{assessment['qualifying_event_count']} "
            "met preliminary evidence criteria."
        )

        if assessment.get(
            "cross_category_corroboration",
            False,
        ):
            findings.append(
                "Two or more qualifying telemetry categories "
                "were recorded on the same device. "
                "A causal relationship is not verified."
            )

        elif assessment.get(
            "detection_signal_corroboration",
            False,
        ):
            findings.append(
                "Stored detector evidence contains two or more "
                "independent supporting signals. The incident "
                "remains single-category telemetry, and a causal "
                "cross-category relationship is not verified."
            )

        else:
            findings.append(
                "Insufficient independent corroboration for "
                "cross-category confirmation."
            )

        if processes:
            observation_count = sum(
                int(process.get("observation_count") or 1)
                for process in processes
                if isinstance(process, dict)
            )

            findings.append(
                f"{len(processes)} canonical process entity/entities "
                f"represent {observation_count} recorded process "
                "observation(s)."
            )

        if files:
            findings.append(
                f"{len(files)} qualifying file "
                "artifact(s) recorded."
            )

        if network:
            findings.append(
                f"{len(network)} qualifying network "
                "endpoint(s) recorded."
            )

        if registry:
            findings.append(
                f"{len(registry)} qualifying registry "
                "artifact(s) recorded."
            )

        if indicators:
            findings.append(
                f"{len(indicators)} reported indicators "
                "were retained for analyst validation."
            )

        findings.append(
            "No attack confirmation or containment "
            "authorization is issued by this agent."
        )

        return findings

    # ============================================================
    # INVESTIGATE INCIDENT
    # ============================================================

    def investigate(self, incident: dict) -> dict:
        incident = self.safe_dict(incident)
        validation_mode = self.is_validation_incident(incident)

        events = [
            event
            for event in self.safe_list(
                incident.get("timeline")
            )
            if isinstance(event, dict)
        ]

        qualifying = self.get_qualifying_events(
            incident
        )

        # In validation mode we retain all recorded telemetry for
        # analyst context while still keeping the evidence gate and
        # attack-confirmation fields explicit.
        analysis_events = (
            events if validation_mode else qualifying
        )

        processes = self.collect_processes(analysis_events)
        files = self.collect_files(analysis_events)
        network = self.collect_network(analysis_events)
        registry = self.collect_registry(analysis_events)
        indicators = self.collect_indicators(analysis_events)

        timeline = self.build_timeline(events)

        category_counts = Counter(
            self.get_category(event)
            for event in events
        )

        findings = self.generate_findings(
            incident,
            events,
            processes,
            files,
            network,
            registry,
            indicators,
        )

        assessment = self.evidence_assessment(
            incident
        )

        strong_detections = self.get_strong_detections(
            incident
        )

        if strong_detections:
            strongest = max(
                strong_detections,
                key=lambda item: float(
                    item.get("risk_score")
                    or item.get("fusion_score")
                    or 0
                ),
            )

            findings.insert(
                0,
                (
                    "Persisted detector evidence: "
                    f"{strongest.get('engine')} reported "
                    f"{strongest.get('threat_type')} at "
                    f"{strongest.get('severity')} severity "
                    f"(risk/fusion score "
                    f"{strongest.get('risk_score') or strongest.get('fusion_score')})."
                ),
            )

        priority = self.determine_priority(
            incident
        )

        response_review_required = bool(
            strong_detections
            and float(
                assessment.get("max_detection_risk") or 0
            ) >= 60
        )

        return {
            "incident_id": incident.get("incident_id"),
            "agent": self.name,
            "investigated_at": self.now_iso(),
            "priority": priority,
            "incident_score": incident.get(
                "correlation_score", 0
            ),
            "incident_severity": incident.get(
                "severity", "INFO"
            ),
            "event_count": len(events),
            "qualifying_event_count": len(qualifying),
            "category_counts": dict(category_counts),
            "processes": processes,
            "files": files,
            "network_connections": network,
            "registry_artifacts": registry,
            "indicators": indicators,
            "detections": self.get_stored_detections(incident),
            "strong_detections": strong_detections,
            "findings": findings,
            "timeline": timeline,
            "evidence_assessment": assessment,
            "requires_response": response_review_required,
            "response_review_only": response_review_required,
            "attack_confirmed": False,
            "confidence_calibrated": False,
            "validation_only": validation_mode,
            "production_eligible": not validation_mode,
        }

