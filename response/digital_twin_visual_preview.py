
"""
SENTINEL-X Evidence-Aware Digital Twin Preview V2

READ ONLY:
- Does not access or modify the production database.
- Does not create incidents, SOC cases or approvals.
- Does not execute real endpoint actions.
- Maintains the existing API response contract.
- Uses deterministic heuristics, not trained AI efficacy models.
"""

from copy import deepcopy

from response.endpoint_digital_twin import EndpointDigitalTwin
from response.digital_twin_response_planner import (
    DigitalTwinResponsePlanner,
)
from response.digital_twin_simulator import DigitalTwinSimulator
from response.digital_twin_risk_predictor import (
    DigitalTwinRiskPredictor,
)
from response.digital_twin_decision_integration import (
    DigitalTwinDecisionIntegration,
)


CATEGORIES = (
    "processes",
    "files",
    "network_connections",
    "registry_artifacts",
)

CATEGORY_MAP = {
    "PROCESS": ("processes", "process"),
    "FILE": ("files", "file"),
    "NETWORK": ("network_connections", "network"),
    "REGISTRY": ("registry_artifacts", "registry"),
}


def obj(value):
    return value if isinstance(value, dict) else {}


def items(value):
    return [
        entry for entry in value
        if isinstance(entry, dict)
    ] if isinstance(value, list) else []


def valid_pid(value):
    try:
        pid = int(value)
        return pid if pid > 4 else None
    except (TypeError, ValueError):
        return None


def clean_mode(value):
    return str(value or "UNKNOWN").upper()


def untrusted_mode(value):
    text = clean_mode(value)
    return (
        "SHADOW" in text
        or "LEGACY_UNVERIFIED" in text
    )


def entity_key(category, entry):
    entry = obj(entry)
    device = entry.get("device_id")

    if category == "processes":
        pid = valid_pid(entry.get("pid"))
        created = (
            entry.get("process_create_time")
            or entry.get("create_time")
        )
        if device and pid and created:
            return (
                "PROCESS", str(device),
                str(pid), str(created),
            )

    if category == "files":
        if device and entry.get("sha256"):
            return (
                "FILE", str(device),
                str(entry["sha256"]),
            )
        if device and entry.get("path"):
            return (
                "FILE_PATH", str(device),
                str(entry["path"]),
            )

    if category == "network_connections":
        event_id = (
            entry.get("connection_id")
            or entry.get("event_id")
        )
        if device and event_id:
            return (
                "NETWORK",
                str(device),
                str(event_id),
            )

    if category == "registry_artifacts":
        if device and entry.get("key"):
            return (
                "REGISTRY", str(device),
                str(entry["key"]),
                str(entry.get("value_name")),
            )

    return None


def deduplicate(category, values):
    result = []
    seen = set()

    for entry in items(values):
        identity = entity_key(category, entry)

        if identity and identity in seen:
            continue

        if identity:
            seen.add(identity)

        result.append(deepcopy(entry))

    return result[:100]


class DigitalTwinVisualPreview:

    def __init__(self):
        self.planner = DigitalTwinResponsePlanner()
        self.simulator = DigitalTwinSimulator()
        self.predictor = DigitalTwinRiskPredictor()
        self.integration = DigitalTwinDecisionIntegration()

    def evidence_from(self, incident, intelligence):
        incident = obj(incident)
        intelligence = obj(intelligence)

        coordinated = obj(
            intelligence.get("coordinated_analysis")
        )
        context = obj(coordinated.get("context"))

        enriched = (
            obj(coordinated.get("evidence"))
            or obj(context.get("evidence"))
        )

        evidence = {
            category: deduplicate(
                category,
                enriched.get(category),
            )
            for category in CATEGORIES
        }

        observations = {
            category: []
            for category in CATEGORIES
        }

        for event in items(
            incident.get("timeline")
        )[:200]:
            category_name = str(
                event.get("event_category")
                or event.get("event_type")
                or ""
            ).upper()

            metadata = obj(event.get("metadata"))

            for keyword, (category, field) in (
                CATEGORY_MAP.items()
            ):
                if keyword not in category_name:
                    continue

                part = (
                    obj(event.get(field))
                    or obj(metadata.get(field))
                )

                if part:
                    observations[category].append({
                        **deepcopy(part),
                        "event_id": event.get("event_id"),
                        "device_id": (
                            event.get("device_id")
                            or part.get("device_id")
                        ),
                        "source_mode": metadata.get(
                            "detection_mode",
                            "UNKNOWN",
                        ),
                        "observed_severity":
                            event.get("severity"),
                    })
                break

        for category in CATEGORIES:
            if not evidence[category]:
                evidence[category] = deduplicate(
                    category,
                    observations[category],
                )

        # Historical malware probabilities must not be
        # reused when their feature extraction version
        # is incompatible with the current runtime.
        for file_item in evidence["files"]:
            file_item.pop("malware_probability", None)

        return evidence

    def qualifying_event_ids(self, incident):
        """
        Conservative source-level screening.

        This is NOT a replacement for the actual
        evidence validator. Global validation is still
        required before plan evaluation.

        An event with an unknown category, missing ID,
        low severity or SHADOW designation does not
        become a qualifying target reference.
        """
        qualifying = set()

        for event in items(
            obj(incident).get("timeline")
        ):
            event_id = event.get("event_id")

            severity = str(
                event.get("severity") or ""
            ).upper()

            metadata = obj(event.get("metadata"))

            mode = (
                metadata.get("detection_mode")
                or event.get("detection_mode")
                or event.get("source_mode")
            )

            if (
                event_id is not None
                and severity in (
                    "MEDIUM", "HIGH", "CRITICAL"
                )
                and not untrusted_mode(mode)
            ):
                qualifying.add(str(event_id))

        return qualifying

    def target_eligible(
        self,
        entity,
        timeline_present,
        qualifying_ids,
    ):
        """
        Enriched entities without verified linkage are
        not promoted to response targets.

        Synthetic unit fixtures may omit a timeline;
        their eligibility is controlled separately
        by explicitly injected test validation.
        """
        entity = obj(entity)

        if untrusted_mode(entity.get("source_mode")):
            return False

        severity = str(
            entity.get("observed_severity") or ""
        ).upper()

        if severity in ("INFO", "LOW"):
            return False

        if timeline_present:
            event_id = entity.get("event_id")
            return (
                event_id is not None
                and str(event_id) in qualifying_ids
            )

        return True

    def hypothetical_actions(
        self,
        twin,
        incident=None,
    ):
        incident = obj(incident)
        timeline = items(incident.get("timeline"))
        qualifying = self.qualifying_event_ids(
            incident
        )
        timeline_present = bool(timeline)

        proposed = []
        represented_categories = set()
        represented_devices = set()

        # Stable identity must include PID, creation
        # time and device. The legacy simulator still
        # matches by PID, so this remains virtual only.
        for process in twin.processes:
            pid = valid_pid(process.get("pid"))
            created = (
                process.get("process_create_time")
                or process.get("create_time")
            )
            device = process.get("device_id")

            if not (pid and created and device):
                continue

            if not self.target_eligible(
                process, timeline_present, qualifying
            ):
                continue

            duplicates = sum(
                valid_pid(other.get("pid")) == pid
                for other in twin.processes
            )

            if duplicates != 1:
                continue

            proposed.append({
                "action_type": "TERMINATE_PROCESS",
                "target": {"pid": pid},
                "scenario_only": True,
                "evidence_reference":
                    process.get("event_id"),
                "scenario_basis":
                    "Observed process with device, "
                    "PID and creation-time identity.",
            })

            represented_categories.add("PROCESS")
            represented_devices.add(str(device))
            break

        for file_item in twin.files:
            path = file_item.get("path")
            device = file_item.get("device_id")

            if not (
                isinstance(path, str)
                and path.strip()
                and device
            ):
                continue

            if not self.target_eligible(
                file_item, timeline_present, qualifying
            ):
                continue

            proposed.append({
                "action_type": "QUARANTINE_FILE",
                "target": {
                    "path": path,
                    "sha256": file_item.get("sha256"),
                },
                "scenario_only": True,
                "evidence_reference":
                    file_item.get("event_id"),
                "scenario_basis":
                    "Observed file with path and device.",
            })

            represented_categories.add("FILE")
            represented_devices.add(str(device))
            break

        for connection in twin.network_connections:
            address = connection.get("remote_ip")
            device = connection.get("device_id")

            if not (
                isinstance(address, str)
                and address.strip()
                and address not in (
                    "None", "0.0.0.0"
                )
                and device
            ):
                continue

            if not self.target_eligible(
                connection, timeline_present, qualifying
            ):
                continue

            proposed.append({
                "action_type": "BLOCK_NETWORK",
                "target": {
                    "remote_ip": address,
                    "remote_port":
                        connection.get("remote_port"),
                },
                "scenario_only": True,
                "evidence_reference":
                    connection.get("event_id"),
                "scenario_basis":
                    "Observed network endpoint on "
                    "an identified device.",
            })

            represented_categories.add("NETWORK")
            represented_devices.add(str(device))
            break

        for artifact in twin.persistence_artifacts:
            key = artifact.get("key")
            device = artifact.get("device_id")

            if not (key and device):
                continue

            if not self.target_eligible(
                artifact, timeline_present, qualifying
            ):
                continue

            proposed.append({
                "action_type":
                    "REMEDIATE_PERSISTENCE",
                "target": {
                    "key": key,
                    "value_name":
                        artifact.get("value_name"),
                },
                "scenario_only": True,
                "evidence_reference":
                    artifact.get("event_id"),
                "scenario_basis":
                    "Observed persistence artifact "
                    "on an identified device.",
            })

            represented_categories.add("REGISTRY")
            represented_devices.add(str(device))
            break

        # Do not automatically add isolation for a
        # single uncorroborated entity. Even when this
        # condition passes, isolation is hypothetical.
        if (
            len(represented_categories) >= 2
            and len(represented_devices) == 1
            and proposed
        ):
            proposed.append({
                "action_type": "ISOLATE_ENDPOINT",
                "target": {},
                "scenario_only": True,
                "scenario_basis":
                    "Hypothetical comparison for "
                    "corroborated multi-category "
                    "activity on one device.",
            })

        return proposed

    def playback(self, source, plan):
        working = self.planner.build_twin(source)

        initial = self.predictor.calculate_predicted_risk(
            working
        )

        frames = [{
            "step": 0,
            "action_type": "BASELINE",
            "status": "OBSERVED_TWIN_BASELINE",
            "success": True,
            "risk_score":
                initial["predicted_risk_score"],
            "risk_components": initial["components"],
            "state": working.get_state_summary(),
            "virtual_only": True,
        }]

        for position, action in enumerate(
            items(plan.get("actions")), 1
        ):
            try:
                result = self.simulator.simulate_action(
                    working,
                    action.get("action_type"),
                    obj(action.get("target")),
                )
            except Exception as error:
                result = {
                    "success": False,
                    "status": "SIMULATION_ERROR",
                    "details": type(error).__name__,
                }

            projection = (
                self.predictor.calculate_predicted_risk(
                    working
                )
            )

            frames.append({
                "step": position,
                "action_type":
                    action.get("action_type"),
                "status":
                    result.get("status", "UNKNOWN"),
                "success":
                    result.get("success") is True,
                "risk_score":
                    projection["predicted_risk_score"],
                "risk_components":
                    projection["components"],
                "state":
                    working.get_state_summary(),
                "virtual_only": True,
            })

        return frames

    def evaluate(self, incident, intelligence):
        incident = obj(incident)
        intelligence = obj(intelligence)

        incident_id = str(
            incident.get("incident_id") or ""
        )

        validation = obj(
            intelligence.get("evidence_validation")
        )

        status = str(
            intelligence.get("status") or "UNKNOWN"
        ).upper()

        evidence_passed = (
            validation.get("passed") is True
        )
        investigation_complete = (
            status == "COMPLETED"
        )

        eligible = (
            evidence_passed
            and investigation_complete
        )

        evidence = self.evidence_from(
            incident,
            intelligence,
        )

        twin = EndpointDigitalTwin(
            incident_id=incident_id,
            initial_risk_score=0,
        )

        twin.load_evidence(evidence)

        baseline_projection = (
            self.predictor.calculate_predicted_risk(
                twin
            )
        )

        baseline = baseline_projection[
            "predicted_risk_score"
        ]

        twin.initial_risk_score = baseline
        twin.initial_risk_level = (
            twin.score_to_level(baseline)
        )
        twin.update_risk(baseline)

        ranked = []
        candidate_actions = []

        if eligible:
            candidate_actions = (
                self.hypothetical_actions(
                    twin,
                    incident,
                )
            )

            plans = (
                self.integration.build_response_plans(
                    candidate_actions
                )
                if candidate_actions
                else []
            )

            if plans:
                comparison = (
                    self.planner.compare_plans(
                        twin,
                        plans,
                    )
                )

                ranked = deepcopy(
                    comparison.get("ranked_plans", [])
                )

                for plan in ranked:
                    frames = self.playback(twin, plan)

                    plan["playback"] = frames
                    plan["hypothetical"] = True
                    plan["approval_eligible"] = False
                    plan["response_authorized"] = False

                    plan["score_type"] = (
                        "HEURISTIC_RANKING_SCORE"
                    )

                    plan["reduction_semantics"] = (
                        "REDUCTION_OF_MODELED_COMPONENTS"
                    )

                    plan["baseline_components"] = (
                        baseline_projection["components"]
                    )

                    plan["residual_components"] = (
                        frames[-1]["risk_components"]
                    )

                    plan["virtual_action_failures"] = [
                        frame["action_type"]
                        for frame in frames[1:]
                        if not frame["success"]
                    ]

                    plan["limitations"] = [
                        "Not a learned causal outcome.",
                        "No real containment performed.",
                        "Risk reduction is model-only.",
                    ]

        if not investigation_complete:
            decision = "INCOMPLETE_INVESTIGATION"
        elif not evidence_passed:
            decision = (
                "INSUFFICIENT_AUTHORITATIVE_EVIDENCE"
            )
        elif not ranked:
            decision = "NO_EVALUABLE_VIRTUAL_PLAN"
        else:
            decision = (
                "HYPOTHETICAL_PLAN_COMPARISON_ONLY"
            )

        evidence_counts = {
            category: len(items(evidence[category]))
            for category in CATEGORIES
        }

        return {
            "incident_id": incident_id,
            "source":
                "HISTORICAL_OBSERVATIONAL_EVIDENCE",
            "mode": "HYPOTHETICAL_READ_ONLY",
            "preview_only": True,
            "simulation_mode": True,
            "real_endpoint_modified": False,
            "soc_case_created": False,
            "approval_eligible": False,
            "response_authorized": False,

            "model_type":
                "HEURISTIC_DIGITAL_TWIN_V1",

            "score_note": (
                "Heuristic virtual risk components; "
                "not attack probabilities or "
                "verified mitigation outcomes."
            ),

            "investigation_status": status,
            "evidence_validation": validation,
            "investigation_risk_score":
                intelligence.get("risk_score"),

            "initial_risk_score": baseline,
            "baseline_risk_components":
                baseline_projection["components"],
            "baseline_risk_explanation":
                baseline_projection[
                    "component_explanation"
                ],

            "risk_semantics":
                "MODELED_HEURISTIC_COMPONENTS",

            "plan_evaluation_eligible": eligible,
            "candidate_actions":
                deepcopy(candidate_actions),
            "plans_evaluated": len(ranked),
            "ranked_plans": ranked,
            "best_plan":
                ranked[0] if ranked else None,
            "decision": decision,
            "evidence_counts": evidence_counts,

            "limitations": [
                "Evidence may be observational or uncertain.",
                "Global evidence validation is distinct "
                "from per-entity linkage quality.",
                "A virtual success is not real containment.",
                "Zero modeled risk does not prove safety.",
                "Scores are heuristic, not AI outcome "
                "probabilities.",
                "No SOC case or real response created.",
            ],
        }
