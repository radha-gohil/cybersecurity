
"""
SENTINEL-X Synthetic SOC API

Runs independently at http://127.0.0.1:8013/api/v1

No production DB imports, reads, or writes.
No real endpoint actions.
GET and OPTIONS only.
Ollama is optional and localhost-only.

Run from repository root:
    python tests/synthetic_soc_api.py
"""

import json
import re
import sys
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from response.digital_twin_visual_preview import (
    DigitalTwinVisualPreview,
)

HOST = "127.0.0.1"
PORT = 8013
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "qwen3:4b"

LAB_IDS = (
    "LAB-HIGH",
    "LAB-LOW",
    "LAB-SHADOW",
    "LAB-INCOMPLETE",
)


def fixture(name):
    high = name == "LAB-HIGH"
    shadow = name == "LAB-SHADOW"
    incomplete = name == "LAB-INCOMPLETE"
    network_enabled = name != "LAB-LOW"

    device = f"{name}-DEVICE"
    source_mode = (
        "SHADOW_VALIDATION"
        if shadow else "SYNTHETIC_TEST"
    )
    score = (
        85 if high else
        25 if name == "LAB-LOW" else
        90 if shadow else 70
    )

    process_event = f"{name}-PROCESS"
    network_event = f"{name}-NETWORK"

    process = {
        "pid": 5252,
        "process_create_time": "2026-01-01T10:00:00Z",
        "device_id": device,
        "event_id": process_event,
        "name": "synthetic-process.exe",
        "behavior_score": score,
        "combined_threat_score": score,
        "source_mode": source_mode,
    }

    network = {
        "device_id": device,
        "event_id": network_event,
        "remote_ip": "198.51.100.20",
        "remote_port": 443,
        "source_mode": source_mode,
    }

    timeline = [{
        "event_id": process_event,
        "event_category": "PROCESS",
        "device_id": device,
        "severity": "HIGH",
        "metadata": {"detection_mode": source_mode},
    }]

    if network_enabled:
        timeline.append({
            "event_id": network_event,
            "event_category": "NETWORK",
            "device_id": device,
            "severity": "INFO" if incomplete else "HIGH",
            "metadata": {"detection_mode": source_mode},
        })

    evidence = {
        "processes": [process],
        "files": [],
        "network_connections":
            [network] if network_enabled else [],
        "registry_artifacts": [],
    }

    incident = {
        "incident_id": name,
        "title": {
            "LAB-HIGH": "Synthetic multistage observation",
            "LAB-LOW": "Synthetic process-only observation",
            "LAB-SHADOW": "Synthetic SHADOW exclusion",
            "LAB-INCOMPLETE": "Synthetic incomplete investigation",
        }[name],
        "severity": "HIGH",
        "status": "AWAITING_INVESTIGATION",
        "device_id": device,
        "event_count": len(timeline),
        "timeline": timeline,
        "soc_case_exists": name == "LAB-HIGH",
        "simulation_mode": True,
        "synthetic": True,
    }

    passed = not incomplete
    intelligence = {
        "status": "INCOMPLETE" if incomplete else "COMPLETED",
        "risk_score": None,
        "evidence_validation": {
            "passed": passed,
            "validation_policy":
                "INJECTED_SYNTHETIC_FIXTURE",
            "authoritative_event_count":
                len(timeline) if passed else 1,
            "rejected_event_count":
                0 if passed else 1,
            "reasons":
                [] if passed else [
                    "Insufficient synthetic corroboration."
                ],
            "categories_by_device": {
                device: [
                    event["event_category"]
                    for event in timeline
                ]
            } if passed else {},
        },
        "coordinated_analysis": {
            "evidence": deepcopy(evidence),
            "agent_outputs": {},
        },
        "synthetic_fixture": True,
    }

    return incident, intelligence


ENGINE = DigitalTwinVisualPreview()
RECORDS = {}

for lab_id in LAB_IDS:
    incident, intelligence = fixture(lab_id)
    twin = ENGINE.evaluate(incident, intelligence)
    RECORDS[lab_id] = {
        "incident": incident,
        "intelligence": intelligence,
        "twin": twin,
    }


def synthetic_case():
    """
    A fabricated, explicitly labeled SOC case for
    testing the existing Approvals read-only page.
    No case is persisted to a database.
    """
    return {
        "incident_id": "LAB-HIGH",
        "status": "AWAITING_ANALYST_REVIEW",
        "simulation_mode": True,
        "synthetic": True,
        "ticket": {
            "ticket_id": "LAB-TICKET-001",
            "approval_status": "PENDING",
            "priority": "HIGH",
        },
        "response_actions": [{
            "action_id": "LAB-ACTION-001",
            "action_type": "BLOCK_NETWORK",
            "description":
                "Synthetic approval-review record only.",
            "target": {
                "remote_ip": "198.51.100.20",
                "remote_port": 443,
            },
            "severity": "HIGH",
            "impact": "LOW",
            "approval_status": "PENDING",
            "reason":
                "Demonstration of the read-only review UI.",
            "synthetic": True,
        }],
    }


def scene_facts(record):
    """
    These statements are derived from recorded fields.
    LLM output cannot replace them with invented facts.
    """
    twin = record["twin"]
    intelligence = record["intelligence"]
    validation = intelligence["evidence_validation"]

    scenes = [{
        "kind": "EVIDENCE",
        "focus": "endpoint",
        "heading": "Review the observations",
        "text": (
            f"Recorded virtual entities: "
            f"{twin['evidence_counts']['processes']} process, "
            f"{twin['evidence_counts']['network_connections']} "
            f"network connection, "
            f"{twin['evidence_counts']['files']} file and "
            f"{twin['evidence_counts']['registry_artifacts']} "
            f"registry artifact."
        ),
        "score": twin["initial_risk_score"],
        "components": twin["baseline_risk_components"],
        "state": None,
        "success": None,
    }]

    scenes.append({
        "kind": "VALIDATION",
        "focus": "endpoint",
        "heading": "Validate the investigation",
        "text": (
            "Synthetic fixture validation flag: "
            f"{'passed' if validation['passed'] else 'failed'}. "
            f"Investigation: {intelligence['status']}. "
            "This flag was injected for testing and was not "
            "produced by the real evidence validator."
        ),
        "score": twin["initial_risk_score"],
        "components": twin["baseline_risk_components"],
        "state": None,
        "success": validation["passed"],
    })

    if twin["plans_evaluated"] == 0:
        scenes.append({
            "kind": "BLOCKED",
            "focus": "endpoint",
            "heading": "No protection scenario",
            "text": (
                "The Digital Twin returned no evaluable "
                "protection plan. No virtual action is "
                "presented as an authorized response."
            ),
            "score": twin["initial_risk_score"],
            "components": twin["baseline_risk_components"],
            "state": None,
            "success": False,
        })
    else:
        plan = twin["best_plan"]

        for frame in plan.get("playback", []):
            action = str(frame.get("action_type") or "UNKNOWN")
            focus = (
                "process" if "PROCESS" in action
                else "file" if "FILE" in action
                else "network" if (
                    "NETWORK" in action or "ISOLATE" in action
                )
                else "registry" if "PERSISTENCE" in action
                else "endpoint"
            )

            if action == "BASELINE":
                heading = "Establish the virtual baseline"
                statement = (
                    "This is the cloned endpoint before "
                    "the virtual response actions."
                )
            else:
                heading = action.replace("_", " ").title()
                statement = (
                    f"The simulator recorded "
                    f"{frame.get('status', 'UNKNOWN')} for "
                    f"{action}. Virtual success: "
                    f"{frame.get('success') is True}. "
                    "This is not a real endpoint outcome."
                )

            scenes.append({
                "kind": "SIMULATION",
                "focus": focus,
                "heading": heading,
                "text": statement,
                "score": frame.get("risk_score"),
                "components": frame.get("risk_components", {}),
                "state": frame.get("state"),
                "success": frame.get("success"),
            })

    scenes.append({
        "kind": "REPORT",
        "focus": "endpoint",
        "heading": "Interpret the result",
        "text": (
            f"Plans evaluated: {twin['plans_evaluated']}. "
            "All projections are heuristic. Zero modeled "
            "risk does not prove elimination of a threat. "
            "No SOC promotion, approval or real response "
            "was executed."
        ),
        "score": twin["initial_risk_score"],
        "components": twin["baseline_risk_components"],
        "state": None,
        "success": None,
    })

    return scenes


def optional_llm_direction(scenes):
    """
    Ollama only selects presentation emphasis and pacing.
    It cannot write new actions, scores, outcomes or text.
    Timeout or invalid output => deterministic fallback.
    """
    allowed_emphasis = {"action", "risk", "state"}
    allowed_pace = {"slow", "normal", "fast"}

    fallback = [{
        "emphasis": "action",
        "pace": "normal",
    } for _ in scenes]

    prompt = (
        "You direct a defensive cybersecurity EDUCATIONAL "
        "storyboard. Return only a JSON object: "
        '{"directions":[{"emphasis":"action","pace":"normal"}]}. '
        "Use exactly one direction per scene in order. "
        "Allowed emphasis: action,risk,state. "
        "Allowed pace: slow,normal,fast. "
        "Do not write narration, claims or commands. "
        "Scene headings: " +
        json.dumps([scene["heading"] for scene in scenes])
    )

    body = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
    }).encode("utf-8")

    try:
        request = Request(
            OLLAMA_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=4) as response:
            result = json.load(response)

        parsed = json.loads(result.get("response", "{}"))
        directions = parsed.get("directions")

        if (
            not isinstance(directions, list)
            or len(directions) != len(scenes)
        ):
            return fallback, "DETERMINISTIC_FALLBACK"

        safe_directions = []

        for item in directions:
            if not isinstance(item, dict):
                return fallback, "DETERMINISTIC_FALLBACK"

            emphasis = item.get("emphasis")
            pace = item.get("pace")

            if (
                emphasis not in allowed_emphasis
                or pace not in allowed_pace
            ):
                return fallback, "DETERMINISTIC_FALLBACK"

            safe_directions.append({
                "emphasis": emphasis,
                "pace": pace,
            })

        return safe_directions, "LOCAL_OLLAMA"
    except Exception:
        return fallback, "DETERMINISTIC_FALLBACK"


def storyboard(lab_id):
    record = RECORDS[lab_id]
    scenes = scene_facts(record)
    directions, provider = optional_llm_direction(scenes)

    for scene, direction in zip(scenes, directions):
        scene["direction"] = direction

    return {
        "incident_id": lab_id,
        "source": "ISOLATED_SYNTHETIC_FIXTURE",
        "synthetic": True,
        "llm_provider": provider,
        "validation_injected": True,
        "preview_only": True,
        "response_authorized": False,
        "scenes": scenes,
    }


class Handler(BaseHTTPRequestHandler):

    def send_json(self, payload, status=200):
        encoded = json.dumps(
            payload, default=str
        ).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type", "application/json"
        )
        self.send_header(
            "Content-Length", str(len(encoded))
        )
        self.send_header(
            "Cache-Control", "no-store"
        )

        # Explicit local Vite origins only.
        origin = self.headers.get("Origin", "")
        if origin in (
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:5174",
            "http://localhost:5174",
        ):
            self.send_header(
                "Access-Control-Allow-Origin", origin
            )
            self.send_header("Vary", "Origin")

        self.send_header(
            "Access-Control-Allow-Methods", "GET, OPTIONS"
        )
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type"
        )
        self.send_header(
            "X-Content-Type-Options", "nosniff"
        )
        self.end_headers()
        self.wfile.write(encoded)

    def do_OPTIONS(self):
        self.send_json({})

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = unquote(parsed.path)
        prefix = "/api/v1/"

        if not path.startswith(prefix):
            return self.send_json(
                {"detail": "Not found"}, 404
            )

        route = path[len(prefix):].strip("/")
        parts = route.split("/")

        if route == "health":
            return self.send_json({
                "status": "HEALTHY",
                "service": "ISOLATED_SYNTHETIC_SOC",
                "simulation_mode": True,
                "real_response_execution": False,
            })

        if route == "detected-incidents":
            return self.send_json({
                "count": len(RECORDS),
                "incidents": [
                    entry["incident"]
                    for entry in RECORDS.values()
                ],
                "simulation_mode": True,
                "synthetic": True,
            })

        if route == "cases":
            return self.send_json({
                "count": 1,
                "cases": [synthetic_case()],
                "synthetic": True,
            })

        if route == "dashboard/summary":
            return self.send_json({
                "total_detected_incidents": len(RECORDS),
                "persistent_soc_cases": 1,
                "pending_approvals": 1,
                "simulation_mode": True,
                "synthetic": True,
            })

        if len(parts) >= 2 and parts[0] == "detected-incidents":
            lab_id = parts[1]
            record = RECORDS.get(lab_id)

            if record is None:
                return self.send_json(
                    {"detail": "Unknown fixture"}, 404
                )

            if len(parts) == 2:
                return self.send_json(record["incident"])

            if parts[2:] == ["analysis-preview"]:
                return self.send_json({
                    "incident_id": lab_id,
                    "preview_only": True,
                    "soc_case_created": False,
                    "intelligence": record["intelligence"],
                    "synthetic": True,
                })

            if parts[2:] == ["digital-twin-preview"]:
                return self.send_json(record["twin"])

        if len(parts) >= 2 and parts[0] == "cases":
            if parts[1] != "LAB-HIGH":
                return self.send_json(
                    {"detail": "Case not found"}, 404
                )

            case = synthetic_case()

            if len(parts) == 2:
                return self.send_json(case)

            if parts[2:] == ["responses"]:
                return self.send_json({
                    "response_actions": case["response_actions"],
                    "synthetic": True,
                })

            if parts[2:] == ["digital-twin"]:
                return self.send_json({
                    "incident_id": "LAB-HIGH",
                    "decision": RECORDS[
                        "LAB-HIGH"
                    ]["twin"],
                    "simulation_mode": True,
                    "real_endpoint_modified": False,
                    "synthetic": True,
                })

        if (
            len(parts) == 2
            and parts[0] == "ai-storyboard"
            and parts[1] in RECORDS
        ):
            return self.send_json(storyboard(parts[1]))

        return self.send_json(
            {"detail": "Route unavailable in synthetic lab"},
            404,
        )

    def do_POST(self):
        self.send_json({
            "detail": "Synthetic API is read-only"
        }, 405)

    def do_PUT(self):
        self.send_json({"detail": "Writes disabled"}, 405)

    def do_DELETE(self):
        self.send_json({"detail": "Writes disabled"}, 405)


if __name__ == "__main__":
    print("SENTINEL-X SYNTHETIC API")
    print(f"  http://{HOST}:{PORT}/api/v1/health")
    print("  Database access: NONE")
    print("  Real responses: DISABLED")
    print("  LLM: optional localhost Ollama")
    print("  Ctrl+C to exit")

    server = ThreadingHTTPServer(
        (HOST, PORT), Handler
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
