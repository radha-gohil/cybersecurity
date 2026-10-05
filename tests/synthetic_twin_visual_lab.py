
"""
SENTINEL-X — Isolated Digital Twin Visual Lab

Standalone, localhost-only synthetic simulation viewer.

Uses the real DigitalTwinVisualPreview engine.
Does not use FastAPI or the production database.
All evidence is synthetic.

Run tests:
    python tests/synthetic_twin_visual_lab.py --self-test

Launch:
    python tests/synthetic_twin_visual_lab.py

Then open:
    http://127.0.0.1:8765
"""

import argparse
import json
import sys
from copy import deepcopy
from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from response.digital_twin_visual_preview import (
    DigitalTwinVisualPreview,
)


HOST = "127.0.0.1"
PORT = 8765


# ============================================================
# ISOLATED FIXTURE GENERATION
# ============================================================

def build_synthetic_case(
    case_id,
    process_score,
    include_network=True,
    source_mode="SYNTHETIC_TEST",
):
    """
    These are test fixtures, not actual SOC detections.

    The evidence validator's passing result is deliberately
    injected for isolated integration testing. This does
    NOT test the real production evidence validator.
    """

    device_id = f"{case_id}-DEVICE"

    process_event_id = f"{case_id}-PROCESS-EVENT"
    network_event_id = f"{case_id}-NETWORK-EVENT"

    process = {
        "pid": 5252,
        "device_id": device_id,
        "process_create_time":
            "2026-01-01T10:00:00Z",
        "name": "synthetic-test-process.exe",
        "combined_threat_score": process_score,
        "behavior_score": process_score,
        "anomaly_score": 0,
        "event_id": process_event_id,
        "source_mode": source_mode,
    }

    network = {
        "device_id": device_id,
        "event_id": network_event_id,
        "remote_ip": "198.51.100.20",
        "remote_port": 443,
        "protocol": "TCP",
        "source_mode": source_mode,
    }

    evidence = {
        "processes": [process],
        "files": [],
        "network_connections":
            [network] if include_network else [],
        "registry_artifacts": [],
    }

    timeline = [{
        "event_id": process_event_id,
        "event_category": "PROCESS",
        "device_id": device_id,
        "severity": "HIGH",
        "metadata": {
            "detection_mode": source_mode,
        },
    }]

    if include_network:
        timeline.append({
            "event_id": network_event_id,
            "event_category": "NETWORK",
            "device_id": device_id,
            "severity": "HIGH",
            "metadata": {
                "detection_mode": source_mode,
            },
        })

    incident = {
        "incident_id": case_id,
        "title": f"Synthetic scenario: {case_id}",
        "device_id": device_id,
        "timeline": timeline,
        "synthetic": True,
    }

    intelligence = {
        "status": "COMPLETED",
        "risk_score": None,
        "evidence_validation": {
            "passed": True,
            "validation_policy":
                "ISOLATED_INJECTED_TEST_FIXTURE",
            "authoritative_event_count":
                len(timeline),
            "rejected_event_count": 0,
            "reasons": [],
            "categories_by_device": {
                device_id: [
                    entry["event_category"]
                    for entry in timeline
                ],
            },
        },
        "coordinated_analysis": {
            "evidence": deepcopy(evidence),
        },
    }

    return incident, intelligence, evidence


def make_demonstrations():
    engine = DigitalTwinVisualPreview()

    scenarios = [
        {
            "id": "LAB-HIGH",
            "title": "High-score virtual scenario",
            "description":
                "Synthetic process and network observations "
                "with a higher process feature score.",
            "process_score": 85,
            "include_network": True,
            "mode": "SYNTHETIC_TEST",
        },
        {
            "id": "LAB-LOW",
            "title": "Lower-score process scenario",
            "description":
                "Synthetic process-only observation "
                "with a lower process feature score.",
            "process_score": 25,
            "include_network": False,
            "mode": "SYNTHETIC_TEST",
        },
        {
            "id": "LAB-SHADOW",
            "title": "Shadow-source exclusion",
            "description":
                "A synthetic example demonstrating that "
                "shadow observations are not selected as "
                "virtual protection targets.",
            "process_score": 90,
            "include_network": True,
            "mode": "SHADOW_VALIDATION",
        },
    ]

    demonstrations = []

    for scenario in scenarios:
        incident, intelligence, evidence = (
            build_synthetic_case(
                case_id=scenario["id"],
                process_score=scenario["process_score"],
                include_network=scenario["include_network"],
                source_mode=scenario["mode"],
            )
        )

        before_incident = deepcopy(incident)
        before_intelligence = deepcopy(intelligence)

        result = engine.evaluate(
            incident,
            intelligence,
        )

        if incident != before_incident:
            raise AssertionError(
                "The preview mutated its incident input."
            )

        if intelligence != before_intelligence:
            raise AssertionError(
                "The preview mutated its intelligence input."
            )

        demonstrations.append({
            "id": scenario["id"],
            "title": scenario["title"],
            "description": scenario["description"],
            "synthetic": True,
            "validation_origin":
                "INJECTED_FIXTURE_NOT_REAL_VALIDATOR",
            "evidence": evidence,
            "timeline": incident["timeline"],
            "result": result,
        })

    return demonstrations


# ============================================================
# SELF-TEST
# ============================================================

def self_test():
    demos = make_demonstrations()

    assert len(demos) == 3

    by_id = {
        item["id"]: item
        for item in demos
    }

    high = by_id["LAB-HIGH"]["result"]
    low = by_id["LAB-LOW"]["result"]
    shadow = by_id["LAB-SHADOW"]["result"]

    # Positive path
    assert high["plans_evaluated"] > 0
    assert low["plans_evaluated"] > 0

    # Incident-specific modeled baselines
    assert (
        high["initial_risk_score"]
        > low["initial_risk_score"]
    )

    # No shadow-based virtual action targets
    assert shadow["plans_evaluated"] == 0
    assert shadow["candidate_actions"] == []

    # No unsupported network action for process-only case
    assert all(
        action.get("action_type") != "BLOCK_NETWORK"
        for action in low["candidate_actions"]
    )

    # Validate frame and risk component contracts
    for demo in demos:
        result = demo["result"]

        assert result["preview_only"] is True
        assert result["simulation_mode"] is True
        assert result["soc_case_created"] is False
        assert result["approval_eligible"] is False
        assert result["response_authorized"] is False
        assert result["real_endpoint_modified"] is False

        assert (
            result["plans_evaluated"]
            == len(result["ranked_plans"])
        )

        assert isinstance(
            result["baseline_risk_components"],
            dict,
        )

        for plan in result["ranked_plans"]:
            assert plan["hypothetical"] is True
            assert plan["approval_eligible"] is False
            assert plan["response_authorized"] is False

            frames = plan["playback"]

            assert (
                len(frames)
                == len(plan["actions"]) + 1
            )

            assert frames[0]["action_type"] == "BASELINE"

            for frame in frames:
                assert "risk_components" in frame
                assert "risk_score" in frame
                assert "state" in frame

    print("=" * 58)
    print("SENTINEL-X ISOLATED VISUAL LAB SELF-TEST")
    print("=" * 58)

    for demo in demos:
        result = demo["result"]

        print(
            f"{demo['id']}: "
            f"baseline={result['initial_risk_score']} "
            f"plans={result['plans_evaluated']} "
            f"decision={result['decision']}"
        )

    print("-" * 58)
    print("PASS: Synthetic fixtures evaluated in memory.")
    print("PASS: Different feature scores affect baseline.")
    print("PASS: Shadow-only entities excluded.")
    print("PASS: Virtual playback fields validated.")
    print("PASS: No source mutation or response authorization.")
    print("PASS: No production database used.")
    print("=" * 58)


# ============================================================
# LOCAL GRAPHICAL VIEWER
# ============================================================

HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
 content="width=device-width, initial-scale=1">
<title>SENTINEL-X | Isolated Digital Twin Lab</title>
<style>
* { box-sizing: border-box; }

:root {
  color-scheme: dark;
  font-family: Inter, "Segoe UI", Arial, sans-serif;
  background: #090f1c;
  color: #e2e8f0;
}

body {
  margin: 0;
  padding: 24px;
}

main {
  max-width: 1330px;
  margin: 0 auto;
}

h1 {
  margin: 0;
  font-size: 29px;
}

h2 { font-size: 18px; margin: 0 0 18px; }

p {
  color: #94a3b8;
  line-height: 1.6;
}

.top {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 14px;
  margin-bottom: 22px;
}

.tag {
  display: inline-block;
  padding: 7px 11px;
  border-radius: 50px;
  background: #123449;
  color: #7dd3fc;
  font-size: 11px;
  font-weight: 750;
}

.warning {
  padding: 14px 17px;
  margin: 16px 0 22px;
  border: 1px solid #885d1d;
  border-radius: 12px;
  background: #271d0d;
  color: #fbbf24;
  font-size: 13px;
}

.card {
  background: #111827;
  border: 1px solid #223148;
  border-radius: 16px;
  padding: 23px;
  margin-bottom: 20px;
}

.grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.metric {
  border: 1px solid #29354a;
  background: #0f172a;
  border-radius: 13px;
  padding: 15px;
}

.metric small {
  color: #94a3b8;
  font-size: 11px;
}

.metric strong {
  display: block;
  margin-top: 8px;
  font-size: 25px;
  color: #93c5fd;
}

select, button {
  font: inherit;
  border-radius: 9px;
  border: 1px solid #415273;
  padding: 11px 15px;
  background: #17243a;
  color: #e2e8f0;
}

button {
  cursor: pointer;
  transition: 0.15s;
}

button:hover:not(:disabled) {
  border-color: #60a5fa;
  background: #1b3453;
}

button:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

select {
  width: min(100%, 460px);
  margin-top: 10px;
}

.plan {
  background: #0c1727;
  border: 1px solid #263952;
  border-radius: 12px;
  padding: 15px;
  margin-bottom: 12px;
}

.plan.selected {
  border-color: #22c55e;
}

.plan button { margin-top: 11px; }

.muted {
  color: #94a3b8;
  font-size: 12px;
}

.bar {
  height: 9px;
  margin-top: 6px;
  border-radius: 10px;
  background: #26354e;
  overflow: hidden;
}

.bar > div {
  height: 100%;
  background: #60a5fa;
  transition: width 0.25s;
}

.component {
  margin: 13px 0;
}

.component header {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
}

svg {
  width: 100%;
  background: #0a1425;
  border: 1px solid #223148;
  border-radius: 12px;
  margin-top: 12px;
}

svg text {
  font-family: Arial, sans-serif;
}

.node {
  fill: #16243a;
  stroke: #64748b;
  stroke-width: 1.5;
  transition: fill 0.2s, stroke 0.2s;
}

.node.active {
  fill: #17372f;
  stroke: #22c55e;
  stroke-width: 3;
}

.node.failed {
  fill: #47311a;
  stroke: #f59e0b;
}

.center {
  fill: #193454;
  stroke: #60a5fa;
  stroke-width: 2;
}

.center.isolated {
  fill: #4a2e22;
  stroke: #f59e0b;
}

.controls {
  display: flex;
  gap: 9px;
  flex-wrap: wrap;
  margin: 16px 0;
}

pre {
  background: #091323;
  border-radius: 10px;
  border: 1px solid #26334b;
  padding: 15px;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 260px;
  overflow: auto;
  font-size: 12px;
}

.list {
  padding-left: 18px;
  font-size: 12px;
  line-height: 1.8;
  color: #cbd5e1;
}

#status { color: #fbbf24; font-size: 12px; }

@media(max-width: 800px) {
  body { padding: 12px; }
  .grid { grid-template-columns: 1fr; }
  .metrics { grid-template-columns: repeat(2, 1fr); }
}
</style>
</head>

<body>
<main>
  <section class="top">
    <div>
      <h1>SENTINEL-X</h1>
      <p>Isolated Digital Twin — Synthetic Visualization Lab</p>
    </div>
    <div>
      <span class="tag">SYNTHETIC FIXTURE</span>
      <span class="tag">SIMULATION ONLY</span>
      <span class="tag">NO SOC PROMOTION</span>
    </div>
  </section>

  <div class="warning">
    All evidence in this lab is synthetic. The test fixture injects
    its own passing validation flag; the real evidence validator has
    not independently approved these observations. Risk reductions
    are heuristic changes to a cloned endpoint, not measured
    prevention of an attack.
  </div>

  <section class="card">
    <h2>Scenario Selection</h2>
    <select id="scenario"></select>
    <p id="description"></p>
    <span id="status"></span>
  </section>

  <section class="card">
    <h2>Evidence and Investigation</h2>
    <div id="metrics" class="metrics"></div>
    <div id="validation"></div>
  </section>

  <section class="grid">
    <div class="card">
      <h2>Initial Modeled Risk</h2>
      <div id="baseline"></div>
    </div>
    <div class="card">
      <h2>Evidence Provenance</h2>
      <div id="provenance"></div>
    </div>
  </section>

  <section class="grid">
    <div class="card">
      <h2>Hypothetical Plans</h2>
      <div id="plans"></div>
    </div>
    <div class="card">
      <h2>Selected Plan</h2>
      <div id="selectedPlan"></div>
    </div>
  </section>

  <section class="card">
    <h2>Animated Virtual Endpoint</h2>
    <svg viewBox="0 0 620 250" aria-label="Digital Twin">
      <g stroke="#3b82f6" stroke-width="2"
         stroke-dasharray="6 6" opacity=".6">
        <path d="M258 110 L155 64"/>
        <path d="M365 110 L464 64"/>
        <path d="M258 165 L155 201"/>
        <path d="M365 165 L464 201"/>
      </g>

      <rect id="endpoint" class="center"
        x="253" y="102" width="114" height="70" rx="12"/>
      <text x="310" y="135" fill="#dbeafe"
        font-size="12" text-anchor="middle">ENDPOINT</text>
      <text id="endpointLabel" x="310" y="151"
        fill="#93c5fd" font-size="10"
        text-anchor="middle">DIGITAL TWIN</text>

      <g data-node="process">
        <rect class="node" x="48" y="29"
          width="110" height="48" rx="10"/>
        <text x="103" y="57" fill="#e2e8f0"
          text-anchor="middle" font-size="11">PROCESSES</text>
      </g>

      <g data-node="network">
        <rect class="node" x="464" y="29"
          width="110" height="48" rx="10"/>
        <text x="519" y="57" fill="#e2e8f0"
          text-anchor="middle" font-size="11">NETWORK</text>
      </g>

      <g data-node="file">
        <rect class="node" x="48" y="179"
          width="110" height="48" rx="10"/>
        <text x="103" y="207" fill="#e2e8f0"
          text-anchor="middle" font-size="11">FILES</text>
      </g>

      <g data-node="registry">
        <rect class="node" x="464" y="179"
          width="110" height="48" rx="10"/>
        <text x="519" y="207" fill="#e2e8f0"
          text-anchor="middle" font-size="11">REGISTRY</text>
      </g>
    </svg>

    <div class="controls">
      <button id="previous">Previous</button>
      <button id="play">Play</button>
      <button id="next">Next</button>
      <button id="reset">Replay</button>
    </div>

    <div id="frameSummary" class="muted"></div>
    <div id="stepRisk"></div>

    <div class="bar">
      <div id="progress" style="width:0%"></div>
    </div>
  </section>

  <section class="grid">
    <div class="card">
      <h2>Current Step Risk Components</h2>
      <div id="currentComponents"></div>
    </div>
    <div class="card">
      <h2>Virtual State Snapshot</h2>
      <pre id="state"></pre>
    </div>
  </section>

  <section class="card">
    <h2>Interpretation and Limitations</h2>
    <ul class="list" id="limitations"></ul>
  </section>
</main>

<script>
"use strict";

let scenarios = [];
let currentScenario = null;
let currentPlan = null;
let frameIndex = 0;
let timer = null;

const $ = (id) => document.getElementById(id);

function safe(value) {
  if (value === null || value === undefined || value === "") {
    return "Not recorded";
  }
  return String(value);
}

function escapeHtml(value) {
  return safe(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function stopPlayback() {
  if (timer !== null) {
    clearInterval(timer);
    timer = null;
  }
  $("play").textContent = "Play";
}

function field(label, value) {
  return '<div class="metric"><small>' +
    escapeHtml(label) + '</small><strong>' +
    escapeHtml(value) + '</strong></div>';
}

function componentRows(components) {
  const names = {
    process: "Process",
    file: "File",
    network: "Network",
    persistence: "Registry / Persistence",
    isolation_adjustment: "Isolation adjustment"
  };

  const source = components || {};
  const rows = Object.keys(names);

  return rows.map((key) => {
    if (source[key] === undefined) {
      return "";
    }

    const value = Number(source[key]) || 0;
    const percent = Math.min(100, Math.abs(value));

    return '<div class="component">' +
      '<header><span>' + escapeHtml(names[key]) +
      '</span><strong>' + escapeHtml(value) +
      '</strong></header><div class="bar">' +
      '<div style="width:' + percent +
      '%"></div></div></div>';
  }).join("");
}

function selectedResult() {
  return currentScenario?.result || {};
}

function renderScenario() {
  stopPlayback();
  frameIndex = 0;

  const selected = $("scenario").value;

  currentScenario = scenarios.find(
    (item) => item.id === selected
  ) || null;

  if (!currentScenario) {
    return;
  }

  const result = selectedResult();
  const counts = result.evidence_counts || {};
  const validation = result.evidence_validation || {};

  $("description").textContent =
    currentScenario.description;

  $("metrics").innerHTML =
    field("Processes", counts.processes ?? "—") +
    field("Files", counts.files ?? "—") +
    field("Network", counts.network_connections ?? "—") +
    field("Registry", counts.registry_artifacts ?? "—");

  $("validation").innerHTML =
    '<p>Investigation: <strong>' +
    escapeHtml(result.investigation_status) +
    '</strong> | Fixture validation: <strong>' +
    escapeHtml(validation.passed === true
      ? "INJECTED TRUE" : "FALSE") +
    '</strong> | Plans: <strong>' +
    escapeHtml(result.plans_evaluated) +
    '</strong></p>';

  $("baseline").innerHTML =
    '<div style="font-size:43px;font-weight:800;color:#f87171">' +
    escapeHtml(result.initial_risk_score) +
    '<small style="font-size:15px"> / 100</small></div>' +
    '<p>Heuristic baseline, not attack probability.</p>' +
    componentRows(result.baseline_risk_components);

  const timeline = currentScenario.timeline || [];

  $("provenance").innerHTML =
    '<p class="muted">These are synthetic observations. ' +
    'Event IDs show the fixture references used for linkage.</p>' +
    timeline.map((event) =>
      '<div class="plan">' +
      '<strong>' + escapeHtml(event.event_category) +
      '</strong><p>Event: ' +
      escapeHtml(event.event_id) +
      '</p><p>Device: ' +
      escapeHtml(event.device_id) +
      '</p><p>Source mode: ' +
      escapeHtml(event.metadata?.detection_mode) +
      '</p></div>'
    ).join("");

  const plans = result.ranked_plans || [];

  $("plans").innerHTML = plans.length
    ? plans.map((plan, index) =>
        '<div class="plan" id="plan-' + index + '">' +
        '<strong>' + escapeHtml(plan.plan_name) +
        '</strong>' +
        '<p>Residual heuristic: ' +
        escapeHtml(plan.predicted_residual_risk) +
        '</p><p>Ranking: ' +
        escapeHtml(plan.plan_score) +
        '</p><button data-plan="' + index +
        '">View virtual playback</button></div>'
      ).join("")
    : '<div class="warning">No eligible virtual plans.</div>';

  document.querySelectorAll("[data-plan]").forEach(
    (button) => {
      button.addEventListener("click", () => {
        const index = Number(button.dataset.plan);
        selectPlan(index);
      });
    }
  );

  currentPlan = null;
  if (plans.length) {
    selectPlan(0);
  } else {
    $("selectedPlan").textContent =
      "No plan available for this scenario.";
    renderFrame();
  }

  $("limitations").innerHTML = (
    result.limitations || []
  ).map((item) =>
    "<li>" + escapeHtml(item) + "</li>"
  ).join("");

  $("status").textContent =
    "Fixture-only demonstration. " +
    result.decision;
}

function selectPlan(index) {
  stopPlayback();

  const plans = selectedResult().ranked_plans || [];
  currentPlan = plans[index] || null;
  frameIndex = 0;

  document.querySelectorAll(".plan.selected").forEach(
    (element) => element.classList.remove("selected")
  );

  $("plan-" + index)?.classList.add("selected");

  if (!currentPlan) {
    renderFrame();
    return;
  }

  const actions = currentPlan.actions || [];

  $("selectedPlan").innerHTML =
    '<h3>' +
    escapeHtml(currentPlan.plan_name) +
    '</h3><p>' +
    escapeHtml(currentPlan.description) +
    '</p><p><strong>Virtual actions:</strong></p>' +
    '<ul class="list">' +
    actions.map((action) =>
      "<li>" +
      escapeHtml(action.action_type) +
      "<br><small>" +
      escapeHtml(
        action.scenario_basis || "Hypothetical action"
      ) +
      "</small></li>"
    ).join("") +
    "</ul>" +
    '<p>Operational impact: ' +
    escapeHtml(
      currentPlan.operational_impact?.impact_level
    ) +
    '</p><p>Residual risk: ' +
    escapeHtml(currentPlan.predicted_residual_risk) +
    '</p><p>Modeled reduction: ' +
    escapeHtml(
      currentPlan.risk_reduction_percentage
    ) +
    '%</p><p class="muted">This ranking has no ' +
    'approval or execution authority.</p>';

  renderFrame();
}

function frameType(actionType) {
  const action = String(actionType || "").toUpperCase();

  if (action.includes("PROCESS")) return "process";
  if (action.includes("FILE")) return "file";
  if (
    action.includes("NETWORK") ||
    action.includes("ISOLATE")
  ) return "network";
  if (action.includes("PERSISTENCE")) return "registry";

  return null;
}

function renderFrame() {
  const frames = currentPlan?.playback || [];
  const frame = frames[frameIndex] || null;

  const type = frameType(frame?.action_type);

  document.querySelectorAll("[data-node]").forEach(
    (node) => {
      const rectangle = node.querySelector("rect");
      rectangle.classList.remove("active", "failed");

      if (node.dataset.node === type) {
        rectangle.classList.add(
          frame?.success === true ? "active" : "failed"
        );
      }
    }
  );

  const state = frame?.state || {};
  const isolated = state.endpoint_isolated === true;

  $("endpoint").classList.toggle("isolated", isolated);
  $("endpointLabel").textContent =
    isolated ? "VIRTUAL ISOLATION" : "DIGITAL TWIN";

  $("frameSummary").textContent = frame
    ? "Step " + (frameIndex + 1) +
      "/" + frames.length +
      " | " + safe(frame.action_type) +
      " | " + safe(frame.status)
    : "No playback frames available.";

  $("stepRisk").innerHTML = frame
    ? '<p>Modeled risk at this step: <strong>' +
      escapeHtml(frame.risk_score) +
      '</strong> | Virtual success: ' +
      escapeHtml(frame.success === true
        ? "Yes" : "No") + '</p>'
    : '<p class="muted">No virtual action is selected.</p>';

  $("currentComponents").innerHTML =
    componentRows(frame?.risk_components);

  $("state").textContent = frame
    ? JSON.stringify(state, null, 2)
    : "No recorded virtual snapshot.";

  $("progress").style.width = frames.length
    ? ((frameIndex + 1) / frames.length * 100) + "%"
    : "0%";

  $("previous").disabled =
    !frame || frameIndex === 0;

  $("next").disabled =
    !frame || frameIndex >= frames.length - 1;

  $("play").disabled =
    frames.length < 2 ||
    frameIndex >= frames.length - 1;

  $("reset").disabled = !frame;
}

function nextFrame() {
  const frames = currentPlan?.playback || [];

  if (frameIndex >= frames.length - 1) {
    stopPlayback();
    return;
  }

  frameIndex += 1;
  renderFrame();

  if (frameIndex >= frames.length - 1) {
    stopPlayback();
  }
}

$("previous").addEventListener("click", () => {
  stopPlayback();
  frameIndex = Math.max(0, frameIndex - 1);
  renderFrame();
});

$("next").addEventListener("click", () => {
  stopPlayback();
  nextFrame();
});

$("play").addEventListener("click", () => {
  if (timer !== null) {
    stopPlayback();
    return;
  }

  $("play").textContent = "Pause";
  timer = setInterval(nextFrame, 1300);
});

$("reset").addEventListener("click", () => {
  stopPlayback();
  frameIndex = 0;
  renderFrame();
});

$("scenario").addEventListener(
  "change",
  renderScenario
);

async function loadData() {
  try {
    const response = await fetch("/api/demo", {
      cache: "no-store",
    });

    if (!response.ok) {
      throw new Error("Fixture request failed.");
    }

    const data = await response.json();
    scenarios = data.scenarios || [];

    $("scenario").innerHTML = scenarios.map(
      (item) =>
        '<option value="' +
        escapeHtml(item.id) + '">' +
        escapeHtml(item.title) + "</option>"
    ).join("");

    if (scenarios.length) {
      renderScenario();
    } else {
      $("status").textContent =
        "No synthetic scenarios generated.";
    }
  } catch (error) {
    $("status").textContent =
      "Unable to load synthetic fixtures: " +
      error.message;
  }
}

loadData();
</script>
</body>
</html>
"""


# ============================================================
# LOCAL READ-ONLY HTTP SERVER
# ============================================================

class LabHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        path = urlsplit(self.path).path

        if path == "/":
            payload = HTML.encode("utf-8")
            content_type = "text/html; charset=utf-8"

        elif path == "/api/demo":
            try:
                result = {
                    "lab": "SENTINEL-X_SYNTHETIC_TWIN",
                    "synthetic": True,
                    "uses_production_database": False,
                    "real_response_execution": False,
                    "validation_origin":
                        "INJECTED_FIXTURE_NOT_REAL_VALIDATOR",
                    "scenarios": make_demonstrations(),
                }

                payload = json.dumps(
                    result,
                    default=str,
                ).encode("utf-8")

            except Exception as error:
                self.send_error(
                    500,
                    f"Fixture generation failed: "
                    f"{type(error).__name__}",
                )
                return

            content_type = "application/json"

        else:
            self.send_error(404, "Not found")
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none';",
        )
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        self.send_error(
            405,
            "Read-only demonstration: POST disabled",
        )

    def do_PUT(self):
        self.send_error(405, "Writes disabled")

    def do_DELETE(self):
        self.send_error(405, "Writes disabled")


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run isolated fixture assertions and exit.",
    )

    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    # Check fixtures before opening the HTTP server.
    self_test()

    server = ThreadingHTTPServer(
        (HOST, PORT),
        LabHandler,
    )

    print()
    print("SENTINEL-X ISOLATED VISUAL LAB")
    print(f"Open: http://{HOST}:{PORT}")
    print("Synthetic fixtures only.")
    print("No FastAPI or production database access.")
    print("Press Ctrl+C to stop.")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping isolated visual lab.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
