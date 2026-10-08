from __future__ import annotations

import json
import sys
import time


from agents.protection_decision_agent import (
    ProtectionDecisionAgent,
)

from agents.security_graph_context_service import (
    SecurityGraphContextService,
)


# ================================================================
# CONTROLLED GRAPH SOURCES
# ================================================================


class FakeSubgraphService:

    def get_process_subgraph(
        self,
        *,
        pid,
        device_id=None,
        process_name=None,
        max_hops=2,
        include_event_nodes=True,
    ):

        return {

            "found":
                True,

            "center_node": {

                "node_id":
                    "PROCESS:test-device:4242",

                "node_type":
                    "PROCESS",

                "properties": {

                    "pid":
                        pid,

                    "process_name":
                        process_name,

                    "device_id":
                        device_id,
                },
            },

            "summary": {

                "node_count":
                    3,

                "edge_count":
                    2,

                "max_hops":
                    max_hops,
            },

            "nodes": [

                {
                    "node_id":
                        "PROCESS:test-device:4242",

                    "node_type":
                        "PROCESS",
                },

                {
                    "node_id":
                        "FILE:test.ps1",

                    "node_type":
                        "FILE",
                },

                {
                    "node_id":
                        "NETWORK:198.51.100.25:443",

                    "node_type":
                        "NETWORK",
                },
            ],

            "edges": [

                {
                    "source_node_id":
                        "PROCESS:test-device:4242",

                    "target_node_id":
                        "FILE:test.ps1",

                    "edge_type":
                        "TOUCHED_FILE",

                    "verified":
                        False,

                    "provenance_status":
                        "OBSERVED_OR_STORED_RELATIONSHIP",
                },

                {
                    "source_node_id":
                        "PROCESS:test-device:4242",

                    "target_node_id":
                        "NETWORK:198.51.100.25:443",

                    "edge_type":
                        "CONNECTED_TO",

                    "verified":
                        False,

                    "provenance_status":
                        "OBSERVED_OR_STORED_RELATIONSHIP",
                },
            ],
        }


class FakeGraphResultStore:

    def get_latest_for_pid(
        self,
        pid,
    ):

        return {

            "id":
                77,

            "event_id":
                "GRAPH-AI-AB-001",

            "pid":
                pid,

            "process_name":
                "powershell.exe",

            "available":
                True,

            "state":
                "AVAILABLE",

            "graph_anomaly_score":
                81.5,

            "score_band":
                "HIGH_ANOMALY",

            "suspicious":
                True,

            "should_alert":
                True,

            "operating_mode":
                "SHADOW_GRAPH_AI",

            # Must never reach AI context.
            "embedding":
                [
                    0.1,
                    0.2,
                    0.3,
                ],
        }


# ================================================================
# SECURITY INPUT
# ================================================================


def build_threat():

    return {

        "id":
            "AB-GRAPH-DETECTION",

        "detection_id":
            8101,

        "event_id":
            "AB-GRAPH-EVENT",

        "incident_id":
            "AB-GRAPH-INCIDENT",

        "device_id":
            "test-device",

        "category":
            "PROCESS",

        "event_type":
            "process_start",

        "threat_type":
            "POWERSHELL_SUSPICIOUS_BEHAVIOR",

        "engine":
            "process_behavior",

        "severity":
            "HIGH",

        "verdict":
            "SUSPICIOUS",

        "confidence":
            0.84,

        "confidence_semantics":
            "DETECTOR_CONFIDENCE_NOT_PROBABILITY",

        "risk": {

            "detection": {

                "score":
                    78.0,

                "semantics":
                    "DETECTOR_RISK_SCORE_NOT_PROBABILITY",

                "source":
                    "PROCESS_BEHAVIOR",
            }
        },

        "evidence": {

            "observed": [

                {
                    "event_type":
                        "process_start",

                    "process_name":
                        "powershell.exe",

                    "pid":
                        4242,

                    "command_line":
                        (
                            "powershell.exe "
                            "-WindowStyle Hidden "
                            "-File "
                            "C:\\Users\\Public\\test.ps1"
                        ),
                }
            ]
        },

        "model_evidence": {

            "signals": [

                "hidden_powershell_execution",
            ]
        },

        "visibility": {

            "synthetic":
                True,
        },

        "contract_validation": {

            "valid":
                True,
        },
    }


# ================================================================
# ENRICHMENT
# ================================================================


def build_enriched():

    return {

        "incident_id":
            "AB-GRAPH-INCIDENT",

        "processes": [

            {
                "name":
                    "powershell.exe",

                "pid":
                    4242,

                "device_id":
                    "test-device",
            }
        ],

        "files": [

            {
                "path":
                    "C:\\Users\\Public\\test.ps1",

                "device_id":
                    "test-device",
            }
        ],

        "network_connections": [

            {
                "pid":
                    4242,

                "device_id":
                    "test-device",

                "remote_ip":
                    "198.51.100.25",

                "remote_port":
                    443,
            }
        ],

        "registry_artifacts":
            [],

        "relationships":
            [],

        "identity_links":
            [],
    }


# ================================================================
# HELPERS
# ================================================================


def heading(
    text: str,
):

    print()

    print(
        "=" * 110
    )

    print(
        text
    )

    print(
        "=" * 110
    )


def print_result(
    result,
):

    print(
        json.dumps(
            result,
            indent=2,
            default=str,
        )
    )


def combined_ai_text(
    result,
):

    parts = []


    for key in [

        "reasoning_summary",
        "evidence_used",
        "corroborating_signals",
        "uncertainties",
    ]:

        value = (
            result.get(
                key
            )
            or []
        )


        if isinstance(
            value,
            list,
        ):

            parts.extend(

                str(
                    item
                )

                for item in value
            )


    parts.append(

        str(
            result.get(
                "why_not_more_aggressive"
            )
            or ""
        )
    )


    parts.append(

        str(
            result.get(
                "why_not_less_aggressive"
            )
            or ""
        )
    )


    return (
        " ".join(
            parts
        )
        .lower()
    )


# ================================================================
# COMMON RESULT VALIDATION
# ================================================================


def validate_common(
    result,
):

    failures = []


    if (
        result.get(
            "ai_available"
        )
        is not True
    ):

        failures.append(
            "AI unavailable."
        )


    if (
        result.get(
            "provider"
        )
        !=
        "GROQ"
    ):

        failures.append(
            "Provider is not GROQ."
        )


    if (
        result.get(
            "decision"
        )
        not in {
            "SAFE",
            "MONITOR",
            "ASK_USER",
            "PROTECT",
        }
    ):

        failures.append(
            "Invalid decision."
        )


    if not (
        result.get(
            "reasoning_summary"
        )
        or []
    ):

        failures.append(
            "Reasoning missing."
        )


    if not (
        result.get(
            "evidence_used"
        )
        or []
    ):

        failures.append(
            "Evidence used missing."
        )


    if (
        result.get(
            "simulation_only"
        )
        is not True
    ):

        failures.append(
            "simulation_only != True"
        )


    if (
        result.get(
            "execution_allowed"
        )
        is not False
    ):

        failures.append(
            "execution_allowed != False"
        )


    if (
        result.get(
            "automatic_execution_allowed"
        )
        is not False
    ):

        failures.append(
            "automatic_execution_allowed != False"
        )


    if (
        result.get(
            "real_response_executed"
        )
        is not False
    ):

        failures.append(
            "real_response_executed != False"
        )


    if (
        result.get(
            "decision"
        )
        ==
        "PROTECT"

        and

        result.get(
            "digital_twin_required"
        )
        is not True
    ):

        failures.append(
            (
                "PROTECT did not require "
                "Digital Twin."
            )
        )


    return failures


# ================================================================
# MAIN
# ================================================================


def main() -> int:

    heading(
        (
            "SENTINEL-X 7D.3 — "
            "AI GRAPH CONTEXT A/B VALIDATION"
        )
    )


    threat = (
        build_threat()
    )


    enriched = (
        build_enriched()
    )


    graph_service = (
        SecurityGraphContextService(

            subgraph_service=
                FakeSubgraphService(),

            graph_result_store=
                FakeGraphResultStore(),
        )
    )


    graph_context = (
        graph_service.build(

            threat=
                threat,

            enriched_evidence=
                enriched,
        )
    )


    agent = (
        ProtectionDecisionAgent()
    )


    # ============================================================
    # A — WITHOUT GRAPH
    # ============================================================

    heading(
        "A — AI DECISION WITHOUT GRAPH CONTEXT"
    )


    result_without_graph = (
        agent.decide(

            threat=
                threat,

            enriched_evidence=
                enriched,

            graph_rag_context=
                None,
        )
    )


    print_result(
        result_without_graph
    )


    # ============================================================
    # WAIT BETWEEN GROQ CALLS
    # ============================================================

    print()
    print(
        "Waiting 6 seconds before second Groq request..."
    )


    time.sleep(
        6
    )


    # ============================================================
    # B — WITH GRAPH
    # ============================================================

    heading(
        "B — AI DECISION WITH GRAPH CONTEXT"
    )


    result_with_graph = (
        agent.decide(

            threat=
                threat,

            enriched_evidence=
                enriched,

            graph_rag_context=
                graph_context,
        )
    )


    print_result(
        result_with_graph
    )


    failures = []


    # ============================================================
    # COMMON VALIDATION
    # ============================================================

    for failure in validate_common(
        result_without_graph
    ):

        failures.append(
            f"WITHOUT GRAPH: {failure}"
        )


    for failure in validate_common(
        result_with_graph
    ):

        failures.append(
            f"WITH GRAPH: {failure}"
        )


    # ============================================================
    # GRAPH AVAILABILITY DIFFERENCE
    # ============================================================

    without_availability = (
        result_without_graph.get(
            "evidence_availability"
        )
        or {}
    )


    with_availability = (
        result_with_graph.get(
            "evidence_availability"
        )
        or {}
    )


    if (
        without_availability.get(
            "graph_rag_context"
        )
        is not False
    ):

        failures.append(
            (
                "Without-graph result incorrectly "
                "reports graph context available."
            )
        )


    if (
        with_availability.get(
            "graph_rag_context"
        )
        is not True
    ):

        failures.append(
            (
                "With-graph result did not report "
                "graph context available."
            )
        )


    # ============================================================
    # DID AI ACTUALLY USE GRAPH EVIDENCE?
    # ============================================================

    with_text = (
        combined_ai_text(
            result_with_graph
        )
    )


    graph_terms = [

        "graph",

        "graph anomaly",

        "81.5",

        "high_anomaly",

        "high anomaly",

        "touched_file",

        "touched file",

        "connected_to",

        "connected to",

        "provenance",

        "process-to-file",

        "process to file",

        "process-to-network",

        "process to network",
    ]


    graph_evidence_used = any(

        term in with_text

        for term in graph_terms
    )


    if not graph_evidence_used:

        failures.append(
            (
                "AI received graph context but "
                "did not reference graph evidence."
            )
        )


    # ============================================================
    # GRAPH MUST NOT BE TREATED AS CERTAIN PROOF
    # ============================================================

    forbidden_certainty = [

        "graph proves",

        "graph confirms malicious",

        "graph confirms the attack",

        "graph proves malicious",

        "81.5% malicious",

        "81.5 percent malicious",

        "81.5 probability",
    ]


    for phrase in (
        forbidden_certainty
    ):

        if phrase in with_text:

            failures.append(
                (
                    "AI treated graph evidence as "
                    "certain/probabilistic proof: "
                    f"{phrase}"
                )
            )


    # ============================================================
    # A/B COMPARISON
    #
    # IMPORTANT:
    # We DO NOT require the graph-enabled result to be more
    # aggressive.
    # ============================================================

    heading(
        "A/B COMPARISON"
    )


    print(
        "WITHOUT GRAPH"
    )

    print(
        "  Decision   :",
        result_without_graph.get(
            "decision"
        ),
    )

    print(
        "  Assessment :",
        result_without_graph.get(
            "threat_assessment"
        ),
    )

    print(
        "  Confidence :",
        result_without_graph.get(
            "confidence"
        ),
    )

    print(
        "  Action     :",
        result_without_graph.get(
            "recommended_action"
        ),
    )


    print()

    print(
        "WITH GRAPH"
    )

    print(
        "  Decision   :",
        result_with_graph.get(
            "decision"
        ),
    )

    print(
        "  Assessment :",
        result_with_graph.get(
            "threat_assessment"
        ),
    )

    print(
        "  Confidence :",
        result_with_graph.get(
            "confidence"
        ),
    )

    print(
        "  Action     :",
        result_with_graph.get(
            "recommended_action"
        ),
    )


    print()

    print(
        "Graph evidence referenced:",
        graph_evidence_used,
    )


    # ============================================================
    # FINAL
    # ============================================================

    heading(
        "7D.3 AI GRAPH CONTEXT RESULT"
    )


    if failures:

        print(
            f"TOTAL FAILURES: {len(failures)}"
        )


        for failure in failures:

            print(
                "FAIL:",
                failure,
            )


        print()

        print(
            "RESULT: FAIL"
        )

        return 1


    print(
        "Baseline AI reasoning            : PASS"
    )

    print(
        "Graph-enabled AI reasoning       : PASS"
    )

    print(
        "Graph availability propagation   : PASS"
    )

    print(
        "Graph evidence actually used     : PASS"
    )

    print(
        "Graph anomaly semantics          : PASS"
    )

    print(
        "No forced escalation             : PASS"
    )

    print(
        "Digital Twin invariant           : PASS"
    )

    print(
        "Simulation-only boundary         : PASS"
    )

    print()

    print(
        "RESULT: PASS"
    )

    print(
        (
            "SENTINEL-X 7D.3 Graph Security "
            "Context is ready to close."
        )
    )


    return 0


if __name__ == "__main__":

    sys.exit(
        main()
    )