from __future__ import annotations

import json
import sys


from agents.evidence_context_builder import (
    EvidenceContextBuilder,
)

from agents.security_graph_context_service import (
    SecurityGraphContextService,
)


# ================================================================
# CONTROLLED GRAPH SERVICES
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

            "found": True,

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
                "node_count": 3,
                "edge_count": 2,
                "max_hops": max_hops,
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
                55,

            "event_id":
                "GRAPH-BRIDGE-001",

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

            "embedding":
                [1, 2, 3, 4],
        }


# ================================================================
# INPUT
# ================================================================


def build_threat():

    return {

        "id":
            "graph-bridge-detection",

        "detection_id":
            7001,

        "event_id":
            "GRAPH-BRIDGE-EVENT",

        "incident_id":
            "GRAPH-BRIDGE-INCIDENT",

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
            0.89,

        "confidence_semantics":
            "DETECTOR_CONFIDENCE_NOT_PROBABILITY",

        "risk": {
            "detection": {
                "score": 82.0,
                "semantics":
                    "DETECTOR_RISK_SCORE_NOT_PROBABILITY",
                "source":
                    "PROCESS_BEHAVIOR",
            }
        },

        "evidence": {
            "observed": [
                {
                    "process_name":
                        "powershell.exe",

                    "pid":
                        4242,

                    "command_line":
                        (
                            "powershell.exe "
                            "-WindowStyle Hidden "
                            "-File C:\\Users\\Public\\test.ps1"
                        ),
                }
            ]
        },

        "model_evidence": {
            "signals": [
                "hidden_powershell_execution"
            ]
        },

        "visibility": {
            "synthetic": True
        },

        "contract_validation": {
            "valid": True
        },
    }


def build_enriched():

    return {

        "incident_id":
            "GRAPH-BRIDGE-INCIDENT",

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

                "remote_ip":
                    "198.51.100.25",

                "remote_port":
                    443,

                "device_id":
                    "test-device",
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
# MAIN
# ================================================================


def main() -> int:

    print("=" * 110)

    print(
        "SENTINEL-X 7D.3 — GRAPH CONTEXT -> "
        "EVIDENCE CONTEXT BRIDGE"
    )

    print("=" * 110)


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


    builder = (
        EvidenceContextBuilder()
    )


    # ============================================================
    # GRAPH RETRIEVAL
    # ============================================================

    graph_context = (
        graph_service.build(

            threat=
                threat,

            enriched_evidence=
                enriched,
        )
    )


    # ============================================================
    # EVIDENCE CONTEXT
    # ============================================================

    evidence_context = (
        builder.build(

            threat=
                threat,

            enriched_evidence=
                enriched,

            graph_rag_context=
                graph_context,
        )
    )


    print()
    print("[1] GRAPH CONTEXT")

    print(
        json.dumps(
            graph_context,
            indent=2,
            default=str,
        )
    )


    print()
    print("[2] EVIDENCE CONTEXT AVAILABILITY")

    print(
        json.dumps(
            evidence_context.get(
                "evidence_availability"
            ),
            indent=2,
        )
    )


    print()
    print("[3] GRAPH SLOT")

    graph_slot = (
        evidence_context
        .get(
            "security_context",
            {}
        )
        .get(
            "graph_rag"
        )
    )


    print(
        json.dumps(
            graph_slot,
            indent=2,
            default=str,
        )
    )


    failures = []


    # ============================================================
    # CONTEXT SCHEMA
    # ============================================================

    if (
        evidence_context.get(
            "schema_version"
        )
        !=
        "sentinelx.ai.evidence-context.v1"
    ):

        failures.append(
            "Evidence context schema changed."
        )


    # ============================================================
    # GRAPH AVAILABILITY
    # ============================================================

    availability = (
        evidence_context.get(
            "evidence_availability"
        )
        or {}
    )


    if (
        availability.get(
            "graph_rag_context"
        )
        is not True
    ):

        failures.append(
            "graph_rag_context availability is not true."
        )


    if not isinstance(
        graph_slot,
        dict,
    ):

        failures.append(
            "graph_rag slot is not a dictionary."
        )


    elif (
        graph_slot.get(
            "schema_version"
        )
        !=
        "sentinelx.ai.security-graph-context.v1"
    ):

        failures.append(
            "Wrong graph context schema in graph_rag slot."
        )


    # ============================================================
    # GRAPH SOURCES
    # ============================================================

    expected_sources = {
        "INCIDENT_ATTACK_GRAPH",
        "PROCESS_PROVENANCE_SUBGRAPH",
        "GRAPH_AI_RESULT",
    }


    actual_sources = set(

        graph_slot.get(
            "sources",
            []
        )

        if isinstance(
            graph_slot,
            dict,
        )

        else []
    )


    if not expected_sources.issubset(
        actual_sources
    ):

        failures.append(
            "Required graph sources missing."
        )


    # ============================================================
    # GRAPH AI
    # ============================================================

    graph_ai = (

        graph_slot.get(
            "graph_ai_evidence",
            {}
        )

        if isinstance(
            graph_slot,
            dict,
        )

        else {}
    )


    graph_ai_result = (
        graph_ai.get(
            "result"
        )
        or {}
    )


    if (
        graph_ai_result.get(
            "graph_anomaly_score"
        )
        !=
        81.5
    ):

        failures.append(
            "Graph anomaly score lost."
        )


    if (
        "embedding"
        in graph_ai_result
    ):

        failures.append(
            "Graph embedding leaked."
        )


    # ============================================================
    # RELATIONSHIPS
    # ============================================================

    relationships = (

        graph_slot.get(
            "retrieved_relationships"
        )
        or []

        if isinstance(
            graph_slot,
            dict,
        )

        else []
    )


    if not relationships:

        failures.append(
            "Retrieved graph relationships missing."
        )


    # ============================================================
    # POLICY
    # ============================================================

    graph_policy = (

        graph_slot.get(
            "interpretation_policy"
        )
        or {}

        if isinstance(
            graph_slot,
            dict,
        )

        else {}
    )


    if (
        graph_policy.get(
            "graph_is_supporting_context_not_proof"
        )
        is not True
    ):

        failures.append(
            "Graph evidence policy missing."
        )


    if (
        graph_policy.get(
            "graph_anomaly_score_is_not_probability"
        )
        is not True
    ):

        failures.append(
            "Graph anomaly semantics missing."
        )


    # ============================================================
    # VALIDATION PROVENANCE STILL SEPARATE
    # ============================================================

    provenance = (
        evidence_context.get(
            "provenance_context"
        )
        or {}
    )


    if (
        provenance.get(
            "synthetic"
        )
        is not True
    ):

        failures.append(
            "Synthetic provenance was not preserved."
        )


    if (
        provenance.get(
            "reasoning_use"
        )
        !=
        "AUDIT_ONLY_NOT_SECURITY_EVIDENCE"
    ):

        failures.append(
            "Provenance reasoning boundary changed."
        )


    # ============================================================
    # SAFETY
    # ============================================================

    safety = (
        evidence_context.get(
            "safety_context"
        )
        or {}
    )


    if (
        safety.get(
            "simulation_only"
        )
        is not True
    ):

        failures.append(
            "simulation_only changed."
        )


    if (
        safety.get(
            "execution_allowed"
        )
        is not False
    ):

        failures.append(
            "execution_allowed changed."
        )


    # ============================================================
    # FINAL
    # ============================================================

    print()
    print("=" * 110)

    print(
        "7D.3 GRAPH/EVIDENCE BRIDGE RESULT"
    )

    print("=" * 110)


    if failures:

        for failure in failures:

            print(
                "FAIL:",
                failure,
            )

        print()

        print(
            f"RESULT: FAIL ({len(failures)} problems)"
        )

        return 1


    print(
        "Graph retrieval                 : PASS"
    )

    print(
        "EvidenceContextBuilder graph_rag: PASS"
    )

    print(
        "Graph availability reporting    : PASS"
    )

    print(
        "Graph-AI semantics              : PASS"
    )

    print(
        "Relationship context            : PASS"
    )

    print(
        "Embedding exclusion             : PASS"
    )

    print(
        "Provenance separation           : PASS"
    )

    print(
        "Simulation boundary             : PASS"
    )

    print()

    print(
        "RESULT: PASS"
    )


    return 0


if __name__ == "__main__":

    sys.exit(
        main()
    )