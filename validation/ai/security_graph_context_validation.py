from __future__ import annotations

import json
import sys


from agents.security_graph_context_service import (
    SecurityGraphContextService,
)


# ================================================================
# FAKE PERSISTENT SUBGRAPH SERVICE
#
# We inject this only for this integration validation so the test
# does not depend on whatever graph records currently exist in the
# active Sentinel-X database.
#
# Actual ProcessSubgraphService itself is separately validated by
# the project's existing graph tests.
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
                    4,

                "edge_count":
                    3,

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

                {
                    "node_id":
                        "EVENT:evt-1",

                    "node_type":
                        "EVENT",
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


# ================================================================
# FAKE PERSISTED GRAPH-AI RESULT
# ================================================================


class FakeGraphResultStore:

    def get_latest_for_pid(
        self,
        pid,
    ):

        return {

            "id":
                101,

            "event_id":
                "GRAPH-TEST-001",

            "pid":
                pid,

            "process_name":
                "powershell.exe",

            "available":
                True,

            "state":
                "AVAILABLE",

            "graph_anomaly_score":
                82.4,

            "score_band":
                "HIGH_ANOMALY",

            "suspicious":
                True,

            "should_alert":
                True,

            "operating_mode":
                "SHADOW_GRAPH_AI",

            # This must NOT be forwarded by our graph context
            # service.
            "embedding":
                [0.1, 0.2, 0.3, 0.4],
        }


# ================================================================
# CONTROLLED ENRICHED EVIDENCE
# ================================================================


def build_enriched_evidence():

    return {

        "incident_id":
            "GRAPH-CTX-INC-001",

        "processes": [

            {
                "name":
                    "powershell.exe",

                "pid":
                    4242,

                "device_id":
                    "test-device",

                "exe":
                    (
                        "C:\\Windows\\System32\\"
                        "WindowsPowerShell\\v1.0\\powershell.exe"
                    ),
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

        "registry_artifacts": [],

        "relationships": [

            {
                "source_type":
                    "PROCESS",

                "source":
                    "powershell.exe",

                "relationship":
                    "CONNECTED_TO",

                "target_type":
                    "NETWORK",

                "target":
                    "198.51.100.25",

                "match_score":
                    100,

                "confidence":
                    0,

                "verified":
                    False,

                "provenance_status":
                    "INFERRED",

                "requires_validation":
                    True,
            }
        ],

        "identity_links": [],
    }


def build_threat():

    return {

        "id":
            "detection-graph-validation",

        "detection_id":
            999,

        "event_id":
            "GRAPH-CTX-EVT-001",

        "incident_id":
            "GRAPH-CTX-INC-001",

        "device_id":
            "test-device",

        "category":
            "PROCESS",

        "threat_type":
            "POWERSHELL_SUSPICIOUS_BEHAVIOR",

        "severity":
            "HIGH",

        "verdict":
            "SUSPICIOUS",

        "evidence": {

            "observed": [

                {
                    "process_name":
                        "powershell.exe",

                    "pid":
                        4242,
                }
            ]
        },
    }


# ================================================================
# MAIN
# ================================================================


def main() -> int:

    print(
        "=" * 110
    )

    print(
        "SENTINEL-X 7D.3 — SECURITY GRAPH CONTEXT VALIDATION"
    )

    print(
        "=" * 110
    )


    service = (
        SecurityGraphContextService(

            subgraph_service=
                FakeSubgraphService(),

            graph_result_store=
                FakeGraphResultStore(),
        )
    )


    print()
    print(
        "[1] SERVICE STATUS"
    )

    print(
        json.dumps(
            service.status(),
            indent=2,
        )
    )


    print()
    print(
        "[2] BUILD GRAPH CONTEXT"
    )


    result = (
        service.build(

            threat=
                build_threat(),

            enriched_evidence=
                build_enriched_evidence(),
        )
    )


    print(
        json.dumps(
            result,
            indent=2,
            default=str,
        )
    )


    failures = []


    # ============================================================
    # SCHEMA
    # ============================================================

    if (
        result.get(
            "schema_version"
        )
        !=
        "sentinelx.ai.security-graph-context.v1"
    ):

        failures.append(
            "Graph context schema invalid."
        )


    if (
        result.get(
            "service_version"
        )
        !=
        "7D.3-v1"
    ):

        failures.append(
            "Graph context version invalid."
        )


    # ============================================================
    # AVAILABILITY
    # ============================================================

    if (
        result.get(
            "available"
        )
        is not True
    ):

        failures.append(
            "Graph context is unavailable."
        )


    expected_sources = {

        "INCIDENT_ATTACK_GRAPH",

        "PROCESS_PROVENANCE_SUBGRAPH",

        "GRAPH_AI_RESULT",
    }


    actual_sources = set(
        result.get(
            "sources"
        )
        or []
    )


    if not expected_sources.issubset(
        actual_sources
    ):

        failures.append(
            (
                "Expected graph sources missing: "
                f"{sorted(expected_sources - actual_sources)}"
            )
        )


    # ============================================================
    # PROCESS IDENTITY
    # ============================================================

    identity = (
        result.get(
            "process_identity"
        )
        or {}
    )


    if (
        identity.get(
            "pid"
        )
        !=
        4242
    ):

        failures.append(
            "Process PID was not resolved."
        )


    if (
        identity.get(
            "process_name"
        )
        !=
        "powershell.exe"
    ):

        failures.append(
            "Process name was not resolved."
        )


    # ============================================================
    # ATTACK GRAPH
    # ============================================================

    attack_graph = (
        result.get(
            "incident_attack_graph"
        )
        or {}
    )


    if (
        attack_graph.get(
            "available"
        )
        is not True
    ):

        failures.append(
            "Incident attack graph unavailable."
        )


    if (
        int(
            attack_graph.get(
                "node_count"
            )
            or 0
        )
        <= 0
    ):

        failures.append(
            "Incident attack graph contains no nodes."
        )


    # ============================================================
    # PROCESS SUBGRAPH
    # ============================================================

    process_graph = (
        result.get(
            "process_provenance_subgraph"
        )
        or {}
    )


    if (
        process_graph.get(
            "available"
        )
        is not True
    ):

        failures.append(
            "Process provenance subgraph unavailable."
        )


    # ============================================================
    # GRAPH AI
    # ============================================================

    graph_ai = (
        result.get(
            "graph_ai_evidence"
        )
        or {}
    )


    if (
        graph_ai.get(
            "available"
        )
        is not True
    ):

        failures.append(
            "Graph AI evidence unavailable."
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
        82.4
    ):

        failures.append(
            "Graph anomaly score not preserved."
        )


    if (
        "embedding"
        in graph_ai_result
    ):

        failures.append(
            "Graph embedding leaked into AI context."
        )


    # ============================================================
    # RELATIONSHIP FACTS
    # ============================================================

    relationships = (
        result.get(
            "retrieved_relationships"
        )
        or []
    )


    if not relationships:

        failures.append(
            "No graph relationships retrieved."
        )


    # ============================================================
    # INTERPRETATION POLICY
    # ============================================================

    policy = (
        result.get(
            "interpretation_policy"
        )
        or {}
    )


    required_policy = {

        "graph_is_supporting_context_not_proof",

        "graph_anomaly_score_is_not_probability",

        "stored_edge_is_not_proof_of_attack",

        "unverified_relationship_is_not_attribution",

        "inferred_relationship_requires_corroboration",

        "empty_graph_is_not_benign_evidence",
    }


    for key in required_policy:

        if (
            policy.get(
                key
            )
            is not True
        ):

            failures.append(
                f"Missing graph policy: {key}"
            )


    # ============================================================
    # SAFETY
    # ============================================================

    if (
        result.get(
            "simulation_only"
        )
        is not True
    ):

        failures.append(
            "simulation_only is not True."
        )


    if (
        result.get(
            "execution_allowed"
        )
        is not False
    ):

        failures.append(
            "execution_allowed is not False."
        )


    # ============================================================
    # EMPTY GRAPH BEHAVIOR
    # ============================================================

    print()
    print(
        "[3] EMPTY GRAPH SAFETY"
    )


    empty_result = (
        SecurityGraphContextService(
            subgraph_service=
                FakeSubgraphService(),
            graph_result_store=
                FakeGraphResultStore(),
        )
        .build(

            threat={

                "id":
                    "empty-test",

                "event_id":
                    "EMPTY-GRAPH-EVENT",

                "category":
                    "FILE",

                "threat_type":
                    "UNKNOWN_FILE",
            },

            enriched_evidence=None,
        )
    )


    # No PID means provenance and Graph AI should not be invented.
    if (
        empty_result[
            "process_identity"
        ][
            "resolved"
        ]
        is not False
    ):

        failures.append(
            "Empty graph test invented process identity."
        )


    # ============================================================
    # FINAL
    # ============================================================

    print()

    print(
        "=" * 110
    )

    print(
        "7D.3 SECURITY GRAPH CONTEXT RESULT"
    )

    print(
        "=" * 110
    )


    if failures:

        print(
            f"TOTAL FAILURES : {len(failures)}"
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
        "AttackGraphAgent integration       : PASS"
    )

    print(
        "Process provenance integration     : PASS"
    )

    print(
        "Graph-AI evidence integration      : PASS"
    )

    print(
        "Process identity resolution        : PASS"
    )

    print(
        "Graph relationship retrieval       : PASS"
    )

    print(
        "Graph evidence interpretation      : PASS"
    )

    print(
        "Embedding exclusion                : PASS"
    )

    print(
        "No-evidence safety                 : PASS"
    )

    print(
        "Simulation boundary                : PASS"
    )

    print()
    print(
        "RESULT: PASS"
    )

    print(
        (
            "SENTINEL-X Security Graph Context "
            "Service is ready for EvidenceContextBuilder integration."
        )
    )

    return 0


if __name__ == "__main__":

    sys.exit(
        main()
    )