from agents.attack_graph_agent import (
    AttackGraphAgent,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X ATTACK GRAPH TEST"
    )
    print("=" * 80)


    enriched_evidence = {

        "incident_id":
            "INC-GRAPH-001",

        # ========================================================
        # PROCESS
        # ========================================================

        "processes": [

            {
                "pid":
                    5000,

                "ppid":
                    1000,

                "name":
                    "demo.exe",

                "exe":
                    r"C:\Temp\demo.exe",

                "behavior_score":
                    75,

                "anomaly_score":
                    60,

                "combined_threat_score":
                    90,
            },
        ],


        # ========================================================
        # FILE
        # ========================================================

        "files": [

            {
                "name":
                    "demo.exe",

                "path":
                    r"C:\Temp\demo.exe",

                "sha256":
                    "GRAPH_TEST_HASH",

                "malware_probability":
                    0.92,

                "static_risk_score":
                    70,
            },
        ],


        # ========================================================
        # NETWORK
        # ========================================================

        "network_connections": [

            {
                "pid":
                    5000,

                "process_name":
                    "demo.exe",

                "protocol":
                    "TCP",

                "remote_ip":
                    "203.0.113.90",

                "remote_port":
                    443,
            },
        ],


        # ========================================================
        # REGISTRY
        # ========================================================

        "registry_artifacts": [

            {
                "key":
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                "value_name":
                    "DemoApp",

                "value_data":
                    r"C:\Temp\demo.exe",
            },
        ],


        # ========================================================
        # RELATIONSHIPS
        # ========================================================

        "relationships": [

            {
                "source_type":
                    "PROCESS",

                "source":
                    "demo.exe",

                "relationship":
                    "EXECUTABLE_FILE",

                "target_type":
                    "FILE",

                "target":
                    r"C:\Temp\demo.exe",

                "confidence":
                    100,
            },


            {
                "source_type":
                    "PROCESS",

                "source":
                    "demo.exe",

                "relationship":
                    "CONNECTED_TO",

                "target_type":
                    "NETWORK",

                "target":
                    "203.0.113.90",

                "confidence":
                    100,
            },


            {
                "source_type":
                    "REGISTRY",

                "source":
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                "relationship":
                    "REFERENCES",

                "target_type":
                    "FILE",

                "target":
                    r"C:\Temp\demo.exe",

                "confidence":
                    100,
            },


            {
                "source_type":
                    "REGISTRY",

                "source":
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                "relationship":
                    "PERSISTENCE_REFERENCE",

                "target_type":
                    "PROCESS",

                "target":
                    "demo.exe",

                "confidence":
                    90,
            },
        ],
    }


    agent = (
        AttackGraphAgent()
    )


    result = (
        agent.generate(
            enriched_evidence
        )
    )


    # ============================================================
    # SUMMARY
    # ============================================================

    print()
    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )

    print(
        "Agent:",
        result[
            "agent"
        ],
    )


    summary = (
        result[
            "summary"
        ]
    )


    print()
    print(
        "GRAPH SUMMARY"
    )

    print(
        "Nodes:",
        summary[
            "nodes"
        ],
    )

    print(
        "Edges:",
        summary[
            "edges"
        ],
    )

    print(
        "Node Types:",
        summary[
            "node_types"
        ],
    )


    # ============================================================
    # NODES
    # ============================================================

    print()
    print("=" * 80)
    print(
        "GRAPH NODES"
    )
    print("=" * 80)


    for node in result[
        "graph"
    ][
        "nodes"
    ]:

        print()

        print(
            "ID:",
            node[
                "id"
            ],
        )

        print(
            "Type:",
            node.get(
                "type"
            ),
        )

        print(
            "Label:",
            node.get(
                "label"
            ),
        )


    # ============================================================
    # EDGES
    # ============================================================

    print()
    print("=" * 80)
    print(
        "GRAPH EDGES"
    )
    print("=" * 80)


    for edge in result[
        "graph"
    ][
        "edges"
    ]:

        print()

        print(
            edge[
                "source"
            ],
            "--",
            edge.get(
                "relationship"
            ),
            "-->",
            edge[
                "target"
            ],
        )

        print(
            "Confidence:",
            edge.get(
                "confidence"
            ),
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    node_count_pass = (
        result[
            "graph"
        ][
            "node_count"
        ]
        == 4
    )


    edge_count_pass = (
        result[
            "graph"
        ][
            "edge_count"
        ]
        >= 4
    )


    node_types = (
        result[
            "summary"
        ][
            "node_types"
        ]
    )


    process_pass = (
        node_types[
            "PROCESS"
        ]
        == 1
    )


    file_pass = (
        node_types[
            "FILE"
        ]
        == 1
    )


    network_pass = (
        node_types[
            "NETWORK"
        ]
        == 1
    )


    registry_pass = (
        node_types[
            "REGISTRY"
        ]
        == 1
    )


    relationships = [

        edge.get(
            "relationship"
        )

        for edge in result[
            "graph"
        ][
            "edges"
        ]
    ]


    executable_pass = (
        "EXECUTABLE_FILE"
        in relationships
    )


    network_edge_pass = (
        "CONNECTED_TO"
        in relationships
    )


    persistence_pass = (
        "PERSISTENCE_REFERENCE"
        in relationships
    )


    print()
    print("=" * 80)
    print(
        "FINAL ATTACK GRAPH VALIDATION"
    )
    print("=" * 80)


    print(
        "Graph node count:",
        "PASS"
        if node_count_pass
        else "FAIL",
    )


    print(
        "Graph edge count:",
        "PASS"
        if edge_count_pass
        else "FAIL",
    )


    print(
        "Process node:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "File node:",
        "PASS"
        if file_pass
        else "FAIL",
    )


    print(
        "Network node:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Registry node:",
        "PASS"
        if registry_pass
        else "FAIL",
    )


    print(
        "Process -> File edge:",
        "PASS"
        if executable_pass
        else "FAIL",
    )


    print(
        "Process -> Network edge:",
        "PASS"
        if network_edge_pass
        else "FAIL",
    )


    print(
        "Persistence relationship:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    overall = all(
        [
            node_count_pass,
            edge_count_pass,
            process_pass,
            file_pass,
            network_pass,
            registry_pass,
            executable_pass,
            network_edge_pass,
            persistence_pass,
        ]
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )

    print("=" * 80)


if __name__ == "__main__":

    main()