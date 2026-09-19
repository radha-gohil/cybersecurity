from agents.incident_intelligence_orchestrator import (
    IncidentIntelligenceOrchestrator,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X INCIDENT INTELLIGENCE ORCHESTRATOR TEST"
    )
    print("=" * 80)


    incident = {

        "incident_id":
            "INC-ORCHESTRATOR-001",

        "title":
            "Correlated Process File Network Registry Activity",

        "severity":
            "CRITICAL",

        "correlation_score":
            92,

        "categories": [
            "PROCESS",
            "FILE",
            "NETWORK",
            "REGISTRY",
        ],

        "timeline": [

            # ====================================================
            # PROCESS
            # ====================================================

            {

                "event_id":
                    "proc-001",

                "timestamp_unix":
                    1000,

                "event_type":
                    "process_start",

                "source":
                    "process_monitor",

                "severity":
                    "HIGH",

                "process": {

                    "pid":
                        5000,

                    "ppid":
                        1000,

                    "name":
                        "demo.exe",

                    "exe":
                        r"C:\Temp\demo.exe",

                    "cmdline":
                        r"C:\Temp\demo.exe",

                    "parent_name":
                        "explorer.exe",

                    "behavior_score":
                        75,

                    "anomaly_score":
                        65,

                    "combined_threat_score":
                        90,

                    "behavior_indicators": [
                        "suspicious_execution",
                    ],
                },

                "file":
                    {},

                "network":
                    {},

                "registry":
                    {},

                "metadata":
                    {},
            },


            # ====================================================
            # FILE
            # ====================================================

            {

                "event_id":
                    "file-001",

                "timestamp_unix":
                    1010,

                "event_type":
                    "file_modify",

                "source":
                    "file_monitor",

                "severity":
                    "HIGH",

                "process":
                    {},

                "file": {

                    "name":
                        "demo.exe",

                    "path":
                        r"C:\Temp\demo.exe",

                    "extension":
                        ".exe",

                    "size":
                        250000,

                    "md5":
                        "ORCH_MD5",

                    "sha1":
                        "ORCH_SHA1",

                    "sha256":
                        "ORCH_SHA256",

                    "entropy":
                        7.2,

                    "is_pe":
                        True,

                    "static_risk_score":
                        72,

                    "static_severity":
                        "HIGH",

                    "ml_prediction":
                        1,

                    "malware_probability":
                        0.94,

                    "ml_confidence":
                        0.94,

                    "static_reasons": [
                        "Executable or script file type",
                        "High entropy executable",
                    ],
                },

                "network":
                    {},

                "registry":
                    {},

                "metadata":
                    {},
            },


            # ====================================================
            # NETWORK
            # ====================================================

            {

                "event_id":
                    "network-001",

                "timestamp_unix":
                    1020,

                "event_type":
                    "network_connect",

                "source":
                    "network_monitor",

                "severity":
                    "HIGH",

                "process":
                    {},

                "file":
                    {},

                "network": {

                    "pid":
                        5000,

                    "process_name":
                        "demo.exe",

                    "protocol":
                        "TCP",

                    "local_ip":
                        "192.168.1.10",

                    "local_port":
                        51000,

                    "remote_ip":
                        "203.0.113.150",

                    "remote_port":
                        443,

                    "status":
                        "ESTABLISHED",
                },

                "registry":
                    {},

                "metadata":
                    {},
            },


            # ====================================================
            # REGISTRY
            # ====================================================

            {

                "event_id":
                    "registry-001",

                "timestamp_unix":
                    1030,

                "event_type":
                    "registry_change",

                "source":
                    "registry_monitor",

                "severity":
                    "HIGH",

                "process":
                    {},

                "file":
                    {},

                "network":
                    {},

                "registry": {

                    "key":
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                    "value_name":
                        "DemoApp",

                    "value_data":
                        r"C:\Temp\demo.exe",
                },

                "metadata":
                    {},
            },
        ],
    }


    orchestrator = (
        IncidentIntelligenceOrchestrator()
    )


    result = (
        orchestrator.process_incident(
            incident
        )
    )


    # ============================================================
    # PRINT PIPELINE STATUS
    # ============================================================

    print()
    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )

    print(
        "Pipeline Status:",
        result[
            "status"
        ],
    )


    # ============================================================
    # TRIAGE
    # ============================================================

    print()
    print("-" * 80)
    print(
        "TRIAGE"
    )
    print("-" * 80)

    print(
        "Priority:",
        result[
            "triage"
        ][
            "priority"
        ],
    )

    print(
        "Score:",
        result[
            "triage"
        ][
            "triage_score"
        ],
    )


    # ============================================================
    # INVESTIGATION
    # ============================================================

    print()
    print("-" * 80)
    print(
        "INVESTIGATION"
    )
    print("-" * 80)

    print(
        "Priority:",
        result[
            "investigation"
        ][
            "priority"
        ],
    )

    print(
        "Event Count:",
        result[
            "investigation"
        ][
            "event_count"
        ],
    )


    # ============================================================
    # EVIDENCE
    # ============================================================

    print()
    print("-" * 80)
    print(
        "EVIDENCE"
    )
    print("-" * 80)

    print(
        result[
            "evidence"
        ][
            "summary"
        ]
    )


    # ============================================================
    # TIMELINE
    # ============================================================

    print()
    print("-" * 80)
    print(
        "ATTACK TIMELINE"
    )
    print("-" * 80)

    for item in result[
        "attack_timeline"
    ][
        "attack_story"
    ]:

        print(
            item
        )


    # ============================================================
    # ATTACK GRAPH
    # ============================================================

    print()
    print("-" * 80)
    print(
        "ATTACK GRAPH"
    )
    print("-" * 80)

    print(
        "Nodes:",
        result[
            "attack_graph"
        ][
            "summary"
        ][
            "nodes"
        ],
    )

    print(
        "Edges:",
        result[
            "attack_graph"
        ][
            "summary"
        ][
            "edges"
        ],
    )


    # ============================================================
    # RISK
    # ============================================================

    print()
    print("-" * 80)
    print(
        "RISK"
    )
    print("-" * 80)

    print(
        "Risk Score:",
        result[
            "risk"
        ][
            "risk_score"
        ],
    )

    print(
        "Risk Level:",
        result[
            "risk"
        ][
            "risk_level"
        ],
    )

    print(
        "Requires Response:",
        result[
            "risk"
        ][
            "requires_response"
        ],
    )


    # ============================================================
    # REPORT
    # ============================================================

    print()
    print("-" * 80)
    print(
        "FINAL REPORT"
    )
    print("-" * 80)

    print(
        result[
            "report"
        ][
            "text_report"
        ]
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    status_pass = (
        result[
            "status"
        ]
        == "COMPLETED"
    )


    triage_pass = (
        result[
            "triage"
        ][
            "priority"
        ]
        == "P1"
    )


    investigation_pass = (
        result[
            "investigation"
        ][
            "event_count"
        ]
        == 4
    )


    evidence_pass = (
        result[
            "evidence"
        ][
            "summary"
        ][
            "process_count"
        ]
        >= 1

        and result[
            "evidence"
        ][
            "summary"
        ][
            "file_count"
        ]
        >= 1

        and result[
            "evidence"
        ][
            "summary"
        ][
            "network_count"
        ]
        >= 1

        and result[
            "evidence"
        ][
            "summary"
        ][
            "registry_count"
        ]
        >= 1
    )


    timeline_pass = (
        len(
            result[
                "attack_timeline"
            ][
                "attack_story"
            ]
        )
        == 4
    )


    graph_pass = (
        result[
            "attack_graph"
        ][
            "summary"
        ][
            "nodes"
        ]
        >= 4

        and result[
            "attack_graph"
        ][
            "summary"
        ][
            "edges"
        ]
        >= 3
    )


    risk_pass = (
        result[
            "risk"
        ][
            "risk_level"
        ]
        == "CRITICAL"

        and result[
            "risk"
        ][
            "risk_score"
        ]
        >= 80
    )


    report_pass = (
        "SENTINEL-X INCIDENT INVESTIGATION REPORT"
        in result[
            "report"
        ][
            "text_report"
        ]
    )


    print()
    print("=" * 80)
    print(
        "FINAL ORCHESTRATOR VALIDATION"
    )
    print("=" * 80)


    print(
        "Pipeline completed:",
        "PASS"
        if status_pass
        else "FAIL",
    )

    print(
        "Triage:",
        "PASS"
        if triage_pass
        else "FAIL",
    )

    print(
        "Investigation:",
        "PASS"
        if investigation_pass
        else "FAIL",
    )

    print(
        "Evidence enrichment:",
        "PASS"
        if evidence_pass
        else "FAIL",
    )

    print(
        "Attack timeline:",
        "PASS"
        if timeline_pass
        else "FAIL",
    )

    print(
        "Attack graph:",
        "PASS"
        if graph_pass
        else "FAIL",
    )

    print(
        "Risk assessment:",
        "PASS"
        if risk_pass
        else "FAIL",
    )

    print(
        "Investigation report:",
        "PASS"
        if report_pass
        else "FAIL",
    )


    overall = all(
        [
            status_pass,
            triage_pass,
            investigation_pass,
            evidence_pass,
            timeline_pass,
            graph_pass,
            risk_pass,
            report_pass,
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