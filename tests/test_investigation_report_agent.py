from agents.investigation_report_agent import (
    InvestigationReportAgent,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X INVESTIGATION REPORT TEST"
    )
    print("=" * 80)


    # ============================================================
    # INCIDENT
    # ============================================================

    incident = {

        "incident_id":
            "INC-REPORT-001",

        "severity":
            "CRITICAL",

        "correlation_score":
            92,
    }


    # ============================================================
    # TRIAGE
    # ============================================================

    triage = {

        "incident_id":
            "INC-REPORT-001",

        "priority":
            "P1",

        "triage_score":
            100,

        "requires_investigation":
            True,

        "reasons": [

            "Very high multi-event correlation score.",

            "Possible persistence-related registry activity detected.",

            "Network communication is associated with the incident.",
        ],
    }


    # ============================================================
    # INVESTIGATION
    # ============================================================

    investigation = {

        "incident_id":
            "INC-REPORT-001",

        "priority":
            "IMMEDIATE",

        "findings": [

            "Activity spans 4 telemetry categories.",

            "1 process entity involved.",

            "1 file entity involved.",

            "1 network connection observed.",

            "1 registry-related artifact observed.",
        ],

        "indicators": [

            "suspicious_execution",

            "High entropy executable",
        ],
    }


    # ============================================================
    # EVIDENCE
    # ============================================================

    evidence = {

        "incident_id":
            "INC-REPORT-001",

        "processes": [

            {

                "pid":
                    5000,

                "name":
                    "demo.exe",

                "exe":
                    r"C:\Temp\demo.exe",

                "behavior_score":
                    75,

                "anomaly_score":
                    65,

                "combined_threat_score":
                    90,
            },
        ],


        "files": [

            {

                "name":
                    "demo.exe",

                "path":
                    r"C:\Temp\demo.exe",

                "sha256":
                    "REPORT_TEST_SHA256",

                "malware_probability":
                    0.94,
            },
        ],


        "network_connections": [

            {

                "pid":
                    5000,

                "process_name":
                    "demo.exe",

                "remote_ip":
                    "203.0.113.111",

                "remote_port":
                    443,
            },
        ],


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


        "iocs": {

            "hashes": [

                "REPORT_TEST_SHA256",
            ],

            "file_paths": [

                r"C:\Temp\demo.exe",
            ],

            "remote_ips": [

                "203.0.113.111",
            ],

            "registry_keys": [

                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            ],
        },
    }


    # ============================================================
    # ATTACK TIMELINE
    # ============================================================

    attack_timeline = {

        "attack_stages": [

            "EXECUTION",

            "FILE_ACTIVITY",

            "COMMAND_OR_NETWORK_ACTIVITY",

            "PERSISTENCE",
        ],

        "attack_story": [

            "1. [PROCESS] Process started: demo.exe (PID 5000)",

            r"2. [FILE] File modified: C:\Temp\demo.exe",

            "3. [NETWORK] demo.exe connected to 203.0.113.111:443",

            r"4. [REGISTRY] Persistence activity in HKCU\...\Run",
        ],
    }


    # ============================================================
    # ATTACK GRAPH
    # ============================================================

    attack_graph = {

        "summary": {

            "nodes":
                4,

            "edges":
                4,

            "node_types": {

                "PROCESS":
                    1,

                "FILE":
                    1,

                "NETWORK":
                    1,

                "REGISTRY":
                    1,
            },
        },
    }


    # ============================================================
    # RISK
    # ============================================================

    risk = {

        "incident_id":
            "INC-REPORT-001",

        "risk_score":
            100,

        "risk_level":
            "CRITICAL",

        "requires_response":
            True,

        "recommended_action":
            "Immediate analyst review and containment recommendation.",

        "reasons": [

            "Very high cross-event correlation.",

            "Very high malware-model probability.",

            "Strong suspicious process behavior.",

            "Persistence-related activity is present.",

            "Network communication is associated with the incident.",
        ],

        "components": {

            "correlation": {

                "value":
                    92,

                "points":
                    15,
            },

            "malware_probability": {

                "value":
                    0.94,

                "points":
                    20,
            },

            "behavior": {

                "value":
                    75,

                "points":
                    15,
            },

            "persistence": {

                "value":
                    True,

                "points":
                    10,
            },
        },
    }


    # ============================================================
    # GENERATE REPORT
    # ============================================================

    agent = (
        InvestigationReportAgent()
    )


    result = (
        agent.generate(
            incident,
            triage,
            investigation,
            evidence,
            attack_timeline,
            attack_graph,
            risk,
        )
    )


    # ============================================================
    # PRINT REPORT
    # ============================================================

    print()
    print(
        result[
            "text_report"
        ]
    )


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    incident_pass = (
        result[
            "incident_id"
        ]
        == "INC-REPORT-001"
    )


    priority_pass = (
        result[
            "decision"
        ][
            "triage_priority"
        ]
        == "P1"
    )


    risk_pass = (
        result[
            "decision"
        ][
            "risk_level"
        ]
        == "CRITICAL"
    )


    response_pass = (
        result[
            "decision"
        ][
            "requires_response"
        ]
        is True
    )


    hash_pass = (
        "REPORT_TEST_SHA256"
        in result[
            "iocs"
        ][
            "hashes"
        ]
    )


    ip_pass = (
        "203.0.113.111"
        in result[
            "iocs"
        ][
            "remote_ips"
        ]
    )


    attack_pass = (
        len(
            result[
                "attack"
            ][
                "attack_story"
            ]
        )
        == 4
    )


    graph_pass = (
        result[
            "attack"
        ][
            "graph_nodes"
        ]
        == 4

        and result[
            "attack"
        ][
            "graph_edges"
        ]
        == 4
    )


    report_pass = (
        "SENTINEL-X INCIDENT INVESTIGATION REPORT"
        in result[
            "text_report"
        ]

        and "CRITICAL"
        in result[
            "text_report"
        ]
    )


    print()
    print("=" * 80)
    print(
        "FINAL INVESTIGATION REPORT VALIDATION"
    )
    print("=" * 80)


    print(
        "Incident identification:",
        "PASS"
        if incident_pass
        else "FAIL",
    )

    print(
        "Triage priority:",
        "PASS"
        if priority_pass
        else "FAIL",
    )

    print(
        "Risk assessment:",
        "PASS"
        if risk_pass
        else "FAIL",
    )

    print(
        "Response recommendation:",
        "PASS"
        if response_pass
        else "FAIL",
    )

    print(
        "Hash IOC:",
        "PASS"
        if hash_pass
        else "FAIL",
    )

    print(
        "Network IOC:",
        "PASS"
        if ip_pass
        else "FAIL",
    )

    print(
        "Attack reconstruction:",
        "PASS"
        if attack_pass
        else "FAIL",
    )

    print(
        "Attack graph summary:",
        "PASS"
        if graph_pass
        else "FAIL",
    )

    print(
        "Human-readable report:",
        "PASS"
        if report_pass
        else "FAIL",
    )


    overall = all(
        [
            incident_pass,
            priority_pass,
            risk_pass,
            response_pass,
            hash_pass,
            ip_pass,
            attack_pass,
            graph_pass,
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