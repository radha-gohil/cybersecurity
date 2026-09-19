from agents.evidence_enrichment_agent import (
    EvidenceEnrichmentAgent,
)


def main():

    print()
    print("=" * 75)
    print(
        "SENTINEL-X EVIDENCE ENRICHMENT TEST"
    )
    print("=" * 75)


    incident = {

        "incident_id":
            "INC-EVIDENCE-001",

        "timeline": [

            # ====================================================
            # PROCESS
            # ====================================================

            {

                "event_id":
                    "proc-001",

                "event_type":
                    "process_start",

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
                        60,

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

                "event_type":
                    "file_modify",

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
                        "MD5_TEST",

                    "sha1":
                        "SHA1_TEST",

                    "sha256":
                        "SHA256_TEST",

                    "entropy":
                        7.2,

                    "is_pe":
                        True,

                    "static_risk_score":
                        70,

                    "static_severity":
                        "HIGH",

                    "ml_prediction":
                        1,

                    "malware_probability":
                        0.92,

                    "ml_confidence":
                        0.92,

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

                "event_type":
                    "network_connect",

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
                        "203.0.113.50",

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

                "event_type":
                    "registry_change",

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


    agent = (
        EvidenceEnrichmentAgent()
    )


    result = (
        agent.enrich(
            incident
        )
    )


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


    # ============================================================
    # SUMMARY
    # ============================================================

    print()
    print(
        "SUMMARY"
    )

    for key, value in result[
        "summary"
    ].items():

        print(
            f"{key}: {value}"
        )


    # ============================================================
    # PROCESSES
    # ============================================================

    print()
    print(
        "PROCESSES"
    )

    for item in result[
        "processes"
    ]:

        print(
            item
        )


    # ============================================================
    # FILES
    # ============================================================

    print()
    print(
        "FILES"
    )

    for item in result[
        "files"
    ]:

        print(
            item
        )


    # ============================================================
    # NETWORK
    # ============================================================

    print()
    print(
        "NETWORK"
    )

    for item in result[
        "network_connections"
    ]:

        print(
            item
        )


    # ============================================================
    # REGISTRY
    # ============================================================

    print()
    print(
        "REGISTRY"
    )

    for item in result[
        "registry_artifacts"
    ]:

        print(
            item
        )


    # ============================================================
    # IOCS
    # ============================================================

    print()
    print(
        "IOCS"
    )

    for key, value in result[
        "iocs"
    ].items():

        print(
            f"{key}: {value}"
        )


    # ============================================================
    # INDICATORS
    # ============================================================

    print()
    print(
        "INDICATORS"
    )

    for indicator in result[
        "indicators"
    ]:

        print(
            " -",
            indicator
        )


    # ============================================================
    # RELATIONSHIPS
    # ============================================================

    print()
    print(
        "RELATIONSHIPS"
    )

    for relationship in result[
        "relationships"
    ]:

        print(
            relationship
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    process_pass = (
        len(
            result[
                "processes"
            ]
        )
        >= 1
    )


    file_pass = (
        len(
            result[
                "files"
            ]
        )
        >= 1
    )


    network_pass = (
        len(
            result[
                "network_connections"
            ]
        )
        >= 1
    )


    registry_pass = (
        len(
            result[
                "registry_artifacts"
            ]
        )
        >= 1
    )


    hash_pass = (
        "SHA256_TEST"
        in result[
            "iocs"
        ][
            "hashes"
        ]
    )


    ip_pass = (
        "203.0.113.50"
        in result[
            "iocs"
        ][
            "remote_ips"
        ]
    )


    relationships_pass = (
        len(
            result[
                "relationships"
            ]
        )
        >= 3
    )


    print()
    print("=" * 75)
    print(
        "FINAL EVIDENCE VALIDATION"
    )
    print("=" * 75)


    print(
        "Process evidence:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "File evidence:",
        "PASS"
        if file_pass
        else "FAIL",
    )


    print(
        "Network evidence:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Registry evidence:",
        "PASS"
        if registry_pass
        else "FAIL",
    )


    print(
        "Hash extraction:",
        "PASS"
        if hash_pass
        else "FAIL",
    )


    print(
        "IP extraction:",
        "PASS"
        if ip_pass
        else "FAIL",
    )


    print(
        "Relationship extraction:",
        "PASS"
        if relationships_pass
        else "FAIL",
    )


    overall = all(
        [
            process_pass,
            file_pass,
            network_pass,
            registry_pass,
            hash_pass,
            ip_pass,
            relationships_pass,
        ]
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )


    print("=" * 75)


if __name__ == "__main__":

    main()