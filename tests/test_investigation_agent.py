from agents.investigation_agent import (
    InvestigationAgent,
)


def main():

    print()
    print("=" * 75)
    print(
        "SENTINEL-X INVESTIGATION AGENT TEST"
    )
    print("=" * 75)


    incident = {

        "incident_id":
            "INVESTIGATION-TEST-001",

        "title":
            "Correlated FILE + NETWORK + PROCESS + REGISTRY Activity",

        "status":
            "NEW",

        "correlation_score":
            90,

        "severity":
            "CRITICAL",

        "timeline": [

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
                    "MEDIUM",

                "process": {

                    "pid":
                        7000,

                    "name":
                        "demo.exe",

                    "exe":
                        r"C:\Temp\demo.exe",

                    "behavior_indicators": [
                        "script_interpreter",
                    ],
                },

                "file": {},

                "network": {},

                "registry": {},

                "metadata": {},
            },


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

                "process": {},

                "file": {

                    "name":
                        "demo.exe",

                    "path":
                        r"C:\Temp\demo.exe",

                    "sha256":
                        "TEST_HASH_001",

                    "is_pe":
                        True,

                    "static_risk_score":
                        65,

                    "malware_probability":
                        0.82,

                    "static_reasons": [
                        "Executable or script file type",
                        "High entropy executable",
                    ],
                },

                "network": {},

                "registry": {},

                "metadata": {},
            },


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

                "process": {},

                "file": {},

                "network": {

                    "pid":
                        7000,

                    "process_name":
                        "demo.exe",

                    "protocol":
                        "TCP",

                    "remote_ip":
                        "203.0.113.70",

                    "remote_port":
                        443,

                    "status":
                        "ESTABLISHED",
                },

                "registry": {},

                "metadata": {},
            },


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

                "process": {},

                "file": {},

                "network": {},

                "registry": {

                    "key":
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                    "value_name":
                        "DemoApp",

                    "value_data":
                        r"C:\Temp\demo.exe",
                },

                "metadata": {},
            },
        ],
    }


    agent = (
        InvestigationAgent()
    )


    result = (
        agent.investigate(
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

    print(
        "Priority:",
        result[
            "priority"
        ],
    )

    print(
        "Incident Score:",
        result[
            "incident_score"
        ],
    )

    print(
        "Severity:",
        result[
            "incident_severity"
        ],
    )

    print(
        "Event Count:",
        result[
            "event_count"
        ],
    )

    print(
        "Category Counts:",
        result[
            "category_counts"
        ],
    )


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


    print()
    print(
        "INDICATORS"
    )

    for item in result[
        "indicators"
    ]:

        print(
            " -",
            item
        )


    print()
    print(
        "FINDINGS"
    )

    for item in result[
        "findings"
    ]:

        print(
            " -",
            item
        )


    print()
    print(
        "Requires Response:",
        result[
            "requires_response"
        ],
    )


    print()
    print("=" * 75)
    print(
        "INVESTIGATION AGENT TEST COMPLETE"
    )
    print("=" * 75)


if __name__ == "__main__":

    main()