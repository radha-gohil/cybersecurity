from agents.triage_agent import (
    TriageAgent,
)


def print_result(
    result,
):

    print()
    print("-" * 75)

    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )

    print(
        "Priority:",
        result[
            "priority"
        ],
    )

    print(
        "Triage Score:",
        result[
            "triage_score"
        ],
    )

    print(
        "Recommendation:",
        result[
            "recommendation"
        ],
    )

    print(
        "Categories:",
        result[
            "categories"
        ],
    )

    print(
        "Malware Probability:",
        result[
            "malware_probability"
        ],
    )

    print(
        "Behavior Score:",
        result[
            "behavior_score"
        ],
    )

    print(
        "Anomaly Score:",
        result[
            "anomaly_score"
        ],
    )

    print(
        "Persistence:",
        result[
            "persistence_detected"
        ],
    )

    print(
        "Network Activity:",
        result[
            "network_activity"
        ],
    )

    print(
        "Requires Investigation:",
        result[
            "requires_investigation"
        ],
    )


    print()
    print(
        "Reasons:"
    )


    for reason in result[
        "reasons"
    ]:

        print(
            " -",
            reason
        )


def main():

    print()
    print("=" * 75)
    print(
        "SENTINEL-X TRIAGE AGENT TEST"
    )
    print("=" * 75)


    # ============================================================
    # CRITICAL INCIDENT
    # ============================================================

    critical_incident = {

        "incident_id":
            "INC-CRITICAL-001",

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

            {
                "event_id":
                    "proc-001",

                "event_type":
                    "process_start",

                "severity":
                    "HIGH",

                "process": {

                    "pid":
                        5000,

                    "name":
                        "demo.exe",

                    "behavior_score":
                        75,

                    "anomaly_score":
                        65,
                },

                "file": {},

                "network": {},

                "registry": {},

                "metadata": {},
            },


            {
                "event_id":
                    "file-001",

                "event_type":
                    "file_modify",

                "severity":
                    "HIGH",

                "process": {},

                "file": {

                    "name":
                        "demo.exe",

                    "path":
                        r"C:\Temp\demo.exe",

                    "malware_probability":
                        0.91,
                },

                "network": {},

                "registry": {},

                "metadata": {},
            },


            {
                "event_id":
                    "network-001",

                "event_type":
                    "network_connect",

                "severity":
                    "HIGH",

                "process": {},

                "file": {},

                "network": {

                    "pid":
                        5000,

                    "remote_ip":
                        "203.0.113.10",

                    "remote_port":
                        443,
                },

                "registry": {},

                "metadata": {},
            },


            {
                "event_id":
                    "registry-001",

                "event_type":
                    "registry_change",

                "severity":
                    "HIGH",

                "process": {},

                "file": {},

                "network": {},

                "registry": {

                    "key":
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

                    "value_name":
                        "Demo",

                    "value_data":
                        r"C:\Temp\demo.exe",
                },

                "metadata": {},
            },
        ],
    }


    # ============================================================
    # MEDIUM INCIDENT
    # ============================================================

    medium_incident = {

        "incident_id":
            "INC-MEDIUM-001",

        "severity":
            "MEDIUM",

        "correlation_score":
            45,

        "categories": [
            "PROCESS",
            "FILE",
        ],

        "timeline": [

            {
                "event_id":
                    "proc-002",

                "event_type":
                    "process_start",

                "severity":
                    "MEDIUM",

                "process": {

                    "pid":
                        6000,

                    "name":
                        "example.exe",

                    "behavior_score":
                        35,

                    "anomaly_score":
                        20,
                },

                "file": {},

                "network": {},

                "registry": {},

                "metadata": {},
            },

            {
                "event_id":
                    "file-002",

                "event_type":
                    "file_modify",

                "severity":
                    "LOW",

                "process": {},

                "file": {

                    "name":
                        "example.exe",

                    "path":
                        r"C:\Temp\example.exe",

                    "malware_probability":
                        0.30,
                },

                "network": {},

                "registry": {},

                "metadata": {},
            },
        ],
    }


    # ============================================================
    # LOW INCIDENT
    # ============================================================

    low_incident = {

        "incident_id":
            "INC-LOW-001",

        "severity":
            "LOW",

        "correlation_score":
            10,

        "categories": [
            "PROCESS",
        ],

        "timeline": [

            {
                "event_id":
                    "proc-003",

                "event_type":
                    "process_start",

                "severity":
                    "INFO",

                "process": {

                    "pid":
                        7000,

                    "name":
                        "notepad.exe",

                    "behavior_score":
                        0,

                    "anomaly_score":
                        0,
                },

                "file": {},

                "network": {},

                "registry": {},

                "metadata": {},
            },
        ],
    }


    agent = (
        TriageAgent()
    )


    results = (
        agent.triage_incidents(
            [
                low_incident,
                medium_incident,
                critical_incident,
            ]
        )
    )


    for result in results:

        print_result(
            result
        )


    # ============================================================
    # FINAL VALIDATION
    # ============================================================

    print()
    print("=" * 75)
    print(
        "FINAL TRIAGE VALIDATION"
    )
    print("=" * 75)


    highest = (
        results[
            0
        ]
    )


    critical_pass = (
        highest[
            "incident_id"
        ]
        == "INC-CRITICAL-001"
        and highest[
            "priority"
        ]
        == "P1"
    )


    medium_result = next(

        item

        for item in results

        if item[
            "incident_id"
        ]
        == "INC-MEDIUM-001"
    )


    medium_pass = (
        medium_result[
            "priority"
        ]
        in [
            "P2",
            "P3",
        ]
    )


    low_result = next(

        item

        for item in results

        if item[
            "incident_id"
        ]
        == "INC-LOW-001"
    )


    low_pass = (
        low_result[
            "priority"
        ]
        == "P4"
    )


    print(
        "Critical incident ranked first:",
        "PASS"
        if critical_pass
        else "FAIL",
    )


    print(
        "Medium incident classification:",
        "PASS"
        if medium_pass
        else "FAIL",
    )


    print(
        "Benign/low incident classification:",
        "PASS"
        if low_pass
        else "FAIL",
    )


    overall = (
        critical_pass
        and medium_pass
        and low_pass
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