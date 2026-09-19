from response.integrated_response_pipeline import (
    IntegratedResponsePipeline,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X INTELLIGENCE -> RESPONSE INTEGRATION TEST"
    )
    print("=" * 80)


    # ============================================================
    # SYNTHETIC INCIDENT ONLY
    # ============================================================

    incident = {

        "incident_id":
            "INC-END2END-001",

        "title":
            "Synthetic Multi-Source Incident",

        "severity":
            "CRITICAL",

        "correlation_score":
            95,

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
                    "e2e-process-001",

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
                        7000,

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
                        85,

                    "anomaly_score":
                        75,

                    "combined_threat_score":
                        98,

                    "behavior_indicators": [
                        "suspicious_execution"
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
                    "e2e-file-001",

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

                    "sha256":
                        "END2END_SHA256",

                    "is_pe":
                        True,

                    "static_risk_score":
                        80,

                    "malware_probability":
                        0.97,

                    "static_reasons": [
                        "High entropy executable"
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
                    "e2e-network-001",

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
                        7000,

                    "process_name":
                        "demo.exe",

                    "protocol":
                        "TCP",

                    "local_ip":
                        "192.168.1.10",

                    "local_port":
                        50000,

                    "remote_ip":
                        "203.0.113.90",

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
                    "e2e-registry-001",

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
                        (
                            r"HKCU\Software\Microsoft"
                            r"\Windows\CurrentVersion\Run"
                        ),

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


    # ============================================================
    # AUTONOMY LEVEL 2
    # RECOMMEND-ONLY MODE
    # ============================================================

    pipeline = (
        IntegratedResponsePipeline(

            autonomy_level=2,

            simulation_mode=True,
        )
    )


    result = (
        pipeline.process_incident(
            incident
        )
    )


    # ============================================================
    # PRINT SUMMARY
    # ============================================================

    print()
    print(
        "Incident ID:",
        result[
            "incident_id"
        ],
    )

    print(
        "Status:",
        result[
            "status"
        ],
    )

    print(
        "Autonomy Level:",
        result[
            "autonomy_level"
        ],
    )

    print(
        "Simulation Mode:",
        result[
            "simulation_mode"
        ],
    )

    print(
        "Mapped Actions:",
        result[
            "mapped_action_count"
        ],
    )

    print(
        "Automatic Safe Actions:",
        result[
            "automatic_safe_action_count"
        ],
    )

    print(
        "Approval Queue:",
        result[
            "approval_queue_count"
        ],
    )

    print(
        "Active Containment Performed:",
        result[
            "active_containment_performed"
        ],
    )


    # ============================================================
    # SAFE ACTIONS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "AUTOMATIC SAFE ACTIONS"
    )
    print("=" * 80)


    for action in result[
        "automatic_safe_actions"
    ]:

        print()

        print(
            "Action:",
            action[
                "action_type"
            ],
        )

        print(
            "Execution Status:",
            action[
                "execution_status"
            ],
        )


    # ============================================================
    # APPROVAL QUEUE
    # ============================================================

    print()
    print("=" * 80)
    print(
        "ANALYST APPROVAL QUEUE"
    )
    print("=" * 80)


    for action in result[
        "approval_queue"
    ]:

        print()

        print(
            "Action ID:",
            action[
                "action_id"
            ],
        )

        print(
            "Action:",
            action[
                "action_type"
            ],
        )

        print(
            "Approval:",
            action[
                "approval_status"
            ],
        )

        print(
            "Execution:",
            action[
                "execution_status"
            ],
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


    autonomy_pass = (
        result[
            "autonomy_level"
        ]
        == 2
    )


    mapped_pass = (
        result[
            "mapped_action_count"
        ]
        >= 5
    )


    safe_types = {

        item[
            "action_type"
        ]

        for item in result[
            "automatic_safe_actions"
        ]
    }


    monitor_pass = (
        "MONITOR_INCIDENT"
        in safe_types
    )


    investigate_pass = (
        "INVESTIGATE_INCIDENT"
        in safe_types
    )


    approval_types = {

        item[
            "action_type"
        ]

        for item in result[
            "approval_queue"
        ]
    }


    quarantine_pass = (
        "QUARANTINE_FILE"
        in approval_types
    )


    process_pass = (
        "TERMINATE_PROCESS"
        in approval_types
    )


    network_pass = (
        "BLOCK_NETWORK"
        in approval_types
    )


    persistence_pass = (
        "REMEDIATE_PERSISTENCE"
        in approval_types
    )


    isolation_pass = (
        "ISOLATE_ENDPOINT"
        in approval_types
    )


    approval_status_pass = all(

        item[
            "approval_status"
        ]
        == "PENDING"

        for item in result[
            "approval_queue"
        ]
    )


    execution_status_pass = all(

        item[
            "execution_status"
        ]
        == "NOT_EXECUTED"

        for item in result[
            "approval_queue"
        ]
    )


    no_containment_pass = (
        result[
            "active_containment_performed"
        ]
        is False
    )


    routed_execution_pass = all(

        item.get(
            "executed"
        )
        is False

        for item in result[
            "routed_results"
        ]
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL INTELLIGENCE -> RESPONSE VALIDATION"
    )
    print("=" * 80)


    print(
        "Pipeline completed:",
        "PASS"
        if status_pass
        else "FAIL",
    )


    print(
        "Autonomy level 2:",
        "PASS"
        if autonomy_pass
        else "FAIL",
    )


    print(
        "Response actions generated:",
        "PASS"
        if mapped_pass
        else "FAIL",
    )


    print(
        "Monitor action routed safely:",
        "PASS"
        if monitor_pass
        else "FAIL",
    )


    print(
        "Investigation routed safely:",
        "PASS"
        if investigate_pass
        else "FAIL",
    )


    print(
        "Quarantine requires approval:",
        "PASS"
        if quarantine_pass
        else "FAIL",
    )


    print(
        "Process response requires approval:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "Network response requires approval:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Persistence response requires approval:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Isolation requires approval:",
        "PASS"
        if isolation_pass
        else "FAIL",
    )


    print(
        "Approval queue pending:",
        "PASS"
        if approval_status_pass
        else "FAIL",
    )


    print(
        "Approval actions not executed:",
        "PASS"
        if execution_status_pass
        else "FAIL",
    )


    print(
        "Safe routes perform no real execution:",
        "PASS"
        if routed_execution_pass
        else "FAIL",
    )


    print(
        "No active containment:",
        "PASS"
        if no_containment_pass
        else "FAIL",
    )


    overall = all(
        [
            status_pass,
            autonomy_pass,
            mapped_pass,
            monitor_pass,
            investigate_pass,
            quarantine_pass,
            process_pass,
            network_pass,
            persistence_pass,
            isolation_pass,
            approval_status_pass,
            execution_status_pass,
            routed_execution_pass,
            no_containment_pass,
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