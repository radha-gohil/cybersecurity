from response.network_response_manager import (
    NetworkResponseManager,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X NETWORK RESPONSE MANAGER TEST"
    )
    print("=" * 80)


    manager = (
        NetworkResponseManager(
            simulation_mode=True
        )
    )


    # ============================================================
    # SYNTHETIC NETWORK TARGETS
    #
    # Documentation-range IPs only.
    # No firewall or connection is modified.
    # ============================================================

    connections = [

        {
            "remote_ip":
                "203.0.113.10",

            "remote_port":
                443,

            "pid":
                11111,

            "process_name":
                "demo.exe",
        },

        {
            "remote_ip":
                "198.51.100.25",

            "remote_port":
                8443,

            "pid":
                22222,

            "process_name":
                "example.exe",
        },
    ]


    result = (
        manager.process_targets(

            incident_id=
                "INC-NETWORK-001",

            action_id=
                "ACT-NETWORK-001",

            connections=
                connections,

            reason=
                "Synthetic network-response simulation.",
        )
    )


    # ============================================================
    # PRINT RESULTS
    # ============================================================

    print()
    print(
        "Simulation Mode:",
        result[
            "simulation_mode"
        ],
    )

    print(
        "Target Count:",
        result[
            "target_count"
        ],
    )

    print(
        "Successful Simulations:",
        result[
            "successful_simulations"
        ],
    )

    print(
        "Failed Simulations:",
        result[
            "failed_simulations"
        ],
    )

    print(
        "Real Network Block Performed:",
        result[
            "real_network_block_performed"
        ],
    )


    print()
    print("=" * 80)
    print(
        "NETWORK RESPONSE RECORDS"
    )
    print("=" * 80)


    for item in result[
        "results"
    ]:

        print()

        print(
            "Status:",
            item.get(
                "status"
            ),
        )

        print(
            "Remote IP:",
            item.get(
                "remote_ip"
            ),
        )

        print(
            "Remote Port:",
            item.get(
                "remote_port"
            ),
        )

        print(
            "PID:",
            item.get(
                "pid"
            ),
        )

        print(
            "Process:",
            item.get(
                "process_name"
            ),
        )

        print(
            "Network Block Performed:",
            item.get(
                "network_block_performed"
            ),
        )

        print(
            "Firewall Modified:",
            item.get(
                "firewall_modified"
            ),
        )

        print(
            "Connection Terminated:",
            item.get(
                "connection_terminated"
            ),
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    simulation_pass = (
        result[
            "simulation_mode"
        ]
        is True
    )


    count_pass = (
        result[
            "target_count"
        ]
        == 2
    )


    success_pass = (
        result[
            "successful_simulations"
        ]
        == 2
    )


    no_real_block_pass = (
        result[
            "real_network_block_performed"
        ]
        is False
    )


    records_pass = all(

        item.get(
            "status"
        )
        == "SIMULATED"

        for item in result[
            "results"
        ]
    )


    no_firewall_change_pass = all(

        item.get(
            "firewall_modified"
        )
        is False

        for item in result[
            "results"
        ]
    )


    no_connection_termination_pass = all(

        item.get(
            "connection_terminated"
        )
        is False

        for item in result[
            "results"
        ]
    )


    # ============================================================
    # INVALID IP TEST
    # ============================================================

    invalid_ip_result = (
        manager.simulate_block(

            incident_id=
                "INC-NETWORK-002",

            action_id=
                "ACT-NETWORK-002",

            network_target={
                "remote_ip":
                    "999.999.999.999",

                "remote_port":
                    443,
            },

            reason=
                "Invalid IP test.",
        )
    )


    invalid_ip_pass = (

        invalid_ip_result[
            "success"
        ]
        is False

        and

        invalid_ip_result[
            "status"
        ]
        == "INVALID_TARGET"

        and

        invalid_ip_result[
            "network_block_performed"
        ]
        is False
    )


    # ============================================================
    # INVALID PORT TEST
    # ============================================================

    invalid_port_result = (
        manager.simulate_block(

            incident_id=
                "INC-NETWORK-003",

            action_id=
                "ACT-NETWORK-003",

            network_target={
                "remote_ip":
                    "203.0.113.50",

                "remote_port":
                    70000,
            },

            reason=
                "Invalid port test.",
        )
    )


    invalid_port_pass = (

        invalid_port_result[
            "success"
        ]
        is False

        and

        invalid_port_result[
            "status"
        ]
        == "INVALID_TARGET"
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL NETWORK RESPONSE VALIDATION"
    )
    print("=" * 80)


    print(
        "Simulation mode enabled:",
        "PASS"
        if simulation_pass
        else "FAIL",
    )


    print(
        "Two network targets processed:",
        "PASS"
        if count_pass
        else "FAIL",
    )


    print(
        "Both simulations successful:",
        "PASS"
        if success_pass
        else "FAIL",
    )


    print(
        "No real network block:",
        "PASS"
        if no_real_block_pass
        else "FAIL",
    )


    print(
        "Simulation records created:",
        "PASS"
        if records_pass
        else "FAIL",
    )


    print(
        "No firewall changes:",
        "PASS"
        if no_firewall_change_pass
        else "FAIL",
    )


    print(
        "No connection terminated:",
        "PASS"
        if no_connection_termination_pass
        else "FAIL",
    )


    print(
        "Invalid IP rejected:",
        "PASS"
        if invalid_ip_pass
        else "FAIL",
    )


    print(
        "Invalid port rejected:",
        "PASS"
        if invalid_port_pass
        else "FAIL",
    )


    overall = all(
        [
            simulation_pass,
            count_pass,
            success_pass,
            no_real_block_pass,
            records_pass,
            no_firewall_change_pass,
            no_connection_termination_pass,
            invalid_ip_pass,
            invalid_port_pass,
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