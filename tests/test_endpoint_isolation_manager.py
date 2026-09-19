from response.endpoint_isolation_manager import (
    EndpointIsolationManager,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X ENDPOINT ISOLATION MANAGER TEST"
    )
    print("=" * 80)


    manager = (
        EndpointIsolationManager(
            simulation_mode=True
        )
    )


    # ============================================================
    # SYNTHETIC ENDPOINT TARGET
    #
    # No real network setting is modified.
    # ============================================================

    endpoint_target = {

        "hostname":
            "SENTINEL-TEST-ENDPOINT",

        "device_id":
            "DEVICE-SYNTHETIC-001",

        "management_channel":
            "SOC_CONTROL_CHANNEL",
    }


    result = (
        manager.process_target(

            incident_id=
                "INC-ISOLATION-001",

            action_id=
                "ACT-ISOLATION-001",

            endpoint_target=
                endpoint_target,

            reason=
                "Synthetic endpoint-isolation simulation.",
        )
    )


    isolation_result = (
        result[
            "result"
        ]
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
        "Status:",
        isolation_result[
            "status"
        ],
    )

    print(
        "Hostname:",
        isolation_result[
            "hostname"
        ],
    )

    print(
        "Device ID:",
        isolation_result[
            "device_id"
        ],
    )

    print(
        "Management Channel:",
        isolation_result[
            "management_channel"
        ],
    )

    print(
        "Endpoint Isolated:",
        isolation_result[
            "endpoint_isolated"
        ],
    )

    print(
        "Firewall Modified:",
        isolation_result[
            "firewall_modified"
        ],
    )

    print(
        "Routes Modified:",
        isolation_result[
            "routes_modified"
        ],
    )

    print(
        "Network Adapter Modified:",
        isolation_result[
            "network_adapter_modified"
        ],
    )


    # ============================================================
    # PRINT ISOLATION PLAN
    # ============================================================

    print()
    print("=" * 80)
    print(
        "SIMULATED ISOLATION PLAN"
    )
    print("=" * 80)


    for step in isolation_result[
        "isolation_plan"
    ]:

        print()

        print(
            "Step:",
            step[
                "step"
            ],
        )

        print(
            "Action:",
            step[
                "action"
            ],
        )

        print(
            "Description:",
            step[
                "description"
            ],
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


    status_pass = (
        isolation_result[
            "status"
        ]
        == "SIMULATED"
    )


    plan_pass = (
        len(
            isolation_result[
                "isolation_plan"
            ]
        )
        == 4
    )


    no_isolation_pass = (
        isolation_result[
            "endpoint_isolated"
        ]
        is False
    )


    no_firewall_pass = (
        isolation_result[
            "firewall_modified"
        ]
        is False
    )


    no_routes_pass = (
        isolation_result[
            "routes_modified"
        ]
        is False
    )


    no_adapter_pass = (
        isolation_result[
            "network_adapter_modified"
        ]
        is False
    )


    no_real_isolation_pass = (
        result[
            "real_endpoint_isolation_performed"
        ]
        is False
    )


    management_plan_pass = any(

        step[
            "action"
        ]
        == "PRESERVE_SOC_MANAGEMENT_PATH"

        for step in isolation_result[
            "isolation_plan"
        ]
    )


    # ============================================================
    # INVALID TARGET TEST
    # ============================================================

    invalid_result = (
        manager.simulate_isolation(

            incident_id=
                "INC-ISOLATION-002",

            action_id=
                "ACT-ISOLATION-002",

            endpoint_target={

                "hostname":
                    "TEST-ENDPOINT",
            },

            reason=
                "Invalid target test.",
        )
    )


    invalid_pass = (

        invalid_result[
            "success"
        ]
        is False

        and

        invalid_result[
            "status"
        ]
        == "INVALID_TARGET"

        and

        invalid_result[
            "endpoint_isolated"
        ]
        is False
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL ENDPOINT ISOLATION VALIDATION"
    )
    print("=" * 80)


    print(
        "Simulation mode enabled:",
        "PASS"
        if simulation_pass
        else "FAIL",
    )


    print(
        "Isolation simulation created:",
        "PASS"
        if status_pass
        else "FAIL",
    )


    print(
        "Isolation plan generated:",
        "PASS"
        if plan_pass
        else "FAIL",
    )


    print(
        "SOC management path preserved in plan:",
        "PASS"
        if management_plan_pass
        else "FAIL",
    )


    print(
        "Endpoint not actually isolated:",
        "PASS"
        if no_isolation_pass
        else "FAIL",
    )


    print(
        "No firewall modification:",
        "PASS"
        if no_firewall_pass
        else "FAIL",
    )


    print(
        "No route modification:",
        "PASS"
        if no_routes_pass
        else "FAIL",
    )


    print(
        "No adapter modification:",
        "PASS"
        if no_adapter_pass
        else "FAIL",
    )


    print(
        "No real endpoint isolation:",
        "PASS"
        if no_real_isolation_pass
        else "FAIL",
    )


    print(
        "Invalid target rejected:",
        "PASS"
        if invalid_pass
        else "FAIL",
    )


    overall = all(
        [
            simulation_pass,
            status_pass,
            plan_pass,
            management_plan_pass,
            no_isolation_pass,
            no_firewall_pass,
            no_routes_pass,
            no_adapter_pass,
            no_real_isolation_pass,
            invalid_pass,
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