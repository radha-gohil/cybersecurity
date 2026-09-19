from response.persistence_response_manager import (
    PersistenceResponseManager,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X PERSISTENCE RESPONSE MANAGER TEST"
    )
    print("=" * 80)


    manager = (
        PersistenceResponseManager(
            simulation_mode=True
        )
    )


    # ============================================================
    # SYNTHETIC REGISTRY ARTIFACTS
    #
    # No real registry values are modified.
    # ============================================================

    registry_artifacts = [

        {

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

        {

            "key":
                (
                    r"HKCU\Software\Microsoft"
                    r"\Windows\CurrentVersion\RunOnce"
                ),

            "value_name":
                "ExampleApp",

            "value_data":
                r"C:\Temp\example.exe",
        },
    ]


    result = (
        manager.process_targets(

            incident_id=
                "INC-PERSISTENCE-001",

            action_id=
                "ACT-PERSISTENCE-001",

            registry_artifacts=
                registry_artifacts,

            reason=
                "Synthetic persistence-response simulation.",
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
        "Real Registry Modification Performed:",
        result[
            "real_registry_modification_performed"
        ],
    )


    print()
    print("=" * 80)
    print(
        "PERSISTENCE RESPONSE RECORDS"
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
            "Registry Key:",
            item.get(
                "registry_key"
            ),
        )

        print(
            "Value Name:",
            item.get(
                "value_name"
            ),
        )

        print(
            "Value Data:",
            item.get(
                "value_data"
            ),
        )

        print(
            "Persistence Type:",
            item.get(
                "persistence_type"
            ),
        )

        print(
            "Registry Modified:",
            item.get(
                "registry_modified"
            ),
        )

        print(
            "Artifact Removed:",
            item.get(
                "artifact_removed"
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


    no_real_registry_change_pass = (
        result[
            "real_registry_modification_performed"
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


    no_registry_modify_pass = all(

        item.get(
            "registry_modified"
        )
        is False

        for item in result[
            "results"
        ]
    )


    no_removal_pass = all(

        item.get(
            "artifact_removed"
        )
        is False

        for item in result[
            "results"
        ]
    )


    run_detected_pass = (

        result[
            "results"
        ][
            0
        ][
            "persistence_type"
        ]
        == "RUN_KEY"
    )


    runonce_detected_pass = (

        result[
            "results"
        ][
            1
        ][
            "persistence_type"
        ]
        == "RUNONCE_KEY"
    )


    # ============================================================
    # INVALID TARGET TEST
    # ============================================================

    invalid_result = (
        manager.simulate_remediation(

            incident_id=
                "INC-PERSISTENCE-002",

            action_id=
                "ACT-PERSISTENCE-002",

            persistence_target={

                "value_name":
                    "MissingKey",
            },

            reason=
                "Invalid persistence target test.",
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
            "registry_modified"
        ]
        is False
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL PERSISTENCE RESPONSE VALIDATION"
    )
    print("=" * 80)


    print(
        "Simulation mode enabled:",
        "PASS"
        if simulation_pass
        else "FAIL",
    )


    print(
        "Two persistence targets processed:",
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
        "No real registry modification:",
        "PASS"
        if no_real_registry_change_pass
        else "FAIL",
    )


    print(
        "Simulation records created:",
        "PASS"
        if records_pass
        else "FAIL",
    )


    print(
        "No registry values changed:",
        "PASS"
        if no_registry_modify_pass
        else "FAIL",
    )


    print(
        "No persistence artifact removed:",
        "PASS"
        if no_removal_pass
        else "FAIL",
    )


    print(
        "Run key recognized:",
        "PASS"
        if run_detected_pass
        else "FAIL",
    )


    print(
        "RunOnce key recognized:",
        "PASS"
        if runonce_detected_pass
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
            count_pass,
            success_pass,
            no_real_registry_change_pass,
            records_pass,
            no_registry_modify_pass,
            no_removal_pass,
            run_detected_pass,
            runonce_detected_pass,
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