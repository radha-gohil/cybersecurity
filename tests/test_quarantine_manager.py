from response.quarantine_manager import (
    QuarantineManager,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X QUARANTINE MANAGER TEST"
    )
    print("=" * 80)


    manager = (
        QuarantineManager(
            simulation_mode=True
        )
    )


    # ============================================================
    # SAFE SYNTHETIC FILE METADATA
    #
    # No real file is touched.
    # ============================================================

    files = [

        {
            "path":
                r"C:\Temp\demo.exe",

            "sha256":
                "QUARANTINE_TEST_SHA256_001",
        },

        {
            "path":
                r"C:\Temp\example.dll",

            "sha256":
                "QUARANTINE_TEST_SHA256_002",
        },
    ]


    result = (
        manager.process_targets(

            incident_id=
                "INC-QUARANTINE-001",

            action_id=
                "ACT-SYNTHETIC-001",

            files=
                files,

            reason=
                "Synthetic quarantine simulation test.",
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
        "Real Quarantine Performed:",
        result[
            "real_quarantine_performed"
        ],
    )


    print()
    print("=" * 80)
    print(
        "QUARANTINE RECORDS"
    )
    print("=" * 80)


    for item in result[
        "results"
    ]:

        print()

        print(
            "Success:",
            item.get(
                "success"
            ),
        )

        print(
            "Status:",
            item.get(
                "status"
            ),
        )

        print(
            "Quarantine ID:",
            item.get(
                "quarantine_id"
            ),
        )

        print(
            "Original Path:",
            item.get(
                "original_path"
            ),
        )

        print(
            "SHA256:",
            item.get(
                "sha256"
            ),
        )

        print(
            "Simulated Destination:",
            item.get(
                "simulated_destination"
            ),
        )

        print(
            "File Moved:",
            item.get(
                "file_moved"
            ),
        )

        print(
            "File Deleted:",
            item.get(
                "file_deleted"
            ),
        )

        print(
            "File Modified:",
            item.get(
                "file_modified"
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


    no_real_quarantine_pass = (
        result[
            "real_quarantine_performed"
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


    no_file_move_pass = all(

        item.get(
            "file_moved"
        )
        is False

        for item in result[
            "results"
        ]
    )


    no_file_delete_pass = all(

        item.get(
            "file_deleted"
        )
        is False

        for item in result[
            "results"
        ]
    )


    no_file_modify_pass = all(

        item.get(
            "file_modified"
        )
        is False

        for item in result[
            "results"
        ]
    )


    quarantine_directory_pass = (
        manager.quarantine_root.exists()
    )


    # ============================================================
    # INVALID TARGET TEST
    # ============================================================

    invalid_result = (
        manager.simulate_quarantine(

            incident_id=
                "INC-QUARANTINE-002",

            action_id=
                "ACT-SYNTHETIC-002",

            file_target={

                "path":
                    r"C:\Temp\missing_hash.exe",
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
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL QUARANTINE MANAGER VALIDATION"
    )
    print("=" * 80)


    print(
        "Simulation mode enabled:",
        "PASS"
        if simulation_pass
        else "FAIL",
    )


    print(
        "Two targets processed:",
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
        "No real quarantine:",
        "PASS"
        if no_real_quarantine_pass
        else "FAIL",
    )


    print(
        "Simulation records created:",
        "PASS"
        if records_pass
        else "FAIL",
    )


    print(
        "No file moved:",
        "PASS"
        if no_file_move_pass
        else "FAIL",
    )


    print(
        "No file deleted:",
        "PASS"
        if no_file_delete_pass
        else "FAIL",
    )


    print(
        "No file modified:",
        "PASS"
        if no_file_modify_pass
        else "FAIL",
    )


    print(
        "Quarantine directory available:",
        "PASS"
        if quarantine_directory_pass
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
            no_real_quarantine_pass,
            records_pass,
            no_file_move_pass,
            no_file_delete_pass,
            no_file_modify_pass,
            quarantine_directory_pass,
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