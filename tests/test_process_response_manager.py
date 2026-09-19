from response.process_response_manager import (
    ProcessResponseManager,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X PROCESS RESPONSE MANAGER TEST"
    )
    print("=" * 80)


    manager = (
        ProcessResponseManager(
            simulation_mode=True
        )
    )


    # ============================================================
    # SYNTHETIC PROCESS TARGETS
    #
    # No process is actually terminated.
    # ============================================================

    processes = [

        {

            "pid":
                11111,

            "name":
                "demo.exe",

            "exe":
                r"C:\Temp\demo.exe",

            "threat_score":
                95,
        },

        {

            "pid":
                22222,

            "name":
                "example.exe",

            "exe":
                r"C:\Temp\example.exe",

            "threat_score":
                80,
        },
    ]


    result = (
        manager.process_targets(

            incident_id=
                "INC-PROCESS-001",

            action_id=
                "ACT-PROCESS-001",

            processes=
                processes,

            reason=
                "Synthetic process-response simulation.",
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
        "Real Process Termination Performed:",
        result[
            "real_process_termination_performed"
        ],
    )


    print()
    print("=" * 80)
    print(
        "PROCESS RESPONSE RECORDS"
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
            "Executable:",
            item.get(
                "executable"
            ),
        )

        print(
            "Threat Score:",
            item.get(
                "threat_score"
            ),
        )

        print(
            "Process Terminated:",
            item.get(
                "process_terminated"
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


    no_real_termination_pass = (
        result[
            "real_process_termination_performed"
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


    no_process_killed_pass = all(

        item.get(
            "process_terminated"
        )
        is False

        for item in result[
            "results"
        ]
    )


    # ============================================================
    # INVALID PID TEST
    # ============================================================

    invalid_result = (
        manager.simulate_termination(

            incident_id=
                "INC-PROCESS-002",

            action_id=
                "ACT-PROCESS-002",

            process_target={

                "pid":
                    -1,

                "name":
                    "invalid.exe",
            },

            reason=
                "Invalid PID test.",
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
            "process_terminated"
        ]
        is False
    )


    # ============================================================
    # MISSING PROCESS NAME TEST
    # ============================================================

    missing_name_result = (
        manager.simulate_termination(

            incident_id=
                "INC-PROCESS-003",

            action_id=
                "ACT-PROCESS-003",

            process_target={

                "pid":
                    33333,
            },

            reason=
                "Missing name test.",
        )
    )


    missing_name_pass = (

        missing_name_result[
            "success"
        ]
        is False

        and

        missing_name_result[
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
        "FINAL PROCESS RESPONSE VALIDATION"
    )
    print("=" * 80)


    print(
        "Simulation mode enabled:",
        "PASS"
        if simulation_pass
        else "FAIL",
    )


    print(
        "Two process targets processed:",
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
        "No real termination:",
        "PASS"
        if no_real_termination_pass
        else "FAIL",
    )


    print(
        "Simulation records created:",
        "PASS"
        if records_pass
        else "FAIL",
    )


    print(
        "No process killed:",
        "PASS"
        if no_process_killed_pass
        else "FAIL",
    )


    print(
        "Invalid PID rejected:",
        "PASS"
        if invalid_pass
        else "FAIL",
    )


    print(
        "Missing process name rejected:",
        "PASS"
        if missing_name_pass
        else "FAIL",
    )


    overall = all(
        [
            simulation_pass,
            count_pass,
            success_pass,
            no_real_termination_pass,
            records_pass,
            no_process_killed_pass,
            invalid_pass,
            missing_name_pass,
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