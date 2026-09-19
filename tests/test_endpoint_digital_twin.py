from response.endpoint_digital_twin import (
    EndpointDigitalTwin,
)

from response.digital_twin_simulator import (
    DigitalTwinSimulator,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X ENDPOINT CYBER DIGITAL TWIN TEST"
    )
    print("=" * 80)


    # ============================================================
    # SYNTHETIC EVIDENCE
    # ============================================================

    evidence = {

        "processes": [

            {
                "pid":
                    7000,

                "name":
                    "demo.exe",

                "exe":
                    r"C:\Temp\demo.exe",

                "combined_threat_score":
                    95,
            },
        ],


        "files": [

            {
                "name":
                    "demo.exe",

                "path":
                    r"C:\Temp\demo.exe",

                "sha256":
                    "DIGITAL_TWIN_SHA256",

                "malware_probability":
                    0.96,
            },
        ],


        "network_connections": [

            {
                "pid":
                    7000,

                "process_name":
                    "demo.exe",

                "remote_ip":
                    "203.0.113.100",

                "remote_port":
                    443,
            },
        ],


        "registry_artifacts": [

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
        ],
    }


    # ============================================================
    # CREATE DIGITAL TWIN
    # ============================================================

    twin = (
        EndpointDigitalTwin(

            incident_id=
                "INC-TWIN-001",

            initial_risk_score=
                96,

            initial_risk_level=
                "CRITICAL",
        )
    )


    twin.load_evidence(
        evidence
    )


    simulator = (
        DigitalTwinSimulator()
    )


    # ============================================================
    # INITIAL STATE
    # ============================================================

    initial_summary = (
        twin.get_state_summary()
    )


    print()
    print(
        "Twin ID:",
        twin.twin_id,
    )

    print(
        "Initial Risk:",
        twin.initial_risk_score,
        twin.initial_risk_level,
    )

    print(
        "Initial State:",
        initial_summary,
    )


    # ============================================================
    # SIMULATE PROCESS TERMINATION
    # ============================================================

    process_result = (
        simulator.simulate_action(

            twin,

            action_type=
                "TERMINATE_PROCESS",

            target={
                "pid":
                    7000,
            },
        )
    )


    # ============================================================
    # SIMULATE FILE QUARANTINE
    # ============================================================

    file_result = (
        simulator.simulate_action(

            twin,

            action_type=
                "QUARANTINE_FILE",

            target={
                "path":
                    r"C:\Temp\demo.exe",

                "sha256":
                    "DIGITAL_TWIN_SHA256",
            },
        )
    )


    # ============================================================
    # SIMULATE PERSISTENCE REMOVAL
    # ============================================================

    persistence_result = (
        simulator.simulate_action(

            twin,

            action_type=
                "REMEDIATE_PERSISTENCE",

            target={
                "key":
                    (
                        r"HKCU\Software\Microsoft"
                        r"\Windows\CurrentVersion\Run"
                    ),

                "value_name":
                    "DemoApp",
            },
        )
    )


    # ============================================================
    # SIMULATE ENDPOINT ISOLATION
    # ============================================================

    isolation_result = (
        simulator.simulate_action(

            twin,

            action_type=
                "ISOLATE_ENDPOINT",
        )
    )


    # ============================================================
    # FINAL TWIN STATE
    # ============================================================

    final_summary = (
        twin.get_state_summary()
    )


    print()
    print("=" * 80)
    print(
        "FINAL DIGITAL TWIN STATE"
    )
    print("=" * 80)


    print(
        "Active Processes:",
        final_summary[
            "active_processes"
        ],
    )

    print(
        "Active Files:",
        final_summary[
            "active_files"
        ],
    )

    print(
        "Active Network Connections:",
        final_summary[
            "active_network_connections"
        ],
    )

    print(
        "Active Persistence Artifacts:",
        final_summary[
            "active_persistence_artifacts"
        ],
    )

    print(
        "Endpoint Isolated:",
        final_summary[
            "endpoint_isolated"
        ],
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    twin_pass = (
        twin.twin_id.startswith(
            "TWIN-"
        )
    )


    initial_state_pass = (

        initial_summary[
            "active_processes"
        ]
        == 1

        and

        initial_summary[
            "active_files"
        ]
        == 1

        and

        initial_summary[
            "active_network_connections"
        ]
        == 1

        and

        initial_summary[
            "active_persistence_artifacts"
        ]
        == 1
    )


    process_pass = (

        process_result[
            "success"
        ]
        is True

        and

        final_summary[
            "active_processes"
        ]
        == 0
    )


    file_pass = (

        file_result[
            "success"
        ]
        is True

        and

        final_summary[
            "active_files"
        ]
        == 0
    )


    network_pass = (
        final_summary[
            "active_network_connections"
        ]
        == 0
    )


    persistence_pass = (

        persistence_result[
            "success"
        ]
        is True

        and

        final_summary[
            "active_persistence_artifacts"
        ]
        == 0
    )


    isolation_pass = (

        isolation_result[
            "success"
        ]
        is True

        and

        final_summary[
            "endpoint_isolated"
        ]
        is True
    )


    history_pass = (
        len(
            twin.simulation_history
        )
        == 4
    )


    real_endpoint_pass = (
        twin.to_dict()[
            "real_endpoint_modified"
        ]
        is False
    )


    # ============================================================
    # PRINT VALIDATION
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL DIGITAL TWIN VALIDATION"
    )
    print("=" * 80)


    print(
        "Digital twin created:",
        "PASS"
        if twin_pass
        else "FAIL",
    )


    print(
        "Endpoint state loaded:",
        "PASS"
        if initial_state_pass
        else "FAIL",
    )


    print(
        "Process termination simulated:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "File quarantine simulated:",
        "PASS"
        if file_pass
        else "FAIL",
    )


    print(
        "Network effect simulated:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Persistence remediation simulated:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Endpoint isolation simulated:",
        "PASS"
        if isolation_pass
        else "FAIL",
    )


    print(
        "Simulation history recorded:",
        "PASS"
        if history_pass
        else "FAIL",
    )


    print(
        "Real endpoint unchanged:",
        "PASS"
        if real_endpoint_pass
        else "FAIL",
    )


    overall = all(
        [
            twin_pass,
            initial_state_pass,
            process_pass,
            file_pass,
            network_pass,
            persistence_pass,
            isolation_pass,
            history_pass,
            real_endpoint_pass,
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