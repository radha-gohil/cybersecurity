from response.endpoint_digital_twin import (
    EndpointDigitalTwin,
)

from response.digital_twin_simulator import (
    DigitalTwinSimulator,
)

from response.digital_twin_risk_predictor import (
    DigitalTwinRiskPredictor,
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X DIGITAL TWIN RISK & IMPACT PREDICTOR TEST"
    )
    print("=" * 80)


    # ============================================================
    # SYNTHETIC ENDPOINT EVIDENCE
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

                "behavior_score":
                    85,

                "anomaly_score":
                    75,

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
                    "TWIN_RISK_SHA256",

                "malware_probability":
                    0.96,

                "static_risk_score":
                    80,
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
    # CREATE TWIN
    # ============================================================

    twin = EndpointDigitalTwin(

        incident_id=
            "INC-TWIN-RISK-001",

        initial_risk_score=
            96,

        initial_risk_level=
            "CRITICAL",
    )


    twin.load_evidence(
        evidence
    )


    simulator = (
        DigitalTwinSimulator()
    )


    predictor = (
        DigitalTwinRiskPredictor()
    )


    # ============================================================
    # BEFORE RESPONSE
    # ============================================================

    before = (
        predictor.predict(
            twin
        )
    )


    print()
    print("=" * 80)
    print(
        "BEFORE RESPONSE SIMULATION"
    )
    print("=" * 80)


    print(
        "Initial Risk:",
        before[
            "initial_risk_score"
        ],
    )

    print(
        "Predicted Current Risk:",
        before[
            "predicted_residual_risk"
        ],
    )

    print(
        "Current Risk Level:",
        before[
            "predicted_residual_level"
        ],
    )


    # ============================================================
    # SIMULATE RESPONSE PLAN
    # ============================================================

    simulator.simulate_action(

        twin,

        "TERMINATE_PROCESS",

        {
            "pid":
                7000,
        },
    )


    simulator.simulate_action(

        twin,

        "QUARANTINE_FILE",

        {
            "path":
                r"C:\Temp\demo.exe",

            "sha256":
                "TWIN_RISK_SHA256",
        },
    )


    simulator.simulate_action(

        twin,

        "REMEDIATE_PERSISTENCE",

        {
            "key":
                (
                    r"HKCU\Software\Microsoft"
                    r"\Windows\CurrentVersion\Run"
                ),

            "value_name":
                "DemoApp",
        },
    )


    # ============================================================
    # AFTER RESPONSE
    # ============================================================

    after = (
        predictor.predict(
            twin
        )
    )


    print()
    print("=" * 80)
    print(
        "AFTER RESPONSE SIMULATION"
    )
    print("=" * 80)


    print(
        "Initial Risk:",
        after[
            "initial_risk_score"
        ],
    )

    print(
        "Predicted Residual Risk:",
        after[
            "predicted_residual_risk"
        ],
    )

    print(
        "Predicted Residual Level:",
        after[
            "predicted_residual_level"
        ],
    )

    print(
        "Risk Reduction:",
        after[
            "risk_reduction"
        ],
    )

    print(
        "Risk Reduction %:",
        after[
            "risk_reduction_percentage"
        ],
    )

    print(
        "Response Effectiveness:",
        after[
            "response_effectiveness"
        ],
    )

    print(
        "Operational Impact:",
        after[
            "operational_impact"
        ][
            "impact_level"
        ],
    )

    print(
        "Recommended Decision:",
        after[
            "recommended_decision"
        ],
    )


    # ============================================================
    # COMPONENTS
    # ============================================================

    print()
    print("=" * 80)
    print(
        "PREDICTED RISK COMPONENTS"
    )
    print("=" * 80)


    for key, value in after[
        "risk_components"
    ].items():

        print(
            f"{key}: {value}"
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    initial_pass = (
        after[
            "initial_risk_score"
        ]
        == 96
    )


    reduced_pass = (
        after[
            "predicted_residual_risk"
        ]
        < 96
    )


    strong_reduction_pass = (
        after[
            "risk_reduction"
        ]
        > 50
    )


    percentage_pass = (
        after[
            "risk_reduction_percentage"
        ]
        >= 50
    )


    effectiveness_pass = (
        after[
            "response_effectiveness"
        ]
        in {
            "HIGH",
            "VERY_HIGH",
        }
    )


    process_removed_pass = (
        after[
            "risk_components"
        ][
            "process"
        ]
        == 0
    )


    file_removed_pass = (
        after[
            "risk_components"
        ][
            "file"
        ]
        == 0
    )


    network_removed_pass = (
        after[
            "risk_components"
        ][
            "network"
        ]
        == 0
    )


    persistence_removed_pass = (
        after[
            "risk_components"
        ][
            "persistence"
        ]
        == 0
    )


    real_endpoint_pass = (
        after[
            "real_endpoint_modified"
        ]
        is False
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL DIGITAL TWIN RISK PREDICTION VALIDATION"
    )
    print("=" * 80)


    print(
        "Initial risk preserved:",
        "PASS"
        if initial_pass
        else "FAIL",
    )


    print(
        "Residual risk reduced:",
        "PASS"
        if reduced_pass
        else "FAIL",
    )


    print(
        "Strong risk reduction:",
        "PASS"
        if strong_reduction_pass
        else "FAIL",
    )


    print(
        "Risk reduction percentage:",
        "PASS"
        if percentage_pass
        else "FAIL",
    )


    print(
        "Response effectiveness:",
        "PASS"
        if effectiveness_pass
        else "FAIL",
    )


    print(
        "Process risk removed:",
        "PASS"
        if process_removed_pass
        else "FAIL",
    )


    print(
        "File risk removed:",
        "PASS"
        if file_removed_pass
        else "FAIL",
    )


    print(
        "Network risk removed:",
        "PASS"
        if network_removed_pass
        else "FAIL",
    )


    print(
        "Persistence risk removed:",
        "PASS"
        if persistence_removed_pass
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
            initial_pass,
            reduced_pass,
            strong_reduction_pass,
            percentage_pass,
            effectiveness_pass,
            process_removed_pass,
            file_removed_pass,
            network_removed_pass,
            persistence_removed_pass,
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