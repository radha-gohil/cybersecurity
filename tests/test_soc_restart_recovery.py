from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)


TEST_INCIDENT = (
    "INC-RESTART-RECOVERY-001"
)


def build_intelligence():

    return {

        "risk_score":
            96,

        "risk_level":
            "CRITICAL",

        "risk": {

            "risk_score":
                96,

            "risk_level":
                "CRITICAL",
        },

        "coordinated_analysis": {

            "evidence": {

                "processes": [

                    {
                        "pid":
                            8100,

                        "name":
                            "recovery-demo.exe",

                        "exe":
                            (
                                r"C:\Temp"
                                r"\recovery-demo.exe"
                            ),

                        "behavior_score":
                            90,

                        "anomaly_score":
                            82,

                        "combined_threat_score":
                            96,
                    }
                ],

                "files": [

                    {
                        "name":
                            "recovery-demo.exe",

                        "path":
                            (
                                r"C:\Temp"
                                r"\recovery-demo.exe"
                            ),

                        "sha256":
                            "RESTART_RECOVERY_SHA256",

                        "malware_probability":
                            0.97,

                        "static_risk_score":
                            85,
                    }
                ],

                "network_connections": [

                    {
                        "pid":
                            8100,

                        "process_name":
                            "recovery-demo.exe",

                        "remote_ip":
                            "203.0.113.230",

                        "remote_port":
                            443,
                    }
                ],

                "registry_artifacts": [

                    {
                        "key":
                            (
                                r"HKCU\Software\Microsoft"
                                r"\Windows\CurrentVersion\Run"
                            ),

                        "value_name":
                            "RecoveryDemo",

                        "value_data":
                            (
                                r"C:\Temp"
                                r"\recovery-demo.exe"
                            ),
                    }
                ],
            },
        },

        "response": {

            "recommendations": [

                {
                    "recommendation_type":
                        "QUARANTINE_REVIEW",
                },

                {
                    "recommendation_type":
                        "PROCESS_TERMINATION_REVIEW",
                },

                {
                    "recommendation_type":
                        "NETWORK_BLOCK_REVIEW",
                },

                {
                    "recommendation_type":
                        "PERSISTENCE_REMEDIATION_REVIEW",
                },

                {
                    "recommendation_type":
                        "ENDPOINT_ISOLATION_REVIEW",
                },
            ],
        },
    }


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X SOC RESTART RECOVERY TEST"
    )
    print("=" * 80)


    # ============================================================
    # INSTANCE 1
    #
    # Represents the first API/server process.
    # ============================================================

    workflow_1 = (
        PersistentSOCWorkflow(
            simulation_mode=True
        )
    )


    existing = (
        workflow_1.recover_case(
            TEST_INCIDENT
        )
    )


    # ------------------------------------------------------------
    # Create only when test incident is not already in DB.
    # This makes the test safe to rerun.
    # ------------------------------------------------------------

    if existing is None:

        original_case = (
            workflow_1.create_case(

                incident_id=
                    TEST_INCIDENT,

                intelligence=
                    build_intelligence(),
            )
        )

    else:

        original_case = existing


    print()
    print(
        "Original Case Status:",
        original_case[
            "status"
        ],
    )

    print(
        "Original Response Actions:",
        original_case[
            "response_action_count"
        ],
    )


    # ============================================================
    # SIMULATE SERVER RESTART
    #
    # Create a completely new PersistentSOCWorkflow instance.
    # It has no dependency on the original Python case object.
    # ============================================================

    del workflow_1


    workflow_2 = (
        PersistentSOCWorkflow(
            simulation_mode=True
        )
    )


    recovered_case = (
        workflow_2.recover_case(
            TEST_INCIDENT
        )
    )


    print()
    print("=" * 80)
    print(
        "AFTER SIMULATED SERVER RESTART"
    )
    print("=" * 80)


    if recovered_case is None:

        print(
            "Recovered Case: NONE"
        )

        print()
        print(
            "OVERALL: FAIL"
        )

        return


    print(
        "Recovered Incident:",
        recovered_case[
            "incident_id"
        ],
    )

    print(
        "Recovered Status:",
        recovered_case[
            "status"
        ],
    )

    print(
        "Recovered Actions:",
        recovered_case[
            "response_action_count"
        ],
    )

    print(
        "Recovered From Database:",
        recovered_case[
            "recovered_from_database"
        ],
    )


    # ============================================================
    # RECOVER TICKET
    # ============================================================

    recovered_ticket = (
        workflow_2.recover_ticket(
            TEST_INCIDENT
        )
    )


    print(
        "Recovered Ticket:",
        (
            recovered_ticket.ticket_id
            if recovered_ticket
            else None
        ),
    )


    # ============================================================
    # VALIDATION BEFORE APPROVAL
    # ============================================================

    recovery_pass = (
        recovered_case
        is not None
    )


    incident_pass = (

        recovered_case[
            "incident_id"
        ]
        == TEST_INCIDENT
    )


    database_flag_pass = (

        recovered_case[
            "recovered_from_database"
        ]
        is True
    )


    ticket_pass = (
        recovered_ticket
        is not None
    )


    decision_pass = (

        recovered_case.get(
            "decision"
        )

        is not None
    )


    plan_pass = (

        recovered_case[
            "decision"
        ][
            "best_plan"
        ][
            "plan_name"
        ]
        == "Targeted Full Remediation"
    )


    action_count_pass = (

        recovered_case[
            "response_action_count"
        ]
        == 4
    )


    initial_action_state_pass = all(

        action.approval_status
        == "PENDING"

        for action in recovered_case[
            "response_actions"
        ]
    )


    # ============================================================
    # APPROVE AFTER RESTART
    # ============================================================

    approval_result = (
        workflow_2.approve_case(

            incident_id=
                TEST_INCIDENT,

            analyst=
                "SOCAnalystRestart",

            comment=
                (
                    "Case restored after simulated "
                    "server restart and approved."
                ),
        )
    )


    print()
    print("=" * 80)
    print(
        "POST-RESTART APPROVAL"
    )
    print("=" * 80)


    print(
        "Approval Success:",
        approval_result.get(
            "success"
        ),
    )

    print(
        "Status:",
        approval_result.get(
            "status"
        ),
    )

    print(
        "Real Response Executed:",
        approval_result.get(
            "real_response_executed"
        ),
    )


    # ============================================================
    # SIMULATE SECOND RESTART
    # ============================================================

    del workflow_2


    workflow_3 = (
        PersistentSOCWorkflow(
            simulation_mode=True
        )
    )


    final_case = (
        workflow_3.recover_case(
            TEST_INCIDENT
        )
    )


    final_ticket = (
        workflow_3.recover_ticket(
            TEST_INCIDENT
        )
    )


    final_actions = (
        final_case[
            "response_actions"
        ]
    )


    # ============================================================
    # FINAL STATE VALIDATION
    # ============================================================

    approval_pass = (
        approval_result.get(
            "success"
        )
        is True
    )


    persisted_ticket_approval_pass = (

        final_ticket
        is not None

        and

        final_ticket.approval_status
        == "APPROVED"
    )


    persisted_action_approval_pass = all(

        action.approval_status
        == "APPROVED"

        for action
        in final_actions
    )


    persisted_ready_pass = all(

        action.execution_status
        == "READY"

        for action
        in final_actions
    )


    second_restart_pass = (
        final_case.get(
            "recovered_from_database"
        )
        is True
    )


    safety_pass = (
        approval_result.get(
            "real_response_executed"
        )
        is False
    )


    # ============================================================
    # FINAL RESULT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL RESTART RECOVERY VALIDATION"
    )
    print("=" * 80)


    print(
        "Case recovered after restart:",
        "PASS"
        if recovery_pass
        else "FAIL",
    )


    print(
        "Incident identity preserved:",
        "PASS"
        if incident_pass
        else "FAIL",
    )


    print(
        "Recovery source confirmed:",
        "PASS"
        if database_flag_pass
        else "FAIL",
    )


    print(
        "SOC ticket recovered:",
        "PASS"
        if ticket_pass
        else "FAIL",
    )


    print(
        "Digital Twin decision recovered:",
        "PASS"
        if decision_pass
        else "FAIL",
    )


    print(
        "Selected plan recovered:",
        "PASS"
        if plan_pass
        else "FAIL",
    )


    print(
        "Four response actions recovered:",
        "PASS"
        if action_count_pass
        else "FAIL",
    )


    print(
        "Pending action state recovered:",
        "PASS"
        if initial_action_state_pass
        else "FAIL",
    )


    print(
        "Post-restart analyst approval:",
        "PASS"
        if approval_pass
        else "FAIL",
    )


    print(
        "Ticket approval survived second restart:",
        "PASS"
        if persisted_ticket_approval_pass
        else "FAIL",
    )


    print(
        "Action approvals survived second restart:",
        "PASS"
        if persisted_action_approval_pass
        else "FAIL",
    )


    print(
        "READY states survived second restart:",
        "PASS"
        if persisted_ready_pass
        else "FAIL",
    )


    print(
        "Second restart recovery:",
        "PASS"
        if second_restart_pass
        else "FAIL",
    )


    print(
        "No real endpoint response executed:",
        "PASS"
        if safety_pass
        else "FAIL",
    )


    overall = all(
        [
            recovery_pass,
            incident_pass,
            database_flag_pass,
            ticket_pass,
            decision_pass,
            plan_pass,
            action_count_pass,
            initial_action_state_pass,
            approval_pass,
            persisted_ticket_approval_pass,
            persisted_action_approval_pass,
            persisted_ready_pass,
            second_restart_pass,
            safety_pass,
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