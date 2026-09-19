from response.response_action import (
    ResponseAction,
)

from response.approval_workflow import (
    ApprovalWorkflow,
)

from response.response_orchestrator import (
    ResponseOrchestrator,
)


def prepare_action(
    action,
    workflow,
):

    workflow.request_approval(
        action
    )

    workflow.approve(

        action=
            action,

        analyst=
            "SyntheticSOCAnalyst",

        comment=
            "Approved for response-orchestrator simulation.",
    )

    workflow.mark_ready(
        action
    )


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X UNIFIED RESPONSE ORCHESTRATOR TEST"
    )
    print("=" * 80)


    workflow = (
        ApprovalWorkflow()
    )


    orchestrator = (
        ResponseOrchestrator(
            simulation_mode=True
        )
    )


    # ============================================================
    # 1. QUARANTINE
    # ============================================================

    quarantine_action = ResponseAction(

        incident_id=
            "INC-ORCH-001",

        action_type=
            "QUARANTINE_FILE",

        target={

            "files": [

                {
                    "path":
                        r"C:\Temp\demo.exe",

                    "sha256":
                        "ORCHESTRATOR_SHA256",
                },
            ],
        },

        reason=
            "Synthetic quarantine routing.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    prepare_action(
        quarantine_action,
        workflow,
    )


    quarantine_result = (
        orchestrator.execute(
            quarantine_action
        )
    )


    # ============================================================
    # 2. PROCESS
    # ============================================================

    process_action = ResponseAction(

        incident_id=
            "INC-ORCH-001",

        action_type=
            "TERMINATE_PROCESS",

        target={

            "processes": [

                {
                    "pid":
                        12345,

                    "name":
                        "demo.exe",

                    "exe":
                        r"C:\Temp\demo.exe",

                    "threat_score":
                        95,
                },
            ],
        },

        reason=
            "Synthetic process routing.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    prepare_action(
        process_action,
        workflow,
    )


    process_result = (
        orchestrator.execute(
            process_action
        )
    )


    # ============================================================
    # 3. NETWORK
    # ============================================================

    network_action = ResponseAction(

        incident_id=
            "INC-ORCH-001",

        action_type=
            "BLOCK_NETWORK",

        target={

            "connections": [

                {
                    "remote_ip":
                        "203.0.113.80",

                    "remote_port":
                        443,

                    "pid":
                        12345,

                    "process_name":
                        "demo.exe",
                },
            ],
        },

        reason=
            "Synthetic network routing.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    prepare_action(
        network_action,
        workflow,
    )


    network_result = (
        orchestrator.execute(
            network_action
        )
    )


    # ============================================================
    # 4. PERSISTENCE
    # ============================================================

    persistence_action = ResponseAction(

        incident_id=
            "INC-ORCH-001",

        action_type=
            "REMEDIATE_PERSISTENCE",

        target={

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
        },

        reason=
            "Synthetic persistence routing.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    prepare_action(
        persistence_action,
        workflow,
    )


    persistence_result = (
        orchestrator.execute(
            persistence_action
        )
    )


    # ============================================================
    # 5. ENDPOINT ISOLATION
    # ============================================================

    isolation_action = ResponseAction(

        incident_id=
            "INC-ORCH-001",

        action_type=
            "ISOLATE_ENDPOINT",

        target={

            "hostname":
                "SENTINEL-TEST-ENDPOINT",

            "device_id":
                "DEVICE-SYNTHETIC-001",

            "management_channel":
                "SOC_CONTROL_CHANNEL",
        },

        reason=
            "Synthetic isolation routing.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "CRITICAL",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    prepare_action(
        isolation_action,
        workflow,
    )


    isolation_result = (
        orchestrator.execute(
            isolation_action
        )
    )


    # ============================================================
    # 6. PENDING ACTION SHOULD BE BLOCKED
    # ============================================================

    pending_action = ResponseAction(

        incident_id=
            "INC-ORCH-002",

        action_type=
            "QUARANTINE_FILE",

        target={

            "files": [

                {
                    "path":
                        r"C:\Temp\pending.exe",

                    "sha256":
                        "PENDING_SHA256",
                },
            ],
        },

        reason=
            "Pending action test.",

        requested_by=
            "ResponseRecommendationAgent",

        risk_level=
            "HIGH",

        approval_required=
            True,

        policy_decision=
            "RECOMMEND_ONLY",
    )


    pending_result = (
        orchestrator.execute(
            pending_action
        )
    )


    # ============================================================
    # PRINT ROUTING RESULTS
    # ============================================================

    results = [

        (
            "Quarantine",
            quarantine_result,
        ),

        (
            "Process",
            process_result,
        ),

        (
            "Network",
            network_result,
        ),

        (
            "Persistence",
            persistence_result,
        ),

        (
            "Isolation",
            isolation_result,
        ),
    ]


    print()
    print("=" * 80)
    print(
        "RESPONSE ROUTING RESULTS"
    )
    print("=" * 80)


    for name, result in results:

        print()

        print(
            name
        )

        print(
            "Status:",
            result[
                "status"
            ],
        )

        print(
            "Action:",
            result[
                "action_type"
            ],
        )

        print(
            "Executed:",
            result[
                "executed"
            ],
        )


    # ============================================================
    # VALIDATION
    # ============================================================

    quarantine_pass = (

        quarantine_result[
            "status"
        ]
        == "SIMULATED"

        and

        quarantine_result[
            "handler_result"
        ][
            "manager"
        ]
        == "QuarantineManager"
    )


    process_pass = (

        process_result[
            "status"
        ]
        == "SIMULATED"

        and

        process_result[
            "handler_result"
        ][
            "manager"
        ]
        == "ProcessResponseManager"
    )


    network_pass = (

        network_result[
            "status"
        ]
        == "SIMULATED"

        and

        network_result[
            "handler_result"
        ][
            "manager"
        ]
        == "NetworkResponseManager"
    )


    persistence_pass = (

        persistence_result[
            "status"
        ]
        == "SIMULATED"

        and

        persistence_result[
            "handler_result"
        ][
            "manager"
        ]
        == "PersistenceResponseManager"
    )


    isolation_pass = (

        isolation_result[
            "status"
        ]
        == "SIMULATED"

        and

        isolation_result[
            "handler_result"
        ][
            "manager"
        ]
        == "EndpointIsolationManager"
    )


    no_execution_pass = all(

        result[
            "executed"
        ]
        is False

        for _, result in results
    )


    pending_pass = (

        pending_result[
            "status"
        ]
        == "BLOCKED"

        and

        pending_result[
            "executed"
        ]
        is False
    )


    audit_pass = (
        orchestrator.audit_log.log_path.exists()
    )


    # ============================================================
    # FINAL OUTPUT
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL RESPONSE ORCHESTRATOR VALIDATION"
    )
    print("=" * 80)


    print(
        "Quarantine routing:",
        "PASS"
        if quarantine_pass
        else "FAIL",
    )


    print(
        "Process routing:",
        "PASS"
        if process_pass
        else "FAIL",
    )


    print(
        "Network routing:",
        "PASS"
        if network_pass
        else "FAIL",
    )


    print(
        "Persistence routing:",
        "PASS"
        if persistence_pass
        else "FAIL",
    )


    print(
        "Endpoint isolation routing:",
        "PASS"
        if isolation_pass
        else "FAIL",
    )


    print(
        "No real execution:",
        "PASS"
        if no_execution_pass
        else "FAIL",
    )


    print(
        "Pending action blocked:",
        "PASS"
        if pending_pass
        else "FAIL",
    )


    print(
        "Audit log available:",
        "PASS"
        if audit_pass
        else "FAIL",
    )


    overall = all(
        [
            quarantine_pass,
            process_pass,
            network_pass,
            persistence_pass,
            isolation_pass,
            no_execution_pass,
            pending_pass,
            audit_pass,
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