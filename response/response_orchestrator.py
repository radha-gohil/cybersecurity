from response.quarantine_manager import (
    QuarantineManager,
)

from response.process_response_manager import (
    ProcessResponseManager,
)

from response.network_response_manager import (
    NetworkResponseManager,
)

from response.persistence_response_manager import (
    PersistenceResponseManager,
)

from response.endpoint_isolation_manager import (
    EndpointIsolationManager,
)

from response.response_action import (
    ResponseAction,
)

from response.response_audit_log import (
    ResponseAuditLog,
)


class ResponseOrchestrator:

    def __init__(
        self,
        simulation_mode=True,
        audit_log=None,
    ):

        self.name = "ResponseOrchestrator"

        self.simulation_mode = bool(
            simulation_mode
        )

        self.audit_log = (
            audit_log
            if audit_log is not None
            else ResponseAuditLog()
        )

        self.quarantine_manager = (
            QuarantineManager(
                simulation_mode=
                    self.simulation_mode
            )
        )

        self.process_manager = (
            ProcessResponseManager(
                simulation_mode=
                    self.simulation_mode
            )
        )

        self.network_manager = (
            NetworkResponseManager(
                simulation_mode=
                    self.simulation_mode
            )
        )

        self.persistence_manager = (
            PersistenceResponseManager(
                simulation_mode=
                    self.simulation_mode
            )
        )

        self.isolation_manager = (
            EndpointIsolationManager(
                simulation_mode=
                    self.simulation_mode
            )
        )


    # ============================================================
    # VALIDATE ACTION
    # ============================================================

    def validate_action(
        self,
        action,
    ):

        if not isinstance(
            action,
            ResponseAction,
        ):

            raise TypeError(
                "action must be a ResponseAction object."
            )


    # ============================================================
    # ROUTE ACTION
    # ============================================================

    def execute(
        self,
        action: ResponseAction,
        actor: str = "ResponseOrchestrator",
    ) -> dict:

        self.validate_action(
            action
        )


        # --------------------------------------------------------
        # ACTION MUST BE READY
        # --------------------------------------------------------

        if (
            action.execution_status
            != "READY"
        ):

            self.audit_log.write(

                event_type=
                    "RESPONSE_ORCHESTRATOR_BLOCKED",

                action=
                    action.to_dict(),

                actor=
                    actor,

                details={

                    "reason":
                        "Action is not READY.",
                },
            )


            return {

                "success":
                    False,

                "status":
                    "BLOCKED",

                "action_id":
                    action.action_id,

                "action_type":
                    action.action_type,

                "reason":
                    "Action is not READY.",

                "executed":
                    False,
            }


        # --------------------------------------------------------
        # APPROVAL CHECK
        # --------------------------------------------------------

        if not action.can_execute():

            self.audit_log.write(

                event_type=
                    "RESPONSE_ORCHESTRATOR_BLOCKED",

                action=
                    action.to_dict(),

                actor=
                    actor,

                details={

                    "reason":
                        "Action is not approved.",
                },
            )


            return {

                "success":
                    False,

                "status":
                    "BLOCKED",

                "action_id":
                    action.action_id,

                "action_type":
                    action.action_type,

                "reason":
                    "Action is not approved.",

                "executed":
                    False,
            }


        # --------------------------------------------------------
        # POLICY DENIED
        # --------------------------------------------------------

        if str(
            action.policy_decision
        ).upper() == "DENY":

            self.audit_log.write(

                event_type=
                    "RESPONSE_ORCHESTRATOR_BLOCKED",

                action=
                    action.to_dict(),

                actor=
                    actor,

                details={

                    "reason":
                        "Policy denied action.",
                },
            )


            return {

                "success":
                    False,

                "status":
                    "BLOCKED",

                "action_id":
                    action.action_id,

                "action_type":
                    action.action_type,

                "reason":
                    "Policy denied action.",

                "executed":
                    False,
            }


        # ========================================================
        # MONITOR INCIDENT
        # ========================================================

        if action.action_type == "MONITOR_INCIDENT":

            result = {

                "success":
                    True,

                "status":
                    "SIMULATED",

                "action":
                    "MONITOR_INCIDENT",

                "message":
                    "Incident monitoring continued.",

                "executed":
                    False,
            }


        # ========================================================
        # INVESTIGATE INCIDENT
        # ========================================================

        elif action.action_type == "INVESTIGATE_INCIDENT":

            result = {

                "success":
                    True,

                "status":
                    "SIMULATED",

                "action":
                    "INVESTIGATE_INCIDENT",

                "message":
                    "Incident investigation continued.",

                "executed":
                    False,
            }


        # ========================================================
        # QUARANTINE FILE
        # ========================================================

        elif action.action_type == "QUARANTINE_FILE":

            files = (
                action.target.get(
                    "files",
                    [],
                )
            )


            result = (
                self.quarantine_manager.process_targets(

                    incident_id=
                        action.incident_id,

                    action_id=
                        action.action_id,

                    files=
                        files,

                    reason=
                        action.reason,
                )
            )


        # ========================================================
        # TERMINATE PROCESS
        # ========================================================

        elif action.action_type == "TERMINATE_PROCESS":

            processes = (
                action.target.get(
                    "processes",
                    [],
                )
            )


            result = (
                self.process_manager.process_targets(

                    incident_id=
                        action.incident_id,

                    action_id=
                        action.action_id,

                    processes=
                        processes,

                    reason=
                        action.reason,
                )
            )


        # ========================================================
        # BLOCK NETWORK
        # ========================================================

        elif action.action_type == "BLOCK_NETWORK":

            connections = (
                action.target.get(
                    "connections",
                    [],
                )
            )


            result = (
                self.network_manager.process_targets(

                    incident_id=
                        action.incident_id,

                    action_id=
                        action.action_id,

                    connections=
                        connections,

                    reason=
                        action.reason,
                )
            )


        # ========================================================
        # REMEDIATE PERSISTENCE
        # ========================================================

        elif action.action_type == "REMEDIATE_PERSISTENCE":

            registry_artifacts = (
                action.target.get(
                    "registry_artifacts",
                    [],
                )
            )


            result = (
                self.persistence_manager.process_targets(

                    incident_id=
                        action.incident_id,

                    action_id=
                        action.action_id,

                    registry_artifacts=
                        registry_artifacts,

                    reason=
                        action.reason,
                )
            )


        # ========================================================
        # ISOLATE ENDPOINT
        # ========================================================

        elif action.action_type == "ISOLATE_ENDPOINT":

            result = (
                self.isolation_manager.process_target(

                    incident_id=
                        action.incident_id,

                    action_id=
                        action.action_id,

                    endpoint_target=
                        action.target,

                    reason=
                        action.reason,
                )
            )


        else:

            result = {

                "success":
                    False,

                "status":
                    "UNSUPPORTED_ACTION",

                "executed":
                    False,

                "message":
                    (
                        f"Unsupported action type: "
                        f"{action.action_type}"
                    ),
            }


        # ========================================================
        # AUDIT RESULT
        # ========================================================

        self.audit_log.write(

            event_type=
                "RESPONSE_ACTION_ROUTED",

            action=
                action.to_dict(),

            actor=
                actor,

            details={

                "simulation_mode":
                    self.simulation_mode,

                "result":
                    result,
            },
        )


        # ========================================================
        # IMPORTANT:
        # NO ACTUAL RESPONSE IS PERFORMED
        # ========================================================

        return {

            "success":
                result.get(
                    "success",
                    True,
                ),

            "status":
                "SIMULATED"
                if self.simulation_mode
                else "EXECUTION_DISABLED",

            "action_id":
                action.action_id,

            "incident_id":
                action.incident_id,

            "action_type":
                action.action_type,

            "simulation_mode":
                self.simulation_mode,

            "executed":
                False,

            "handler_result":
                result,
        }