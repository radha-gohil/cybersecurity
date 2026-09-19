from datetime import datetime, timezone

from response.response_action import (
    ResponseAction,
)

from response.response_audit_log import (
    ResponseAuditLog,
)


class SafeResponseController:

    def __init__(
        self,
        audit_log=None,
        dry_run=True,
    ):

        self.name = "SafeResponseController"

        self.audit_log = (
            audit_log
            if audit_log is not None
            else ResponseAuditLog()
        )

        self.dry_run = bool(
            dry_run
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(self):

        return datetime.now(
            timezone.utc
        ).isoformat()


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
    # IS RESPONSE ACTION
    # ============================================================

    def is_response_action(
        self,
        action_type: str,
    ) -> bool:

        return str(
            action_type
        ).upper() in {

            "QUARANTINE_FILE",

            "TERMINATE_PROCESS",

            "BLOCK_NETWORK",

            "REMEDIATE_PERSISTENCE",

            "ISOLATE_ENDPOINT",
        }


    # ============================================================
    # PRECHECK
    # ============================================================

    def precheck(
        self,
        action: ResponseAction,
    ) -> dict:

        self.validate_action(
            action
        )


        issues = []


        # --------------------------------------------------------
        # CANCELLED
        # --------------------------------------------------------

        if (
            action.execution_status
            == "CANCELLED"
        ):

            issues.append(
                "Action has been cancelled."
            )


        # --------------------------------------------------------
        # APPROVAL
        # --------------------------------------------------------

        if (
            action.approval_required
            and
            action.approval_status
            != "APPROVED"
        ):

            issues.append(
                "Required approval is not complete."
            )


        # --------------------------------------------------------
        # READY STATUS
        # --------------------------------------------------------

        if (
            action.execution_status
            != "READY"
        ):

            issues.append(
                "Action is not in READY state."
            )


        # --------------------------------------------------------
        # POLICY
        # --------------------------------------------------------

        policy_decision = str(
            action.policy_decision
        ).upper()


        if (
            self.is_response_action(
                action.action_type
            )
            and
            policy_decision
            == "DENY"
        ):

            issues.append(
                "Policy explicitly denied this action."
            )


        passed = (
            len(
                issues
            )
            == 0
        )


        return {

            "passed":
                passed,

            "action_id":
                action.action_id,

            "action_type":
                action.action_type,

            "approval_status":
                action.approval_status,

            "execution_status":
                action.execution_status,

            "policy_decision":
                action.policy_decision,

            "dry_run":
                self.dry_run,

            "issues":
                issues,
        }


    # ============================================================
    # BUILD DRY RUN RESULT
    # ============================================================

    def build_dry_run_result(
        self,
        action: ResponseAction,
    ) -> dict:

        action_type = (
            action.action_type
        )


        descriptions = {

            "MONITOR_INCIDENT":
                (
                    "Would continue monitoring "
                    "the incident."
                ),

            "INVESTIGATE_INCIDENT":
                (
                    "Would continue incident "
                    "investigation."
                ),

            "QUARANTINE_FILE":
                (
                    "Would route the approved file "
                    "target to the quarantine manager."
                ),

            "TERMINATE_PROCESS":
                (
                    "Would route the approved process "
                    "target to the process response manager."
                ),

            "BLOCK_NETWORK":
                (
                    "Would route the approved network "
                    "target to the network response manager."
                ),

            "REMEDIATE_PERSISTENCE":
                (
                    "Would route the approved persistence "
                    "artifact to the persistence response manager."
                ),

            "ISOLATE_ENDPOINT":
                (
                    "Would route the approved endpoint "
                    "to the isolation manager."
                ),
        }


        return {

            "action_id":
                action.action_id,

            "incident_id":
                action.incident_id,

            "action_type":
                action.action_type,

            "target":
                action.target,

            "dry_run":
                True,

            "executed":
                False,

            "message":
                descriptions.get(
                    action_type,
                    "Would route action to response handler.",
                ),
        }


    # ============================================================
    # ROUTE ACTION
    # ============================================================

    def route(
        self,
        action: ResponseAction,
        actor: str = "SafeResponseController",
    ) -> dict:

        self.validate_action(
            action
        )


        precheck_result = (
            self.precheck(
                action
            )
        )


        # --------------------------------------------------------
        # BLOCK IF PRECHECK FAILS
        # --------------------------------------------------------

        if not precheck_result[
            "passed"
        ]:

            self.audit_log.write(

                event_type=
                    "RESPONSE_PRECHECK_BLOCKED",

                action=
                    action.to_dict(),

                actor=
                    actor,

                details={

                    "issues":
                        precheck_result[
                            "issues"
                        ],
                },
            )


            return {

                "success":
                    False,

                "status":
                    "BLOCKED",

                "action_id":
                    action.action_id,

                "precheck":
                    precheck_result,

                "dry_run":
                    self.dry_run,

                "executed":
                    False,
            }


        # --------------------------------------------------------
        # DRY RUN MODE
        # --------------------------------------------------------

        if self.dry_run:

            dry_run_result = (
                self.build_dry_run_result(
                    action
                )
            )


            action.add_audit_entry(

                event=
                    "DRY_RUN_ROUTED",

                actor=
                    actor,

                details={
                    "action_type":
                        action.action_type,
                },
            )


            self.audit_log.write(

                event_type=
                    "DRY_RUN_ROUTED",

                action=
                    action.to_dict(),

                actor=
                    actor,

                details=
                    dry_run_result,
            )


            return {

                "success":
                    True,

                "status":
                    "DRY_RUN",

                "action_id":
                    action.action_id,

                "precheck":
                    precheck_result,

                "dry_run":
                    True,

                "executed":
                    False,

                "result":
                    dry_run_result,
            }


        # --------------------------------------------------------
        # ACTIVE EXECUTION INTENTIONALLY DISABLED
        # --------------------------------------------------------

        self.audit_log.write(

            event_type=
                "ACTIVE_EXECUTION_DISABLED",

            action=
                action.to_dict(),

            actor=
                actor,
        )


        return {

            "success":
                False,

            "status":
                "EXECUTION_DISABLED",

            "action_id":
                action.action_id,

            "dry_run":
                False,

            "executed":
                False,

            "message":
                (
                    "Active response execution is disabled "
                    "in the current development build."
                ),
        }