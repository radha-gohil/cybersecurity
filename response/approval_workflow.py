from datetime import datetime, timezone

from response.response_action import (
    ResponseAction,
)

from response.response_audit_log import (
    ResponseAuditLog,
)


class ApprovalWorkflow:

    def __init__(
        self,
        audit_log=None,
    ):

        self.name = "ApprovalWorkflow"

        self.audit_log = (
            audit_log
            if audit_log is not None
            else ResponseAuditLog()
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(
        self,
    ) -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # VALIDATE ACTION OBJECT
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
    # GET STATUS
    # ============================================================

    def get_status(
        self,
        action: ResponseAction,
    ) -> dict:

        self.validate_action(
            action
        )


        return {

            "action_id":
                action.action_id,

            "incident_id":
                action.incident_id,

            "action_type":
                action.action_type,

            "approval_required":
                action.approval_required,

            "approval_status":
                action.approval_status,

            "execution_status":
                action.execution_status,

            "policy_decision":
                action.policy_decision,

            "can_execute":
                action.can_execute(),
        }


    # ============================================================
    # REQUEST APPROVAL
    # ============================================================

    def request_approval(
        self,
        action: ResponseAction,
        actor: str = "ResponseController",
    ) -> dict:

        self.validate_action(
            action
        )


        if not action.approval_required:

            result = {

                "success":
                    True,

                "action_id":
                    action.action_id,

                "approval_status":
                    "NOT_REQUIRED",

                "message":
                    "This action does not require approval.",
            }


            self.audit_log.write(

                event_type=
                    "APPROVAL_NOT_REQUIRED",

                action=
                    action.to_dict(),

                actor=
                    actor,
            )


            return result


        if action.approval_status == "APPROVED":

            return {

                "success":
                    False,

                "action_id":
                    action.action_id,

                "approval_status":
                    action.approval_status,

                "message":
                    "Action is already approved.",
            }


        if action.approval_status == "REJECTED":

            return {

                "success":
                    False,

                "action_id":
                    action.action_id,

                "approval_status":
                    action.approval_status,

                "message":
                    "Action has already been rejected.",
            }


        action.add_audit_entry(

            event=
                "APPROVAL_REQUESTED",

            actor=
                actor,

            details={

                "action_type":
                    action.action_type,

                "risk_level":
                    action.risk_level,

                "policy_decision":
                    action.policy_decision,
            },
        )


        self.audit_log.write(

            event_type=
                "APPROVAL_REQUESTED",

            action=
                action.to_dict(),

            actor=
                actor,
        )


        return {

            "success":
                True,

            "action_id":
                action.action_id,

            "approval_status":
                action.approval_status,

            "message":
                "Approval request recorded.",
        }


    # ============================================================
    # APPROVE ACTION
    # ============================================================

    def approve(
        self,
        action: ResponseAction,
        analyst: str,
        comment: str = None,
    ) -> dict:

        self.validate_action(
            action
        )


        if not action.approval_required:

            return {

                "success":
                    False,

                "action_id":
                    action.action_id,

                "message":
                    "This action does not require approval.",
            }


        if action.approval_status == "APPROVED":

            return {

                "success":
                    False,

                "action_id":
                    action.action_id,

                "message":
                    "Action is already approved.",
            }


        if action.approval_status == "REJECTED":

            return {

                "success":
                    False,

                "action_id":
                    action.action_id,

                "message":
                    "Rejected actions cannot be approved.",
            }


        action.approve(
            actor=analyst
        )


        action.add_audit_entry(

            event=
                "ANALYST_APPROVAL_COMMENT",

            actor=
                analyst,

            details={

                "comment":
                    comment,
            },
        )


        self.audit_log.write(

            event_type=
                "ACTION_APPROVED",

            action=
                action.to_dict(),

            actor=
                analyst,

            details={

                "comment":
                    comment,
            },
        )


        return {

            "success":
                True,

            "action_id":
                action.action_id,

            "approval_status":
                action.approval_status,

            "can_execute":
                action.can_execute(),

            "message":
                "Action approved.",
        }


    # ============================================================
    # REJECT ACTION
    # ============================================================

    def reject(
        self,
        action: ResponseAction,
        analyst: str,
        reason: str,
    ) -> dict:

        self.validate_action(
            action
        )


        if not action.approval_required:

            return {

                "success":
                    False,

                "action_id":
                    action.action_id,

                "message":
                    "This action does not require approval.",
            }


        if action.approval_status == "APPROVED":

            return {

                "success":
                    False,

                "action_id":
                    action.action_id,

                "message":
                    "Approved action cannot be rejected here.",
            }


        if action.approval_status == "REJECTED":

            return {

                "success":
                    False,

                "action_id":
                    action.action_id,

                "message":
                    "Action is already rejected.",
            }


        action.reject(

            actor=
                analyst,

            reason=
                reason,
        )


        self.audit_log.write(

            event_type=
                "ACTION_REJECTED",

            action=
                action.to_dict(),

            actor=
                analyst,

            details={

                "reason":
                    reason,
            },
        )


        return {

            "success":
                True,

            "action_id":
                action.action_id,

            "approval_status":
                action.approval_status,

            "execution_status":
                action.execution_status,

            "can_execute":
                action.can_execute(),

            "message":
                "Action rejected.",
        }


    # ============================================================
    # MARK ACTION READY
    # ============================================================

    def mark_ready(
        self,
        action: ResponseAction,
        actor: str = "ResponseController",
    ) -> dict:

        self.validate_action(
            action
        )


        if not action.can_execute():

            return {

                "success":
                    False,

                "action_id":
                    action.action_id,

                "message":
                    "Action cannot be marked READY because approval is incomplete.",
            }


        action.mark_ready(
            actor=actor
        )


        self.audit_log.write(

            event_type=
                "ACTION_READY",

            action=
                action.to_dict(),

            actor=
                actor,
        )


        return {

            "success":
                True,

            "action_id":
                action.action_id,

            "execution_status":
                action.execution_status,

            "message":
                "Action marked READY.",
        }