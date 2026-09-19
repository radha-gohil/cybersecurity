from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List
import uuid


VALID_ACTION_TYPES = {
    "MONITOR_INCIDENT",
    "INVESTIGATE_INCIDENT",
    "QUARANTINE_FILE",
    "TERMINATE_PROCESS",
    "BLOCK_NETWORK",
    "REMEDIATE_PERSISTENCE",
    "ISOLATE_ENDPOINT",
}


VALID_APPROVAL_STATES = {
    "NOT_REQUIRED",
    "PENDING",
    "APPROVED",
    "REJECTED",
}


VALID_EXECUTION_STATES = {
    "NOT_EXECUTED",
    "READY",
    "EXECUTING",
    "SUCCESS",
    "FAILED",
    "CANCELLED",
}


@dataclass
class ResponseAction:

    incident_id: str

    action_type: str

    reason: str

    requested_by: str

    target: Dict[str, Any] = field(
        default_factory=dict
    )

    risk_level: str = "INFO"

    approval_required: bool = True

    policy_decision: str = "UNKNOWN"

    action_id: str = field(
        default_factory=lambda:
            f"ACT-{uuid.uuid4().hex[:12].upper()}"
    )

    approval_status: str = "PENDING"

    execution_status: str = "NOT_EXECUTED"

    created_at: str = field(
        default_factory=lambda:
            datetime.now(
                timezone.utc
            ).isoformat()
    )

    updated_at: str = field(
        default_factory=lambda:
            datetime.now(
                timezone.utc
            ).isoformat()
    )

    audit_history: List[Dict[str, Any]] = field(
        default_factory=list
    )


    # ============================================================
    # INITIAL VALIDATION
    # ============================================================

    def __post_init__(self):

        self.action_type = str(
            self.action_type
        ).upper()

        self.risk_level = str(
            self.risk_level
        ).upper()

        self.policy_decision = str(
            self.policy_decision
        ).upper()

        if self.action_type not in VALID_ACTION_TYPES:

            raise ValueError(
                f"Invalid action type: {self.action_type}"
            )


        if not isinstance(
            self.target,
            dict,
        ):

            self.target = {}


        if self.approval_required:

            self.approval_status = "PENDING"

        else:

            self.approval_status = "NOT_REQUIRED"


        self.add_audit_entry(
            event="ACTION_CREATED",
            actor=self.requested_by,
            details={
                "action_type":
                    self.action_type,

                "policy_decision":
                    self.policy_decision,
            },
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(self):

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # AUDIT ENTRY
    # ============================================================

    def add_audit_entry(
        self,
        event: str,
        actor: str,
        details: dict = None,
    ):

        self.audit_history.append(
            {
                "timestamp":
                    self.now_iso(),

                "event":
                    event,

                "actor":
                    actor,

                "details":
                    details
                    if isinstance(
                        details,
                        dict,
                    )
                    else {},
            }
        )

        self.updated_at = (
            self.now_iso()
        )


    # ============================================================
    # APPROVE
    # ============================================================

    def approve(
        self,
        actor: str,
    ):

        if not self.approval_required:

            return


        self.approval_status = (
            "APPROVED"
        )

        self.add_audit_entry(
            event="ACTION_APPROVED",
            actor=actor,
        )


    # ============================================================
    # REJECT
    # ============================================================

    def reject(
        self,
        actor: str,
        reason: str = None,
    ):

        if not self.approval_required:

            return


        self.approval_status = (
            "REJECTED"
        )

        self.execution_status = (
            "CANCELLED"
        )

        self.add_audit_entry(
            event="ACTION_REJECTED",
            actor=actor,
            details={
                "reason":
                    reason,
            },
        )


    # ============================================================
    # MARK READY
    # ============================================================

    def mark_ready(
        self,
        actor: str,
    ):

        if (
            self.approval_required
            and self.approval_status
            != "APPROVED"
        ):

            raise PermissionError(
                "Action cannot become READY "
                "without approval."
            )


        self.execution_status = (
            "READY"
        )

        self.add_audit_entry(
            event="ACTION_READY",
            actor=actor,
        )


    # ============================================================
    # MARK SUCCESS
    # ============================================================

    def mark_success(
        self,
        actor: str,
        details: dict = None,
    ):

        self.execution_status = (
            "SUCCESS"
        )

        self.add_audit_entry(
            event="ACTION_SUCCESS",
            actor=actor,
            details=details,
        )


    # ============================================================
    # MARK FAILED
    # ============================================================

    def mark_failed(
        self,
        actor: str,
        error: str,
    ):

        self.execution_status = (
            "FAILED"
        )

        self.add_audit_entry(
            event="ACTION_FAILED",
            actor=actor,
            details={
                "error":
                    str(
                        error
                    ),
            },
        )


    # ============================================================
    # CAN EXECUTE
    # ============================================================

    def can_execute(self) -> bool:

        if self.execution_status == "CANCELLED":

            return False


        if self.approval_required:

            return (
                self.approval_status
                == "APPROVED"
            )


        return True


    # ============================================================
    # EXPORT
    # ============================================================

    def to_dict(self):

        return {
            "action_id":
                self.action_id,

            "incident_id":
                self.incident_id,

            "action_type":
                self.action_type,

            "target":
                self.target,

            "reason":
                self.reason,

            "requested_by":
                self.requested_by,

            "risk_level":
                self.risk_level,

            "approval_required":
                self.approval_required,

            "approval_status":
                self.approval_status,

            "policy_decision":
                self.policy_decision,

            "execution_status":
                self.execution_status,

            "can_execute":
                self.can_execute(),

            "created_at":
                self.created_at,

            "updated_at":
                self.updated_at,

            "audit_history":
                self.audit_history,
        }