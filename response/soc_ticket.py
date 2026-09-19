from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid


VALID_PRIORITIES = {
    "P1",
    "P2",
    "P3",
    "P4",
}

VALID_STATUSES = {
    "OPEN",
    "IN_REVIEW",
    "AWAITING_APPROVAL",
    "APPROVED",
    "REJECTED",
    "RESOLVED",
    "CLOSED",
}


@dataclass
class SOCTicket:

    incident_id: str

    title: str

    priority: str

    risk_score: int

    risk_level: str

    selected_plan: str = ""

    predicted_residual_risk: int = 0

    operational_impact: str = "UNKNOWN"

    explanation: str = ""

    approval_required: bool = False

    approval_status: str = "NOT_REQUIRED"

    assigned_analyst: str = ""

    status: str = "OPEN"

    ticket_id: str = field(
        default_factory=lambda:
        "TKT-"
        + uuid.uuid4().hex[:12].upper()
    )

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


    # ============================================================
    # POST INIT VALIDATION
    # ============================================================

    def __post_init__(self):

        self.priority = str(
            self.priority
        ).upper()

        self.status = str(
            self.status
        ).upper()

        self.risk_level = str(
            self.risk_level
        ).upper()

        self.operational_impact = str(
            self.operational_impact
        ).upper()

        self.approval_status = str(
            self.approval_status
        ).upper()


        if self.priority not in VALID_PRIORITIES:

            self.priority = "P4"


        if self.status not in VALID_STATUSES:

            self.status = "OPEN"


        try:

            self.risk_score = int(
                self.risk_score
            )

        except (
            TypeError,
            ValueError,
        ):

            self.risk_score = 0


        self.risk_score = max(
            0,
            min(
                self.risk_score,
                100,
            ),
        )


        try:

            self.predicted_residual_risk = int(
                self.predicted_residual_risk
            )

        except (
            TypeError,
            ValueError,
        ):

            self.predicted_residual_risk = 0


        self.predicted_residual_risk = max(
            0,
            min(
                self.predicted_residual_risk,
                100,
            ),
        )


    # ============================================================
    # UPDATE TIMESTAMP
    # ============================================================

    def touch(self):

        self.updated_at = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # UPDATE STATUS
    # ============================================================

    def set_status(
        self,
        status: str,
    ):

        status = str(
            status
        ).upper()


        if status not in VALID_STATUSES:

            raise ValueError(
                f"Invalid ticket status: {status}"
            )


        self.status = status

        self.touch()


    # ============================================================
    # ASSIGN ANALYST
    # ============================================================

    def assign_analyst(
        self,
        analyst: str,
    ):

        self.assigned_analyst = str(
            analyst
        ).strip()

        self.touch()


    # ============================================================
    # UPDATE APPROVAL
    # ============================================================

    def set_approval_status(
        self,
        approval_status: str,
    ):

        self.approval_status = str(
            approval_status
        ).upper()

        self.touch()


    # ============================================================
    # EXPORT
    # ============================================================

    def to_dict(self):

        return {

            "ticket_id":
                self.ticket_id,

            "incident_id":
                self.incident_id,

            "title":
                self.title,

            "priority":
                self.priority,

            "risk_score":
                self.risk_score,

            "risk_level":
                self.risk_level,

            "selected_plan":
                self.selected_plan,

            "predicted_residual_risk":
                self.predicted_residual_risk,

            "operational_impact":
                self.operational_impact,

            "explanation":
                self.explanation,

            "approval_required":
                self.approval_required,

            "approval_status":
                self.approval_status,

            "assigned_analyst":
                self.assigned_analyst,

            "status":
                self.status,

            "created_at":
                self.created_at,

            "updated_at":
                self.updated_at,
        }