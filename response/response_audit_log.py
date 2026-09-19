import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


class ResponseAuditLog:

    def __init__(
        self,
        log_path=None,
    ):

        project_root = (
            Path(__file__)
            .resolve()
            .parent
            .parent
        )

        if log_path is None:

            log_path = (
                project_root
                / "data"
                / "logs"
                / "response_audit.jsonl"
            )

        self.log_path = Path(
            log_path
        )

        self.log_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.lock = Lock()


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
    # WRITE AUDIT RECORD
    # ============================================================

    def write(
        self,
        event_type: str,
        action: dict,
        actor: str,
        details: dict = None,
    ) -> dict:

        if not isinstance(
            action,
            dict,
        ):

            action = {}

        if not isinstance(
            details,
            dict,
        ):

            details = {}


        record = {

            "timestamp":
                self.now_iso(),

            "event_type":
                str(
                    event_type
                ),

            "actor":
                str(
                    actor
                ),

            "action_id":
                action.get(
                    "action_id"
                ),

            "incident_id":
                action.get(
                    "incident_id"
                ),

            "action_type":
                action.get(
                    "action_type"
                ),

            "approval_status":
                action.get(
                    "approval_status"
                ),

            "execution_status":
                action.get(
                    "execution_status"
                ),

            "policy_decision":
                action.get(
                    "policy_decision"
                ),

            "details":
                details,
        }


        with self.lock:

            with self.log_path.open(
                "a",
                encoding="utf-8",
            ) as file:

                file.write(
                    json.dumps(
                        record,
                        ensure_ascii=False,
                    )
                    + "\n"
                )


        return record