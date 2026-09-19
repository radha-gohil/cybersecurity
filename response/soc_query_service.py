from response.soc_case_store import (
    SOCCaseStore,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)

from response.response_action_store import (
    ResponseActionStore,
)


class SOCQueryService:

    def __init__(
        self,
        case_store=None,
        ticket_store=None,
        action_store=None,
    ):

        self.name = "SOCQueryService"

        self.case_store = (
            case_store
            if case_store is not None
            else SOCCaseStore()
        )

        self.ticket_store = (
            ticket_store
            if ticket_store is not None
            else SOCTicketStore()
        )

        self.action_store = (
            action_store
            if action_store is not None
            else ResponseActionStore()
        )


    # ============================================================
    # HELPERS
    # ============================================================

    def normalize(
        self,
        value,
    ):

        if value is None:
            return None

        return str(
            value
        ).strip().upper()


    def serialize(
        self,
        value,
    ):

        if value is None:
            return None

        if isinstance(
            value,
            (
                str,
                int,
                float,
                bool,
            ),
        ):
            return value

        if isinstance(
            value,
            dict,
        ):
            return {
                str(key):
                    self.serialize(
                        item
                    )

                for key, item
                in value.items()
            }

        if isinstance(
            value,
            (
                list,
                tuple,
                set,
            ),
        ):
            return [
                self.serialize(
                    item
                )

                for item in value
            ]

        if hasattr(
            value,
            "to_dict",
        ):
            return self.serialize(
                value.to_dict()
            )

        return str(
            value
        )


    # ============================================================
    # INCIDENT SEARCH
    # ============================================================

    def search_incidents(
        self,
        risk_level=None,
        status=None,
        min_risk=None,
        max_risk=None,
        limit=100,
    ):

        risk_level = (
            self.normalize(
                risk_level
            )
        )

        status = (
            self.normalize(
                status
            )
        )

        limit = max(
            1,
            min(
                int(limit),
                1000,
            ),
        )


        cases = (
            self.case_store.list_cases(
                limit=1000
            )
        )


        results = []


        for case in cases:

            case_risk_level = (
                self.normalize(
                    case.get(
                        "risk_level"
                    )
                )
            )

            case_status = (
                self.normalize(
                    case.get(
                        "case_status"
                    )
                )
            )

            risk_score = (
                case.get(
                    "risk_score"
                )
            )


            if (
                risk_level
                and case_risk_level
                != risk_level
            ):
                continue


            if (
                status
                and case_status
                != status
            ):
                continue


            if (
                min_risk is not None
                and risk_score is not None
                and float(risk_score)
                < float(min_risk)
            ):
                continue


            if (
                max_risk is not None
                and risk_score is not None
                and float(risk_score)
                > float(max_risk)
            ):
                continue


            results.append(
                case
            )


            if len(
                results
            ) >= limit:
                break


        return {

            "count":
                len(
                    results
                ),

            "filters": {

                "risk_level":
                    risk_level,

                "status":
                    status,

                "min_risk":
                    min_risk,

                "max_risk":
                    max_risk,
            },

            "incidents":
                results,
        }


    # ============================================================
    # TICKET SEARCH
    # ============================================================

    def search_tickets(
        self,
        priority=None,
        status=None,
        approval_status=None,
        incident_id=None,
        limit=100,
    ):

        priority = (
            self.normalize(
                priority
            )
        )

        status = (
            self.normalize(
                status
            )
        )

        approval_status = (
            self.normalize(
                approval_status
            )
        )

        limit = max(
            1,
            min(
                int(limit),
                1000,
            ),
        )


        tickets = (
            self.ticket_store.list_tickets(
                limit=1000
            )
        )


        results = []


        for ticket in tickets:

            if (
                priority
                and self.normalize(
                    ticket.get(
                        "priority"
                    )
                )
                != priority
            ):
                continue


            if (
                status
                and self.normalize(
                    ticket.get(
                        "status"
                    )
                )
                != status
            ):
                continue


            if (
                approval_status
                and self.normalize(
                    ticket.get(
                        "approval_status"
                    )
                )
                != approval_status
            ):
                continue


            if (
                incident_id
                and ticket.get(
                    "incident_id"
                )
                != incident_id
            ):
                continue


            results.append(
                ticket
            )


            if len(
                results
            ) >= limit:
                break


        return {

            "count":
                len(
                    results
                ),

            "filters": {

                "priority":
                    priority,

                "status":
                    status,

                "approval_status":
                    approval_status,

                "incident_id":
                    incident_id,
            },

            "tickets":
                results,
        }


    # ============================================================
    # RESPONSE ACTION SEARCH
    # ============================================================

    def search_actions(
        self,
        incident_id=None,
        action_type=None,
        approval_status=None,
        execution_status=None,
        risk_level=None,
        limit=100,
    ):

        action_type = (
            self.normalize(
                action_type
            )
        )

        approval_status = (
            self.normalize(
                approval_status
            )
        )

        execution_status = (
            self.normalize(
                execution_status
            )
        )

        risk_level = (
            self.normalize(
                risk_level
            )
        )

        limit = max(
            1,
            min(
                int(limit),
                1000,
            ),
        )


        actions = (
            self.action_store.list_actions(
                limit=1000
            )
        )


        results = []


        for action in actions:

            if (
                incident_id
                and action.incident_id
                != incident_id
            ):
                continue


            if (
                action_type
                and self.normalize(
                    action.action_type
                )
                != action_type
            ):
                continue


            if (
                approval_status
                and self.normalize(
                    action.approval_status
                )
                != approval_status
            ):
                continue


            if (
                execution_status
                and self.normalize(
                    action.execution_status
                )
                != execution_status
            ):
                continue


            if (
                risk_level
                and self.normalize(
                    action.risk_level
                )
                != risk_level
            ):
                continue


            results.append(
                self.serialize(
                    action
                )
            )


            if len(
                results
            ) >= limit:
                break


        return {

            "count":
                len(
                    results
                ),

            "filters": {

                "incident_id":
                    incident_id,

                "action_type":
                    action_type,

                "approval_status":
                    approval_status,

                "execution_status":
                    execution_status,

                "risk_level":
                    risk_level,
            },

            "actions":
                results,
        }