from response.soc_case_store import (
    SOCCaseStore,
)

from response.soc_ticket_store import (
    SOCTicketStore,
)

from response.response_action_store import (
    ResponseActionStore,
)

from response.incident_evidence_store import (
    IncidentEvidenceStore,
)


class BackendIntegrityService:

    def __init__(
        self,
        case_store=None,
        ticket_store=None,
        action_store=None,
        evidence_store=None,
    ):

        self.name = "BackendIntegrityService"

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

        self.evidence_store = (
            evidence_store
            if evidence_store is not None
            else IncidentEvidenceStore()
        )


    # ============================================================
    # CHECK ONE INCIDENT
    # ============================================================

    def check_incident(
        self,
        incident_id,
    ):

        issues = []


        # --------------------------------------------------------
        # CASE
        # --------------------------------------------------------

        case = (
            self.case_store.get_case(
                incident_id
            )
        )


        if case is None:

            return {

                "incident_id":
                    incident_id,

                "valid":
                    False,

                "issues": [
                    "SOC_CASE_NOT_FOUND"
                ],

                "case_found":
                    False,

                "ticket_found":
                    False,

                "response_action_count":
                    0,

                "evidence_count":
                    0,

                "timeline_count":
                    0,
            }


        # --------------------------------------------------------
        # TICKET
        # --------------------------------------------------------

        ticket_id = (
            case.get(
                "ticket_id"
            )
        )


        ticket = None


        if ticket_id:

            ticket = (
                self.ticket_store.get_ticket(
                    ticket_id
                )
            )


        if ticket is None:

            issues.append(
                "SOC_TICKET_NOT_FOUND"
            )


        # --------------------------------------------------------
        # RESPONSE ACTIONS
        # --------------------------------------------------------

        actions = (
            self.action_store.get_by_incident(
                incident_id
            )
        )


        # --------------------------------------------------------
        # EVIDENCE
        # --------------------------------------------------------

        evidence_count = (
            self.evidence_store.count_evidence(
                incident_id
            )
        )


        timeline_count = (
            self.evidence_store.count_timeline(
                incident_id
            )
        )


        # ========================================================
        # INCIDENT ID CONSISTENCY
        # ========================================================

        if ticket is not None:

            if (
                ticket.get(
                    "incident_id"
                )
                != incident_id
            ):

                issues.append(
                    "TICKET_INCIDENT_ID_MISMATCH"
                )


        for action in actions:

            if (
                action.incident_id
                != incident_id
            ):

                issues.append(
                    (
                        "ACTION_INCIDENT_ID_MISMATCH:"
                        f"{action.action_id}"
                    )
                )


        # ========================================================
        # APPROVAL CONSISTENCY
        # ========================================================

        if ticket is not None:

            ticket_approval = (
                ticket.get(
                    "approval_status"
                )
            )


            # ----------------------------------------------------
            # APPROVED ticket:
            # approval-required actions should also be approved.
            # ----------------------------------------------------

            if ticket_approval == "APPROVED":

                for action in actions:

                    if (

                        action.approval_required

                        and

                        action.approval_status
                        != "APPROVED"
                    ):

                        issues.append(
                            (
                                "APPROVED_TICKET_WITH_"
                                "UNAPPROVED_ACTION:"
                                f"{action.action_id}"
                            )
                        )


            # ----------------------------------------------------
            # REJECTED ticket:
            # approval-required actions should not be READY.
            # ----------------------------------------------------

            if ticket_approval == "REJECTED":

                for action in actions:

                    if (
                        action.execution_status
                        in {
                            "READY",
                            "EXECUTING",
                            "SUCCESS",
                        }
                    ):

                        issues.append(
                            (
                                "REJECTED_TICKET_WITH_"
                                "ACTIVE_ACTION:"
                                f"{action.action_id}"
                            )
                        )


        # ========================================================
        # RESPONSE ACTION STATE CONSISTENCY
        # ========================================================

        for action in actions:

            if (

                action.approval_required

                and

                action.execution_status
                in {
                    "READY",
                    "EXECUTING",
                    "SUCCESS",
                }

                and

                action.approval_status
                != "APPROVED"
            ):

                issues.append(
                    (
                        "ACTION_READY_WITHOUT_APPROVAL:"
                        f"{action.action_id}"
                    )
                )


            if (

                action.approval_status
                == "REJECTED"

                and

                action.execution_status
                != "CANCELLED"
            ):

                issues.append(
                    (
                        "REJECTED_ACTION_NOT_CANCELLED:"
                        f"{action.action_id}"
                    )
                )


        # ========================================================
        # CASE/TICKET STATUS CONSISTENCY
        # ========================================================

        if ticket is not None:

            case_status = (
                case.get(
                    "status"
                )
            )


            ticket_status = (
                ticket.get(
                    "status"
                )
            )


            ticket_approval = (
                ticket.get(
                    "approval_status"
                )
            )


            if (

                ticket_approval
                == "APPROVED"

                and

                ticket_status
                != "APPROVED"
            ):

                issues.append(
                    "TICKET_APPROVAL_STATUS_MISMATCH"
                )


            if (

                ticket_approval
                == "REJECTED"

                and

                ticket_status
                != "REJECTED"
            ):

                issues.append(
                    "TICKET_REJECTION_STATUS_MISMATCH"
                )


            if (

                case_status
                == "REJECTED"

                and

                ticket_approval
                != "REJECTED"
            ):

                issues.append(
                    "CASE_REJECTED_BUT_TICKET_NOT_REJECTED"
                )


        # ========================================================
        # RESULT
        # ========================================================

        return {

            "incident_id":
                incident_id,

            "valid":
                len(
                    issues
                )
                == 0,

            "issues":
                issues,

            "case_found":
                True,

            "ticket_found":
                ticket is not None,

            "response_action_count":
                len(
                    actions
                ),

            "evidence_count":
                evidence_count,

            "timeline_count":
                timeline_count,

            "case_status":
                case.get(
                    "status"
                ),

            "ticket_status":
                (
                    ticket.get(
                        "status"
                    )
                    if ticket
                    else None
                ),

            "ticket_approval_status":
                (
                    ticket.get(
                        "approval_status"
                    )
                    if ticket
                    else None
                ),
        }


    # ============================================================
    # CHECK ALL INCIDENTS
    # ============================================================

    def check_all(
        self,
        limit=1000,
    ):

        cases = (
            self.case_store.list_cases(
                limit=limit
            )
        )


        results = []


        for case in cases:

            incident_id = (
                case.get(
                    "incident_id"
                )
            )


            if not incident_id:

                continue


            result = (
                self.check_incident(
                    incident_id
                )
            )


            results.append(
                result
            )


        valid_count = sum(

            1

            for result in results

            if result.get(
                "valid"
            )
            is True
        )


        invalid_count = (
            len(
                results
            )
            - valid_count
        )


        return {

            "checked":
                len(
                    results
                ),

            "valid":
                valid_count,

            "invalid":
                invalid_count,

            "healthy":
                invalid_count
                == 0,

            "results":
                results,
        }