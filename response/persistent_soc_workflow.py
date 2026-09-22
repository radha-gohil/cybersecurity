from response.unified_soc_workflow import (
    UnifiedSOCWorkflow,
)

from response.soc_case_store import (
    SOCCaseStore,
)

from response.response_action_store import (
    ResponseActionStore,
)

from response.incident_evidence_store import (
    IncidentEvidenceStore,
)

from response.soc_ticket import (
    SOCTicket,
)

from response.mitigation_verifier import (
    MitigationVerifier,
)


class PersistentSOCWorkflow:

    def __init__(
        self,
        simulation_mode=True,
        case_store=None,
        action_store=None,
        evidence_store=None,
        mitigation_verifier=None,
    ):

        self.name = "PersistentSOCWorkflow"

        self.simulation_mode = bool(
            simulation_mode
        )

        # ========================================================
        # CORE SOC WORKFLOW
        # ========================================================

        self.workflow = UnifiedSOCWorkflow(
            simulation_mode=self.simulation_mode
        )

        # ========================================================
        # PERSISTENCE STORES
        # ========================================================

        self.case_store = (
            case_store
            if case_store is not None
            else SOCCaseStore()
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

        # ========================================================
        # MITIGATION VERIFIER
        #
        # Simulation-only verification layer.
        # ========================================================

        self.mitigation_verifier = (
            mitigation_verifier
            if mitigation_verifier is not None
            else MitigationVerifier()
        )

    # ============================================================
    # SAFE HELPERS
    # ============================================================

    def safe_dict(
        self,
        value,
    ):

        if isinstance(
            value,
            dict,
        ):
            return value

        return {}

    def safe_list(
        self,
        value,
    ):

        if isinstance(
            value,
            list,
        ):
            return value

        return []

    # ============================================================
    # TICKET RECONSTRUCTION
    # ============================================================

    def ticket_from_data(
        self,
        data,
    ):

        if not isinstance(
            data,
            dict,
        ):

            raise TypeError(
                "ticket data must be a dictionary."
            )

        if not data.get(
            "ticket_id"
        ):

            raise ValueError(
                "ticket_id is missing."
            )

        return SOCTicket(

            ticket_id=data[
                "ticket_id"
            ],

            incident_id=data[
                "incident_id"
            ],

            title=data.get(
                "title",
                (
                    "SENTINEL-X Incident "
                    + data[
                        "incident_id"
                    ]
                ),
            ),

            priority=data.get(
                "priority",
                "P4",
            ),

            risk_score=data.get(
                "risk_score",
                0,
            ),

            risk_level=data.get(
                "risk_level",
                "INFO",
            ),

            selected_plan=data.get(
                "selected_plan",
                "",
            ),

            predicted_residual_risk=data.get(
                "predicted_residual_risk",
                0,
            ),

            operational_impact=data.get(
                "operational_impact",
                "UNKNOWN",
            ),

            explanation=data.get(
                "explanation",
                "",
            ),

            approval_required=bool(
                data.get(
                    "approval_required",
                    False,
                )
            ),

            approval_status=data.get(
                "approval_status",
                "NOT_REQUIRED",
            ),

            assigned_analyst=data.get(
                "assigned_analyst",
                "",
            ),

            status=data.get(
                "status",
                "OPEN",
            ),

            created_at=data.get(
                "created_at"
            ),

            updated_at=data.get(
                "updated_at"
            ),
        )

    # ============================================================
    # EXTRACT EVIDENCE FROM INTELLIGENCE
    # ============================================================

    def extract_evidence(
        self,
        intelligence,
    ):

        intelligence = self.safe_dict(
            intelligence
        )

        coordinated = self.safe_dict(
            intelligence.get(
                "coordinated_analysis"
            )
        )

        # --------------------------------------------------------
        # LOCATION 1
        # coordinated_analysis -> evidence
        # --------------------------------------------------------

        evidence = self.safe_dict(
            coordinated.get(
                "evidence"
            )
        )

        if evidence:
            return evidence

        # --------------------------------------------------------
        # LOCATION 2
        # coordinated_analysis -> context -> evidence
        # --------------------------------------------------------

        context = self.safe_dict(
            coordinated.get(
                "context"
            )
        )

        evidence = self.safe_dict(
            context.get(
                "evidence"
            )
        )

        if evidence:
            return evidence

        # --------------------------------------------------------
        # LOCATION 3
        # intelligence -> evidence
        # --------------------------------------------------------

        evidence = self.safe_dict(
            intelligence.get(
                "evidence"
            )
        )

        return evidence

    # ============================================================
    # BUILD SIMPLE ATTACK TIMELINE FROM EVIDENCE
    # ============================================================

    def build_timeline_from_evidence(
        self,
        evidence,
    ):

        evidence = self.safe_dict(
            evidence
        )

        timeline = []

        # ========================================================
        # PROCESS
        # ========================================================

        for process in self.safe_list(
            evidence.get(
                "processes"
            )
        ):

            timeline.append(
                {
                    "event_type":
                        "PROCESS_ACTIVITY",

                    "timestamp":
                        process.get(
                            "timestamp"
                        )
                        or process.get(
                            "time"
                        ),

                    "description":
                        (
                            "Process activity associated "
                            "with the incident."
                        ),

                    "entity":
                        process,
                }
            )

        # ========================================================
        # FILE
        # ========================================================

        for file_item in self.safe_list(
            evidence.get(
                "files"
            )
        ):

            timeline.append(
                {
                    "event_type":
                        "FILE_ACTIVITY",

                    "timestamp":
                        file_item.get(
                            "timestamp"
                        )
                        or file_item.get(
                            "time"
                        ),

                    "description":
                        (
                            "File activity associated "
                            "with the incident."
                        ),

                    "entity":
                        file_item,
                }
            )

        # ========================================================
        # NETWORK
        # ========================================================

        for connection in self.safe_list(
            evidence.get(
                "network_connections"
            )
        ):

            timeline.append(
                {
                    "event_type":
                        "NETWORK_ACTIVITY",

                    "timestamp":
                        connection.get(
                            "timestamp"
                        )
                        or connection.get(
                            "time"
                        ),

                    "description":
                        (
                            "Network activity associated "
                            "with the incident."
                        ),

                    "entity":
                        connection,
                }
            )

        # ========================================================
        # REGISTRY / PERSISTENCE
        # ========================================================

        for registry_item in self.safe_list(
            evidence.get(
                "registry_artifacts"
            )
        ):

            timeline.append(
                {
                    "event_type":
                        "PERSISTENCE_ACTIVITY",

                    "timestamp":
                        registry_item.get(
                            "timestamp"
                        )
                        or registry_item.get(
                            "time"
                        ),

                    "description":
                        (
                            "Registry persistence activity "
                            "associated with the incident."
                        ),

                    "entity":
                        registry_item,
                }
            )

        # ========================================================
        # ORDER TIMELINE
        # ========================================================

        def timeline_sort_key(
            item,
        ):

            timestamp = item.get(
                "timestamp"
            )

            return (
                timestamp is None,
                str(
                    timestamp
                    or ""
                ),
            )

        timeline.sort(
            key=timeline_sort_key
        )

        return timeline

    # ============================================================
    # EXTRACT TIMELINE FROM INTELLIGENCE
    # ============================================================

    def extract_timeline(
        self,
        intelligence,
        evidence,
    ):

        intelligence = self.safe_dict(
            intelligence
        )

        possible_locations = [

            intelligence.get(
                "attack_timeline"
            ),

            intelligence.get(
                "timeline"
            ),
        ]

        coordinated = self.safe_dict(
            intelligence.get(
                "coordinated_analysis"
            )
        )

        possible_locations.extend(
            [
                coordinated.get(
                    "attack_timeline"
                ),

                coordinated.get(
                    "timeline"
                ),
            ]
        )

        investigation = self.safe_dict(
            intelligence.get(
                "investigation"
            )
        )

        possible_locations.extend(
            [
                investigation.get(
                    "attack_timeline"
                ),

                investigation.get(
                    "timeline"
                ),
            ]
        )

        for candidate in possible_locations:

            if (
                isinstance(
                    candidate,
                    list,
                )
                and candidate
            ):

                return candidate

        # --------------------------------------------------------
        # FALLBACK
        # --------------------------------------------------------

        return self.build_timeline_from_evidence(
            evidence
        )

    # ============================================================
    # PERSIST CASE + RESPONSE ACTIONS
    # ============================================================

    def persist_case(
        self,
        case_result,
    ):

        if not isinstance(
            case_result,
            dict,
        ):

            raise TypeError(
                "case_result must be a dictionary."
            )

        incident_id = case_result.get(
            "incident_id"
        )

        if not incident_id:

            raise ValueError(
                "incident_id missing from case."
            )

        # --------------------------------------------------------
        # SAVE CASE
        # --------------------------------------------------------

        self.case_store.save_case(
            case_result
        )

        # --------------------------------------------------------
        # SAVE RESPONSE ACTIONS
        # --------------------------------------------------------

        actions = case_result.get(
            "response_actions",
            [],
        )

        saved_action_ids = []

        for action in actions:

            action_id = (
                self.action_store.save_action(
                    action
                )
            )

            saved_action_ids.append(
                action_id
            )

        return {
            "success":
                True,

            "incident_id":
                incident_id,

            "saved_action_count":
                len(
                    saved_action_ids
                ),

            "saved_action_ids":
                saved_action_ids,
        }

    # ============================================================
    # CREATE NEW SOC CASE
    # ============================================================

    def create_case(
        self,
        incident_id,
        intelligence,
    ):

        existing = self.case_store.get_case(
            incident_id
        )

        if existing is not None:

            raise ValueError(
                (
                    "SOC case already exists for incident "
                    f"{incident_id}."
                )
            )

        # ========================================================
        # RUN UNIFIED SOC WORKFLOW
        # ========================================================

        case_result = (
            self.workflow.create_case(

                incident_id=
                    incident_id,

                intelligence=
                    intelligence,
            )
        )

        # ========================================================
        # PERSIST CORE CASE
        # ========================================================

        persistence = self.persist_case(
            case_result
        )

        # ========================================================
        # EXTRACT + PERSIST EVIDENCE
        # ========================================================

        evidence = self.extract_evidence(
            intelligence
        )

        evidence_result = (
            self.evidence_store.save_evidence_bundle(

                incident_id=
                    incident_id,

                evidence=
                    evidence,

                replace_existing=
                    True,
            )
        )

        # ========================================================
        # EXTRACT + PERSIST TIMELINE
        # ========================================================

        timeline = self.extract_timeline(

            intelligence=
                intelligence,

            evidence=
                evidence,
        )

        timeline_result = (
            self.evidence_store.save_timeline(

                incident_id=
                    incident_id,

                timeline=
                    timeline,

                replace_existing=
                    True,
            )
        )

        # ========================================================
        # PERSISTENCE INFORMATION
        # ========================================================

        case_result[
            "persistence"
        ] = {

            **persistence,

            "evidence":
                evidence_result,

            "timeline":
                timeline_result,
        }

        return case_result

    # ============================================================
    # RECOVER CASE AFTER RESTART
    # ============================================================

    def recover_case(
        self,
        incident_id,
    ):

        stored_case = self.case_store.get_case(
            incident_id
        )

        if stored_case is None:

            return None

        # ========================================================
        # RESPONSE ACTIONS
        # ========================================================

        actions = (
            self.action_store.get_by_incident(
                incident_id
            )
        )

        # ========================================================
        # EVIDENCE
        # ========================================================

        evidence = (
            self.evidence_store.get_evidence_bundle(
                incident_id
            )
        )

        # ========================================================
        # TIMELINE
        # ========================================================

        timeline = (
            self.evidence_store.get_timeline(
                incident_id
            )
        )

        # ========================================================
        # RECOVERED CASE
        # ========================================================

        recovered = {

            "workflow":
                self.name,

            "incident_id":
                incident_id,

            "status":
                stored_case.get(
                    "status"
                ),

            "decision":
                stored_case.get(
                    "decision",
                    {},
                ),

            "explanation":
                stored_case.get(
                    "explanation",
                    {},
                ),

            "ticket_data":
                stored_case.get(
                    "ticket_data",
                    {},
                ),

            "response_actions":
                actions,

            "response_action_count":
                len(
                    actions
                ),

            "evidence":
                evidence,

            "timeline":
                timeline,

            # ====================================================
            # NEW:
            # Restore simulated mitigation verification.
            # ====================================================

            "mitigation_verification":
                stored_case.get(
                    "mitigation_verification",
                    {},
                ),

            "created_at":
                stored_case.get(
                    "created_at"
                ),

            "updated_at":
                stored_case.get(
                    "updated_at"
                ),

            "recovered_from_database":
                True,

            "simulation_mode":
                self.simulation_mode,

            # ----------------------------------------------------
            # SENTINEL-X currently performs no real endpoint
            # response through this workflow.
            # ----------------------------------------------------

            "real_response_executed":
                False,
        }

        return recovered

    # ============================================================
    # RECOVER SOC TICKET
    # ============================================================

    def recover_ticket(
        self,
        incident_id,
    ):

        case_result = self.recover_case(
            incident_id
        )

        if case_result is None:

            return None

        ticket_data = case_result.get(
            "ticket_data"
        )

        if not ticket_data:

            return None

        return self.ticket_from_data(
            ticket_data
        )

    # ============================================================
    # APPROVE PERSISTED CASE
    # ============================================================

    def approve_case(
        self,
        incident_id,
        analyst,
        comment="",
    ):

        case_result = self.recover_case(
            incident_id
        )

        if case_result is None:

            raise ValueError(
                (
                    "SOC case not found for incident "
                    f"{incident_id}."
                )
            )

        ticket = self.recover_ticket(
            incident_id
        )

        if ticket is None:

            raise ValueError(
                "SOC ticket could not be restored."
            )

        # ========================================================
        # STATUS VALIDATION
        # ========================================================

        if (
            ticket.approval_status
            == "APPROVED"
        ):

            raise ValueError(
                "SOC ticket is already approved."
            )

        if (
            ticket.approval_status
            == "REJECTED"
        ):

            raise ValueError(
                "Rejected SOC ticket cannot be approved."
            )

        # ========================================================
        # APPROVAL WORKFLOW
        # ========================================================

        result = (
            self.workflow.approve_case(

                case_result=
                    case_result,

                ticket=
                    ticket,

                analyst=
                    analyst,

                comment=
                    comment,
            )
        )

        case_result[
            "status"
        ] = result.get(
            "status",
            case_result.get(
                "status"
            ),
        )

        case_result[
            "ticket_data"
        ] = ticket.to_dict()

        # ========================================================
        # SAVE RESPONSE ACTIONS
        # ========================================================

        for action in case_result.get(
            "response_actions",
            [],
        ):

            self.action_store.save_action(
                action
            )

        # ========================================================
        # SAVE UPDATED CASE
        # ========================================================

        self.case_store.save_case(
            case_result
        )

        result[
            "persisted"
        ] = True

        return result

    # ============================================================
    # REJECT PERSISTED CASE
    # ============================================================

    def reject_case(
        self,
        incident_id,
        analyst,
        reason,
    ):

        case_result = self.recover_case(
            incident_id
        )

        if case_result is None:

            raise ValueError(
                (
                    "SOC case not found for incident "
                    f"{incident_id}."
                )
            )

        ticket = self.recover_ticket(
            incident_id
        )

        if ticket is None:

            raise ValueError(
                "SOC ticket could not be restored."
            )

        # ========================================================
        # STATUS VALIDATION
        # ========================================================

        if (
            ticket.approval_status
            == "APPROVED"
        ):

            raise ValueError(
                "Approved SOC ticket cannot be rejected."
            )

        if (
            ticket.approval_status
            == "REJECTED"
        ):

            raise ValueError(
                "SOC ticket is already rejected."
            )

        # ========================================================
        # REJECTION WORKFLOW
        # ========================================================

        result = (
            self.workflow.reject_case(

                case_result=
                    case_result,

                ticket=
                    ticket,

                analyst=
                    analyst,

                reason=
                    reason,
            )
        )

        case_result[
            "status"
        ] = "REJECTED"

        case_result[
            "ticket_data"
        ] = ticket.to_dict()

        # ========================================================
        # SAVE RESPONSE ACTIONS
        # ========================================================

        for action in case_result.get(
            "response_actions",
            [],
        ):

            self.action_store.save_action(
                action
            )

        # ========================================================
        # SAVE UPDATED CASE
        # ========================================================

        self.case_store.save_case(
            case_result
        )

        result[
            "persisted"
        ] = True

        return result

    # ============================================================
    # VERIFY SIMULATED MITIGATION
    # ============================================================

    def verify_simulated_mitigation(
        self,
        incident_id,
        before_state,
        simulated_after_state,
        response_result,
    ):

        """
        Verify a simulated mitigation outcome and persist
        the verification result with the SOC case.

        IMPORTANT:

        This method does NOT execute real mitigation.

        It only compares supplied before/after simulation
        state using MitigationVerifier.
        """

        # ========================================================
        # SAFETY GUARD 1
        #
        # Entire persistent workflow must be simulation mode.
        # ========================================================

        if not self.simulation_mode:

            raise ValueError(
                "Mitigation verification is available only "
                "when PersistentSOCWorkflow is running in "
                "simulation_mode=True."
            )

        # ========================================================
        # RECOVER CASE
        # ========================================================

        case_result = self.recover_case(
            incident_id
        )

        if case_result is None:

            raise ValueError(
                (
                    "SOC case not found for incident "
                    f"{incident_id}."
                )
            )

        # ========================================================
        # INPUT VALIDATION
        # ========================================================

        if not isinstance(
            before_state,
            dict,
        ):

            raise TypeError(
                "before_state must be a dictionary."
            )

        if not isinstance(
            simulated_after_state,
            dict,
        ):

            raise TypeError(
                "simulated_after_state must be a dictionary."
            )

        if not isinstance(
            response_result,
            dict,
        ):

            raise TypeError(
                "response_result must be a dictionary."
            )

        # ========================================================
        # SAFETY GUARD 2
        #
        # Reject anything explicitly claiming to be a real
        # response result.
        # ========================================================

        if (
            response_result.get(
                "simulation_mode",
                True,
            )
            is not True
        ):

            raise ValueError(
                "Real response results cannot be verified "
                "through the simulation-only mitigation "
                "verification workflow."
            )

        # ========================================================
        # FORCE SAFE COPY
        # ========================================================

        safe_response_result = dict(
            response_result
        )

        safe_response_result[
            "simulation_mode"
        ] = True

        # ========================================================
        # RUN MITIGATION VERIFIER
        # ========================================================

        verification = (
            self.mitigation_verifier.verify(

                before_state=
                    before_state,

                simulated_after_state=
                    simulated_after_state,

                response_result=
                    safe_response_result,
            )
        )

        # ========================================================
        # PERSIST VERIFICATION RESULT
        #
        # This means:
        #
        # "The simulated response appears effective according
        #  to the model."
        #
        # It does NOT mean a real endpoint was remediated.
        # ========================================================

        case_result[
            "mitigation_verification"
        ] = verification

        case_result[
            "simulation_mode"
        ] = True

        case_result[
            "real_response_executed"
        ] = False

        self.case_store.save_case(
            case_result
        )

        # ========================================================
        # RESULT
        # ========================================================

        return {

            "success":
                True,

            "incident_id":
                incident_id,

            "status":
                verification.get(
                    "status"
                ),

            "verification":
                verification,

            "persisted":
                True,

            "simulation_mode":
                True,

            "real_response_executed":
                False,
        }

    # ============================================================
    # GET MITIGATION VERIFICATION
    # ============================================================

    def get_mitigation_verification(
        self,
        incident_id,
    ):

        case_result = self.recover_case(
            incident_id
        )

        if case_result is None:

            return None

        return case_result.get(
            "mitigation_verification",
            {},
        )

    # ============================================================
    # LIST CASES
    # ============================================================

    def list_cases(
        self,
        limit=100,
    ):

        return self.case_store.list_cases(
            limit=limit
        )

    # ============================================================
    # GET RESPONSE ACTIONS
    # ============================================================

    def get_response_actions(
        self,
        incident_id,
    ):

        return (
            self.action_store.get_by_incident(
                incident_id
            )
        )

    # ============================================================
    # GET PERSISTED EVIDENCE
    # ============================================================

    def get_evidence(
        self,
        incident_id,
    ):

        return (
            self.evidence_store.get_evidence_bundle(
                incident_id
            )
        )

    # ============================================================
    # GET PERSISTED TIMELINE
    # ============================================================

    def get_timeline(
        self,
        incident_id,
    ):

        return (
            self.evidence_store.get_timeline(
                incident_id
            )
        )