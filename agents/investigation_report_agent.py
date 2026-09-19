from datetime import datetime, timezone


class InvestigationReportAgent:

    def __init__(self):

        self.name = "InvestigationReportAgent"


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
    # SAFE HELPERS
    # ============================================================

    def safe_dict(
        self,
        value,
    ) -> dict:

        if isinstance(
            value,
            dict,
        ):

            return value

        return {}


    def safe_list(
        self,
        value,
    ) -> list:

        if isinstance(
            value,
            list,
        ):

            return value

        return []


    # ============================================================
    # BUILD EXECUTIVE SUMMARY
    # ============================================================

    def build_executive_summary(
        self,
        incident: dict,
        triage: dict,
        risk: dict,
    ) -> str:

        incident_id = (
            incident.get(
                "incident_id"
            )
            or "UNKNOWN"
        )

        severity = str(
            incident.get(
                "severity",
                "INFO",
            )
        ).upper()

        correlation_score = (
            incident.get(
                "correlation_score",
                0,
            )
        )

        priority = (
            triage.get(
                "priority",
                "UNKNOWN",
            )
        )

        risk_score = (
            risk.get(
                "risk_score",
                0,
            )
        )

        risk_level = (
            risk.get(
                "risk_level",
                "INFO",
            )
        )


        return (

            f"Incident {incident_id} was classified as "
            f"{severity} with correlation score "
            f"{correlation_score}. "

            f"Triage priority is {priority}. "

            f"The final explainable risk assessment produced "
            f"a score of {risk_score}/100 "
            f"({risk_level})."
        )


    # ============================================================
    # BUILD ENTITY SUMMARY
    # ============================================================

    def build_entity_summary(
        self,
        evidence: dict,
    ) -> dict:

        processes = (
            self.safe_list(
                evidence.get(
                    "processes"
                )
            )
        )

        files = (
            self.safe_list(
                evidence.get(
                    "files"
                )
            )
        )

        network = (
            self.safe_list(
                evidence.get(
                    "network_connections"
                )
            )
        )

        registry = (
            self.safe_list(
                evidence.get(
                    "registry_artifacts"
                )
            )
        )


        return {

            "process_count":
                len(
                    processes
                ),

            "file_count":
                len(
                    files
                ),

            "network_count":
                len(
                    network
                ),

            "registry_count":
                len(
                    registry
                ),

            "processes":
                processes,

            "files":
                files,

            "network_connections":
                network,

            "registry_artifacts":
                registry,
        }


    # ============================================================
    # BUILD IOC SUMMARY
    # ============================================================

    def build_ioc_summary(
        self,
        evidence: dict,
    ) -> dict:

        iocs = (
            self.safe_dict(
                evidence.get(
                    "iocs"
                )
            )
        )


        return {

            "hashes":
                self.safe_list(
                    iocs.get(
                        "hashes"
                    )
                ),

            "file_paths":
                self.safe_list(
                    iocs.get(
                        "file_paths"
                    )
                ),

            "remote_ips":
                self.safe_list(
                    iocs.get(
                        "remote_ips"
                    )
                ),

            "registry_keys":
                self.safe_list(
                    iocs.get(
                        "registry_keys"
                    )
                ),
        }


    # ============================================================
    # BUILD ATTACK SUMMARY
    # ============================================================

    def build_attack_summary(
        self,
        attack_timeline: dict,
        attack_graph: dict,
    ) -> dict:

        stages = (
            self.safe_list(
                attack_timeline.get(
                    "attack_stages"
                )
            )
        )

        story = (
            self.safe_list(
                attack_timeline.get(
                    "attack_story"
                )
            )
        )

        graph_summary = (
            self.safe_dict(
                attack_graph.get(
                    "summary"
                )
            )
        )


        return {

            "attack_stages":
                stages,

            "attack_story":
                story,

            "graph_nodes":
                graph_summary.get(
                    "nodes",
                    0,
                ),

            "graph_edges":
                graph_summary.get(
                    "edges",
                    0,
                ),

            "graph_node_types":
                graph_summary.get(
                    "node_types",
                    {},
                ),
        }


    # ============================================================
    # BUILD KEY FINDINGS
    # ============================================================

    def build_key_findings(
        self,
        investigation: dict,
        risk: dict,
    ) -> list:

        findings = []


        investigation_findings = (
            self.safe_list(
                investigation.get(
                    "findings"
                )
            )
        )


        for finding in investigation_findings:

            if finding not in findings:

                findings.append(
                    finding
                )


        risk_reasons = (
            self.safe_list(
                risk.get(
                    "reasons"
                )
            )
        )


        for reason in risk_reasons:

            if reason not in findings:

                findings.append(
                    reason
                )


        return findings


    # ============================================================
    # BUILD DECISION SUMMARY
    # ============================================================

    def build_decision_summary(
        self,
        triage: dict,
        risk: dict,
    ) -> dict:

        return {

            "triage_priority":
                triage.get(
                    "priority"
                ),

            "triage_score":
                triage.get(
                    "triage_score"
                ),

            "risk_score":
                risk.get(
                    "risk_score"
                ),

            "risk_level":
                risk.get(
                    "risk_level"
                ),

            "requires_investigation":
                triage.get(
                    "requires_investigation",
                    False,
                ),

            "requires_response":
                risk.get(
                    "requires_response",
                    False,
                ),

            "recommended_action":
                risk.get(
                    "recommended_action"
                ),
        }


    # ============================================================
    # BUILD HUMAN READABLE REPORT
    # ============================================================

    def build_text_report(
        self,
        report: dict,
    ) -> str:

        lines = []


        lines.append(
            "=" * 80
        )

        lines.append(
            "SENTINEL-X INCIDENT INVESTIGATION REPORT"
        )

        lines.append(
            "=" * 80
        )


        lines.append(
            ""
        )

        lines.append(
            f"Incident ID: "
            f"{report.get('incident_id')}"
        )

        lines.append(
            f"Generated At: "
            f"{report.get('generated_at')}"
        )

        lines.append(
            ""
        )


        # --------------------------------------------------------
        # EXECUTIVE SUMMARY
        # --------------------------------------------------------

        lines.append(
            "EXECUTIVE SUMMARY"
        )

        lines.append(
            "-" * 80
        )

        lines.append(
            report.get(
                "executive_summary",
                ""
            )
        )

        lines.append(
            ""
        )


        # --------------------------------------------------------
        # DECISION
        # --------------------------------------------------------

        decision = (
            report.get(
                "decision",
                {}
            )
        )


        lines.append(
            "SECURITY DECISION"
        )

        lines.append(
            "-" * 80
        )

        lines.append(
            f"Triage Priority: "
            f"{decision.get('triage_priority')}"
        )

        lines.append(
            f"Triage Score: "
            f"{decision.get('triage_score')}"
        )

        lines.append(
            f"Risk Score: "
            f"{decision.get('risk_score')}"
        )

        lines.append(
            f"Risk Level: "
            f"{decision.get('risk_level')}"
        )

        lines.append(
            f"Requires Investigation: "
            f"{decision.get('requires_investigation')}"
        )

        lines.append(
            f"Requires Response: "
            f"{decision.get('requires_response')}"
        )

        lines.append(
            f"Recommended Action: "
            f"{decision.get('recommended_action')}"
        )

        lines.append(
            ""
        )


        # --------------------------------------------------------
        # FINDINGS
        # --------------------------------------------------------

        lines.append(
            "KEY FINDINGS"
        )

        lines.append(
            "-" * 80
        )


        for finding in report.get(
            "key_findings",
            []
        ):

            lines.append(
                f"- {finding}"
            )


        lines.append(
            ""
        )


        # --------------------------------------------------------
        # IOCS
        # --------------------------------------------------------

        iocs = (
            report.get(
                "iocs",
                {}
            )
        )


        lines.append(
            "INDICATORS OF INTEREST"
        )

        lines.append(
            "-" * 80
        )

        lines.append(
            f"Hashes: "
            f"{iocs.get('hashes', [])}"
        )

        lines.append(
            f"File Paths: "
            f"{iocs.get('file_paths', [])}"
        )

        lines.append(
            f"Remote IPs: "
            f"{iocs.get('remote_ips', [])}"
        )

        lines.append(
            f"Registry Keys: "
            f"{iocs.get('registry_keys', [])}"
        )

        lines.append(
            ""
        )


        # --------------------------------------------------------
        # ATTACK STORY
        # --------------------------------------------------------

        attack = (
            report.get(
                "attack",
                {}
            )
        )


        lines.append(
            "RECONSTRUCTED ATTACK TIMELINE"
        )

        lines.append(
            "-" * 80
        )


        for item in attack.get(
            "attack_story",
            []
        ):

            lines.append(
                item
            )


        lines.append(
            ""
        )


        # --------------------------------------------------------
        # ATTACK GRAPH SUMMARY
        # --------------------------------------------------------

        lines.append(
            "ATTACK GRAPH SUMMARY"
        )

        lines.append(
            "-" * 80
        )

        lines.append(
            f"Nodes: "
            f"{attack.get('graph_nodes')}"
        )

        lines.append(
            f"Edges: "
            f"{attack.get('graph_edges')}"
        )

        lines.append(
            f"Node Types: "
            f"{attack.get('graph_node_types')}"
        )

        lines.append(
            ""
        )


        lines.append(
            "=" * 80
        )

        lines.append(
            "END OF SENTINEL-X REPORT"
        )

        lines.append(
            "=" * 80
        )


        return "\n".join(
            lines
        )


    # ============================================================
    # GENERATE REPORT
    # ============================================================

    def generate(
        self,
        incident: dict,
        triage: dict,
        investigation: dict,
        evidence: dict,
        attack_timeline: dict,
        attack_graph: dict,
        risk: dict,
    ) -> dict:

        incident = (
            self.safe_dict(
                incident
            )
        )

        triage = (
            self.safe_dict(
                triage
            )
        )

        investigation = (
            self.safe_dict(
                investigation
            )
        )

        evidence = (
            self.safe_dict(
                evidence
            )
        )

        attack_timeline = (
            self.safe_dict(
                attack_timeline
            )
        )

        attack_graph = (
            self.safe_dict(
                attack_graph
            )
        )

        risk = (
            self.safe_dict(
                risk
            )
        )


        report = {

            "incident_id":
                incident.get(
                    "incident_id"
                ),

            "agent":
                self.name,

            "generated_at":
                self.now_iso(),

            "executive_summary":
                self.build_executive_summary(
                    incident,
                    triage,
                    risk,
                ),

            "decision":
                self.build_decision_summary(
                    triage,
                    risk,
                ),

            "entities":
                self.build_entity_summary(
                    evidence
                ),

            "iocs":
                self.build_ioc_summary(
                    evidence
                ),

            "attack":
                self.build_attack_summary(
                    attack_timeline,
                    attack_graph,
                ),

            "key_findings":
                self.build_key_findings(
                    investigation,
                    risk,
                ),

            "risk_components":
                self.safe_dict(
                    risk.get(
                        "components"
                    )
                ),

            "investigation_priority":
                investigation.get(
                    "priority"
                ),

            "investigation_indicators":
                self.safe_list(
                    investigation.get(
                        "indicators"
                    )
                ),
        }


        report[
            "text_report"
        ] = (
            self.build_text_report(
                report
            )
        )


        return report