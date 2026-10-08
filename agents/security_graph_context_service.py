from __future__ import annotations

from copy import deepcopy

from datetime import (
    datetime,
    timezone,
)

from typing import (
    Any,
    Dict,
    List,
    Optional,
)


from agents.attack_graph_agent import (
    AttackGraphAgent,
)

from ai_detection.graph.process_subgraph_service import (
    ProcessSubgraphService,
)

from ai_detection.graph.process_graph_result_store import (
    ProcessGraphResultStore,
)


# ================================================================
# SENTINEL-X SECURITY GRAPH CONTEXT SERVICE
# ================================================================


class SecurityGraphContextService:
    """
    SENTINEL-X 7D.3 Security Graph Context Service.

    This service retrieves and normalizes graph evidence for
    downstream AI reasoning.

    Sources:

        1. Incident-level AttackGraphAgent graph
        2. Persistent provenance process subgraph
        3. Existing Graph-AI model result

    This component performs NO LLM inference.

    Graph evidence is supporting context.

    It is NOT automatic proof that an attack occurred.
    """

    VERSION = "7D.3-v1"

    SCHEMA_VERSION = (
        "sentinelx.ai.security-graph-context.v1"
    )


    MAX_ATTACK_GRAPH_NODES = 50

    MAX_ATTACK_GRAPH_EDGES = 75

    MAX_PROCESS_GRAPH_NODES = 50

    MAX_PROCESS_GRAPH_EDGES = 75

    MAX_RELATIONSHIP_FACTS = 75


    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(
        self,
        *,
        database_path=None,
        attack_graph_agent=None,
        subgraph_service=None,
        graph_result_store=None,
    ):

        self.name = (
            "SecurityGraphContextService"
        )


        self.database_path = (
            database_path
        )


        self.attack_graph_agent = (
            attack_graph_agent
            if attack_graph_agent is not None
            else AttackGraphAgent()
        )


        # --------------------------------------------------------
        # Keep persistent graph services lazy.
        #
        # Importing this module should not unnecessarily open or
        # initialize graph databases.
        # --------------------------------------------------------

        self._subgraph_service = (
            subgraph_service
        )


        self._graph_result_store = (
            graph_result_store
        )


    # ============================================================
    # TIME
    # ============================================================

    @staticmethod
    def now_iso() -> str:

        return (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


    # ============================================================
    # SAFE TYPES
    # ============================================================

    @staticmethod
    def safe_dict(
        value: Any,
    ) -> Dict:

        return (
            value
            if isinstance(
                value,
                dict,
            )
            else {}
        )


    @staticmethod
    def safe_list(
        value: Any,
    ) -> List:

        return (
            value
            if isinstance(
                value,
                list,
            )
            else []
        )


    @staticmethod
    def safe_string(
        value: Any,
    ) -> str:

        return str(
            value
            or ""
        ).strip()


    @staticmethod
    def safe_int(
        value: Any,
    ) -> Optional[int]:

        try:

            number = int(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return None


        if number <= 0:

            return None


        return number


    # ============================================================
    # LAZY SERVICES
    # ============================================================

    def get_subgraph_service(
        self,
    ):

        if (
            self._subgraph_service
            is None
        ):

            self._subgraph_service = (
                ProcessSubgraphService(

                    database_path=
                        self.database_path
                )
            )


        return (
            self._subgraph_service
        )


    def get_graph_result_store(
        self,
    ):

        if (
            self._graph_result_store
            is None
        ):

            self._graph_result_store = (
                ProcessGraphResultStore(

                    database_path=
                        self.database_path
                )
            )


        return (
            self._graph_result_store
        )


    # ============================================================
    # STATUS
    # ============================================================

    def status(
        self,
    ) -> Dict:

        return {

            "service":
                self.name,

            "version":
                self.VERSION,

            "schema_version":
                self.SCHEMA_VERSION,

            "llm_inference":
                False,

            "attack_graph_available":
                self.attack_graph_agent
                is not None,

            "process_subgraph_supported":
                True,

            "graph_ai_result_supported":
                True,

            "graph_is_supporting_context":
                True,

            "simulation_only":
                True,

            "execution_allowed":
                False,
        }


    # ============================================================
    # RECURSIVE KEY SEARCH
    # ============================================================

    def find_first_value(
        self,
        value: Any,
        keys,
    ):

        normalized_keys = {

            str(
                item
            ).lower()

            for item in keys
        }


        if isinstance(
            value,
            dict,
        ):

            # ----------------------------------------------------
            # Direct keys first
            # ----------------------------------------------------

            for key, item in (
                value.items()
            ):

                if (
                    str(
                        key
                    ).lower()
                    in normalized_keys
                ):

                    if (
                        item
                        is not None
                        and
                        item != ""
                    ):

                        return item


            # ----------------------------------------------------
            # Then descendants
            # ----------------------------------------------------

            for item in (
                value.values()
            ):

                result = (
                    self.find_first_value(
                        item,
                        normalized_keys,
                    )
                )


                if result is not None:

                    return result


        elif isinstance(
            value,
            list,
        ):

            for item in value:

                result = (
                    self.find_first_value(
                        item,
                        normalized_keys,
                    )
                )


                if result is not None:

                    return result


        return None


    # ============================================================
    # PROCESS IDENTITY
    # ============================================================

    def extract_process_identity(
        self,
        *,
        threat: Dict,
        enriched_evidence: Optional[Dict],
    ) -> Dict:

        threat = self.safe_dict(
            threat
        )


        enriched = self.safe_dict(
            enriched_evidence
        )


        # ========================================================
        # Prefer enriched process evidence
        # ========================================================

        for process in self.safe_list(
            enriched.get(
                "processes"
            )
        ):

            process = self.safe_dict(
                process
            )


            pid = self.safe_int(
                process.get(
                    "pid"
                )
            )


            if pid is None:

                continue


            return {

                "resolved":
                    True,

                "source":
                    "ENRICHED_EVIDENCE",

                "pid":
                    pid,

                "process_name":
                    (
                        process.get(
                            "name"
                        )
                        or
                        process.get(
                            "process_name"
                        )
                    ),

                "device_id":
                    (
                        process.get(
                            "device_id"
                        )
                        or
                        threat.get(
                            "device_id"
                        )
                    ),
            }


        # ========================================================
        # Fall back to canonical threat evidence
        # ========================================================

        evidence = self.safe_dict(
            threat.get(
                "evidence"
            )
        )


        pid = self.safe_int(

            self.find_first_value(

                evidence,

                {
                    "pid",
                    "process_id",
                },
            )
        )


        process_name = (
            self.find_first_value(

                evidence,

                {
                    "process_name",
                    "image_name",
                    "executable_name",
                    "process_image",
                },
            )
        )


        if pid is None:

            return {

                "resolved":
                    False,

                "source":
                    "NONE",

                "pid":
                    None,

                "process_name":
                    process_name,

                "device_id":
                    threat.get(
                        "device_id"
                    ),
            }


        return {

            "resolved":
                True,

            "source":
                "CANONICAL_THREAT",

            "pid":
                pid,

            "process_name":
                process_name,

            "device_id":
                threat.get(
                    "device_id"
                ),
        }


    # ============================================================
    # ATTACK GRAPH
    # ============================================================

    def build_attack_graph_context(
        self,
        enriched_evidence: Optional[Dict],
    ) -> Dict:

        enriched = self.safe_dict(
            enriched_evidence
        )


        if not enriched:

            return {

                "available":
                    False,

                "state":
                    "NO_ENRICHED_EVIDENCE",

                "summary":
                    {},

                "nodes":
                    [],

                "edges":
                    [],
            }


        try:

            result = (
                self.attack_graph_agent
                .generate(
                    enriched
                )
            )


        except Exception as error:

            return {

                "available":
                    False,

                "state":
                    "ATTACK_GRAPH_ERROR",

                "error":
                    str(
                        error
                    ),

                "summary":
                    {},

                "nodes":
                    [],

                "edges":
                    [],
            }


        result = self.safe_dict(
            result
        )


        graph = self.safe_dict(
            result.get(
                "graph"
            )
        )


        nodes = self.safe_list(
            graph.get(
                "nodes"
            )
        )


        edges = self.safe_list(
            graph.get(
                "edges"
            )
        )


        summary = self.safe_dict(
            result.get(
                "summary"
            )
        )


        available = bool(
            nodes
            or
            edges
        )


        return {

            "available":
                available,

            "state":
                (
                    "AVAILABLE"
                    if available
                    else
                    "EMPTY_ATTACK_GRAPH"
                ),

            "incident_id":
                result.get(
                    "incident_id"
                ),

            "summary":
                deepcopy(
                    summary
                ),

            "node_count":
                graph.get(
                    "node_count",
                    len(
                        nodes
                    ),
                ),

            "edge_count":
                graph.get(
                    "edge_count",
                    len(
                        edges
                    ),
                ),

            "nodes":
                deepcopy(

                    nodes[
                        :
                        self.MAX_ATTACK_GRAPH_NODES
                    ]
                ),

            "edges":
                deepcopy(

                    edges[
                        :
                        self.MAX_ATTACK_GRAPH_EDGES
                    ]
                ),

            "truncated":
                (

                    len(
                        nodes
                    )
                    >
                    self.MAX_ATTACK_GRAPH_NODES

                    or

                    len(
                        edges
                    )
                    >
                    self.MAX_ATTACK_GRAPH_EDGES
                ),
        }


    # ============================================================
    # PROCESS PROVENANCE SUBGRAPH
    # ============================================================

    def build_process_subgraph_context(
        self,
        process_identity: Dict,
    ) -> Dict:

        process_identity = self.safe_dict(
            process_identity
        )


        pid = self.safe_int(
            process_identity.get(
                "pid"
            )
        )


        if pid is None:

            return {

                "available":
                    False,

                "state":
                    "PROCESS_IDENTITY_UNAVAILABLE",

                "pid":
                    None,

                "nodes":
                    [],

                "edges":
                    [],
            }


        try:

            service = (
                self.get_subgraph_service()
            )


            result = (
                service.get_process_subgraph(

                    pid=
                        pid,

                    process_name=
                        process_identity.get(
                            "process_name"
                        ),

                    device_id=
                        process_identity.get(
                            "device_id"
                        ),

                    max_hops=
                        2,

                    include_event_nodes=
                        True,
                )
            )


        except Exception as error:

            return {

                "available":
                    False,

                "state":
                    "PROCESS_SUBGRAPH_ERROR",

                "pid":
                    pid,

                "error":
                    str(
                        error
                    ),

                "nodes":
                    [],

                "edges":
                    [],
            }


        result = self.safe_dict(
            result
        )


        if (
            result.get(
                "found"
            )
            is not True
        ):

            return {

                "available":
                    False,

                "state":
                    (
                        result.get(
                            "state"
                        )
                        or
                        "PROCESS_GRAPH_NOT_FOUND"
                    ),

                "pid":
                    pid,

                "process_name":
                    process_identity.get(
                        "process_name"
                    ),

                "summary":
                    self.safe_dict(
                        result.get(
                            "summary"
                        )
                    ),

                "nodes":
                    [],

                "edges":
                    [],
            }


        nodes = self.safe_list(
            result.get(
                "nodes"
            )
        )


        edges = self.safe_list(
            result.get(
                "edges"
            )
        )


        return {

            "available":
                True,

            "state":
                "AVAILABLE",

            "pid":
                pid,

            "process_name":
                process_identity.get(
                    "process_name"
                ),

            "device_id":
                process_identity.get(
                    "device_id"
                ),

            "center_node":
                deepcopy(

                    self.safe_dict(
                        result.get(
                            "center_node"
                        )
                    )
                ),

            "summary":
                deepcopy(

                    self.safe_dict(
                        result.get(
                            "summary"
                        )
                    )
                ),

            "nodes":
                deepcopy(

                    nodes[
                        :
                        self.MAX_PROCESS_GRAPH_NODES
                    ]
                ),

            "edges":
                deepcopy(

                    edges[
                        :
                        self.MAX_PROCESS_GRAPH_EDGES
                    ]
                ),

            "truncated":
                (

                    len(
                        nodes
                    )
                    >
                    self.MAX_PROCESS_GRAPH_NODES

                    or

                    len(
                        edges
                    )
                    >
                    self.MAX_PROCESS_GRAPH_EDGES
                ),
        }


    # ============================================================
    # GRAPH-AI RESULT
    # ============================================================

    def build_graph_ai_context(
        self,
        process_identity: Dict,
    ) -> Dict:

        process_identity = self.safe_dict(
            process_identity
        )


        pid = self.safe_int(
            process_identity.get(
                "pid"
            )
        )


        if pid is None:

            return {

                "available":
                    False,

                "state":
                    "PROCESS_IDENTITY_UNAVAILABLE",

                "pid":
                    None,
            }


        try:

            store = (
                self.get_graph_result_store()
            )


            latest = (
                store.get_latest_for_pid(
                    pid
                )
            )


        except Exception as error:

            return {

                "available":
                    False,

                "state":
                    "GRAPH_AI_RESULT_ERROR",

                "pid":
                    pid,

                "error":
                    str(
                        error
                    ),
            }


        latest = self.safe_dict(
            latest
        )


        if not latest:

            return {

                "available":
                    False,

                "state":
                    "NO_GRAPH_AI_RESULT",

                "pid":
                    pid,
            }


        # --------------------------------------------------------
        # Do not send embeddings or arbitrary DB payloads into
        # reasoning context.
        # --------------------------------------------------------

        allowed_keys = {

            "id",
            "event_id",

            "pid",
            "process_name",
            "device_id",

            "available",
            "state",

            "graph_anomaly_score",
            "anomaly_score",

            "score_band",

            "severity",

            "suspicious",
            "should_alert",

            "operating_mode",

            "ai_evidence_coverage",
            "evidence_coverage",

            "created_at",
        }


        compact = {}


        for key in allowed_keys:

            if key in latest:

                compact[
                    key
                ] = deepcopy(
                    latest.get(
                        key
                    )
                )


        nested_result = self.safe_dict(
            latest.get(
                "result"
            )
        )


        if nested_result:

            for key in allowed_keys:

                if (
                    key
                    not in compact

                    and

                    key
                    in nested_result
                ):

                    compact[
                        key
                    ] = deepcopy(

                        nested_result.get(
                            key
                        )
                    )


        return {

            "available":
                True,

            "state":
                "AVAILABLE",

            "pid":
                pid,

            "result":
                compact,

            "interpretation":
                (
                    "Graph anomaly output is supporting "
                    "model evidence. It is not a calibrated "
                    "probability of maliciousness."
                ),
        }


    # ============================================================
    # RETRIEVED RELATIONSHIP FACTS
    # ============================================================

    def build_relationship_facts(
        self,
        *,
        attack_graph: Dict,
        process_subgraph: Dict,
    ) -> List[Dict]:

        facts = []


        # ========================================================
        # INCIDENT ATTACK GRAPH
        # ========================================================

        for edge in self.safe_list(
            attack_graph.get(
                "edges"
            )
        ):

            edge = self.safe_dict(
                edge
            )


            facts.append({

                "source":
                    edge.get(
                        "source"
                    ),

                "relationship":
                    (
                        edge.get(
                            "relationship"
                        )
                        or
                        edge.get(
                            "edge_type"
                        )
                        or
                        "RELATED_TO"
                    ),

                "target":
                    edge.get(
                        "target"
                    ),

                "source_graph":
                    "INCIDENT_ATTACK_GRAPH",

                "verified":
                    bool(
                        edge.get(
                            "verified",
                            False,
                        )
                    ),

                "confidence":
                    edge.get(
                        "confidence"
                    ),

                "provenance_status":
                    (
                        edge.get(
                            "provenance_status"
                        )
                        or
                        (
                            "VERIFIED"
                            if edge.get(
                                "verified"
                            )
                            else
                            "INFERRED_OR_UNVERIFIED"
                        )
                    ),

                "requires_validation":
                    bool(
                        edge.get(
                            "requires_validation",
                            not bool(
                                edge.get(
                                    "verified",
                                    False,
                                )
                            ),
                        )
                    ),
            })


            if (
                len(
                    facts
                )
                >=
                self.MAX_RELATIONSHIP_FACTS
            ):

                return facts


        # ========================================================
        # PERSISTENT PROVENANCE SUBGRAPH
        # ========================================================

        for edge in self.safe_list(
            process_subgraph.get(
                "edges"
            )
        ):

            edge = self.safe_dict(
                edge
            )


            facts.append({

                "source":
                    (
                        edge.get(
                            "source"
                        )
                        or
                        edge.get(
                            "source_node_id"
                        )
                    ),

                "relationship":
                    (
                        edge.get(
                            "edge_type"
                        )
                        or
                        edge.get(
                            "relationship"
                        )
                        or
                        "RELATED_TO"
                    ),

                "target":
                    (
                        edge.get(
                            "target"
                        )
                        or
                        edge.get(
                            "target_node_id"
                        )
                    ),

                "source_graph":
                    "PERSISTENT_PROVENANCE_GRAPH",

                # Persistent graph means the edge was stored,
                # but storage alone does not prove maliciousness.
                "verified":
                    bool(
                        edge.get(
                            "verified",
                            False,
                        )
                    ),

                "provenance_status":
                    (
                        edge.get(
                            "provenance_status"
                        )
                        or
                        "OBSERVED_OR_STORED_RELATIONSHIP"
                    ),

                "requires_validation":
                    bool(
                        edge.get(
                            "requires_validation",
                            False,
                        )
                    ),
            })


            if (
                len(
                    facts
                )
                >=
                self.MAX_RELATIONSHIP_FACTS
            ):

                break


        return facts


    # ============================================================
    # FINAL CONTEXT
    # ============================================================

    def build(
        self,
        *,
        threat: Dict,
        enriched_evidence: Optional[Dict] = None,
    ) -> Dict:

        if not isinstance(
            threat,
            dict,
        ):

            raise TypeError(
                "threat must be a dictionary."
            )


        process_identity = (
            self.extract_process_identity(

                threat=
                    threat,

                enriched_evidence=
                    enriched_evidence,
            )
        )


        attack_graph = (
            self.build_attack_graph_context(
                enriched_evidence
            )
        )


        process_subgraph = (
            self.build_process_subgraph_context(
                process_identity
            )
        )


        graph_ai = (
            self.build_graph_ai_context(
                process_identity
            )
        )


        relationship_facts = (
            self.build_relationship_facts(

                attack_graph=
                    attack_graph,

                process_subgraph=
                    process_subgraph,
            )
        )


        sources = []


        if attack_graph.get(
            "available"
        ):

            sources.append(
                "INCIDENT_ATTACK_GRAPH"
            )


        if process_subgraph.get(
            "available"
        ):

            sources.append(
                "PROCESS_PROVENANCE_SUBGRAPH"
            )


        if graph_ai.get(
            "available"
        ):

            sources.append(
                "GRAPH_AI_RESULT"
            )


        available = bool(
            sources
        )


        return {

            "schema_version":
                self.SCHEMA_VERSION,

            "service":
                self.name,

            "service_version":
                self.VERSION,

            "generated_at":
                self.now_iso(),

            "available":
                available,

            "state":
                (
                    "AVAILABLE"
                    if available
                    else
                    "NO_GRAPH_CONTEXT"
                ),

            "sources":
                sources,

            "security_identity": {

                "security_id":
                    threat.get(
                        "id"
                    ),

                "detection_id":
                    threat.get(
                        "detection_id"
                    ),

                "event_id":
                    threat.get(
                        "event_id"
                    ),

                "incident_id":
                    threat.get(
                        "incident_id"
                    ),

                "category":
                    threat.get(
                        "category"
                    ),

                "threat_type":
                    threat.get(
                        "threat_type"
                    ),
            },

            "process_identity":
                process_identity,

            "incident_attack_graph":
                attack_graph,

            "process_provenance_subgraph":
                process_subgraph,

            "graph_ai_evidence":
                graph_ai,

            "retrieved_relationships":
                relationship_facts,

            # ====================================================
            # CRITICAL REASONING POLICY
            # ====================================================

            "interpretation_policy": {

                "graph_is_supporting_context_not_proof":
                    True,

                "graph_anomaly_score_is_not_probability":
                    True,

                "stored_edge_is_not_proof_of_attack":
                    True,

                "unverified_relationship_is_not_attribution":
                    True,

                "inferred_relationship_requires_corroboration":
                    True,

                "empty_graph_is_not_benign_evidence":
                    True,

                "prefer_observed_graph_relationships":
                    True,
            },

            # ====================================================
            # HARD SAFETY
            # ====================================================

            "simulation_only":
                True,

            "execution_allowed":
                False,
        }


# ================================================================
# SHARED INSTANCE
# ================================================================

shared_security_graph_context_service = (
    SecurityGraphContextService()
)