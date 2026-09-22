import sys
import sqlite3
import tempfile

from pathlib import Path


# ================================================================
# PROJECT ROOT
# ================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


# ================================================================
# IMPORTS
# ================================================================

from response.soc_case_store import (
    SOCCaseStore,
)

from response.persistent_soc_workflow import (
    PersistentSOCWorkflow,
)

from response.mitigation_verifier import (
    MitigationVerifier,
)


# ================================================================
# TEST ACTION STORE
# ================================================================

class InMemoryActionStore:

    def __init__(
        self,
    ):

        self.actions = {}

    def save_action(
        self,
        action,
    ):

        action = dict(
            action
        )

        action_id = (
            action.get(
                "action_id"
            )
            or (
                "test-action-"
                + str(
                    len(
                        self.actions
                    )
                    + 1
                )
            )
        )

        self.actions[
            action_id
        ] = action

        return action_id

    def get_by_incident(
        self,
        incident_id,
    ):

        return [

            dict(
                action
            )

            for action
            in self.actions.values()

            if (
                action.get(
                    "incident_id"
                )
                ==
                incident_id
            )
        ]


# ================================================================
# TEST EVIDENCE STORE
# ================================================================

class InMemoryEvidenceStore:

    def __init__(
        self,
    ):

        self.evidence = {}

        self.timelines = {}

    def save_evidence_bundle(
        self,
        incident_id,
        evidence,
        replace_existing=True,
    ):

        self.evidence[
            incident_id
        ] = dict(
            evidence
            or {}
        )

        return {
            "success": True,
        }

    def save_timeline(
        self,
        incident_id,
        timeline,
        replace_existing=True,
    ):

        self.timelines[
            incident_id
        ] = list(
            timeline
            or []
        )

        return {
            "success": True,
        }

    def get_evidence_bundle(
        self,
        incident_id,
    ):

        return dict(
            self.evidence.get(
                incident_id,
                {},
            )
        )

    def get_timeline(
        self,
        incident_id,
    ):

        return list(
            self.timelines.get(
                incident_id,
                [],
            )
        )


# ================================================================
# DISPLAY
# ================================================================

def separator():

    print(
        "\n"
        + "=" * 72
    )


# ================================================================
# MAIN
# ================================================================

def main():

    separator()

    print(
        "SENTINEL-X REAL SOC CASE STORE "
        "MITIGATION PERSISTENCE TEST"
    )

    separator()

    print(
        "\nUses real SQLite persistence."
    )

    print(
        "Uses a temporary test database."
    )

    print(
        "Production SENTINEL-X database is not modified."
    )

    print(
        "No endpoint response action is executed."
    )

    # ============================================================
    # TEMPORARY DIRECTORY
    # ============================================================

    with tempfile.TemporaryDirectory() as temp_dir:

        temp_dir = Path(
            temp_dir
        )

        database_path = (
            temp_dir
            / "sentinel_soc_test.db"
        )

        print(
            "\nTemporary database:",
            database_path,
        )

        # ========================================================
        # TEST 1
        # CREATE REAL SQLITE STORE
        # ========================================================

        separator()

        print(
            "TEST 1 - CREATE REAL SQLITE SOC CASE STORE"
        )

        case_store = (
            SOCCaseStore(
                database_path=
                    database_path
            )
        )

        if not database_path.exists():

            raise AssertionError(
                "SQLite test database was not created."
            )

        print(
            "SQLite database creation: PASS"
        )

        # ========================================================
        # VERIFY NEW COLUMN
        #
        # IMPORTANT:
        # Explicitly close connection for Windows cleanup.
        # ========================================================

        schema_conn = sqlite3.connect(
            database_path
        )

        try:

            columns = {

                row[
                    1
                ]

                for row in schema_conn.execute(
                    """
                    PRAGMA table_info(soc_cases)
                    """
                ).fetchall()
            }

        finally:

            schema_conn.close()

        print(
            "mitigation_verification_json column:",
            (
                "PRESENT"
                if
                "mitigation_verification_json"
                in columns
                else
                "MISSING"
            ),
        )

        if (
            "mitigation_verification_json"
            not in columns
        ):

            raise AssertionError(
                "Mitigation verification database "
                "column was not created."
            )

        print(
            "Database schema: PASS"
        )

        # ========================================================
        # TEST STORES
        # ========================================================

        action_store = (
            InMemoryActionStore()
        )

        evidence_store = (
            InMemoryEvidenceStore()
        )

        verifier = (
            MitigationVerifier(

                verified_threshold=
                    0.70,

                partial_threshold=
                    0.30,

                acceptable_residual_risk=
                    30.0,
            )
        )

        # ========================================================
        # WORKFLOW
        # ========================================================

        workflow = (
            PersistentSOCWorkflow(

                simulation_mode=
                    True,

                case_store=
                    case_store,

                action_store=
                    action_store,

                evidence_store=
                    evidence_store,

                mitigation_verifier=
                    verifier,
            )
        )

        # ========================================================
        # SYNTHETIC CASE
        # ========================================================

        incident_id = (
            "sqlite-mitigation-test-001"
        )

        case_store.save_case(
            {

                "incident_id":
                    incident_id,

                "status":
                    "AWAITING_ANALYST_REVIEW",

                "decision":
                    {

                        "initial_risk_score":
                            85,

                        "initial_risk_level":
                            "HIGH",

                        "best_plan":
                            {

                                "plan_name":
                                    "synthetic-plan",

                                "predicted_residual_risk":
                                    20,
                            },
                    },

                "explanation":
                    {

                        "summary":
                            (
                                "Synthetic SQLite "
                                "persistence test."
                            ),
                    },

                "ticket_data":
                    {

                        "ticket_id":
                            "ticket-sqlite-001",

                        "risk_score":
                            85,

                        "risk_level":
                            "HIGH",
                    },

                "mitigation_verification":
                    {},
            }
        )

        print(
            "Initial SOC case storage: PASS"
        )

        # ========================================================
        # TEST 2
        # VERIFY SIMULATED MITIGATION
        # ========================================================

        separator()

        print(
            "TEST 2 - VERIFY AND STORE MITIGATION RESULT"
        )

        before_state = {

            "risk_score":
                85,

            "suspicious_event_count":
                12,

            "active_indicator_count":
                8,

            "exposure_score":
                90,
        }

        simulated_after_state = {

            "risk_score":
                20,

            "suspicious_event_count":
                2,

            "active_indicator_count":
                1,

            "exposure_score":
                20,
        }

        response_result = {

            "simulation_mode":
                True,

            "plan_id":
                "synthetic-plan",

            "action":
                "SIMULATED_CONTAINMENT",
        }

        result = (
            workflow.verify_simulated_mitigation(

                incident_id=
                    incident_id,

                before_state=
                    before_state,

                simulated_after_state=
                    simulated_after_state,

                response_result=
                    response_result,
            )
        )

        print(
            "Status:",
            result.get(
                "status"
            ),
        )

        print(
            "Persisted:",
            result.get(
                "persisted"
            ),
        )

        print(
            "Real Response Executed:",
            result.get(
                "real_response_executed"
            ),
        )

        if (
            result.get(
                "status"
            )
            !=
            "SIMULATION_VERIFIED"
        ):

            raise AssertionError(
                "Expected SIMULATION_VERIFIED."
            )

        if (
            result.get(
                "real_response_executed"
            )
            is not False
        ):

            raise AssertionError(
                "Real response execution must remain disabled."
            )

        print(
            "Mitigation verification storage: PASS"
        )

        # ========================================================
        # TEST 3
        # READ DIRECTLY FROM REAL SOCCaseStore
        # ========================================================

        separator()

        print(
            "TEST 3 - READ VERIFICATION FROM SQLITE"
        )

        stored_case = (
            case_store.get_case(
                incident_id
            )
        )

        if stored_case is None:

            raise AssertionError(
                "Stored SOC case could not be read."
            )

        stored_verification = (
            stored_case.get(
                "mitigation_verification",
                {},
            )
        )

        print(
            "Stored Verification Type:",
            stored_verification.get(
                "verification_type"
            ),
        )

        print(
            "Stored Status:",
            stored_verification.get(
                "status"
            ),
        )

        print(
            "Stored Improvement:",
            stored_verification.get(
                "overall_improvement"
            ),
        )

        print(
            "Stored Residual Risk:",
            stored_verification.get(
                "residual_risk"
            ),
        )

        if (
            stored_verification.get(
                "status"
            )
            !=
            "SIMULATION_VERIFIED"
        ):

            raise AssertionError(
                "SOCCaseStore did not restore "
                "mitigation verification."
            )

        if (
            stored_verification.get(
                "verification_type"
            )
            !=
            "SIMULATED_MITIGATION_VERIFICATION"
        ):

            raise AssertionError(
                "Unexpected mitigation verification type."
            )

        print(
            "SQLite JSON recovery: PASS"
        )

        # ========================================================
        # TEST 4
        # SIMULATE APPLICATION RESTART
        # ========================================================

        separator()

        print(
            "TEST 4 - SIMULATED APPLICATION RESTART"
        )

        # --------------------------------------------------------
        # Create a completely new store object pointing to
        # the same SQLite database.
        # --------------------------------------------------------

        restarted_case_store = (
            SOCCaseStore(
                database_path=
                    database_path
            )
        )

        restarted_workflow = (
            PersistentSOCWorkflow(

                simulation_mode=
                    True,

                case_store=
                    restarted_case_store,

                action_store=
                    InMemoryActionStore(),

                evidence_store=
                    InMemoryEvidenceStore(),

                mitigation_verifier=
                    MitigationVerifier(),
            )
        )

        recovered_case = (
            restarted_workflow.recover_case(
                incident_id
            )
        )

        if recovered_case is None:

            raise AssertionError(
                "Case was not recovered after restart."
            )

        recovered_verification = (
            recovered_case.get(
                "mitigation_verification",
                {},
            )
        )

        print(
            "Recovered Status:",
            recovered_verification.get(
                "status"
            ),
        )

        print(
            "Recovered Verification Type:",
            recovered_verification.get(
                "verification_type"
            ),
        )

        print(
            "Recovered Simulation Mode:",
            recovered_case.get(
                "simulation_mode"
            ),
        )

        print(
            "Recovered Real Response Executed:",
            recovered_case.get(
                "real_response_executed"
            ),
        )

        if (
            recovered_verification.get(
                "status"
            )
            !=
            "SIMULATION_VERIFIED"
        ):

            raise AssertionError(
                "Verification did not survive "
                "workflow restart."
            )

        if (
            recovered_verification.get(
                "verification_type"
            )
            !=
            "SIMULATED_MITIGATION_VERIFICATION"
        ):

            raise AssertionError(
                "Verification type did not survive restart."
            )

        if (
            recovered_case.get(
                "simulation_mode"
            )
            is not True
        ):

            raise AssertionError(
                "Recovered case is not in simulation mode."
            )

        if (
            recovered_case.get(
                "real_response_executed"
            )
            is not False
        ):

            raise AssertionError(
                "Real response flag changed unexpectedly."
            )

        print(
            "Restart persistence: PASS"
        )

        # ========================================================
        # TEST 5
        # GETTER AFTER RESTART
        # ========================================================

        separator()

        print(
            "TEST 5 - VERIFICATION GETTER AFTER RESTART"
        )

        getter_result = (
            restarted_workflow
            .get_mitigation_verification(
                incident_id
            )
        )

        print(
            "Getter Status:",
            getter_result.get(
                "status"
            ),
        )

        if (
            getter_result.get(
                "status"
            )
            !=
            "SIMULATION_VERIFIED"
        ):

            raise AssertionError(
                "Verification getter failed "
                "after restart."
            )

        print(
            "Persistent getter: PASS"
        )

        # ========================================================
        # TEST 6
        # LEGACY DATABASE MIGRATION
        # ========================================================

        separator()

        print(
            "TEST 6 - LEGACY DATABASE SCHEMA MIGRATION"
        )

        legacy_database = (
            temp_dir
            / "legacy_soc.db"
        )

        # --------------------------------------------------------
        # CREATE OLD DATABASE SCHEMA
        #
        # Explicit connection + close is important on Windows.
        # --------------------------------------------------------

        legacy_conn = sqlite3.connect(
            legacy_database
        )

        try:

            legacy_conn.execute(
                """
                CREATE TABLE soc_cases (

                    incident_id TEXT PRIMARY KEY,

                    ticket_id TEXT,

                    case_status TEXT NOT NULL,

                    risk_score INTEGER,

                    risk_level TEXT,

                    selected_plan TEXT,

                    predicted_residual_risk INTEGER,

                    decision_json TEXT,

                    explanation_json TEXT,

                    ticket_json TEXT,

                    created_at TEXT NOT NULL,

                    updated_at TEXT NOT NULL
                )
                """
            )

            legacy_conn.commit()

        finally:

            legacy_conn.close()

        # --------------------------------------------------------
        # INITIALIZE CURRENT STORE
        #
        # initialize() should add:
        #
        # mitigation_verification_json
        # --------------------------------------------------------

        legacy_store = (
            SOCCaseStore(
                database_path=
                    legacy_database
            )
        )

        # --------------------------------------------------------
        # CHECK MIGRATED SCHEMA
        #
        # Again explicitly close the connection.
        # --------------------------------------------------------

        legacy_check_conn = (
            legacy_store.get_connection()
        )

        try:

            legacy_columns = {

                row[
                    "name"
                ]

                for row in legacy_check_conn.execute(
                    """
                    PRAGMA table_info(soc_cases)
                    """
                ).fetchall()
            }

        finally:

            legacy_check_conn.close()

        print(
            "Legacy mitigation column:",
            (
                "PRESENT"
                if
                "mitigation_verification_json"
                in legacy_columns
                else
                "MISSING"
            ),
        )

        if (
            "mitigation_verification_json"
            not in legacy_columns
        ):

            raise AssertionError(
                "Legacy database migration failed."
            )

        print(
            "Legacy schema migration: PASS"
        )

        # ========================================================
        # TEST 7
        # VERIFY OLD CASES DEFAULT CLEANLY
        # ========================================================

        separator()

        print(
            "TEST 7 - LEGACY VERIFICATION DEFAULT"
        )

        legacy_case_id = (
            "legacy-case-001"
        )

        # --------------------------------------------------------
        # Insert a row in the migrated database without supplying
        # mitigation verification.
        # --------------------------------------------------------

        legacy_insert_conn = (
            legacy_store.get_connection()
        )

        try:

            now = (
                legacy_store.now_iso()
            )

            legacy_insert_conn.execute(
                """
                INSERT INTO soc_cases (

                    incident_id,

                    ticket_id,

                    case_status,

                    risk_score,

                    risk_level,

                    selected_plan,

                    predicted_residual_risk,

                    decision_json,

                    explanation_json,

                    ticket_json,

                    created_at,

                    updated_at

                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,

                (
                    legacy_case_id,

                    "legacy-ticket",

                    "OPEN",

                    40,

                    "MEDIUM",

                    None,

                    None,

                    "{}",

                    "{}",

                    "{}",

                    now,

                    now,
                ),
            )

            legacy_insert_conn.commit()

        finally:

            legacy_insert_conn.close()

        legacy_case = (
            legacy_store.get_case(
                legacy_case_id
            )
        )

        if legacy_case is None:

            raise AssertionError(
                "Legacy case could not be restored."
            )

        legacy_verification = (
            legacy_case.get(
                "mitigation_verification",
                {},
            )
        )

        print(
            "Legacy Verification:",
            legacy_verification,
        )

        if legacy_verification != {}:

            raise AssertionError(
                "Legacy case should default to an "
                "empty mitigation verification object."
            )

        print(
            "Legacy default recovery: PASS"
        )

        # ========================================================
        # FINAL VALIDATION
        # ========================================================

        separator()

        print(
            "VALIDATION"
        )

        print(
            "Real SOCCaseStore implementation: PASS"
        )

        print(
            "SQLite mitigation column: PASS"
        )

        print(
            "Mitigation JSON persistence: PASS"
        )

        print(
            "Mitigation JSON recovery: PASS"
        )

        print(
            "Application restart recovery: PASS"
        )

        print(
            "Persistent verification getter: PASS"
        )

        print(
            "Legacy database migration: PASS"
        )

        print(
            "Legacy case compatibility: PASS"
        )

        print(
            "SQLite connections closed cleanly: PASS"
        )

        print(
            "Production database modified: NO"
        )

        print(
            "Real endpoint action performed: NO"
        )

        separator()

        print(
            "REAL SOC CASE STORE MITIGATION "
            "PERSISTENCE TEST COMPLETED SUCCESSFULLY"
        )

        separator()


# ================================================================
# RUN
# ================================================================

if __name__ == "__main__":

    main()