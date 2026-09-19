from datetime import datetime, timezone
from pathlib import Path
import uuid


class QuarantineManager:

    def __init__(
        self,
        quarantine_root=None,
        simulation_mode=True,
    ):

        self.name = "QuarantineManager"

        project_root = (
            Path(__file__)
            .resolve()
            .parent
            .parent
        )

        if quarantine_root is None:

            quarantine_root = (
                project_root
                / "data"
                / "quarantine"
            )

        self.quarantine_root = Path(
            quarantine_root
        )

        self.quarantine_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.simulation_mode = bool(
            simulation_mode
        )


    # ============================================================
    # CURRENT TIME
    # ============================================================

    def now_iso(self):

        return datetime.now(
            timezone.utc
        ).isoformat()


    # ============================================================
    # SAFE STRING
    # ============================================================

    def safe_string(
        self,
        value,
    ) -> str:

        if value is None:

            return ""

        return str(
            value
        ).strip()


    # ============================================================
    # GENERATE QUARANTINE ID
    # ============================================================

    def generate_quarantine_id(
        self,
    ) -> str:

        return (
            "QTN-"
            + uuid.uuid4().hex[
                :12
            ].upper()
        )


    # ============================================================
    # VALIDATE FILE TARGET
    # ============================================================

    def validate_file_target(
        self,
        file_target: dict,
    ) -> dict:

        if not isinstance(
            file_target,
            dict,
        ):

            return {

                "valid":
                    False,

                "issues": [
                    "Target must be a dictionary."
                ],
            }


        path_value = (
            self.safe_string(
                file_target.get(
                    "path"
                )
            )
        )


        sha256 = (
            self.safe_string(
                file_target.get(
                    "sha256"
                )
            )
        )


        issues = []


        if not path_value:

            issues.append(
                "Missing file path."
            )


        if not sha256:

            issues.append(
                "Missing SHA256."
            )


        return {

            "valid":
                len(
                    issues
                )
                == 0,

            "issues":
                issues,

            "path":
                path_value,

            "sha256":
                sha256,
        }


    # ============================================================
    # BUILD QUARANTINE RECORD
    # ============================================================

    def build_quarantine_record(
        self,
        incident_id: str,
        action_id: str,
        file_target: dict,
        reason: str,
    ) -> dict:

        validation = (
            self.validate_file_target(
                file_target
            )
        )


        if not validation[
            "valid"
        ]:

            return {

                "success":
                    False,

                "status":
                    "INVALID_TARGET",

                "issues":
                    validation[
                        "issues"
                    ],
            }


        quarantine_id = (
            self.generate_quarantine_id()
        )


        original_path = (
            validation[
                "path"
            ]
        )


        filename = (
            Path(
                original_path
            ).name
        )


        simulated_destination = (

            self.quarantine_root

            / (
                quarantine_id
                + "_"
                + filename
            )
        )


        return {

            "success":
                True,

            "status":
                "SIMULATED",

            "quarantine_id":
                quarantine_id,

            "incident_id":
                incident_id,

            "action_id":
                action_id,

            "original_path":
                original_path,

            "sha256":
                validation[
                    "sha256"
                ],

            "reason":
                reason,

            "simulated_destination":
                str(
                    simulated_destination
                ),

            "created_at":
                self.now_iso(),

            "simulation_mode":
                self.simulation_mode,

            "file_moved":
                False,

            "file_deleted":
                False,

            "file_modified":
                False,
        }


    # ============================================================
    # SIMULATE QUARANTINE
    # ============================================================

    def simulate_quarantine(
        self,
        incident_id: str,
        action_id: str,
        file_target: dict,
        reason: str,
    ) -> dict:

        result = (
            self.build_quarantine_record(

                incident_id=
                    incident_id,

                action_id=
                    action_id,

                file_target=
                    file_target,

                reason=
                    reason,
            )
        )


        if not result.get(
            "success",
            False,
        ):

            return result


        result[
            "message"
        ] = (
            "Quarantine was simulated only. "
            "No file was moved, deleted, renamed, "
            "encrypted, or modified."
        )


        return result


    # ============================================================
    # PROCESS MULTIPLE FILE TARGETS
    # ============================================================

    def process_targets(
        self,
        incident_id: str,
        action_id: str,
        files: list,
        reason: str,
    ) -> dict:

        if not isinstance(
            files,
            list,
        ):

            files = []


        results = []


        for file_target in files:

            result = (
                self.simulate_quarantine(

                    incident_id=
                        incident_id,

                    action_id=
                        action_id,

                    file_target=
                        file_target,

                    reason=
                        reason,
                )
            )

            results.append(
                result
            )


        successful = sum(

            1

            for item in results

            if item.get(
                "success",
                False,
            )
        )


        failed = (
            len(
                results
            )
            - successful
        )


        return {

            "manager":
                self.name,

            "incident_id":
                incident_id,

            "action_id":
                action_id,

            "simulation_mode":
                self.simulation_mode,

            "target_count":
                len(
                    files
                ),

            "successful_simulations":
                successful,

            "failed_simulations":
                failed,

            "results":
                results,

            "real_quarantine_performed":
                False,
        }