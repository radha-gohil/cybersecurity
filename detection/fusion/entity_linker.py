from pathlib import Path


class EntityLinker:

    def __init__(
        self,
        minimum_confidence: int = 40,
    ):

        self.minimum_confidence = (
            minimum_confidence
        )


    # ============================================================
    # NORMALIZE TEXT
    # ============================================================

    def normalize(
        self,
        value,
    ) -> str:

        if value is None:
            return ""

        return str(
            value
        ).strip().lower()


    # ============================================================
    # BASENAME
    # ============================================================

    def get_basename(
        self,
        value,
    ) -> str:

        value = (
            self.normalize(
                value
            )
        )

        if not value:
            return ""

        try:

            return (
                Path(
                    value
                ).name.lower()
            )

        except Exception:

            return value


    # ============================================================
    # EXTRACT PROCESS NAME
    # ============================================================

    def get_process_name(
        self,
        event: dict,
    ) -> str:

        process = (
            event.get(
                "process"
            )
            or {}
        )

        network = (
            event.get(
                "network"
            )
            or {}
        )

        return (
            self.normalize(
                process.get(
                    "name"
                )
                or network.get(
                    "process_name"
                )
            )
        )


    # ============================================================
    # EXTRACT PROCESS PATH
    # ============================================================

    def get_process_path(
        self,
        event: dict,
    ) -> str:

        process = (
            event.get(
                "process"
            )
            or {}
        )

        return (
            self.normalize(
                process.get(
                    "exe"
                )
                or process.get(
                    "path"
                )
            )
        )


    # ============================================================
    # EXTRACT FILE PATH
    # ============================================================

    def get_file_path(
        self,
        event: dict,
    ) -> str:

        file_data = (
            event.get(
                "file"
            )
            or {}
        )

        return (
            self.normalize(
                file_data.get(
                    "path"
                )
            )
        )


    # ============================================================
    # EXTRACT FILE NAME
    # ============================================================

    def get_file_name(
        self,
        event: dict,
    ) -> str:

        file_data = (
            event.get(
                "file"
            )
            or {}
        )

        return (
            self.normalize(
                file_data.get(
                    "name"
                )
                or self.get_basename(
                    file_data.get(
                        "path"
                    )
                )
            )
        )


    # ============================================================
    # EXTRACT HASH
    # ============================================================

    def get_sha256(
        self,
        event: dict,
    ) -> str:

        file_data = (
            event.get(
                "file"
            )
            or {}
        )

        return (
            self.normalize(
                file_data.get(
                    "sha256"
                )
            )
        )


    # ============================================================
    # EXTRACT REGISTRY VALUE DATA
    # ============================================================

    def get_registry_value_data(
        self,
        event: dict,
    ) -> str:

        registry = (
            event.get(
                "registry"
            )
            or {}
        )

        return (
            self.normalize(
                registry.get(
                    "value_data"
                )
                or registry.get(
                    "data"
                )
                or registry.get(
                    "value"
                )
            )
        )


    # ============================================================
    # EXTRACT REGISTRY KEY
    # ============================================================

    def get_registry_key(
        self,
        event: dict,
    ) -> str:

        registry = (
            event.get(
                "registry"
            )
            or {}
        )

        return (
            self.normalize(
                registry.get(
                    "key"
                )
                or registry.get(
                    "registry_key"
                )
                or registry.get(
                    "path"
                )
            )
        )


    # ============================================================
    # SCORE EVENT PAIR
    # ============================================================

    def score_pair(
        self,
        event_a: dict,
        event_b: dict,
    ) -> dict:

        score = 0

        reasons = []


        # ========================================================
        # SHARED HASH
        # ========================================================

        hash_a = (
            self.get_sha256(
                event_a
            )
        )

        hash_b = (
            self.get_sha256(
                event_b
            )
        )


        if (
            hash_a
            and hash_b
            and hash_a == hash_b
        ):

            score += 100

            reasons.append(
                "Exact SHA256 match"
            )


        # ========================================================
        # PROCESS IMAGE PATH == FILE PATH
        # ========================================================

        process_path_a = (
            self.get_process_path(
                event_a
            )
        )

        process_path_b = (
            self.get_process_path(
                event_b
            )
        )

        file_path_a = (
            self.get_file_path(
                event_a
            )
        )

        file_path_b = (
            self.get_file_path(
                event_b
            )
        )


        if (
            process_path_a
            and file_path_b
            and process_path_a == file_path_b
        ):

            score += 90

            reasons.append(
                "Process executable path matches file path"
            )


        if (
            process_path_b
            and file_path_a
            and process_path_b == file_path_a
        ):

            score += 90

            reasons.append(
                "Process executable path matches file path"
            )


        # ========================================================
        # PROCESS NAME == FILE NAME
        # ========================================================

        process_name_a = (
            self.get_process_name(
                event_a
            )
        )

        process_name_b = (
            self.get_process_name(
                event_b
            )
        )

        file_name_a = (
            self.get_file_name(
                event_a
            )
        )

        file_name_b = (
            self.get_file_name(
                event_b
            )
        )


        if (
            process_name_a
            and file_name_b
            and process_name_a
            == file_name_b
        ):

            score += 30

            reasons.append(
                "Process name matches file name"
            )


        if (
            process_name_b
            and file_name_a
            and process_name_b
            == file_name_a
        ):

            score += 30

            reasons.append(
                "Process name matches file name"
            )


        # ========================================================
        # REGISTRY VALUE REFERENCES PROCESS
        # ========================================================

        registry_data_a = (
            self.get_registry_value_data(
                event_a
            )
        )

        registry_data_b = (
            self.get_registry_value_data(
                event_b
            )
        )


        if (
            registry_data_a
            and process_path_b
            and process_path_b
            in registry_data_a
        ):

            score += 80

            reasons.append(
                "Registry value references process executable"
            )


        if (
            registry_data_b
            and process_path_a
            and process_path_a
            in registry_data_b
        ):

            score += 80

            reasons.append(
                "Registry value references process executable"
            )


        # ========================================================
        # REGISTRY VALUE REFERENCES FILE
        # ========================================================

        if (
            registry_data_a
            and file_path_b
            and file_path_b
            in registry_data_a
        ):

            score += 80

            reasons.append(
                "Registry value references file path"
            )


        if (
            registry_data_b
            and file_path_a
            and file_path_a
            in registry_data_b
        ):

            score += 80

            reasons.append(
                "Registry value references file path"
            )


        # ========================================================
        # REGISTRY VALUE REFERENCES BASENAME
        # ========================================================

        if (
            registry_data_a
            and file_name_b
            and file_name_b
            in registry_data_a
        ):

            score += 40

            reasons.append(
                "Registry value references file name"
            )


        if (
            registry_data_b
            and file_name_a
            and file_name_a
            in registry_data_b
        ):

            score += 40

            reasons.append(
                "Registry value references file name"
            )


        # ========================================================
        # CAP SCORE
        # ========================================================

        score = min(
            score,
            100,
        )


        return {

            "linked":
                score
                >= self.minimum_confidence,

            "confidence":
                score,

            "reasons":
                reasons,
        }