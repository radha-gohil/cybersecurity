from detection.fusion.entity_linker import (
    EntityLinker,
)


def main():

    linker = EntityLinker(
        minimum_confidence=40,
    )


    print()
    print("=" * 70)
    print(
        "SENTINEL-X ENTITY LINKER TEST"
    )
    print("=" * 70)


    # ============================================================
    # PROCESS EVENT
    # ============================================================

    process_event = {

        "event_id":
            "proc-entity-001",

        "event_type":
            "process_start",

        "process": {

            "pid":
                5000,

            "name":
                "demo.exe",

            "exe":
                r"C:\Temp\demo.exe",
        },

        "file":
            {},

        "network":
            {},

        "registry":
            {},
    }


    # ============================================================
    # FILE EVENT
    # ============================================================

    file_event = {

        "event_id":
            "file-entity-001",

        "event_type":
            "file_modify",

        "process":
            {},

        "file": {

            "name":
                "demo.exe",

            "path":
                r"C:\Temp\demo.exe",

            "sha256":
                "ABC123",
        },

        "network":
            {},

        "registry":
            {},
    }


    # ============================================================
    # REGISTRY EVENT
    # ============================================================

    registry_event = {

        "event_id":
            "registry-entity-001",

        "event_type":
            "registry_change",

        "process":
            {},

        "file":
            {},

        "network":
            {},

        "registry": {

            "key":
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

            "value_name":
                "DemoApp",

            "value_data":
                r"C:\Temp\demo.exe",
        },
    }


    # ============================================================
    # PROCESS <-> FILE
    # ============================================================

    result = linker.score_pair(
        process_event,
        file_event,
    )


    print()
    print(
        "PROCESS <-> FILE"
    )

    print(
        "Linked:",
        result[
            "linked"
        ],
    )

    print(
        "Confidence:",
        result[
            "confidence"
        ],
    )

    print(
        "Reasons:",
        result[
            "reasons"
        ],
    )


    # ============================================================
    # FILE <-> REGISTRY
    # ============================================================

    result = linker.score_pair(
        file_event,
        registry_event,
    )


    print()
    print(
        "FILE <-> REGISTRY"
    )

    print(
        "Linked:",
        result[
            "linked"
        ],
    )

    print(
        "Confidence:",
        result[
            "confidence"
        ],
    )

    print(
        "Reasons:",
        result[
            "reasons"
        ],
    )


    # ============================================================
    # PROCESS <-> REGISTRY
    # ============================================================

    result = linker.score_pair(
        process_event,
        registry_event,
    )


    print()
    print(
        "PROCESS <-> REGISTRY"
    )

    print(
        "Linked:",
        result[
            "linked"
        ],
    )

    print(
        "Confidence:",
        result[
            "confidence"
        ],
    )

    print(
        "Reasons:",
        result[
            "reasons"
        ],
    )


    print()
    print("=" * 70)


if __name__ == "__main__":

    main()