import json
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(
    r"C:\Users\T10002\Downloads\cyber"
)

DATABASE_PATH = (
    PROJECT_ROOT
    / "data"
    / "database"
    / "sentinel_endpoint.db"
)


# ============================================================
# SAFE JSON PARSER
# ============================================================

def parse_json(
    value,
):

    if value is None:
        return {}

    if isinstance(
        value,
        dict,
    ):
        return value

    try:

        return json.loads(
            value
        )

    except (
        json.JSONDecodeError,
        TypeError,
    ):

        return {}


# ============================================================
# PRINT FIELDS
# ============================================================

def print_fields(
    title,
    data,
):

    print()
    print(
        f"{title}:"
    )

    if not data:

        print(
            "  <empty>"
        )

        return

    for key, value in data.items():

        print(
            f"  {key}: {value}"
        )


# ============================================================
# EXTRACT PID FROM EVENT
# ============================================================

def extract_pid_from_event(
    event,
):

    process_data = parse_json(
        event.get(
            "process_data"
        )
        or event.get(
            "process"
        )
    )

    network_data = parse_json(
        event.get(
            "network_data"
        )
        or event.get(
            "network"
        )
    )

    registry_data = parse_json(
        event.get(
            "registry_data"
        )
        or event.get(
            "registry"
        )
    )

    metadata = parse_json(
        event.get(
            "metadata"
        )
    )


    # --------------------------------------------------------
    # PROCESS PID
    # --------------------------------------------------------

    pid = (
        process_data.get(
            "pid"
        )
    )

    if pid is not None:

        return pid


    # --------------------------------------------------------
    # NETWORK PID
    # --------------------------------------------------------

    pid = (
        network_data.get(
            "pid"
        )
    )

    if pid is not None:

        return pid


    # --------------------------------------------------------
    # REGISTRY PID
    # --------------------------------------------------------

    pid = (
        registry_data.get(
            "pid"
        )
    )

    if pid is not None:

        return pid


    # --------------------------------------------------------
    # METADATA PID
    # --------------------------------------------------------

    pid = (
        metadata.get(
            "pid"
        )
    )

    if pid is not None:

        return pid


    return None


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X REAL EVENT IDENTIFIER VALIDATION"
    )
    print("=" * 80)


    print()
    print(
        "Database:",
        DATABASE_PATH,
    )


    if not DATABASE_PATH.exists():

        print()
        print(
            "ERROR: Database does not exist."
        )

        return


    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = (
        sqlite3.Row
    )


    try:

        cursor = (
            connection.cursor()
        )


        # ========================================================
        # TABLE COLUMNS
        # ========================================================

        cursor.execute(
            """
            PRAGMA table_info(events)
            """
        )


        table_columns = [
            row["name"]
            for row in cursor.fetchall()
        ]


        print()
        print(
            "Events table columns:"
        )

        print(
            table_columns
        )


        # ========================================================
        # LOAD RECENT EVENTS
        # ========================================================

        cursor.execute(
            """
            SELECT *
            FROM events
            ORDER BY rowid DESC
            LIMIT 100
            """
        )


        rows = (
            cursor.fetchall()
        )


        print()
        print(
            "Events inspected:",
            len(
                rows
            ),
        )


        # ========================================================
        # FIND ONE EXAMPLE PER CATEGORY
        # ========================================================

        examples = {}


        for row in rows:

            row_data = dict(
                row
            )


            event_type = str(
                row_data.get(
                    "event_type",
                    ""
                )
            ).lower()


            if (
                event_type.startswith(
                    "process"
                )
                and "PROCESS"
                not in examples
            ):

                examples[
                    "PROCESS"
                ] = row_data


            elif (
                event_type.startswith(
                    "file"
                )
                and "FILE"
                not in examples
            ):

                examples[
                    "FILE"
                ] = row_data


            elif (
                event_type.startswith(
                    "network"
                )
                and "NETWORK"
                not in examples
            ):

                examples[
                    "NETWORK"
                ] = row_data


            elif (
                (
                    event_type.startswith(
                        "registry"
                    )
                    or event_type.startswith(
                        "startup"
                    )
                )
                and "REGISTRY"
                not in examples
            ):

                examples[
                    "REGISTRY"
                ] = row_data


        # ========================================================
        # PRINT EVENTS
        # ========================================================

        categories = [
            "PROCESS",
            "FILE",
            "NETWORK",
            "REGISTRY",
        ]


        for category in categories:

            print()
            print("=" * 80)

            print(
                f"{category} EVENT"
            )

            print("=" * 80)


            event = (
                examples.get(
                    category
                )
            )


            if not event:

                print(
                    "No recent event found."
                )

                continue


            process_data = parse_json(
                event.get(
                    "process_data"
                )
                or event.get(
                    "process"
                )
            )


            file_data = parse_json(
                event.get(
                    "file_data"
                )
                or event.get(
                    "file"
                )
            )


            network_data = parse_json(
                event.get(
                    "network_data"
                )
                or event.get(
                    "network"
                )
            )


            registry_data = parse_json(
                event.get(
                    "registry_data"
                )
                or event.get(
                    "registry"
                )
            )


            metadata = parse_json(
                event.get(
                    "metadata"
                )
            )


            print(
                "Event ID:",
                event.get(
                    "event_id"
                ),
            )

            print(
                "Event Type:",
                event.get(
                    "event_type"
                ),
            )

            print(
                "Source:",
                event.get(
                    "source"
                ),
            )

            print(
                "Severity:",
                event.get(
                    "severity"
                ),
            )


            print_fields(
                "Process Data",
                process_data,
            )

            print_fields(
                "File Data",
                file_data,
            )

            print_fields(
                "Network Data",
                network_data,
            )

            print_fields(
                "Registry Data",
                registry_data,
            )

            print_fields(
                "Metadata",
                metadata,
            )


            # ====================================================
            # IDENTIFIER SUMMARY
            # ====================================================

            pid = (
                extract_pid_from_event(
                    event
                )
            )


            file_path = (
                file_data.get(
                    "path"
                )
            )


            sha256 = (
                file_data.get(
                    "sha256"
                )
            )


            remote_ip = (
                network_data.get(
                    "remote_ip"
                )
                or network_data.get(
                    "raddr_ip"
                )
            )


            remote_port = (
                network_data.get(
                    "remote_port"
                )
                or network_data.get(
                    "raddr_port"
                )
            )


            registry_key = (
                registry_data.get(
                    "key"
                )
                or registry_data.get(
                    "registry_key"
                )
                or registry_data.get(
                    "path"
                )
            )


            print()
            print(
                "IDENTIFIER SUMMARY"
            )

            print(
                "  PID:",
                pid,
            )

            print(
                "  File Path:",
                file_path,
            )

            print(
                "  SHA256:",
                sha256,
            )

            print(
                "  Remote IP:",
                remote_ip,
            )

            print(
                "  Remote Port:",
                remote_port,
            )

            print(
                "  Registry Key:",
                registry_key,
            )


        # ========================================================
        # CORRELATION READINESS
        # ========================================================

        print()
        print("=" * 80)
        print(
            "CORRELATION READINESS"
        )
        print("=" * 80)


        process_event = (
            examples.get(
                "PROCESS"
            )
            or {}
        )

        file_event = (
            examples.get(
                "FILE"
            )
            or {}
        )

        network_event = (
            examples.get(
                "NETWORK"
            )
            or {}
        )

        registry_event = (
            examples.get(
                "REGISTRY"
            )
            or {}
        )


        process_pid = (
            extract_pid_from_event(
                process_event
            )
            if process_event
            else None
        )


        file_pid = (
            extract_pid_from_event(
                file_event
            )
            if file_event
            else None
        )


        network_pid = (
            extract_pid_from_event(
                network_event
            )
            if network_event
            else None
        )


        registry_pid = (
            extract_pid_from_event(
                registry_event
            )
            if registry_event
            else None
        )


        process_has_pid = (
            process_pid
            is not None
        )

        file_has_pid = (
            file_pid
            is not None
        )

        network_has_pid = (
            network_pid
            is not None
        )

        registry_has_pid = (
            registry_pid
            is not None
        )


        print()

        print(
            "Process events contain PID :",
            process_has_pid,
        )

        print(
            "File events contain PID    :",
            file_has_pid,
        )

        print(
            "Network events contain PID :",
            network_has_pid,
        )

        print(
            "Registry events contain PID:",
            registry_has_pid,
        )


        print()

        print(
            "Example PIDs:"
        )

        print(
            "  Process PID :",
            process_pid,
        )

        print(
            "  File PID    :",
            file_pid,
        )

        print(
            "  Network PID :",
            network_pid,
        )

        print(
            "  Registry PID:",
            registry_pid,
        )


        print()
        print(
            "Recommended correlation:"
        )


        if (
            process_has_pid
            and network_has_pid
        ):

            print(
                "  PROCESS <-> NETWORK : READY using PID"
            )

        else:

            print(
                "  PROCESS <-> NETWORK : PID LINK MISSING"
            )


        if (
            process_has_pid
            and file_has_pid
        ):

            print(
                "  PROCESS <-> FILE    : READY using PID"
            )

        else:

            print(
                "  PROCESS <-> FILE    : PID LINK MISSING"
            )


        if (
            process_has_pid
            and registry_has_pid
        ):

            print(
                "  PROCESS <-> REGISTRY: READY using PID"
            )

        else:

            print(
                "  PROCESS <-> REGISTRY: PID LINK MISSING"
            )


        print()

        print(
            "Other usable identifiers:"
        )


        if file_event:

            file_data = parse_json(
                file_event.get(
                    "file_data"
                )
            )

            if file_data.get(
                "sha256"
            ):

                print(
                    "  FILE SHA256         : AVAILABLE"
                )

            if file_data.get(
                "path"
            ):

                print(
                    "  FILE PATH           : AVAILABLE"
                )


        if network_event:

            network_data = parse_json(
                network_event.get(
                    "network_data"
                )
            )

            if network_data.get(
                "remote_ip"
            ):

                print(
                    "  NETWORK REMOTE IP   : AVAILABLE"
                )

            if network_data.get(
                "process_name"
            ):

                print(
                    "  NETWORK PROCESS NAME: AVAILABLE"
                )


        if not registry_event:

            print(
                "  REGISTRY DATA        : NO RECENT SAMPLE"
            )


        print()
        print("=" * 80)
        print(
            "IDENTIFIER VALIDATION COMPLETE"
        )
        print("=" * 80)


    finally:

        connection.close()


if __name__ == "__main__":

    main()