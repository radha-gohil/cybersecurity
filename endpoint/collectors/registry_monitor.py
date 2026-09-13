import time
import winreg
from typing import Dict

from endpoint.agent.telemetry_manager import TelemetryManager
from endpoint.utils.logger import get_logger


logger = get_logger(__name__)


class RegistryMonitor:

    def __init__(
        self,
        polling_interval: float = 5.0,
    ):

        self.polling_interval = polling_interval

        self.running = False

        self.known_values: Dict[str, Dict] = {}

        self.telemetry = TelemetryManager()

        # --------------------------------------------------------
        # READ-ONLY STARTUP REGISTRY LOCATIONS
        # --------------------------------------------------------

        self.registry_locations = [

            {
                "root": winreg.HKEY_CURRENT_USER,

                "root_name":
                    "HKEY_CURRENT_USER",

                "path": (
                    r"Software\Microsoft\Windows"
                    r"\CurrentVersion\Run"
                ),
            },

            {
                "root": winreg.HKEY_CURRENT_USER,

                "root_name":
                    "HKEY_CURRENT_USER",

                "path": (
                    r"Software\Microsoft\Windows"
                    r"\CurrentVersion\RunOnce"
                ),
            },
        ]


    # ============================================================
    # READ REGISTRY KEY
    # ============================================================

    def read_registry_key(
        self,
        root,
        root_name,
        path,
    ) -> dict:

        values = {}

        try:

            with winreg.OpenKey(
                root,
                path,
                0,
                winreg.KEY_READ,
            ) as key:

                index = 0

                while True:

                    try:

                        (
                            name,
                            value,
                            value_type,
                        ) = winreg.EnumValue(
                            key,
                            index,
                        )

                        full_name = (
                            f"{root_name}\\"
                            f"{path}\\"
                            f"{name}"
                        )

                        values[
                            full_name
                        ] = {

                            "name":
                                name,

                            "value":
                                str(value),

                            "type":
                                value_type,

                            "registry_path":
                                (
                                    f"{root_name}"
                                    f"\\{path}"
                                ),
                        }

                        index += 1

                    except OSError:

                        break

        except (
            FileNotFoundError,
            PermissionError,
            OSError,
        ) as error:

            logger.debug(
                "Could not read registry path %s\\%s: %s",
                root_name,
                path,
                error,
            )

        return values


    # ============================================================
    # GET CURRENT SNAPSHOT
    # ============================================================

    def get_current_snapshot(
        self,
    ) -> dict:

        snapshot = {}

        for location in (
            self.registry_locations
        ):

            values = (
                self.read_registry_key(
                    location["root"],
                    location[
                        "root_name"
                    ],
                    location["path"],
                )
            )

            snapshot.update(
                values
            )

        return snapshot


    # ============================================================
    # INITIAL SNAPSHOT
    # ============================================================

    def build_initial_snapshot(
        self,
    ):

        logger.info(
            "Building initial registry snapshot..."
        )

        self.known_values = (
            self.get_current_snapshot()
        )

        logger.info(
            "Initial registry snapshot complete. %s startup values found.",
            len(
                self.known_values
            ),
        )


    # ============================================================
    # EMIT REGISTRY EVENT
    # ============================================================

    def emit_registry_event(
        self,
        event_type: str,
        registry_data: dict,
        metadata: dict = None,
    ):

        if metadata is None:

            metadata = {
                "collector":
                    "RegistryMonitor",
            }

        else:

            metadata = {
                "collector":
                    "RegistryMonitor",

                **metadata,
            }


        self.telemetry.emit(

            event_type=event_type,

            source="registry_monitor",

            severity="INFO",

            registry=registry_data,

            metadata=metadata,
        )


        logger.info(
            "%s | %s | %s",
            event_type.upper(),
            registry_data.get(
                "registry_path"
            ),
            registry_data.get(
                "name"
            ),
        )


    # ============================================================
    # CHECK REGISTRY CHANGES
    # ============================================================

    def check_changes(
        self,
    ):

        current_values = (
            self.get_current_snapshot()
        )


        current_keys = set(
            current_values.keys()
        )

        previous_keys = set(
            self.known_values.keys()
        )


        # --------------------------------------------------------
        # CREATED REGISTRY VALUES
        # --------------------------------------------------------

        created_keys = (
            current_keys
            - previous_keys
        )

        for key in created_keys:

            registry_data = (
                current_values[
                    key
                ]
            )

            self.emit_registry_event(
                event_type="registry_create",
                registry_data=registry_data,
            )


        # --------------------------------------------------------
        # DELETED REGISTRY VALUES
        # --------------------------------------------------------

        deleted_keys = (
            previous_keys
            - current_keys
        )

        for key in deleted_keys:

            registry_data = (
                self.known_values[
                    key
                ]
            )

            self.emit_registry_event(
                event_type="registry_delete",
                registry_data=registry_data,
            )


        # --------------------------------------------------------
        # MODIFIED REGISTRY VALUES
        # --------------------------------------------------------

        common_keys = (
            current_keys
            & previous_keys
        )

        for key in common_keys:

            old_data = (
                self.known_values[
                    key
                ]
            )

            new_data = (
                current_values[
                    key
                ]
            )


            if (
                old_data.get(
                    "value"
                )
                !=
                new_data.get(
                    "value"
                )
            ):

                self.emit_registry_event(

                    event_type=
                        "registry_modify",

                    registry_data=
                        new_data,

                    metadata={

                        "previous_value":
                            old_data.get(
                                "value"
                            ),

                        "new_value":
                            new_data.get(
                                "value"
                            ),
                    },
                )


        # --------------------------------------------------------
        # UPDATE SNAPSHOT
        # --------------------------------------------------------

        self.known_values = (
            current_values
        )


    # ============================================================
    # START REGISTRY MONITOR
    # ============================================================

    def start(
        self,
    ):

        logger.info(
            "Starting SENTINEL-X Registry Monitor..."
        )

        self.running = True

        self.build_initial_snapshot()


        try:

            while self.running:

                self.check_changes()

                time.sleep(
                    self.polling_interval
                )


        except KeyboardInterrupt:

            logger.info(
                "Registry monitor interrupted."
            )


        finally:

            self.stop()


    # ============================================================
    # STOP REGISTRY MONITOR
    # ============================================================

    def stop(
        self,
    ):

        self.running = False

        logger.info(
            "SENTINEL-X Registry Monitor stopped."
        )


# ============================================================
# MANUAL TEST
# ============================================================

if __name__ == "__main__":

    monitor = RegistryMonitor(
        polling_interval=5.0
    )

    monitor.start()