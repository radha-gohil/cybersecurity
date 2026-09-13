from endpoint.models.security_event import SecurityEvent

from endpoint.storage.database import (
    initialize_database,
    save_event,
)


def main():

    initialize_database()


    event = SecurityEvent(

        event_type="process_start",

        source="test_monitor",

        severity="INFO",

        process={

            "name": "notepad.exe",

            "pid": 1234,

            "parent_pid": 1000,

            "parent_name": "explorer.exe",

            "path": (
                r"C:\Windows\System32\notepad.exe"
            ),

            "command_line": (
                "notepad.exe"
            ),

        },

    )


    save_event(
        event
    )


    print(
        "\nTest event saved successfully."
    )

    print(
        event.to_dict()
    )


if __name__ == "__main__":
    main()