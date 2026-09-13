from endpoint.storage.database import (
    initialize_database,
)


def main():

    print(
        "Initializing SENTINEL-X endpoint database..."
    )

    initialize_database()

    print(
        "Endpoint database initialized successfully."
    )


if __name__ == "__main__":
    main()