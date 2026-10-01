import json
import time
import urllib.request
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8003/api/v1"
INTERVAL_SECONDS = 3


def fetch(path):
    with urllib.request.urlopen(
        BASE_URL + path,
        timeout=10,
    ) as response:
        return json.load(response)


def get_counts():
    overview = fetch(
        "/endpoint/overview?recent_limit=100"
    )

    incidents_response = fetch(
        "/detected-incidents?limit=100"
    )

    incidents = incidents_response.get(
        "incidents", []
    )

    if not isinstance(incidents, list):
        incidents = []

    detections = overview.get(
        "detections", []
    )

    if not isinstance(detections, list):
        detections = []

    return {
        "events": int(
            overview.get("event_count", 0)
        ),
        "detections": int(
            overview.get("detection_count", 0)
        ),
        "incidents": len(incidents),
        "recent_detections": detections,
    }


def main():
    print("=" * 65)
    print("SENTINEL-X LIVE THREAT DETECTION VERIFICATION")
    print("=" * 65)

    previous = get_counts()

    print("Baseline:")
    print(
        f"Events={previous['events']} "
        f"Detections={previous['detections']} "
        f"Incidents(first 100)={previous['incidents']}"
    )

    print("\nWatching for new activity. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(INTERVAL_SECONDS)

            current = get_counts()

            event_delta = (
                current["events"] - previous["events"]
            )

            detection_delta = (
                current["detections"]
                - previous["detections"]
            )

            incident_delta = (
                current["incidents"]
                - previous["incidents"]
            )

            timestamp = datetime.now(
                timezone.utc
            ).strftime("%H:%M:%S UTC")

            print(
                f"[{timestamp}] "
                f"New events={event_delta:+d} | "
                f"New detections={detection_delta:+d} | "
                f"Incident count change={incident_delta:+d}"
            )

            if detection_delta > 0:
                print("\nNEW DETECTION RECORDS OBSERVED")

                # Read from the recent records supplied by SQLite.
                # This is a snapshot comparison, not proof that every
                # newly inserted detection is present in this window.
                old_keys = {
                    (
                        str(item.get("detection_id")),
                        str(item.get("event_id")),
                        str(item.get("engine")),
                        str(item.get("threat_type")),
                    )
                    for item in previous["recent_detections"]
                    if isinstance(item, dict)
                }

                for record in current["recent_detections"]:
                    if not isinstance(record, dict):
                        continue

                    key = (
                        str(record.get("detection_id")),
                        str(record.get("event_id")),
                        str(record.get("engine")),
                        str(record.get("threat_type")),
                    )

                    if key not in old_keys:
                        print(
                            json.dumps(
                                record,
                                indent=2,
                                default=str,
                            )
                        )

            previous = current

    except KeyboardInterrupt:
        print("\nLive detection verification stopped.")


if __name__ == "__main__":
    main()