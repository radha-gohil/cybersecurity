from fastapi import Request


@app.get(
    "/api/v1/telemetry/live"
)
def get_live_telemetry(
    request: Request,
):

    manager = (
        request
        .app
        .state
        .telemetry_manager
    )


    snapshot = (
        manager
        .get_live_snapshot()
    )


    return {

        "status":
            "ACTIVE"
            if snapshot["running"]
            else "OFFLINE",

        "running":
            snapshot["running"],

        "total":
            snapshot["total"],

        "recent":
            snapshot["recent"],

        "simulation_mode":
            True,
    }