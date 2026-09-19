from fastapi.testclient import (
    TestClient,
)

from api.main import (
    app,
)


client = TestClient(
    app
)


def main():

    print()
    print("=" * 80)
    print(
        "SENTINEL-X SOC QUERY API TEST"
    )
    print("=" * 80)


    # ============================================================
    # INCIDENT SEARCH
    # ============================================================

    incident_response = (
        client.get(

            "/api/v1/search/incidents",

            params={

                "risk_level":
                    "CRITICAL",

                "min_risk":
                    80,
            },
        )
    )


    incident_data = (
        incident_response.json()
    )


    # ============================================================
    # TICKET SEARCH
    # ============================================================

    ticket_response = (
        client.get(

            "/api/v1/search/tickets",

            params={

                "priority":
                    "P1",
            },
        )
    )


    ticket_data = (
        ticket_response.json()
    )


    # ============================================================
    # PENDING TICKET SEARCH
    # ============================================================

    pending_response = (
        client.get(

            "/api/v1/search/tickets",

            params={

                "approval_status":
                    "PENDING",
            },
        )
    )


    pending_data = (
        pending_response.json()
    )


    # ============================================================
    # RESPONSE ACTION SEARCH
    # ============================================================

    action_response = (
        client.get(

            "/api/v1/search/actions",

            params={

                "risk_level":
                    "CRITICAL",
            },
        )
    )


    action_data = (
        action_response.json()
    )


    # ============================================================
    # READY ACTION SEARCH
    # ============================================================

    ready_response = (
        client.get(

            "/api/v1/search/actions",

            params={

                "execution_status":
                    "READY",
            },
        )
    )


    ready_data = (
        ready_response.json()
    )


    # ============================================================
    # DISPLAY
    # ============================================================

    print()

    print(
        "Critical Incidents:",
        incident_data.get(
            "count"
        ),
    )


    print(
        "P1 Tickets:",
        ticket_data.get(
            "count"
        ),
    )


    print(
        "Pending Tickets:",
        pending_data.get(
            "count"
        ),
    )


    print(
        "Critical Response Actions:",
        action_data.get(
            "count"
        ),
    )


    print(
        "READY Actions:",
        ready_data.get(
            "count"
        ),
    )


    # ============================================================
    # VALIDATION
    # ============================================================

    incident_status_pass = (
        incident_response.status_code
        == 200
    )


    ticket_status_pass = (
        ticket_response.status_code
        == 200
    )


    action_status_pass = (
        action_response.status_code
        == 200
    )


    incident_filter_pass = all(

        item.get(
            "risk_level"
        )
        == "CRITICAL"

        and

        item.get(
            "risk_score",
            0,
        )
        >= 80

        for item
        in incident_data.get(
            "incidents",
            []
        )
    )


    ticket_filter_pass = all(

        item.get(
            "priority"
        )
        == "P1"

        for item
        in ticket_data.get(
            "tickets",
            []
        )
    )


    pending_filter_pass = all(

        item.get(
            "approval_status"
        )
        == "PENDING"

        for item
        in pending_data.get(
            "tickets",
            []
        )
    )


    critical_action_filter_pass = all(

        item.get(
            "risk_level"
        )
        == "CRITICAL"

        for item
        in action_data.get(
            "actions",
            []
        )
    )


    ready_filter_pass = all(

        item.get(
            "execution_status"
        )
        == "READY"

        for item
        in ready_data.get(
            "actions",
            []
        )
    )


    response_structure_pass = (

        isinstance(
            incident_data.get(
                "filters"
            ),
            dict,
        )

        and

        isinstance(
            ticket_data.get(
                "filters"
            ),
            dict,
        )

        and

        isinstance(
            action_data.get(
                "filters"
            ),
            dict,
        )
    )


    # ============================================================
    # FINAL
    # ============================================================

    print()
    print("=" * 80)
    print(
        "FINAL SOC QUERY API VALIDATION"
    )
    print("=" * 80)


    print(
        "Incident search endpoint:",
        "PASS"
        if incident_status_pass
        else "FAIL",
    )


    print(
        "Ticket search endpoint:",
        "PASS"
        if ticket_status_pass
        else "FAIL",
    )


    print(
        "Response action search endpoint:",
        "PASS"
        if action_status_pass
        else "FAIL",
    )


    print(
        "Critical incident filtering:",
        "PASS"
        if incident_filter_pass
        else "FAIL",
    )


    print(
        "P1 ticket filtering:",
        "PASS"
        if ticket_filter_pass
        else "FAIL",
    )


    print(
        "Pending approval filtering:",
        "PASS"
        if pending_filter_pass
        else "FAIL",
    )


    print(
        "Critical action filtering:",
        "PASS"
        if critical_action_filter_pass
        else "FAIL",
    )


    print(
        "READY action filtering:",
        "PASS"
        if ready_filter_pass
        else "FAIL",
    )


    print(
        "Query response structure:",
        "PASS"
        if response_structure_pass
        else "FAIL",
    )


    overall = all(
        [
            incident_status_pass,
            ticket_status_pass,
            action_status_pass,
            incident_filter_pass,
            ticket_filter_pass,
            pending_filter_pass,
            critical_action_filter_pass,
            ready_filter_pass,
            response_structure_pass,
        ]
    )


    print()

    print(
        "OVERALL:",
        "PASS"
        if overall
        else "FAIL",
    )

    print("=" * 80)


if __name__ == "__main__":

    main()