// ================================================================
// SENTINEL-X SOC API CLIENT
// ================================================================

const API_BASE_URL =
    import.meta.env.VITE_SOC_API_BASE_URL ||
    "http://127.0.0.1:8003";


// ================================================================
// GENERIC REQUEST
// ================================================================

async function request(
    endpoint,
    options = {}
) {

    const method =
        (
            options.method ||
            "GET"
        ).toUpperCase();


    const headers = {
        ...(options.headers || {}),
    };


    // Only requests containing a body need JSON Content-Type.
    if (
        options.body !== undefined
        && options.body !== null
    ) {

        headers["Content-Type"] =
            "application/json";
    }


    const response =
        await fetch(
            `${API_BASE_URL}${endpoint}`,
            {
                ...options,
                method,
                headers,
            }
        );


    let data = null;


    try {

        data =
            await response.json();

    } catch {

        data = null;
    }


    if (!response.ok) {

        const message =
            data?.detail
            || data?.message
            || `HTTP ${response.status}: API request failed.`;


        throw new Error(
            message
        );
    }


    return data;
}


// ================================================================
// HEALTH
// ================================================================

export async function getSOCHealth() {

    return request(
        "/api/v1/health"
    );
}


// ================================================================
// ENDPOINT OVERVIEW
// ================================================================

export async function getEndpointOverview() {

    return request(
        "/api/v1/endpoint/overview"
    );
}


// ================================================================
// DASHBOARD SUMMARY
// ================================================================

export async function getSOCDashboardSummary() {

    return request(
        "/api/v1/dashboard/summary"
    );
}


// ================================================================
// SOC CASES
// ================================================================

export async function getSOCCases(
    limit = 100
) {

    return request(
        `/api/v1/cases?limit=${limit}`
    );
}


// ================================================================
// SINGLE SOC CASE
// ================================================================

export async function getSOCCase(
    incidentId
) {

    return request(
        `/api/v1/cases/${incidentId}`
    );
}


// ================================================================
// FULL INCIDENT
// ================================================================

export async function getFullIncident(
    incidentId
) {

    return request(
        `/api/v1/incidents/${incidentId}/full`
    );
}


// ================================================================
// DIGITAL TWIN
// ================================================================

export async function getDigitalTwin(
    incidentId
) {

    return request(
        `/api/v1/cases/${incidentId}/digital-twin`
    );
}


// ================================================================
// RESPONSE ACTIONS
// ================================================================

export async function getResponseActions(
    incidentId
) {

    return request(
        `/api/v1/cases/${incidentId}/responses`
    );
}


// ================================================================
// INCIDENT EVIDENCE
// ================================================================

export async function getIncidentEvidence(
    incidentId
) {

    return request(
        `/api/v1/cases/${incidentId}/evidence`
    );
}


// ================================================================
// INCIDENT TIMELINE
// ================================================================

export async function getIncidentTimeline(
    incidentId
) {

    return request(
        `/api/v1/cases/${incidentId}/timeline`
    );
}


// ================================================================
// APPROVE SOC CASE
// ================================================================

export async function approveSOCCase(
    incidentId,
    analyst,
    comment = ""
) {

    return request(
        `/api/v1/cases/${incidentId}/approve`,
        {
            method: "POST",

            body: JSON.stringify({
                analyst,
                comment,
            }),
        }
    );
}


// ================================================================
// REJECT SOC CASE
// ================================================================

export async function rejectSOCCase(
    incidentId,
    analyst,
    reason
) {

    return request(
        `/api/v1/cases/${incidentId}/reject`,
        {
            method: "POST",

            body: JSON.stringify({
                analyst,
                reason,
            }),
        }
    );
}


// ================================================================
// ALL SOC TICKETS
// ================================================================

export async function getSOCTickets(
    limit = 100
) {

    return request(
        `/api/v1/tickets?limit=${limit}`
    );
}


// ================================================================
// SINGLE SOC TICKET
// ================================================================

export async function getSOCTicket(
    ticketId
) {

    return request(
        `/api/v1/tickets/${ticketId}`
    );
}


// ================================================================
// INCIDENT TICKETS
// ================================================================

export async function getIncidentTickets(
    incidentId
) {

    return request(
        `/api/v1/incidents/${incidentId}/tickets`
    );
}


// ================================================================
// MITIGATION VERIFICATION
// ================================================================

export async function getMitigationVerification(
    incidentId
) {

    return request(
        `/api/v1/cases/${incidentId}/mitigation-verification`
    );
}


// ================================================================
// VERIFY SIMULATED MITIGATION
// ================================================================

export async function verifyMitigation(
    incidentId,
    beforeState,
    simulatedAfterState,
    responseResult = {}
) {

    return request(
        `/api/v1/cases/${incidentId}/mitigation-verification`,
        {
            method: "POST",

            body: JSON.stringify({

                before_state:
                    beforeState,

                simulated_after_state:
                    simulatedAfterState,

                response_result:
                    responseResult,
            }),
        }
    );
}


// ================================================================
// SEARCH INCIDENTS
// ================================================================

export async function searchIncidents(
    query
) {

    return request(
        `/api/v1/search/incidents?query=${encodeURIComponent(
            query
        )}`
    );
}


// ================================================================
// SEARCH TICKETS
// ================================================================

export async function searchTickets(
    query
) {

    return request(
        `/api/v1/search/tickets?query=${encodeURIComponent(
            query
        )}`
    );
}


// ================================================================
// SEARCH RESPONSE ACTIONS
// ================================================================

export async function searchResponseActions(
    query
) {

    return request(
        `/api/v1/search/actions?query=${encodeURIComponent(
            query
        )}`
    );
}


// ================================================================
// BACKEND INTEGRITY
// ================================================================

export async function getBackendIntegrity() {

    return request(
        "/api/v1/integrity"
    );
}


// ================================================================
// INCIDENT INTEGRITY
// ================================================================

export async function getIncidentIntegrity(
    incidentId
) {

    return request(
        `/api/v1/integrity/incidents/${incidentId}`
    );
}


// ================================================================
// EXPORT BASE URL
// ================================================================

export {
    API_BASE_URL,
};