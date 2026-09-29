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
        &&
        options.body !== null
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
            ||
            data?.message
            ||
            `HTTP ${response.status}: API request failed.`;


        throw new Error(
            message
        );
    }


    return data;
}


// ================================================================
// QUERY STRING HELPER
// ================================================================

function buildQueryString(
    params = {}
) {

    if (
        params === null
        ||
        params === undefined
    ) {

        return "";
    }


    if (
        typeof params === "string"
    ) {

        const query =
            new URLSearchParams();


        query.set(
            "query",
            params
        );


        return (
            `?${query.toString()}`
        );
    }


    const query =
        new URLSearchParams();


    Object.entries(
        params
    ).forEach(
        ([
            key,
            value,
        ]) => {

            if (
                value !== undefined
                &&
                value !== null
                &&
                value !== ""
            ) {

                query.set(
                    key,
                    String(
                        value
                    )
                );
            }
        }
    );


    const text =
        query.toString();


    return (
        text
            ? `?${text}`
            : ""
    );
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
// SECURITY RUNTIME
//
// Real runtime source:
//
//   Collector heartbeats
//   Temporal Transformer v2
//   Fusion v3 PRIMARY
//   Fusion v2 rollback
//
// ================================================================

export async function getSecurityRuntime() {

    return request(
        "/api/v1/security/runtime"
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
// DETECTED / CORRELATED INCIDENTS
// ================================================================

export async function getDetectedIncidents(
    limit = 100
) {

    return request(

        `/api/v1/detected-incidents?limit=${encodeURIComponent(
            limit
        )}`
    );
}


// ================================================================
// SINGLE DETECTED / CORRELATED INCIDENT
// ================================================================

export async function getDetectedIncident(
    incidentId
) {

    return request(

        `/api/v1/detected-incidents/${encodeURIComponent(
            incidentId
        )}`
    );
}


// ================================================================
// SOC CASES
// ================================================================

export async function getSOCCases(
    limit = 100
) {

    return request(

        `/api/v1/cases?limit=${encodeURIComponent(
            limit
        )}`
    );
}


// ================================================================
// CREATE SOC CASE
// ================================================================

export async function createSOCCase(
    incidentId,
    intelligence
) {

    return request(
        "/api/v1/cases",
        {
            method:
                "POST",

            body:
                JSON.stringify(
                    {
                        incident_id:
                            incidentId,

                        intelligence:
                            intelligence,
                    }
                ),
        }
    );
}


// ================================================================
// SINGLE SOC CASE
// ================================================================

export async function getSOCCase(
    incidentId
) {

    return request(

        `/api/v1/cases/${encodeURIComponent(
            incidentId
        )}`
    );
}


// ================================================================
// FULL INCIDENT
// ================================================================

export async function getFullIncident(
    incidentId
) {

    return request(

        `/api/v1/incidents/${encodeURIComponent(
            incidentId
        )}/full`
    );
}


// ================================================================
// DIGITAL TWIN
// ================================================================

export async function getDigitalTwin(
    incidentId
) {

    return request(

        `/api/v1/cases/${encodeURIComponent(
            incidentId
        )}/digital-twin`
    );
}


// ================================================================
// RESPONSE ACTIONS
// ================================================================

export async function getResponseActions(
    incidentId
) {

    return request(

        `/api/v1/cases/${encodeURIComponent(
            incidentId
        )}/responses`
    );
}


// ================================================================
// INCIDENT EVIDENCE
// ================================================================

export async function getIncidentEvidence(
    incidentId
) {

    return request(

        `/api/v1/cases/${encodeURIComponent(
            incidentId
        )}/evidence`
    );
}


// ================================================================
// INCIDENT TIMELINE
// ================================================================

export async function getIncidentTimeline(
    incidentId
) {

    return request(

        `/api/v1/cases/${encodeURIComponent(
            incidentId
        )}/timeline`
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

        `/api/v1/cases/${encodeURIComponent(
            incidentId
        )}/approve`,

        {
            method:
                "POST",

            body:
                JSON.stringify(
                    {
                        analyst,
                        comment,
                    }
                ),
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

        `/api/v1/cases/${encodeURIComponent(
            incidentId
        )}/reject`,

        {
            method:
                "POST",

            body:
                JSON.stringify(
                    {
                        analyst,
                        reason,
                    }
                ),
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

        `/api/v1/tickets?limit=${encodeURIComponent(
            limit
        )}`
    );
}


// ================================================================
// SINGLE SOC TICKET
// ================================================================

export async function getSOCTicket(
    ticketId
) {

    return request(

        `/api/v1/tickets/${encodeURIComponent(
            ticketId
        )}`
    );
}


// ================================================================
// INCIDENT TICKETS
// ================================================================

export async function getIncidentTickets(
    incidentId
) {

    return request(

        `/api/v1/incidents/${encodeURIComponent(
            incidentId
        )}/tickets`
    );
}


// ================================================================
// MITIGATION VERIFICATION
// ================================================================

export async function getMitigationVerification(
    incidentId
) {

    return request(

        `/api/v1/cases/${encodeURIComponent(
            incidentId
        )}/mitigation-verification`
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

        `/api/v1/cases/${encodeURIComponent(
            incidentId
        )}/mitigation-verification`,

        {
            method:
                "POST",

            body:
                JSON.stringify(
                    {
                        before_state:
                            beforeState,

                        simulated_after_state:
                            simulatedAfterState,

                        response_result:
                            responseResult,
                    }
                ),
        }
    );
}


// ================================================================
// SEARCH INCIDENTS
// ================================================================

export async function searchIncidents(
    filters = {}
) {

    return request(

        `/api/v1/search/incidents${buildQueryString(
            filters
        )}`
    );
}


// ================================================================
// SEARCH TICKETS
// ================================================================

export async function searchTickets(
    filters = {}
) {

    return request(

        `/api/v1/search/tickets${buildQueryString(
            filters
        )}`
    );
}


// ================================================================
// SEARCH RESPONSE ACTIONS
// ================================================================

export async function searchResponseActions(
    filters = {}
) {

    return request(

        `/api/v1/search/actions${buildQueryString(
            filters
        )}`
    );
}


// ================================================================
// BACKEND INTEGRITY
// ================================================================

export async function getBackendIntegrity(
    limit = 1000
) {

    return request(

        `/api/v1/integrity?limit=${encodeURIComponent(
            limit
        )}`
    );
}


// ================================================================
// INCIDENT INTEGRITY
// ================================================================

export async function getIncidentIntegrity(
    incidentId
) {

    return request(

        `/api/v1/integrity/incidents/${encodeURIComponent(
            incidentId
        )}`
    );
}


// ================================================================
// EXPORT BASE URL
// ================================================================

export {
    API_BASE_URL,
};