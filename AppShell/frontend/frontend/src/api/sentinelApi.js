import axios from "axios";


const API_BASE_URL =
    "http://127.0.0.1:8003/api/v1";


const api = axios.create({

    baseURL: API_BASE_URL,

    timeout: 15000,

    headers: {
        "Content-Type": "application/json",
    },

});


/* ============================================================ */
/* HEALTH */
/* ============================================================ */

export async function getHealth() {

    const response = await api.get(
        "/health"
    );

    return response.data;

}


/* ============================================================ */
/* DASHBOARD */
/* ============================================================ */

export async function getDashboardSummary() {

    const response = await api.get(
        "/dashboard/summary"
    );

    return response.data;

}


/* ============================================================ */
/* INCIDENT SEARCH */
/* ============================================================ */

export async function searchIncidents(
    params = {}
) {

    const response = await api.get(
        "/search/incidents",
        {
            params,
        }
    );

    return response.data;

}


/* ============================================================ */
/* INCIDENT DETAIL */
/* ============================================================ */

export async function getIncidentCase(
    incidentId
) {

    const response = await api.get(
        `/cases/${encodeURIComponent(incidentId)}`
    );

    return response.data;

}


/* ============================================================ */
/* DIGITAL TWIN */
/* ============================================================ */

export async function getDigitalTwin(
    incidentId
) {

    const response = await api.get(
        `/cases/${encodeURIComponent(incidentId)}/digital-twin`
    );

    return response.data;

}


/* ============================================================ */
/* RESPONSE ACTIONS FOR INCIDENT */
/* ============================================================ */

export async function getIncidentResponses(
    incidentId
) {

    const response = await api.get(
        `/cases/${encodeURIComponent(incidentId)}/responses`
    );

    return response.data;

}


/* ============================================================ */
/* APPROVAL */
/* ============================================================ */

export async function approveIncident(
    incidentId,
    payload
) {

    const response = await api.post(
        `/cases/${encodeURIComponent(incidentId)}/approve`,
        payload
    );

    return response.data;

}


/* ============================================================ */
/* TICKETS */
/* ============================================================ */

export async function searchTickets(
    params = {}
) {

    const response = await api.get(
        "/search/tickets",
        {
            params,
        }
    );

    return response.data;

}


/* ============================================================ */
/* RESPONSE ACTION SEARCH */
/* ============================================================ */

export async function searchResponseActions(
    params = {}
) {

    const response = await api.get(
        "/search/actions",
        {
            params,
        }
    );

    return response.data;

}


/* ============================================================ */
/* ENDPOINT OVERVIEW */
/* ============================================================ */

export async function getEndpointOverview() {

    const response = await api.get(
        "/endpoint/overview"
    );

    return response.data;

}


/* ============================================================ */
/* SECURITY RUNTIME */
/* ============================================================ */

export async function getSecurityRuntime() {

    const response = await api.get(
        "/security/runtime"
    );

    return response.data;

}


/* ============================================================ */
/* LIVE TELEMETRY */
/* ============================================================ */

export async function getLiveTelemetry() {

    const response = await api.get(
        "/telemetry/live"
    );

    return response.data;

}
/* ============================================================ */
/* RECENT SECURITY DETECTIONS */
/* ============================================================ */

export async function getLiveDetections(
    limit = 50
) {
    const response = await api.get(
        "/telemetry/detections",
        {
            params: {
                limit,
            },
        }
    );

    return response.data;
}

/* ============================================================ */
/* EXPORT AXIOS INSTANCE */
/* ============================================================ */

export default api;