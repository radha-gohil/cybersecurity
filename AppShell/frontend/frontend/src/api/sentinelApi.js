import axios from "axios";


const API_BASE_URL =
    import.meta.env.VITE_SENTINEL_API_URL
    || "http://127.0.0.1:8003/api/v1";


const api = axios.create({
    baseURL: API_BASE_URL,

    timeout: 15000,

    headers: {
        "Content-Type": "application/json",
    },
});


api.interceptors.response.use(
    (response) => response,

    (error) => {

        console.error(
            "Sentinel-X API Error:",
            error?.response?.status,
            error?.response?.data
            || error.message
        );

        return Promise.reject(
            error
        );
    }
);


/* ============================================================ */
/* SYSTEM */
/* ============================================================ */

export async function getHealth() {

    const response =
        await api.get(
            "/health"
        );

    return response.data;

}


/* ============================================================ */
/* DASHBOARD */
/* ============================================================ */

export async function getDashboardSummary() {

    const response =
        await api.get(
            "/dashboard/summary"
        );

    return response.data;

}


/* ============================================================ */
/* THREATS / INCIDENTS */
/* ============================================================ */

export async function searchIncidents(
    params = {}
) {

    const response =
        await api.get(
            "/search/incidents",
            {
                params,
            }
        );

    return response.data;

}


export async function getIncidentCase(
    incidentId
) {

    const response =
        await api.get(
            `/cases/${incidentId}`
        );

    return response.data;

}


/* ============================================================ */
/* RESPONSE / DIGITAL TWIN */
/* ============================================================ */

export async function getDigitalTwin(
    incidentId
) {

    const response =
        await api.get(
            `/cases/${incidentId}/digital-twin`
        );

    return response.data;

}


export async function getIncidentResponses(
    incidentId
) {

    const response =
        await api.get(
            `/cases/${incidentId}/responses`
        );

    return response.data;

}


/* ============================================================ */
/* APPROVAL */
/* ============================================================ */

export async function approveIncidentAction(
    incidentId,
    payload
) {

    const response =
        await api.post(
            `/cases/${incidentId}/approve`,
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

    const response =
        await api.get(
            "/search/tickets",
            {
                params,
            }
        );

    return response.data;

}


/* ============================================================ */
/* RESPONSE ACTIONS */
/* ============================================================ */

export async function searchResponseActions(
    params = {}
) {

    const response =
        await api.get(
            "/search/response-actions",
            {
                params,
            }
        );

    return response.data;

}


export default api;