import axios from "axios";


const sentinelApi =
    axios.create({

        baseURL:
            "http://127.0.0.1:8003/api/v1",

        timeout: 5000,

        headers: {
            "Content-Type":
                "application/json",
        },

    });


// ================================================================
// HEALTH
// ================================================================

export const getHealth =
    async () => {

        const response =
            await sentinelApi.get(
                "/health"
            );

        return response.data;
    };


// ================================================================
// DASHBOARD
// ================================================================

export const getDashboardSummary =
    async () => {

        const response =
            await sentinelApi.get(
                "/dashboard/summary"
            );

        return response.data;
    };


// ================================================================
// INCIDENTS
// ================================================================

export const searchIncidents =
    async (
        filters = {}
    ) => {

        const response =
            await sentinelApi.get(
                "/search/incidents",
                {
                    params: filters,
                }
            );

        return response.data;
    };


export const getCase =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/cases/${incidentId}`
            );

        return response.data;
    };


export const getFullIncident =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/incidents/${incidentId}/full`
            );

        return response.data;
    };


// ================================================================
// TICKETS
// ================================================================

export const getTickets =
    async () => {

        const response =
            await sentinelApi.get(
                "/tickets"
            );

        return response.data;
    };


export const searchTickets =
    async (
        filters = {}
    ) => {

        const response =
            await sentinelApi.get(
                "/search/tickets",
                {
                    params: filters,
                }
            );

        return response.data;
    };


export const getTicket =
    async (
        ticketId
    ) => {

        const response =
            await sentinelApi.get(
                `/tickets/${ticketId}`
            );

        return response.data;
    };


export const getIncidentTickets =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/incidents/${incidentId}/tickets`
            );

        return response.data;
    };


// ================================================================
// APPROVAL
// ================================================================

export const approveCase =
    async (
        incidentId,
        analyst,
        comment = ""
    ) => {

        const response =
            await sentinelApi.post(
                `/cases/${incidentId}/approve`,
                {
                    analyst,
                    comment,
                }
            );

        return response.data;
    };


export const rejectCase =
    async (
        incidentId,
        analyst,
        reason
    ) => {

        const response =
            await sentinelApi.post(
                `/cases/${incidentId}/reject`,
                {
                    analyst,
                    reason,
                }
            );

        return response.data;
    };


// ================================================================
// RESPONSE ACTIONS
// ================================================================

export const searchActions =
    async (
        filters = {}
    ) => {

        const response =
            await sentinelApi.get(
                "/search/actions",
                {
                    params: filters,
                }
            );

        return response.data;
    };


// ================================================================
// ENDPOINT
// ================================================================

export const getEndpointOverview =
    async () => {

        const response =
            await sentinelApi.get(
                "/endpoint/overview"
            );

        return response.data;
    };


// ================================================================
// INTEGRITY / SYSTEM HEALTH
// ================================================================

export const getIntegritySummary =
    async () => {

        const response =
            await sentinelApi.get(
                "/integrity"
            );

        return response.data;
    };


export const getIncidentIntegrity =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/integrity/incidents/${incidentId}`
            );

        return response.data;
    };


export default sentinelApi;