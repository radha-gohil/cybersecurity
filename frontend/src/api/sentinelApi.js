import axios from "axios";


// ================================================================
// SENTINEL-X SOC API CLIENT
// ================================================================

const sentinelApi =
    axios.create({

        baseURL:
            "http://127.0.0.1:8003/api/v1",

        timeout:
            30000,

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


export const getSOCHealth =
    async () => {

        return getHealth();
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


export const getSOCDashboardSummary =
    async () => {

        return getDashboardSummary();
    };


// ================================================================
// DETECTED / CORRELATED INCIDENTS
// ================================================================

export const getDetectedIncidents =
    async (
        limit = 100
    ) => {

        const response =
            await sentinelApi.get(
                "/detected-incidents",
                {
                    params: {
                        limit,
                    },
                }
            );

        return response.data;
    };


export const getDetectedIncident =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/detected-incidents/${encodeURIComponent(
                    incidentId
                )}`
            );

        return response.data;
    };


// ================================================================
// INVESTIGATE / PROMOTE DETECTED INCIDENT
// ================================================================

export const investigateDetectedIncident =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.post(
                `/detected-incidents/${encodeURIComponent(
                    incidentId
                )}/investigate`
            );

        return response.data;
    };


// ================================================================
// SOC CASES
// ================================================================

export const getSOCCases =
    async (
        limit = 100
    ) => {

        const response =
            await sentinelApi.get(
                "/cases",
                {
                    params: {
                        limit,
                    },
                }
            );

        return response.data;
    };


export const createSOCCase =
    async (
        incidentId,
        intelligence
    ) => {

        const response =
            await sentinelApi.post(
                "/cases",
                {
                    incident_id:
                        incidentId,

                    intelligence:
                        intelligence,
                }
            );

        return response.data;
    };


// ================================================================
// INCIDENT SEARCH
// ================================================================

export const searchIncidents =
    async (
        filters = {}
    ) => {

        const response =
            await sentinelApi.get(
                "/search/incidents",
                {
                    params:
                        filters,
                }
            );

        return response.data;
    };


// ================================================================
// SINGLE SOC CASE
// ================================================================

export const getCase =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/cases/${encodeURIComponent(
                    incidentId
                )}`
            );

        return response.data;
    };


export const getSOCCase =
    async (
        incidentId
    ) => {

        return getCase(
            incidentId
        );
    };


// ================================================================
// FULL INCIDENT
// ================================================================

export const getFullIncident =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/incidents/${encodeURIComponent(
                    incidentId
                )}/full`
            );

        return response.data;
    };


// ================================================================
// DIGITAL TWIN
// ================================================================

export const getDigitalTwin =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/cases/${encodeURIComponent(
                    incidentId
                )}/digital-twin`
            );

        return response.data;
    };


// ================================================================
// RESPONSE ACTIONS
// ================================================================

export const getResponseActions =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/cases/${encodeURIComponent(
                    incidentId
                )}/responses`
            );

        return response.data;
    };


// ================================================================
// INCIDENT EVIDENCE
// ================================================================

export const getIncidentEvidence =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/cases/${encodeURIComponent(
                    incidentId
                )}/evidence`
            );

        return response.data;
    };


// ================================================================
// INCIDENT TIMELINE
// ================================================================

export const getIncidentTimeline =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/cases/${encodeURIComponent(
                    incidentId
                )}/timeline`
            );

        return response.data;
    };


// ================================================================
// TICKETS
// ================================================================

export const getTickets =
    async (
        limit = 100
    ) => {

        const response =
            await sentinelApi.get(
                "/tickets",
                {
                    params: {
                        limit,
                    },
                }
            );

        return response.data;
    };


export const getSOCTickets =
    async (
        limit = 100
    ) => {

        return getTickets(
            limit
        );
    };


export const searchTickets =
    async (
        filters = {}
    ) => {

        const response =
            await sentinelApi.get(
                "/search/tickets",
                {
                    params:
                        filters,
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
                `/tickets/${encodeURIComponent(
                    ticketId
                )}`
            );

        return response.data;
    };


export const getSOCTicket =
    async (
        ticketId
    ) => {

        return getTicket(
            ticketId
        );
    };


export const getIncidentTickets =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/incidents/${encodeURIComponent(
                    incidentId
                )}/tickets`
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
                `/cases/${encodeURIComponent(
                    incidentId
                )}/approve`,
                {
                    analyst,
                    comment,
                }
            );

        return response.data;
    };


export const approveSOCCase =
    async (
        incidentId,
        analyst,
        comment = ""
    ) => {

        return approveCase(
            incidentId,
            analyst,
            comment
        );
    };


// ================================================================
// REJECTION
// ================================================================

export const rejectCase =
    async (
        incidentId,
        analyst,
        reason
    ) => {

        const response =
            await sentinelApi.post(
                `/cases/${encodeURIComponent(
                    incidentId
                )}/reject`,
                {
                    analyst,
                    reason,
                }
            );

        return response.data;
    };


export const rejectSOCCase =
    async (
        incidentId,
        analyst,
        reason
    ) => {

        return rejectCase(
            incidentId,
            analyst,
            reason
        );
    };


// ================================================================
// SEARCH RESPONSE ACTIONS
// ================================================================

export const searchActions =
    async (
        filters = {}
    ) => {

        const response =
            await sentinelApi.get(
                "/search/actions",
                {
                    params:
                        filters,
                }
            );

        return response.data;
    };


export const searchResponseActions =
    async (
        filters = {}
    ) => {

        return searchActions(
            filters
        );
    };


// ================================================================
// ENDPOINT OVERVIEW
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
// MITIGATION VERIFICATION
// ================================================================

export const getMitigationVerification =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/cases/${encodeURIComponent(
                    incidentId
                )}/mitigation-verification`
            );

        return response.data;
    };


export const verifyMitigation =
    async (
        incidentId,
        beforeState,
        simulatedAfterState,
        responseResult = {}
    ) => {

        const response =
            await sentinelApi.post(
                `/cases/${encodeURIComponent(
                    incidentId
                )}/mitigation-verification`,
                {

                    before_state:
                        beforeState,

                    simulated_after_state:
                        simulatedAfterState,

                    response_result:
                        responseResult,
                }
            );

        return response.data;
    };


// ================================================================
// INTEGRITY / SYSTEM HEALTH
// ================================================================

export const getIntegritySummary =
    async (
        limit = 1000
    ) => {

        const response =
            await sentinelApi.get(
                "/integrity",
                {
                    params: {
                        limit,
                    },
                }
            );

        return response.data;
    };


export const getBackendIntegrity =
    async (
        limit = 1000
    ) => {

        return getIntegritySummary(
            limit
        );
    };


export const getIncidentIntegrity =
    async (
        incidentId
    ) => {

        const response =
            await sentinelApi.get(
                `/integrity/incidents/${encodeURIComponent(
                    incidentId
                )}`
            );

        return response.data;
    };


// ================================================================
// EXPORT AXIOS INSTANCE
// ================================================================

export default sentinelApi;