// ================================================================
// SENTINEL-X SOC API CLIENT
// ================================================================

const API_BASE_URL =
  import.meta.env.VITE_SOC_API_BASE_URL ||
  "http://127.0.0.1:8003";


// ================================================================
// GENERIC REQUEST HELPER
// ================================================================

async function request(
  endpoint,
  options = {}
) {
  const response = await fetch(
    `${API_BASE_URL}${endpoint}`,
    {
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },

      ...options,
    }
  );

  let data = null;

  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    const message =
      data?.detail ||
      data?.message ||
      `Request failed with HTTP ${response.status}`;

    throw new Error(message);
  }

  return data;
}


// ================================================================
// SYSTEM / HEALTH
// ================================================================

export async function getSOCHealth() {
  return request(
    "/api/v1/health"
  );
}


export async function getEndpointOverview() {
  return request(
    "/api/v1/endpoint/overview"
  );
}


// ================================================================
// DASHBOARD
// ================================================================

export async function getSOCDashboardSummary() {
  return request(
    "/api/v1/dashboard/summary"
  );
}


// ================================================================
// SOC CASES / INCIDENTS
// ================================================================

export async function getSOCCases(
  limit = 100
) {
  return request(
    `/api/v1/cases?limit=${limit}`
  );
}


export async function getSOCCase(
  incidentId
) {
  return request(
    `/api/v1/cases/${encodeURIComponent(
      incidentId
    )}`
  );
}


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
// EVIDENCE
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
// TIMELINE
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
// ANALYST APPROVAL
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
      method: "POST",

      body: JSON.stringify({
        analyst,
        comment,
      }),
    }
  );
}


// ================================================================
// ANALYST REJECTION
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
      method: "POST",

      body: JSON.stringify({
        analyst,
        reason,
      }),
    }
  );
}


// ================================================================
// TICKETS
// ================================================================

export async function getSOCTickets(
  limit = 100
) {
  return request(
    `/api/v1/tickets?limit=${limit}`
  );
}


export async function getSOCTicket(
  ticketId
) {
  return request(
    `/api/v1/tickets/${encodeURIComponent(
      ticketId
    )}`
  );
}


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


export async function verifyMitigation(
  incidentId,
  beforeState,
  simulatedAfterState,
  responseResult
) {
  return request(
    `/api/v1/cases/${encodeURIComponent(
      incidentId
    )}/mitigation-verification`,
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
// SEARCH
// ================================================================

export async function searchIncidents(
  query
) {
  return request(
    `/api/v1/search/incidents?q=${encodeURIComponent(
      query
    )}`
  );
}


export async function searchTickets(
  query
) {
  return request(
    `/api/v1/search/tickets?q=${encodeURIComponent(
      query
    )}`
  );
}


export async function searchResponseActions(
  query
) {
  return request(
    `/api/v1/search/actions?q=${encodeURIComponent(
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