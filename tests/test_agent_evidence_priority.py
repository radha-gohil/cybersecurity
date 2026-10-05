from agents.risk_assessment_agent import RiskAssessmentAgent

from agents.triage_agent import TriageAgent


def make_incident(info_count):
    events = [
        {
            "event_id": "process-1",
            "event_type": "process_fusion_detection",
            "event_category": "PROCESS",
            "severity": "HIGH",
            "device_id": "test-device",
            "process": {
                "pid": 5056,
                "name": "Code.exe",
            },
        }
    ]

    for index in range(info_count):
        events.append({
            "event_id": f"network-{index}",
            "event_type": "network_connect",
            "event_category": "NETWORK",
            "severity": "INFO",
            "device_id": "test-device",
            "network": {
                "pid": 0,
                "status": "TIME_WAIT",
            },
        })

    return {
        "incident_id": "isolated-triage-test",
        "severity": "HIGH",
        "correlation_score": 75,
        "categories": ["PROCESS", "NETWORK"],
        "timeline": events,
    }


def test_info_events_do_not_increase_priority():
    agent = TriageAgent()

    baseline = agent.triage(make_incident(0))
    repeated = agent.triage(make_incident(22))

    assert (
        repeated["triage_score"]
        == baseline["triage_score"]
    ), (
        "INFO-only network activity increased triage priority."
    )


def test_stored_severity_is_not_independent_evidence():
    agent = TriageAgent()

    incident = make_incident(0)
    original = agent.triage(incident)

    incident["severity"] = "CRITICAL"
    incident["correlation_score"] = 99

    changed = agent.triage(incident)

    assert (
        changed["triage_score"]
        == original["triage_score"]
    ), (
        "Stored severity or correlation score inflated "
        "triage without new supporting evidence."
    )
from agents.investigation_agent import InvestigationAgent


def test_investigation_ignores_inherited_priority():
    agent = InvestigationAgent()

    incident = make_incident(22)
    original = agent.investigate(incident)

    incident["severity"] = "CRITICAL"
    incident["correlation_score"] = 99

    changed = agent.investigate(incident)

    assert changed["priority"] == original["priority"]
    assert changed["requires_response"] == original["requires_response"]


def test_info_network_events_do_not_trigger_response():
    agent = InvestigationAgent()

    result = agent.investigate(make_incident(22))

    assert result["requires_response"] is False
    assert result["priority"] not in {"HIGH", "IMMEDIATE"}
    
    from agents.risk_assessment_agent import RiskAssessmentAgent


def assess_fixture(incident, evidence=None):
    agent = RiskAssessmentAgent()

    investigation = InvestigationAgent().investigate(
        incident
    )

    return agent.assess(
        incident,
        investigation,
        evidence or {},
        {},
        {},
    )


def test_risk_ignores_inherited_severity():
    incident = make_incident(22)

    baseline = assess_fixture(incident)

    incident["severity"] = "CRITICAL"
    incident["correlation_score"] = 99

    changed = assess_fixture(incident)

    assert (
        changed["risk_score"]
        == baseline["risk_score"]
    ), "Inherited labels must not independently increase risk."


def test_info_network_does_not_increase_risk():
    incident = make_incident(22)

    baseline = assess_fixture(incident, {})

    with_network_context = assess_fixture(
        incident,
        {
            "network_connections": [
                {
                    "pid": 0,
                    "remote_ip": "192.0.2.10",
                    "remote_port": 443,
                }
            ]
        },
    )

    assert (
        with_network_context["risk_score"]
        == baseline["risk_score"]
    ), "Ordinary INFO network context must not add risk."
