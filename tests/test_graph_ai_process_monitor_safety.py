"""Isolated Graph AI safety tests; no model loads or database writes."""
from unittest.mock import Mock

from endpoint.collectors.graph_ai_process_monitor import GraphAIProcessMonitor


def bare_monitor():
    monitor = object.__new__(GraphAIProcessMonitor)
    monitor.graph_ai_predictor = Mock()
    monitor.graph_ai_store = Mock()
    return monitor


def test_graph_pid_zero_does_not_call_model_or_store():
    monitor = bare_monitor()
    outcome = monitor.run_graph_ai(process_info={"pid": 0, "name": "System Idle Process"})
    assert outcome["available"] is False
    assert outcome["state"] == "PID_UNAVAILABLE"
    monitor.graph_ai_predictor.predict.assert_not_called()
    monitor.graph_ai_store.save_result.assert_not_called()


def test_graph_invalid_pid_does_not_call_model():
    monitor = bare_monitor()
    for bad in [None, -4, "abc", 0, True, 3.7]:
        outcome = monitor.run_graph_ai(process_info={"pid": bad})
        assert outcome["available"] is False
    monitor.graph_ai_predictor.predict.assert_not_called()


def test_graph_pid_four_remains_eligible_in_shadow():
    monitor = bare_monitor()
    monitor.graph_ai_predictor.predict.return_value = {
        "available": True,
        "state": "GRAPH_INFERENCE_COMPLETE",
        "graph_anomaly_score": 22.0,
        "graph_anomaly_band": "LOW",
    }
    monitor.graph_ai_store.save_result.return_value = 81
    outcome = monitor.run_graph_ai(
        process_info={"pid": 4, "name": "System", "create_time": 0.0},
        event_id="local-test-event",
    )
    assert outcome["result_id"] == 81
    assert outcome["operating_mode"] == "SHADOW_GRAPH_AI"
    monitor.graph_ai_predictor.predict.assert_called_once()
    monitor.graph_ai_store.save_result.assert_called_once()


def test_graph_bad_predictor_result_no_persistence():
    monitor = bare_monitor()
    monitor.graph_ai_predictor.predict.return_value = None
    outcome = monitor.run_graph_ai(process_info={"pid": 9876})
    assert outcome["state"] == "GRAPH_INVALID_PREDICTOR_RESULT"
    monitor.graph_ai_store.save_result.assert_not_called()


def test_graph_score_logging_is_defensive():
    monitor = bare_monitor()
    monitor.graph_ai_predictor.predict.return_value = {
        "available": True,
        "state": "GRAPH_INFERENCE_COMPLETE",
        "graph_anomaly_score": None,
    }
    monitor.graph_ai_store.save_result.return_value = 19
    outcome = monitor.run_graph_ai(process_info={"pid": 9999})
    assert outcome["result_id"] == 19
