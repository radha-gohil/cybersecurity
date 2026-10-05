from endpoint.collectors.process_monitor import ProcessMonitor


def test_pid0_does_not_emit_fusion_alert():

    # Avoid starting collectors or connecting to SQLite.
    monitor = object.__new__(ProcessMonitor)

    class TelemetrySpy:

        def __init__(self):
            self.calls = 0

        def emit(self, **kwargs):
            self.calls += 1
            raise AssertionError(
                "PID 0 must not emit a fusion alert"
            )

    spy = TelemetrySpy()
    monitor.telemetry = spy

    monitor.emit_periodic_fusion_alert(
        process_info={
            "pid": 0,
            "name": "System Idle Process",
        },
        fusion_result={
            "should_alert": True,
            "fusion_score": 95.0,
            "severity": "CRITICAL",
        },
        isolation_result=None,
        autoencoder_result=None,
        feature_record_id=None,
        context={},
    )

    assert spy.calls == 0