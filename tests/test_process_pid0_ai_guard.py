from endpoint.collectors.process_monitor import ProcessMonitor


def test_pid0_skips_ai_feature_extraction():

    monitor = object.__new__(ProcessMonitor)

    class ExtractorSpy:

        def extract(self, **kwargs):
            raise AssertionError(
                "PID 0 must not reach AI feature extraction"
            )

    monitor.ai_feature_extractor = ExtractorSpy()

    result = monitor.collect_ai_behavior_features(
        process_info={
            "pid": 0,
            "name": "System Idle Process",
            "create_time": 0.0,
        },
        context={},
    )

    assert result["record_id"] is None
    assert result["feature_record"] is None
    assert result["isolation_forest"] is None
    assert result["autoencoder"] is None


def test_missing_process_information():

    monitor = object.__new__(ProcessMonitor)

    result = monitor.collect_ai_behavior_features(
        process_info={},
        context={},
    )

    assert result["record_id"] is None
    assert result["feature_record"] is None
    