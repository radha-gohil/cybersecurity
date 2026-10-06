from __future__ import annotations

import csv
import json
from pathlib import Path

from detection.auth.auth_behavior_detector import (
    AuthBehaviorDetector,
)

from endpoint.collectors.windows_auth_collector import (
    WindowsAuthCollector,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

REPORT_DIR = PROJECT_ROOT / "validation" / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

CSV_PATH = REPORT_DIR / "auth_validation.csv"
JSON_PATH = REPORT_DIR / "auth_validation.json"


# ================================================================
# HELPERS
# ================================================================

def auth_event(
    *,
    event_type="login_failure",
    username="user1",
    source_ip="198.51.100.25",
    result="failed",
    record_id=None,
):
    event = {
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "result": result,
        "synthetic_test": True,
    }

    if record_id is not None:
        event["record_id"] = record_id

    return event


def observed_types(findings):
    return sorted(
        {
            str(item.get("detection_type"))
            for item in (findings or [])
            if isinstance(item, dict)
            and item.get("detection_type")
        }
    )


def run_sequence(
    detector,
    events,
):
    all_findings = []
    per_event = []

    for event, timestamp in events:
        findings = detector.analyze(
            event,
            current_time=timestamp,
        )

        all_findings.extend(findings)

        per_event.append(
            {
                "timestamp": timestamp,
                "detections": observed_types(findings),
            }
        )

    return all_findings, per_event


def add_result(
    results,
    scenario_id,
    scenario_name,
    detections,
    expected,
    passed,
    failure_layers="",
    notes="",
):
    results.append(
        {
            "scenario_id": scenario_id,
            "family": "AUTHENTICATION",
            "scenario_name": scenario_name,
            "detections": ",".join(detections),
            "expected": expected,
            "failure_layers": failure_layers,
            "passed": bool(passed),
            "notes": notes,
        }
    )


# ================================================================
# A1-01 — SUCCESSFUL LOGIN
# ================================================================

def scenario_01(results):
    detector = AuthBehaviorDetector()

    findings = detector.analyze(
        auth_event(
            event_type="login_success",
            username="normal_user",
            source_ip="198.51.100.10",
            result="success",
        ),
        current_time=1000.0,
    )

    types = observed_types(findings)
    passed = len(types) == 0

    add_result(
        results,
        "A1-01",
        "Successful login remains quiet",
        types,
        "NO_ALERT",
        passed,
        "" if passed else "AUTH_BEHAVIOR",
        "A successful authentication must not enter failure history.",
    )


# ================================================================
# A1-02 — SINGLE FAILURE
# ================================================================

def scenario_02(results):
    detector = AuthBehaviorDetector()

    findings = detector.analyze(
        auth_event(
            username="normal_user",
            source_ip="198.51.100.20",
        ),
        current_time=2000.0,
    )

    types = observed_types(findings)
    passed = len(types) == 0

    add_result(
        results,
        "A1-02",
        "Single failed login remains quiet",
        types,
        "NO_ALERT",
        passed,
        "" if passed else "AUTH_BEHAVIOR",
    )


# ================================================================
# A1-03 — BELOW REPEATED-FAILURE THRESHOLD
# ================================================================

def scenario_03(results):
    detector = AuthBehaviorDetector()

    sequence = [
        (
            auth_event(
                username="same_user",
                source_ip="198.51.100.30",
            ),
            3000.0 + index,
        )
        for index in range(4)
    ]

    findings, _ = run_sequence(
        detector,
        sequence,
    )

    types = observed_types(findings)

    passed = (
        "REPEATED_LOGIN_FAILURES" not in types
        and "AUTH_BRUTE_FORCE_BEHAVIOR" not in types
    )

    add_result(
        results,
        "A1-03",
        "Four failures stay below repeated threshold",
        types,
        "NO_REPEATED_LOGIN_FAILURES",
        passed,
        "" if passed else "AUTH_THRESHOLD",
        "Current repeated-failure threshold is 5 within 60 seconds.",
    )


# ================================================================
# A1-04 — EXACT REPEATED-FAILURE THRESHOLD
# ================================================================

def scenario_04(results):
    detector = AuthBehaviorDetector()

    sequence = [
        (
            auth_event(
                username="same_user",
                source_ip="198.51.100.40",
            ),
            4000.0 + index,
        )
        for index in range(5)
    ]

    findings, _ = run_sequence(
        detector,
        sequence,
    )

    types = observed_types(findings)

    passed = (
        "REPEATED_LOGIN_FAILURES" in types
        and "MULTI_ACCOUNT_LOGIN_FAILURES" not in types
        and "AUTH_BRUTE_FORCE_BEHAVIOR" not in types
    )

    add_result(
        results,
        "A1-04",
        "Five failures trigger repeated-login signal",
        types,
        "REPEATED_LOGIN_FAILURES",
        passed,
        "" if passed else "AUTH_THRESHOLD",
        "Exact repeated-failure boundary.",
    )


# ================================================================
# A1-05 — MULTI-ACCOUNT / PASSWORD-SPRAY-LIKE SIGNAL
# ================================================================

def scenario_05(results):
    detector = AuthBehaviorDetector()

    users = [
        "user_a",
        "user_b",
        "user_c",
    ]

    sequence = [
        (
            auth_event(
                username=username,
                source_ip="198.51.100.50",
            ),
            5000.0 + index,
        )
        for index, username in enumerate(users)
    ]

    findings, _ = run_sequence(
        detector,
        sequence,
    )

    types = observed_types(findings)

    passed = (
        "MULTI_ACCOUNT_LOGIN_FAILURES" in types
        and "REPEATED_LOGIN_FAILURES" not in types
        and "AUTH_BRUTE_FORCE_BEHAVIOR" not in types
    )

    add_result(
        results,
        "A1-05",
        "Three accounts from one source trigger multi-account signal",
        types,
        "MULTI_ACCOUNT_LOGIN_FAILURES",
        passed,
        "" if passed else "AUTH_MULTI_ACCOUNT",
        "Exact multi-account threshold is 3.",
    )


# ================================================================
# A1-06 — STRONG COMBINED BRUTE-FORCE-LIKE BEHAVIOR
# ================================================================

def scenario_06(results):
    detector = AuthBehaviorDetector()

    users = [
        "admin",
        "user_a",
        "user_b",
        "admin",
        "user_a",
    ]

    sequence = [
        (
            auth_event(
                username=username,
                source_ip="198.51.100.60",
            ),
            6000.0 + index,
        )
        for index, username in enumerate(users)
    ]

    findings, _ = run_sequence(
        detector,
        sequence,
    )

    types = observed_types(findings)

    required = {
        "REPEATED_LOGIN_FAILURES",
        "MULTI_ACCOUNT_LOGIN_FAILURES",
        "AUTH_BRUTE_FORCE_BEHAVIOR",
    }

    passed = required.issubset(
        set(types)
    )

    add_result(
        results,
        "A1-06",
        "Repeated plus multi-account failures trigger combined behavior",
        types,
        "AUTH_BRUTE_FORCE_BEHAVIOR",
        passed,
        "" if passed else "AUTH_COMBINATION_LOGIC",
        "Five failures across three accounts provide both supporting signals.",
    )


# ================================================================
# A1-07 — SOURCE-IP ISOLATION
# ================================================================

def scenario_07(results):
    detector = AuthBehaviorDetector()

    sequence = []

    for index in range(4):
        sequence.append(
            (
                auth_event(
                    username="shared_user",
                    source_ip="198.51.100.71",
                ),
                7000.0 + index,
            )
        )

    for index in range(4):
        sequence.append(
            (
                auth_event(
                    username="shared_user",
                    source_ip="198.51.100.72",
                ),
                7004.0 + index,
            )
        )

    findings, _ = run_sequence(
        detector,
        sequence,
    )

    types = observed_types(findings)

    passed = (
        "REPEATED_LOGIN_FAILURES" not in types
        and "MULTI_ACCOUNT_LOGIN_FAILURES" not in types
        and "AUTH_BRUTE_FORCE_BEHAVIOR" not in types
    )

    add_result(
        results,
        "A1-07",
        "Different source IPs are not incorrectly merged",
        types,
        "NO_ALERT",
        passed,
        "" if passed else "AUTH_SOURCE_ISOLATION",
        "Each source has only four failures.",
    )


# ================================================================
# A1-08 — SUCCESS DOES NOT COUNT AS A FAILURE OR ERASE HISTORY
# ================================================================

def scenario_08(results):
    detector = AuthBehaviorDetector()

    source = "198.51.100.80"

    first_four = [
        (
            auth_event(
                username="user_a",
                source_ip=source,
            ),
            8000.0 + index,
        )
        for index in range(4)
    ]

    pre_findings, _ = run_sequence(
        detector,
        first_four,
    )

    success_findings = detector.analyze(
        auth_event(
            event_type="login_success",
            username="user_a",
            source_ip=source,
            result="success",
        ),
        current_time=8004.0,
    )

    final_findings = detector.analyze(
        auth_event(
            username="user_a",
            source_ip=source,
        ),
        current_time=8005.0,
    )

    all_findings = (
        pre_findings
        + success_findings
        + final_findings
    )

    types = observed_types(
        all_findings
    )

    passed = (
        len(success_findings) == 0
        and "REPEATED_LOGIN_FAILURES" in types
    )

    add_result(
        results,
        "A1-08",
        "Successful login does not become a failure or erase prior failures",
        types,
        "REPEATED_LOGIN_FAILURES_AFTER_5_TOTAL_FAILURES",
        passed,
        "" if passed else "AUTH_SEQUENCE_STATE",
        "The success itself must remain quiet; the fifth actual failure still reaches threshold.",
    )


# ================================================================
# A1-09 — WINDOWS EVENT RECORD DEDUPLICATION
# ================================================================

class _CountingAuthMonitor:

    def __init__(self):
        self.calls = 0

    def process_auth_event(
        self,
        auth_event,
    ):
        self.calls += 1

        return {
            "processed_record_id":
                auth_event.get(
                    "record_id"
                )
        }


def scenario_09(results):
    # Avoid constructing the real AuthMonitor here: this scenario tests
    # WindowsAuthCollector deduplication only and must not emit telemetry.
    collector = WindowsAuthCollector.__new__(
        WindowsAuthCollector
    )

    collector.processed_record_ids = set()

    stub = _CountingAuthMonitor()

    collector.auth_monitor = stub

    event = auth_event(
        username="duplicate_test",
        source_ip="198.51.100.90",
        record_id=9001,
    )

    first = collector.process_normalized_event(
        dict(event)
    )

    second = collector.process_normalized_event(
        dict(event)
    )

    passed = (
        first is not None
        and second is None
        and stub.calls == 1
        and 9001 in collector.processed_record_ids
    )

    add_result(
        results,
        "A1-09",
        "Duplicate Windows EventRecordID is processed once",
        [],
        "DEDUPLICATED",
        passed,
        "" if passed else "WINDOWS_AUTH_DEDUP",
        f"AuthMonitor calls={stub.calls}",
    )


# ================================================================
# A1-10 — MISSING / NOISY DATA
# ================================================================

def scenario_10(results):
    detector = AuthBehaviorDetector()

    cases = [
        auth_event(
            username="",
            source_ip="198.51.100.100",
        ),
        auth_event(
            username="user_a",
            source_ip="",
        ),
        {
            "event_type": "login_failure",
            "result": "failed",
        },
    ]

    all_findings = []

    for index, event in enumerate(cases):
        all_findings.extend(
            detector.analyze(
                event,
                current_time=10000.0 + index,
            )
        )

    types = observed_types(
        all_findings
    )

    passed = len(types) == 0

    add_result(
        results,
        "A1-10",
        "Missing username or source IP fails quiet",
        types,
        "NO_ALERT",
        passed,
        "" if passed else "AUTH_MISSING_DATA",
        "Detector must not invent identity or source evidence.",
    )


# ================================================================
# REPORTING
# ================================================================

def save_reports(results):
    fields = [
        "scenario_id",
        "family",
        "scenario_name",
        "detections",
        "expected",
        "failure_layers",
        "passed",
        "notes",
    ]

    with CSV_PATH.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
        )
        writer.writeheader()
        writer.writerows(results)

    with JSON_PATH.open(
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            {
                "suite":
                    "SENTINEL-X PHASE 5 A1 AUTHENTICATION VALIDATION",

                "scenario_count":
                    len(results),

                "passed":
                    sum(
                        1
                        for row in results
                        if row["passed"]
                    ),

                "failed":
                    sum(
                        1
                        for row in results
                        if not row["passed"]
                    ),

                "results":
                    results,
            },
            handle,
            indent=2,
        )


def print_matrix(results):
    print()
    print("=" * 100)
    print("SENTINEL-X PHASE 5 — A1 AUTHENTICATION VALIDATION")
    print("=" * 100)

    for row in results:
        state = (
            "PASS"
            if row["passed"]
            else "FAIL"
        )

        print(
            f"{row['scenario_id']:<7} "
            f"{state:<5} "
            f"{row['scenario_name']:<56} "
            f"Observed={row['detections'] or 'NONE'}"
        )

    passed = sum(
        1
        for row in results
        if row["passed"]
    )

    print("-" * 100)
    print(
        f"RESULT: {passed}/{len(results)} PASS"
    )
    print(f"CSV   : {CSV_PATH}")
    print(f"JSON  : {JSON_PATH}")
    print("=" * 100)


# ================================================================
# MAIN
# ================================================================

def main():
    results = []

    scenario_01(results)
    scenario_02(results)
    scenario_03(results)
    scenario_04(results)
    scenario_05(results)
    scenario_06(results)
    scenario_07(results)
    scenario_08(results)
    scenario_09(results)
    scenario_10(results)

    save_reports(results)
    print_matrix(results)


if __name__ == "__main__":
    main()
