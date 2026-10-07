from pathlib import Path
import shutil
import sys


# ================================================================
# PROJECT PATHS
# ================================================================

PROJECT_ROOT = Path.cwd()

SEEDER = (
    PROJECT_ROOT
    / "validation"
    / "demo"
    / "seed_full_synthetic_environment.py"
)

BACKUP = (
    PROJECT_ROOT
    / "validation"
    / "demo"
    / "seed_full_synthetic_environment.pre_7c3_alignment.py"
)


# ================================================================
# BASIC VALIDATION
# ================================================================

if not SEEDER.exists():

    raise FileNotFoundError(
        f"Seeder not found:\n{SEEDER}\n\n"
        "Run this script from D:\\R_project\\cybersecurity"
    )


# Normalize line endings internally.
text = (
    SEEDER
    .read_text(
        encoding="utf-8"
    )
    .replace("\r\n", "\n")
    .replace("\r", "\n")
)


# ================================================================
# ALREADY PATCHED CHECK
# ================================================================

already_aligned = all(
    token in text
    for token in [
        '"PORT_SCAN_BEHAVIOR"',
        '"POSSIBLE_DOS_BEHAVIOR"',
        '"DISTRIBUTED_DOS_BEHAVIOR"',
        '"SUSPICIOUS_RUN_KEY_PERSISTENCE"',
        '"SUSPICIOUS_SERVICE_PERSISTENCE"',
        '"AUTH_BRUTE_FORCE_BEHAVIOR"',
        '"PRIVILEGED_GROUP_MEMBERSHIP_CHANGE"',
        '"SUSPICIOUS_SCHEDULED_TASK_PERSISTENCE"',
    ]
)

old_tokens_present = any(
    token in text
    for token in [
        '"PORT_SCAN_ACTIVITY"',
        '"POSSIBLE_DATA_EXFILTRATION"',
        '"HIGH_RATE_NETWORK_BURST"',
        '"UNUSUAL_PRIVILEGED_LOGIN"',
        '"UNEXPECTED_PRIVILEGE_CHANGE"',
        '"SUSPICIOUS_STARTUP_PERSISTENCE"',
        '"startup_behavior"',
    ]
)


if (
    already_aligned
    and not old_tokens_present
):

    print()
    print("=" * 78)
    print("SENTINEL-X 7C.3 FIXTURE ALIGNMENT")
    print("=" * 78)
    print()
    print("Seeder already appears aligned.")
    print("No changes were made.")
    print()

    sys.exit(0)


# ================================================================
# BACKUP
# ================================================================

if not BACKUP.exists():

    shutil.copy2(
        SEEDER,
        BACKUP,
    )

    print(
        f"[BACKUP] {BACKUP}"
    )

else:

    print(
        f"[BACKUP EXISTS] {BACKUP}"
    )


# ================================================================
# HELPERS
# ================================================================

def replace_between(
    source: str,
    start_marker: str,
    end_marker: str,
    replacement: str,
    label: str,
) -> str:

    start = source.find(
        start_marker
    )

    if start < 0:

        raise RuntimeError(
            f"{label}: start marker not found:\n"
            f"{start_marker}"
        )


    end = source.find(
        end_marker,
        start + len(
            start_marker
        ),
    )

    if end < 0:

        raise RuntimeError(
            f"{label}: end marker not found:\n"
            f"{end_marker}"
        )


    replacement = (
        replacement
        .replace(
            "\r\n",
            "\n",
        )
        .replace(
            "\r",
            "\n",
        )
        .rstrip()
    )


    return (
        source[:start]
        +
        replacement
        +
        "\n\n"
        +
        source[end:]
    )


def replace_once(
    source: str,
    old: str,
    new: str,
    label: str,
) -> str:

    if old not in source:

        raise RuntimeError(
            f"{label}: expected text was not found."
        )

    return source.replace(
        old,
        new,
        1,
    )


# ================================================================
# 1. THREAT DETECTION HELPER
#
# Allow deterministic fixtures to preserve the confidence generated
# by the actual detector family instead of forcing every threat to
# confidence=0.91.
# ================================================================

THREAT_HELPER = r'''
def threat_detection(
    engine,
    threat_type,
    risk,
    severity,
    reason,
    confidence=0.91,
):

    return {

        "engine":
            engine,

        "detected":
            True,

        "threat_type":
            threat_type,

        "confidence":
            confidence,

        "risk_score":
            risk,

        "severity":
            severity,

        "reason":
            [
                reason,
                "Synthetic validation metadata only.",
            ],
    }
'''


text = replace_between(
    text,
    "def threat_detection(",
    "# RAW TELEMETRY + DETECTION MATRIX",
    THREAT_HELPER,
    "threat_detection helper",
)


# ================================================================
# 2. NETWORK — BEACON
# ================================================================

text = replace_once(
    text,
    '''event_id=
                "SYNTH-EVT-NET-BEACON",

            event_type=
                "network_security_detection",''',

    '''event_id=
                "SYNTH-EVT-NET-BEACON",

            event_type=
                "network_behavior_alert",''',

    "network beacon event type",
)


text = replace_once(
    text,
    '''                "interval_seconds":
                    10,
            },''',

    '''                "interval_seconds":
                    10,

                "connection_count":
                    5,

                "coefficient_variation":
                    0.0,
            },''',

    "network beacon evidence",
)


text = replace_once(
    text,
    '''                    (
                        "Synthetic periodic connection "
                        "pattern detected."
                    ),
                ),''',

    '''                    (
                        "Synthetic periodic connection "
                        "pattern detected."
                    ),
                    confidence=0.85,
                ),''',

    "network beacon confidence",
)


# ================================================================
# 3. NETWORK — PORT SCAN
# ================================================================

NETWORK_PORT_SCAN = r'''
    # ============================================================
    # NETWORK — PORT SCAN
    #
    # Aligned with NetworkBehaviorTracker:
    #   PORT_SCAN_BEHAVIOR
    #   Risk 75 / HIGH
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-NET-SCAN",

            event_type=
                "network_behavior_alert",

            category=
                "NETWORK",

            severity=
                "HIGH",

            network={
                "pid":
                    4302,

                "process_name":
                    "validation_portscan.exe",

                "remote_ip":
                    "198.51.100.55",

                "remote_port":
                    445,

                "unique_port_count":
                    10,

                "protocol":
                    "TCP",
            },

            detection=
                threat_detection(
                    "network_behavior",
                    "PORT_SCAN_BEHAVIOR",
                    75,
                    "HIGH",
                    (
                        "10 unique destination ports were accessed "
                        "on 198.51.100.55 within 30 seconds."
                    ),
                    confidence=0.50,
                ),
        )
    )
'''


text = replace_between(
    text,
    "    # NETWORK — PORT SCAN",
    "    # NETWORK — EXFILTRATION-LIKE",
    NETWORK_PORT_SCAN,
    "network port scan",
)


# ================================================================
# 4. NETWORK — DOS
#
# The old POSSIBLE_DATA_EXFILTRATION fixture is removed because
# NetworkBehaviorTracker does not currently implement exfiltration
# detection.
#
# It is replaced with a real current detector type:
# POSSIBLE_DOS_BEHAVIOR.
# ================================================================

NETWORK_DOS = r'''
    # ============================================================
    # NETWORK — POSSIBLE DOS
    #
    # Aligned with NetworkBehaviorTracker:
    #   POSSIBLE_DOS_BEHAVIOR
    #   Risk 80 / HIGH
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-NET-DOS",

            event_type=
                "network_behavior_alert",

            category=
                "NETWORK",

            severity=
                "HIGH",

            network={
                "pid":
                    4303,

                "process_name":
                    "validation_dos.exe",

                "remote_ip":
                    "203.0.113.77",

                "remote_port":
                    443,

                "connection_count":
                    30,

                "time_window_seconds":
                    10,

                "protocol":
                    "TCP",
            },

            detection=
                threat_detection(
                    "network_behavior",
                    "POSSIBLE_DOS_BEHAVIOR",
                    80,
                    "HIGH",
                    (
                        "30 connections targeted "
                        "203.0.113.77:443 within 10 seconds."
                    ),
                    confidence=0.50,
                ),
        )
    )
'''


text = replace_between(
    text,
    "    # NETWORK — EXFILTRATION-LIKE",
    "    # NETWORK — DDoS-LIKE BURST",
    NETWORK_DOS,
    "network DOS",
)


# ================================================================
# 5. NETWORK — DISTRIBUTED DOS
# ================================================================

NETWORK_DDOS = r'''
    # ============================================================
    # NETWORK — DISTRIBUTED DOS
    #
    # Aligned with NetworkBehaviorTracker:
    #   DISTRIBUTED_DOS_BEHAVIOR
    #   Risk 90 / CRITICAL
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-NET-DDOS",

            event_type=
                "network_behavior_alert",

            category=
                "NETWORK",

            severity=
                "CRITICAL",

            network={
                "remote_ip":
                    "203.0.113.90",

                "remote_port":
                    443,

                "connection_count":
                    40,

                "unique_source_count":
                    5,

                "time_window_seconds":
                    10,

                "protocol":
                    "TCP",
            },

            detection=
                threat_detection(
                    "network_behavior",
                    "DISTRIBUTED_DOS_BEHAVIOR",
                    90,
                    "CRITICAL",
                    (
                        "40 connections from 5 distinct synthetic "
                        "sources targeted 203.0.113.90:443 "
                        "within 10 seconds."
                    ),
                    confidence=0.50,
                ),
        )
    )
'''


text = replace_between(
    text,
    "    # NETWORK — DDoS-LIKE BURST",
    "    # REGISTRY — BENIGN",
    NETWORK_DDOS,
    "network DDoS",
)


# ================================================================
# 6. REGISTRY — RUN / RUNONCE
# ================================================================

REGISTRY_RUN = r'''
    # ============================================================
    # REGISTRY — SUSPICIOUS RUN KEY PERSISTENCE
    #
    # Aligned with RegistryBehaviorDetector:
    #   SUSPICIOUS_RUN_KEY_PERSISTENCE
    #   Risk 78 / HIGH / confidence 0.82
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-REG-RUN",

            event_type=
                "registry_modify",

            category=
                "REGISTRY",

            severity=
                "HIGH",

            registry={
                "key":
                    (
                        r"HKCU\Software\Microsoft"
                        r"\Windows\CurrentVersion\Run"
                    ),

                "value_name":
                    "ValidationUpdater",

                "value_data":
                    (
                        r"C:\Users\Public"
                        r"\validation_updater.exe"
                    ),
            },

            metadata={
                "attribution_status":
                    "UNKNOWN",
            },

            detection=
                threat_detection(
                    "registry_behavior",
                    "SUSPICIOUS_RUN_KEY_PERSISTENCE",
                    78,
                    "HIGH",
                    (
                        "A Run/RunOnce autorun value was created "
                        "or modified with a suspicious "
                        "user-writable path."
                    ),
                    confidence=0.82,
                ),
        )
    )
'''


text = replace_between(
    text,
    "    # REGISTRY — RUN KEY",
    "    # REGISTRY — SERVICE PERSISTENCE",
    REGISTRY_RUN,
    "registry Run/RunOnce",
)


# ================================================================
# 7. REGISTRY — SERVICE PERSISTENCE
# ================================================================

REGISTRY_SERVICE = r'''
    # ============================================================
    # REGISTRY — SUSPICIOUS SERVICE PERSISTENCE
    #
    # Aligned with RegistryBehaviorDetector:
    #   SUSPICIOUS_SERVICE_PERSISTENCE
    #   Risk 80 / HIGH / confidence 0.84
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-REG-SERVICE",

            event_type=
                "registry_modify",

            category=
                "REGISTRY",

            severity=
                "HIGH",

            registry={
                "key":
                    (
                        r"HKLM\SYSTEM\CurrentControlSet"
                        r"\Services\ValidationService"
                    ),

                "value_name":
                    "ImagePath",

                "value_data":
                    (
                        r"C:\Users\Public"
                        r"\validation_service.exe"
                    ),
            },

            metadata={
                "attribution_status":
                    "UNKNOWN",
            },

            detection=
                threat_detection(
                    "registry_behavior",
                    "SUSPICIOUS_SERVICE_PERSISTENCE",
                    80,
                    "HIGH",
                    (
                        "A Windows service execution value was "
                        "changed to a suspicious "
                        "user-writable path."
                    ),
                    confidence=0.84,
                ),
        )
    )
'''


text = replace_between(
    text,
    "    # REGISTRY — SERVICE PERSISTENCE",
    "    # AUTH — SUCCESS",
    REGISTRY_SERVICE,
    "registry service persistence",
)


# ================================================================
# 8. AUTHENTICATION — BRUTE FORCE
#
# The current detector requires:
#
# repeated failures
# +
# multiple accounts from the same source
#
# 40 + 45 + burst bonus 10 = 95.
# ================================================================

AUTH_BRUTE = r'''
    # ============================================================
    # AUTH — COMBINED BRUTE-FORCE-LIKE BEHAVIOR
    #
    # Aligned with AuthBehaviorDetector:
    #
    #   REPEATED_LOGIN_FAILURES
    #   MULTI_ACCOUNT_LOGIN_FAILURES
    #   AUTH_BRUTE_FORCE_BEHAVIOR
    #
    # Combined score = 95
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-AUTH-BRUTE",

            event_type=
                "security_auth_failure",

            category=
                "SECURITY",

            severity=
                "CRITICAL",

            network={
                "remote_ip":
                    "203.0.113.44",
            },

            metadata={
                "username":
                    "validation.admin",

                "result":
                    "failed",

                "failure_count":
                    25,

                "unique_account_count":
                    3,

                "unique_accounts":
                    [
                        "validation.admin",
                        "validation.user",
                        "validation.service",
                    ],

                "window_seconds":
                    60,
            },

            detection=
                threat_detection(
                    "auth_behavior",
                    "AUTH_BRUTE_FORCE_BEHAVIOR",
                    95,
                    "CRITICAL",
                    (
                        "Repeated authentication failures across "
                        "multiple accounts produced the combined "
                        "brute-force-like behavior signal."
                    ),
                    confidence=0.95,
                ),
        )
    )
'''


text = replace_between(
    text,
    "    # AUTH — BRUTE FORCE",
    "    # AUTH — PRIVILEGED LOGIN",
    AUTH_BRUTE,
    "authentication brute force",
)


# ================================================================
# 9. REMOVE UNSUPPORTED AUTH PRIVILEGED LOGIN FIXTURE
#
# AuthBehaviorDetector currently does not implement:
# UNUSUAL_PRIVILEGED_LOGIN
# ================================================================

text = replace_between(
    text,
    "    # AUTH — PRIVILEGED LOGIN",
    "    # SYSTEM — BENIGN",
    "",
    "remove unsupported privileged login fixture",
)


# ================================================================
# 10. SYSTEM BENIGN ENGINE
# ================================================================

text = replace_once(
    text,

    '''                    "system_behavior",
                    "NORMAL_SYSTEM_ACTIVITY",''',

    '''                    "system_abuse",
                    "NORMAL_SYSTEM_ACTIVITY",''',

    "system benign engine",
)


# ================================================================
# 11. SYSTEM — REAL DETECTOR FIXTURES
#
# Startup/persistence is represented through actual persistence
# surfaces rather than a fake startup_behavior detector.
# ================================================================

SYSTEM_FIXTURES = r'''
    # ============================================================
    # SYSTEM — PRIVILEGED GROUP MEMBERSHIP CHANGE
    #
    # Aligned with SystemAbuseDetector / Windows Event 4732:
    #
    #   PRIVILEGED_GROUP_MEMBERSHIP_CHANGE
    #   Risk 86 / HIGH / confidence 0.90
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-SYSTEM-PRIV",

            event_type=
                "security_group_membership_change",

            category=
                "SYSTEM",

            severity=
                "HIGH",

            metadata={
                "windows_event_id":
                    4732,

                "username":
                    "validation.admin",

                "group_name":
                    "Administrators",

                "member_name":
                    "validation.user",
            },

            detection=
                threat_detection(
                    "system_abuse",
                    "PRIVILEGED_GROUP_MEMBERSHIP_CHANGE",
                    86,
                    "HIGH",
                    (
                        "A synthetic account was added to the "
                        "Administrators group."
                    ),
                    confidence=0.90,
                ),
        )
    )


    # ============================================================
    # SYSTEM — SUSPICIOUS SCHEDULED TASK PERSISTENCE
    #
    # This is one of the real startup/persistence surfaces.
    #
    # Aligned with SystemAbuseDetector / Windows Event 4698:
    #
    #   SUSPICIOUS_SCHEDULED_TASK_PERSISTENCE
    #   Risk 84 / HIGH / confidence 0.88
    # ============================================================

    rows.append(
        add_event(

            event_id=
                "SYNTH-EVT-SYSTEM-STARTUP-TASK",

            event_type=
                "security_scheduled_task_created",

            category=
                "SYSTEM",

            severity=
                "HIGH",

            metadata={
                "windows_event_id":
                    4698,

                "username":
                    "validation.user",

                "task_name":
                    r"\SentinelXValidationUpdater",

                "task_command":
                    (
                        r"powershell.exe -WindowStyle Hidden "
                        r"-File C:\Users\Public\update.ps1"
                    ),

                "task_content":
                    (
                        r"powershell.exe -WindowStyle Hidden "
                        r"-File C:\Users\Public\update.ps1"
                    ),

                "persistence_surface":
                    "SCHEDULED_TASK",
            },

            detection=
                threat_detection(
                    "system_abuse",
                    "SUSPICIOUS_SCHEDULED_TASK_PERSISTENCE",
                    84,
                    "HIGH",
                    (
                        "A scheduled task was created with a "
                        "suspicious PowerShell command in a "
                        "user-writable path."
                    ),
                    confidence=0.88,
                ),
        )
    )
'''


text = replace_between(
    text,
    "    # SYSTEM — PRIVILEGE CHANGE",
    "    # STARTUP — BENIGN",
    SYSTEM_FIXTURES,
    "system detector fixtures",
)


# ================================================================
# 12. REMOVE STANDALONE STARTUP DETECTOR FIXTURES
#
# There is no real startup_behavior detector in the current source.
#
# Startup/persistence is already covered through:
#
# Registry:
#   Run / RunOnce
#   Services
#   Winlogon
#
# System:
#   Scheduled tasks
# ================================================================

text = replace_between(
    text,
    "    # STARTUP — BENIGN",
    "    return rows",
    "",
    "remove standalone startup fixtures",
)


# ================================================================
# 13. INCIDENT FIXTURE ALIGNMENT
# ================================================================

# The old full-chain fixture referenced a synthetic exfiltration
# detection that does not exist in the real NetworkBehaviorTracker.
#
# Reuse the real beaconing signal as the NETWORK component of the
# multi-stage synthetic chain.

text = replace_once(
    text,
    '"SYNTH-EVT-NET-EXFIL",',
    '"SYNTH-EVT-NET-BEACON",',
    "full-chain network event",
)


# Authentication detector now produces a score of 95 and CRITICAL
# for the fully combined brute-force-like scenario.

text = replace_once(
    text,

    '''            "HIGH",
            88,
            ["SECURITY"],
            [
                "SYNTH-EVT-AUTH-BRUTE",
            ],''',

    '''            "CRITICAL",
            95,
            ["SECURITY"],
            [
                "SYNTH-EVT-AUTH-BRUTE",
            ],''',

    "authentication incident score",
)


# Real PORT_SCAN_BEHAVIOR risk is 75.

text = replace_once(
    text,

    '''            "HIGH",
            82,
            ["NETWORK"],
            [
                "SYNTH-EVT-NET-SCAN",
            ],''',

    '''            "HIGH",
            75,
            ["NETWORK"],
            [
                "SYNTH-EVT-NET-SCAN",
            ],''',

    "network scan incident score",
)


# ================================================================
# 14. STALE DETECTOR NAME CHECK
# ================================================================

stale_tokens = [

    '"PORT_SCAN_ACTIVITY"',

    '"POSSIBLE_DATA_EXFILTRATION"',

    '"HIGH_RATE_NETWORK_BURST"',

    '"RUN_KEY_PERSISTENCE"',

    '"SERVICE_PERSISTENCE"',

    '"AUTH_BRUTE_FORCE"',

    '"UNUSUAL_PRIVILEGED_LOGIN"',

    '"UNEXPECTED_PRIVILEGE_CHANGE"',

    '"SUSPICIOUS_STARTUP_PERSISTENCE"',

    '"startup_behavior"',
]


remaining_stale = [

    token
    for token in stale_tokens
    if token in text
]


if remaining_stale:

    raise RuntimeError(
        "Stale fixture tokens remain:\n"
        +
        "\n".join(
            remaining_stale
        )
    )


# ================================================================
# 15. REQUIRED NEW DETECTOR NAME CHECK
# ================================================================

required_tokens = [

    '"PORT_SCAN_BEHAVIOR"',

    '"POSSIBLE_DOS_BEHAVIOR"',

    '"DISTRIBUTED_DOS_BEHAVIOR"',

    '"SUSPICIOUS_RUN_KEY_PERSISTENCE"',

    '"SUSPICIOUS_SERVICE_PERSISTENCE"',

    '"AUTH_BRUTE_FORCE_BEHAVIOR"',

    '"PRIVILEGED_GROUP_MEMBERSHIP_CHANGE"',

    '"SUSPICIOUS_SCHEDULED_TASK_PERSISTENCE"',
]


missing_required = [

    token
    for token in required_tokens
    if token not in text
]


if missing_required:

    raise RuntimeError(
        "Required aligned detector tokens are missing:\n"
        +
        "\n".join(
            missing_required
        )
    )


# ================================================================
# 16. PYTHON SYNTAX VALIDATION
#
# Compile in memory before writing the modified source.
# ================================================================

compile(
    text,
    str(
        SEEDER
    ),
    "exec",
)


# ================================================================
# 17. WRITE
# ================================================================

SEEDER.write_text(
    text,
    encoding="utf-8",
)


# ================================================================
# SUMMARY
# ================================================================

print()
print("=" * 78)
print("SENTINEL-X 7C.3 REMAINING FIXTURE ALIGNMENT")
print("=" * 78)

print()
print(
    f"Updated : {SEEDER}"
)

print(
    f"Backup  : {BACKUP}"
)

print(
    "Syntax  : PASS"
)

print()

print("NETWORK")
print("  SUSPICIOUS_BEACONING")
print("  PORT_SCAN_BEHAVIOR")
print("  POSSIBLE_DOS_BEHAVIOR")
print("  DISTRIBUTED_DOS_BEHAVIOR")

print()

print("REGISTRY")
print("  SUSPICIOUS_RUN_KEY_PERSISTENCE")
print("  SUSPICIOUS_SERVICE_PERSISTENCE")

print()

print("AUTHENTICATION")
print("  AUTH_BRUTE_FORCE_BEHAVIOR")

print()

print("SYSTEM")
print("  PRIVILEGED_GROUP_MEMBERSHIP_CHANGE")
print("  SUSPICIOUS_SCHEDULED_TASK_PERSISTENCE")

print()

print("STARTUP / PERSISTENCE")
print(
    "  Represented by real Registry/System persistence detectors."
)

print(
    "  Standalone fake startup_behavior fixtures removed."
)

print()
print("=" * 78)
print("7C.3 FIXTURE ALIGNMENT COMPLETE")
print("=" * 78)