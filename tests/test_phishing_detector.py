import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:

    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from detection.phishing.phishing_detector import (
    PhishingDetector,
)


def separator():

    print(
        "\n"
        + "=" * 72
    )


def print_detections(
    detections,
):

    for detection in detections:

        print(
            "\n>>> PHISHING DETECTION"
        )

        print(
            "Type:",
            detection.get(
                "detection_type"
            ),
        )

        print(
            "Severity:",
            detection.get(
                "severity"
            ),
        )

        print(
            "Risk:",
            detection.get(
                "risk_score"
            ),
        )

        print(
            "Confidence:",
            detection.get(
                "confidence"
            ),
        )

        print(
            "Reason:",
            detection.get(
                "reason"
            ),
        )


def main():

    separator()

    print(
        "SENTINEL-X PHISHING DETECTOR TEST"
    )

    separator()

    print(
        "\nOffline metadata-only test."
    )

    print(
        "No email is sent."
    )

    print(
        "No URL is opened."
    )

    print(
        "No attachment is executed."
    )

    detector = (
        PhishingDetector(

            phishing_score_threshold=60,

            protected_brand_domains={

                "examplecorp": {
                    "examplecorp.test"
                },
            },
        )
    )

    # ============================================================
    # TEST 1 — BENIGN CONTROL
    # ============================================================

    separator()

    print(
        "TEST 1 - BENIGN EMAIL CONTROL"
    )

    benign_email = {

        "sender":
            (
                "ExampleCorp Support "
                "<support@examplecorp.test>"
            ),

        "display_name":
            "ExampleCorp Support",

        "subject":
            "Monthly service summary",

        "body":
            (
                "Your monthly service summary is available "
                "in the normal customer portal."
            ),

        "urls": [
            "https://portal.examplecorp.test/summary"
        ],

        "attachments": [
            "monthly_summary.pdf"
        ],

        "synthetic_test":
            True,
    }

    benign_detections = (
        detector.analyze(
            benign_email
        )
    )

    print(
        "Detections:",
        len(
            benign_detections
        ),
    )

    if benign_detections:

        print_detections(
            benign_detections
        )

        raise AssertionError(
            "Benign control generated phishing detections."
        )

    print(
        "BENIGN CONTROL: PASS"
    )

    # ============================================================
    # TEST 2 — SYNTHETIC PHISHING-LIKE EMAIL
    # ============================================================

    separator()

    print(
        "TEST 2 - SYNTHETIC PHISHING-LIKE EMAIL"
    )

    suspicious_email = {

        "sender":
            (
                "ExampleCorp Security "
                "<alert@xn--examplecorp-9za.test>"
            ),

        "display_name":
            "ExampleCorp Security",

        "subject":
            (
                "URGENT: Action required - "
                "verify your account immediately"
            ),

        "body":
            (
                "Security alert. Your account will be suspended "
                "within 24 hours. Verify your account immediately "
                "using the link below."
            ),

        # --------------------------------------------------------
        # Documentation-range IP only.
        # The test DOES NOT open this URL.
        # --------------------------------------------------------

        "urls": [

            (
                "http://secure-login.example.test"
                "@198.51.100.77/verify-account"
            )
        ],

        "attachments": [
            "security_update.js"
        ],

        "synthetic_test":
            True,
    }

    detections = (
        detector.analyze(
            suspicious_email
        )
    )

    detected_types = {

        detection.get(
            "detection_type"
        )

        for detection
        in detections
    }

    print(
        "\nDetected types:"
    )

    for detection_type in sorted(
        detected_types
    ):

        print(
            " -",
            detection_type,
        )

    print_detections(
        detections
    )

    # ============================================================
    # VALIDATION
    # ============================================================

    separator()

    print(
        "VALIDATION"
    )

    required = {

        "SUSPICIOUS_SENDER_DOMAIN",

        "DISPLAY_NAME_DOMAIN_MISMATCH",

        "SUSPICIOUS_URL",

        "URGENCY_LANGUAGE",

        "SUSPICIOUS_ATTACHMENT",

        "PHISHING_SUSPICION",
    }

    missing = (
        required
        - detected_types
    )

    if missing:

        raise AssertionError(
            "Missing phishing detections: "
            + str(
                sorted(
                    missing
                )
            )
        )

    print(
        "Suspicious sender domain: PASS"
    )

    print(
        "Display-name/domain mismatch: PASS"
    )

    print(
        "Suspicious URL analysis: PASS"
    )

    print(
        "Urgency language: PASS"
    )

    print(
        "Suspicious attachment: PASS"
    )

    print(
        "Combined phishing suspicion: PASS"
    )

    separator()

    print(
        "ALL PHISHING DETECTOR TESTS PASSED"
    )

    separator()


if __name__ == "__main__":

    main()