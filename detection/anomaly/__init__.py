from collections import defaultdict, deque
from statistics import mean, pstdev
import time


class ProcessAnomalyDetector:

    def __init__(
        self,
        history_size: int = 30,
        minimum_history: int = 5,
        z_threshold: float = 2.5,
    ):

        self.history_size = history_size

        self.minimum_history = minimum_history

        self.z_threshold = z_threshold


        # --------------------------------------------------------
        # Per-process historical behavior
        #
        # Example:
        #
        # {
        #     "chrome.exe": {
        #         "cpu": deque(...),
        #         "memory": deque(...),
        #         "threads": deque(...)
        #     }
        # }
        # --------------------------------------------------------

        self.history = defaultdict(
            lambda: {
                "cpu": deque(
                    maxlen=self.history_size
                ),

                "memory": deque(
                    maxlen=self.history_size
                ),

                "threads": deque(
                    maxlen=self.history_size
                ),
            }
        )


    # ============================================================
    # SAFE FLOAT CONVERSION
    # ============================================================

    def safe_float(
        self,
        value,
        default=0.0,
    ) -> float:

        try:

            if value is None:
                return default

            return float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return default


    # ============================================================
    # Z-SCORE
    # ============================================================

    def calculate_z_score(
        self,
        value: float,
        values,
    ) -> float:

        if len(values) < self.minimum_history:

            return 0.0


        average = mean(
            values
        )

        deviation = pstdev(
            values
        )


        if deviation == 0:

            if value == average:
                return 0.0

            return 3.0


        return (
            value
            - average
        ) / deviation


    # ============================================================
    # SCORE TO SEVERITY
    # ============================================================

    def score_to_severity(
        self,
        score: int,
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 35:
            return "MEDIUM"

        if score >= 15:
            return "LOW"

        return "INFO"


    # ============================================================
    # ANALYZE PROCESS
    # ============================================================

    def analyze(
        self,
        process: dict,
    ) -> dict:

        process_name = str(
            process.get(
                "name",
                "unknown"
            )
        ).lower()


        cpu_percent = self.safe_float(
            process.get(
                "cpu_percent"
            )
        )


        memory_percent = self.safe_float(
            process.get(
                "memory_percent"
            )
        )


        thread_count = self.safe_float(
            process.get(
                "num_threads"
            )
        )


        process_history = (
            self.history[
                process_name
            ]
        )


        cpu_history = list(
            process_history[
                "cpu"
            ]
        )

        memory_history = list(
            process_history[
                "memory"
            ]
        )

        thread_history = list(
            process_history[
                "threads"
            ]
        )


        cpu_z = self.calculate_z_score(
            cpu_percent,
            cpu_history,
        )


        memory_z = self.calculate_z_score(
            memory_percent,
            memory_history,
        )


        thread_z = self.calculate_z_score(
            thread_count,
            thread_history,
        )


        score = 0

        reasons = []

        indicators = []


        # --------------------------------------------------------
        # CPU ANOMALY
        # --------------------------------------------------------

        if abs(
            cpu_z
        ) >= self.z_threshold:

            score += 30

            reasons.append(
                "CPU usage differs significantly from "
                "historical process behavior"
            )

            indicators.append(
                "cpu_anomaly"
            )


        # --------------------------------------------------------
        # MEMORY ANOMALY
        # --------------------------------------------------------

        if abs(
            memory_z
        ) >= self.z_threshold:

            score += 30

            reasons.append(
                "Memory usage differs significantly from "
                "historical process behavior"
            )

            indicators.append(
                "memory_anomaly"
            )


        # --------------------------------------------------------
        # THREAD ANOMALY
        # --------------------------------------------------------

        if abs(
            thread_z
        ) >= self.z_threshold:

            score += 25

            reasons.append(
                "Thread count differs significantly from "
                "historical process behavior"
            )

            indicators.append(
                "thread_anomaly"
            )


        # --------------------------------------------------------
        # SIMPLE HIGH RESOURCE CHECKS
        # --------------------------------------------------------

        if cpu_percent >= 90:

            score += 15

            reasons.append(
                "Very high CPU usage observed"
            )

            indicators.append(
                "high_cpu"
            )


        if memory_percent >= 50:

            score += 15

            reasons.append(
                "Very high memory usage observed"
            )

            indicators.append(
                "high_memory"
            )


        score = min(
            score,
            100,
        )


        severity = (
            self.score_to_severity(
                score
            )
        )


        anomalous = (
            score >= 35
        )


        # --------------------------------------------------------
        # STORE CURRENT SAMPLE AFTER ANALYSIS
        # --------------------------------------------------------

        process_history[
            "cpu"
        ].append(
            cpu_percent
        )


        process_history[
            "memory"
        ].append(
            memory_percent
        )


        process_history[
            "threads"
        ].append(
            thread_count
        )


        return {

            "process_name":
                process_name,

            "anomaly_score":
                score,

            "severity":
                severity,

            "anomalous":
                anomalous,

            "cpu_percent":
                cpu_percent,

            "memory_percent":
                memory_percent,

            "num_threads":
                thread_count,

            "cpu_z_score":
                round(
                    cpu_z,
                    3,
                ),

            "memory_z_score":
                round(
                    memory_z,
                    3,
                ),

            "thread_z_score":
                round(
                    thread_z,
                    3,
                ),

            "indicators":
                indicators,

            "reasons":
                reasons,

            "history_samples":
                len(
                    process_history[
                        "cpu"
                    ]
                ),

            "timestamp":
                time.time(),
        }