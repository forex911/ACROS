from prometheus_client import Counter

jobs_processed_total = Counter(
    "sentinel_jobs_processed_total", 
    "Total number of malware analysis jobs processed"
)

malware_detected_total = Counter(
    "sentinel_malware_detected_total", 
    "Total number of jobs flagged as malicious (score > 60)"
)

sandbox_errors_total = Counter(
    "sentinel_sandbox_errors_total", 
    "Total number of sandbox execution errors"
)
