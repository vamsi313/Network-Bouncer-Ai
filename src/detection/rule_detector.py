# src/detection/rule_detector.py

# --- Configurable Thresholds (tune these for sensitivity) ---
DESTINATION_THRESHOLD = 20   # unique destination IPs
PORT_THRESHOLD = 20          # unique destination ports
CONNECTION_THRESHOLD = 100   # total connections
SCAN_RATE_THRESHOLD = 1.0    # connections per second


def detect_suspicious(row):
    """
    Rule-based detection of port scanning behavior.
    Rules:
      - If a source IP connects to many unique destinations quickly → suspicious
      - If a source IP tries many unique ports quickly → suspicious
      - If a source IP makes an abnormally large number of connections → suspicious
    Returns:
      "Backdoor/Analysis" if any rule fires, else "Normal"
    """
    try:
        is_dest_scan = (
            row["unique_destinations"] > DESTINATION_THRESHOLD
            and row["scan_rate"] > SCAN_RATE_THRESHOLD
        )

        is_port_scan = (
            row["unique_ports"] > PORT_THRESHOLD
            and row["scan_rate"] > SCAN_RATE_THRESHOLD
        )

        is_connection_burst = (
            row["connections"] > CONNECTION_THRESHOLD
            and row["scan_rate"] > SCAN_RATE_THRESHOLD
        )

        if is_dest_scan or is_port_scan or is_connection_burst:
            return "Backdoor/Analysis"

        return "Normal"

    except Exception:
        return "Unknown"