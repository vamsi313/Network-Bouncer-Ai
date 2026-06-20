# Risk Score Weights

DESTINATION_WEIGHT = 0.35
PORT_WEIGHT = 0.35
CONNECTION_WEIGHT = 0.20
SCAN_RATE_WEIGHT = 0.10


def calculate_risk_score(row):

    try:

        destination_score = min(
            (row["unique_destinations"] / 50) * 100,
            100
        )

        port_score = min(
            (row["unique_ports"] / 100) * 100,
            100
        )

        connection_score = min(
            (row["connections"] / 5000) * 100,
            100
        )

        scan_score = min(
            (row["scan_rate"] / 5) * 100,
            100
        )

        score = (
            destination_score * DESTINATION_WEIGHT
            + port_score * PORT_WEIGHT
            + connection_score * CONNECTION_WEIGHT
            + scan_score * SCAN_RATE_WEIGHT
        )

        return round(score, 2)

    except Exception:
        return 0


def severity(score):

    if score >= 80:
        return "Critical"

    elif score >= 60:
        return "High"

    elif score >= 40:
        return "Medium"

    elif score >= 20:
        return "Low"

    return "Normal"