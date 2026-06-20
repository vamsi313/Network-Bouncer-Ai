from src.parser.csv_parser import load_data
from src.features.feature_extractor import extract_features
from src.detection.rule_detector import detect_suspicious
from src.detection.risk_engine import calculate_risk_score, severity
from pathlib import Path
import os

DATASET = "data/UNSW-NB15_1.csv"


def main():
    try:
        os.makedirs("reports", exist_ok=True)

        print("\nLoading dataset...")
        df = load_data(DATASET)

        print("\nExtracting features per source IP...")
        features = extract_features(df)

        if features.empty:
            print("No features extracted.")
            return

        # --- Rule-Based Detection ---
        # Classify each source IP as "Normal" or "Backdoor/Analysis"
        features["classification"] = features.apply(
            detect_suspicious, axis=1
        )

        # --- Risk Score & Severity (Stretch Goal) ---
        features["risk_score"] = features.apply(
            calculate_risk_score, axis=1
        )
        features["severity"] = features["risk_score"].apply(severity)

        # --- Final Verdict (purely rule-based) ---
        features["final_verdict"] = features["classification"]

        # --- Console Output (matches hackathon expected format) ---
        print("\n" + "=" * 50)
        print("   NETWORK BOUNCER AI — THREAT REPORT")
        print("=" * 50)

        suspicious = features[
            features["final_verdict"] == "Backdoor/Analysis"
        ].sort_values(by="risk_score", ascending=False)

        print(f"\nTotal IPs Analysed : {len(features)}")
        print(f"Suspicious IPs     : {len(suspicious)}")
        print(f"Normal IPs         : {len(features) - len(suspicious)}")

        if suspicious.empty:
            print(f"\n[CLEAN] No suspicious activity detected.")
        else:
            print(f"\n[ALERT] SUSPICIOUS ACTIVITY DETECTED:\n")
            for _, row in suspicious.iterrows():
                print(f"  Source IP          : {row['srcip']}")
                print(f"  Connections        : {row['connections']}")
                print(f"  Unique Destinations: {row['unique_destinations']}")
                print(f"  Unique Ports       : {row['unique_ports']}")
                print(f"  Scan Rate          : {round(row['scan_rate'], 2)} conn/sec")
                print(f"  Classification     : {row['final_verdict']}")
                print(f"  Risk Score         : {row['risk_score']}")
                print(f"  Severity           : {row['severity']}")
                print("-" * 40)

        # --- Save Report ---
        report_path = Path("reports") / "suspicious_report.csv"
        features.to_csv(report_path, index=False)
        print(f"\nFull report saved to: {report_path}")
        print("=" * 50)

    except Exception as e:
        print(f"\nApplication Error: {e}")


if __name__ == "__main__":
    main()