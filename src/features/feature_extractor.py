import pandas as pd


def extract_features(df):
    """
    Groups network traffic by source IP and computes:
      - connections        : total number of connections made
      - unique_destinations: number of different destination IPs contacted
      - unique_ports       : number of different destination ports tried
      - scan_rate          : connections per second (connections / time_window)

    Port scanning behaviour = many unique destinations AND ports in a short time.
    """
    try:
        # Drop rows missing critical values
        df = df.dropna(subset=["srcip", "dstip", "dsport", "Stime", "Ltime"])

        # Ensure numeric timestamps
        df["Stime"] = pd.to_numeric(df["Stime"], errors="coerce")
        df["Ltime"] = pd.to_numeric(df["Ltime"], errors="coerce")
        df = df.dropna(subset=["Stime", "Ltime"])

        # Group by source IP — this is the core behaviour analysis
        features = df.groupby("srcip").agg(
            connections=(       "dstip",  "count"),
            unique_destinations=("dstip", "nunique"),
            unique_ports=(      "dsport", "nunique"),
            start_time=(        "Stime",  "min"),
            end_time=(          "Ltime",  "max")
        ).reset_index()

        # Time window per source IP
        features["time_window"] = features["end_time"] - features["start_time"]
        features["time_window"] = features["time_window"].replace(0, 1)  # avoid /0

        # Scan rate = how fast is this IP making connections
        features["scan_rate"] = features["connections"] / features["time_window"]

        print(f"  Features extracted for {len(features):,} unique source IPs.")
        return features

    except Exception as e:
        print(f"Feature Extraction Error: {e}")
        return pd.DataFrame()