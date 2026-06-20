import pandas as pd

# Full UNSW-NB15 column list (no header in CSV file)
COLUMN_NAMES = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur",
    "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "service",
    "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb", "dtcpb",
    "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit", "Djit",
    "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
    "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst",
    "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "Label"
]

# Only keep these after loading each chunk (saves ~90% memory)
NEEDED_COLUMNS = [
    "srcip", "dstip", "dsport", "Stime", "Ltime", "attack_cat", "Label"
]


def load_data(file_path):
    try:
        chunks = []
        chunk_iter = pd.read_csv(
            file_path,
            header=None,
            names=COLUMN_NAMES,
            low_memory=False,
            chunksize=100_000,        # Read 100k rows at a time
            on_bad_lines="skip"       # Skip malformed/corrupt rows
        )

        for i, chunk in enumerate(chunk_iter):
            # Immediately drop unneeded columns to free memory
            keep = [c for c in NEEDED_COLUMNS if c in chunk.columns]
            chunks.append(chunk[keep])
            print(f"  Processed chunk {i + 1} (~{(i + 1) * 100_000:,} rows)...", end="\r")

        df = pd.concat(chunks, ignore_index=True)

        if df.empty:
            raise ValueError("Dataset is empty after loading.")

        # Ensure numeric timestamps
        df["Stime"] = pd.to_numeric(df["Stime"], errors="coerce")
        df["Ltime"] = pd.to_numeric(df["Ltime"], errors="coerce")

        print(f"\n  Dataset loaded: {df.shape[0]:,} rows")
        return df

    except FileNotFoundError:
        print(f"Dataset not found: {file_path}")
        raise

    except MemoryError:
        print("Out of memory. Try reducing chunksize.")
        raise

    except Exception as e:
        print(f"Error loading dataset: {e}")
        raise