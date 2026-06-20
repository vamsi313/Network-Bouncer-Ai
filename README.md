# 🛡️ Network Bouncer AI
### Detecting Suspicious Port Scanning in Data Center Traffic

> **Dell FutureMinds AI Hackathon Submission**

---

## 📌 Problem Statement

In a data center, servers constantly talk to each other (**East-West Traffic**). Under normal conditions, each server communicates with a small, known set of machines. However, when a machine is **compromised by malware**, it starts behaving abnormally — connecting to hundreds of machines and probing thousands of ports in a short time. This is called **Port Scanning**, and it is usually the **first step of a cyberattack**.

**Network Bouncer AI** is a rule-based threat detection system that automatically analyzes network traffic logs, identifies suspicious machines, classifies them as `Normal` or `Backdoor/Analysis`, and presents the findings on an interactive security dashboard.

---

## 🎯 Key Features

| Feature | Description |
|---|---|
| **CSV Parsing** | Efficient chunked reading of large UNSW-NB15 logs (700k+ rows) |
| **Behavior Analysis** | Tracks connections, unique destinations, unique ports per source IP |
| **Rule-Based Detection** | Detects port scanning via configurable thresholds — no black-box ML |
| **Risk Scoring** | Weighted risk score (0–100) based on scan behavior |
| **Severity Classification** | Low / Medium / High / Critical labels per threat |
| **Interactive Dashboard** | Streamlit dashboard with charts, watchlist, and CSV export |
| **Graceful Error Handling** | Handles missing/malformed rows without crashing |

---

## 🔍 Detection Logic (Rule-Based)

The system classifies each source IP as **`Normal`** or **`Backdoor/Analysis`** using 3 transparent rules:

```
Rule 1 — Destination Scan:
  unique_destinations > 20 AND scan_rate > 1.0 conn/sec

Rule 2 — Port Scan:
  unique_ports > 20 AND scan_rate > 1.0 conn/sec

Rule 3 — Connection Burst:
  total_connections > 100 AND scan_rate > 1.0 conn/sec

→ If ANY rule fires → Classification: Backdoor/Analysis
→ Otherwise         → Classification: Normal
```

All thresholds are **configurable** in [`src/detection/rule_detector.py`](src/detection/rule_detector.py).

---

## 🏗️ Architecture

```
UNSW-NB15_1.csv
       │
       ▼
┌─────────────────┐
│   CSV Parser    │  → Chunked reading (100k rows/chunk), loads only needed columns
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│  Feature Extractor  │  → Groups by srcip: connections, unique_destinations,
└────────┬────────────┘    unique_ports, scan_rate
         │
         ▼
┌──────────────────┐
│  Rule Detector   │  → Checks 3 rules → "Normal" or "Backdoor/Analysis"
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Risk Engine     │  → Weighted score (0–100) + Severity label
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────┐
│  Output: Console + CSV Report    │
│  Dashboard: Streamlit (Port 8501)│
└──────────────────────────────────┘
```

---

## 📁 Project Structure

```
Network-Bouncer-Ai/
│
├── network_bouncer.py              ← Main entry point
├── requirements.txt
├── README.md
│
├── data/                           ← ⚠️ Place dataset here (see setup)
│   └── UNSW-NB15_1.csv            ← NOT included (download from Kaggle)
│
├── reports/                        ← Auto-generated after running
│   └── suspicious_report.csv
│
└── src/
    ├── main.py                     ← Orchestrates the full pipeline
    ├── parser/
    │   └── csv_parser.py          ← Memory-efficient chunked CSV reader
    ├── features/
    │   └── feature_extractor.py   ← Per-IP behavior analysis
    ├── detection/
    │   ├── rule_detector.py       ← Core rule-based detection logic
    │   └── risk_engine.py         ← Risk scoring & severity classification
    └── dashboard/
        └── dashboard.py           ← Streamlit interactive dashboard
```

---

## ⚙️ Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/vamsi313/Network-Bouncer-Ai.git
cd Network-Bouncer-Ai
```

### 2. Install Dependencies
```bash
pip install pandas scikit-learn plotly streamlit
```

### 3. ⚠️ Download the Dataset

The dataset is **not included** in this repo (161MB — too large for GitHub).

> **Download UNSW-NB15_1.csv from Kaggle:**
> 👉 https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15

After downloading, place the file here:
```
Network-Bouncer-Ai/
└── data/
    └── UNSW-NB15_1.csv   ← place it here
```

---

##  How to Run

### Step 1 — Run the Analysis Engine
```bash
python network_bouncer.py
```
This reads the dataset, detects all suspicious IPs, and saves the report to `reports/suspicious_report.csv`.

**Example Output:**
```
Loading dataset...
  Dataset loaded: 700,001 rows

Extracting features per source IP...
  Features extracted for 40 unique source IPs.

==================================================
   NETWORK BOUNCER AI — THREAT REPORT
==================================================

Total IPs Analysed : 40
Suspicious IPs     : 12
Normal IPs         : 28

[ALERT] SUSPICIOUS ACTIVITY DETECTED:

  Source IP          : 59.166.0.2
  Connections        : 67,209
  Unique Destinations: 10
  Unique Ports       : 20,322
  Scan Rate          : 2.36 conn/sec
  Classification     : Backdoor/Analysis
  Risk Score         : 66.73
  Severity           : High
```

### Step 2 — Launch the Interactive Dashboard
```bash
python -m streamlit run src/dashboard/dashboard.py
```
Open your browser → **http://localhost:8501**

---

## 📊 Dashboard Preview

The dashboard includes:
- **Metric Cards** — Total IPs, Suspicious count, Critical & High severity counts
- **Traffic Classification Chart** — Normal vs Backdoor/Analysis (Donut chart)
- **Top Risk Scores** — Bar chart of most dangerous IPs
- **Scan Rate Analysis** — Connections-per-second bar chart
- **Severity Breakdown** — Donut chart by severity level
- **Active Threats Watchlist** — Color-coded sortable table
- **Full Report Table** — All 40 IPs with all metrics
- **CSV Export Button** — Download the full report

---

## 📂 Dataset

| Field | Detail |
|---|---|
| **Name** | UNSW-NB15 |
| **Source** | Australian Centre for Cyber Security (ACCS) |
| **Kaggle** | https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15 |
| **File Used** | `UNSW-NB15_1.csv` (~700,000 rows) |
| **Key Columns Used** | `srcip`, `dstip`, `dsport`, `Stime`, `Ltime`, `attack_cat`, `Label` |

---

## 🔑 Key Design Decisions

| Decision | Reasoning |
|---|---|
| **Rule-based over ML** | Explainable, transparent, and simple — perfect for a SOC analyst who needs to trust and understand the output |
| **Chunked CSV reading** | Handles 160MB+ files without crashing — avoids loading full dataset into memory |
| **Only load needed columns** | Reduces memory footprint by ~90% compared to loading all 49 columns |
| **Configurable thresholds** | Allows tuning of sensitivity to reduce false positives in high-traffic environments |
| **Streamlit dashboard** | Gives a clean, actionable view for a security analyst working under time pressure |

---

## 🎯 Hackathon Evaluation Coverage

| Criteria | Implementation |
|---|---|
| Problem Understanding | Port scanning detected via East-West traffic analysis |
| User Thinking | Output designed for SOC analysts — clear IP, ports, rate, classification |
| Architecture | Clean pipeline: Parse → Extract → Detect → Score → Report → Dashboard |
| Logic | 3 transparent, configurable rules with risk scoring |
| Resilience | `on_bad_lines='skip'`, null handling, try/except throughout |
| Reporting | Console output + CSV report + interactive dashboard |
| Scalability | Chunked reading handles large files efficiently |
| Tradeoffs | Rule-based chosen for explainability over ML black-box |
| Explainability | Every rule and weight is documented and readable |

---

## 👨‍💻 Technologies Used

- **Python 3.x**
- **Pandas** — Data processing & groupby analysis
- **Plotly** — Interactive charts
- **Streamlit** — Web dashboard
- **UNSW-NB15 Dataset** — Real-world network traffic logs

---

*Built for the Dell FutureMinds AI Hackathon , By Team Code Pirates*
