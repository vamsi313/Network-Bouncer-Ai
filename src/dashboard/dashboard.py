import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

# ----------------------------
# Page Configuration
# ----------------------------
st.set_page_config(
    page_title="Network Bouncer AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ----------------------------
# Custom Premium CSS
# ----------------------------
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }

    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
        color: #e2e8f0;
    }

    .title-text {
        background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 3.5rem;
        font-weight: 800;
        text-align: center;
        margin-bottom: 0px;
        padding-bottom: 0px;
    }

    .subtitle-text {
        text-align: center;
        color: #94a3b8;
        font-size: 1.2rem;
        margin-top: 0px;
        margin-bottom: 40px;
        font-weight: 300;
    }

    .metric-card {
        background: rgba(30, 41, 59, 0.7);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 15px;
        padding: 20px;
        text-align: center;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 12px 40px 0 rgba(56, 189, 248, 0.2);
        border: 1px solid rgba(56, 189, 248, 0.4);
    }
    .metric-value { font-size: 2.5rem; font-weight: 800; margin: 10px 0; }
    .metric-label { color: #94a3b8; font-size: 1rem; text-transform: uppercase; letter-spacing: 1px; }

    .val-total     { color: #38bdf8; }
    .val-suspicious{ color: #fbbf24; }
    .val-critical  { color: #ef4444; text-shadow: 0 0 10px rgba(239,68,68,0.5); }
    .val-high      { color: #f97316; }

    .block-container { padding-top: 2rem !important; max-width: 1400px; }

    hr { border-color: rgba(255,255,255,0.05); margin: 3rem 0; }

    /* Transparent header */
    header[data-testid="stHeader"] { background-color: transparent !important; }

    /* Hide Deploy button */
    .stDeployButton,
    .stAppDeployButton,
    [data-testid="stDeployButton"] {
        display: none !important;
        visibility: hidden !important;
    }
</style>
""", unsafe_allow_html=True)

# ----------------------------
# Header
# ----------------------------
st.markdown('<div class="title-text">🛡️ Network Bouncer AI</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle-text">Rule-Based Port Scanning Detection · UNSW-NB15 Dataset · Data Center Threat Intelligence</div>', unsafe_allow_html=True)

# ----------------------------
# Load Report
# ----------------------------
@st.cache_data
def load_report():
    BASE_DIR = Path(__file__).resolve().parent.parent.parent
    REPORT_PATH = BASE_DIR / "reports" / "suspicious_report.csv"
    try:
        return pd.read_csv(REPORT_PATH)
    except FileNotFoundError:
        return None
    except Exception:
        return None

df = load_report()

if df is None:
    st.error("🚨 Report not found. Run `python network_bouncer.py` first.")
    st.stop()

# ----------------------------
# Compute Metrics
# ----------------------------
total_ips    = len(df)
suspicious   = len(df[df["final_verdict"] == "Backdoor/Analysis"])
normal_count = total_ips - suspicious
critical_ips = len(df[df["severity"] == "Critical"])
high_ips     = len(df[df["severity"] == "High"])

# ----------------------------
# Top Metric Cards
# ----------------------------
c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f'''
    <div class="metric-card">
        <div class="metric-label">Total Source IPs</div>
        <div class="metric-value val-total">{total_ips:,}</div>
    </div>''', unsafe_allow_html=True)

with c2:
    st.markdown(f'''
    <div class="metric-card">
        <div class="metric-label">Suspicious (Backdoor/Analysis)</div>
        <div class="metric-value val-suspicious">{suspicious:,}</div>
    </div>''', unsafe_allow_html=True)

with c3:
    st.markdown(f'''
    <div class="metric-card">
        <div class="metric-label">Critical Threats</div>
        <div class="metric-value val-critical">{critical_ips:,}</div>
    </div>''', unsafe_allow_html=True)

with c4:
    st.markdown(f'''
    <div class="metric-card">
        <div class="metric-label">High Severity</div>
        <div class="metric-value val-high">{high_ips:,}</div>
    </div>''', unsafe_allow_html=True)

st.markdown("<hr>", unsafe_allow_html=True)

# ----------------------------
# Prepare chart data
# ----------------------------
top = df.sort_values(by="risk_score", ascending=False).head(10)

sev_colors = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#eab308",
    "Low":      "#22c55e",
    "Normal":   "#3b82f6"
}

verdict_colors = {
    "Backdoor/Analysis": "#ef4444",
    "Normal":            "#3b82f6"
}

# ----------------------------
# Row 1: Pie + Bar (Risk Score)
# ----------------------------
c1, c2 = st.columns(2)

with c1:
    st.markdown("### 📊 Traffic Classification")
    fig_pie = px.pie(
        df,
        names="final_verdict",
        color="final_verdict",
        color_discrete_map=verdict_colors,
        title="Normal vs Backdoor/Analysis",
        hole=0.45,
        template="plotly_dark"
    )
    fig_pie.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Outfit", color="#94a3b8")
    )
    st.plotly_chart(fig_pie, use_container_width=True)

with c2:
    st.markdown("### 📈 Top Risk Scores by Source IP")
    risk_fig = px.bar(
        top,
        x="srcip",
        y="risk_score",
        color="severity",
        color_discrete_map=sev_colors,
        title="Top Suspicious IPs by Risk Score",
        template="plotly_dark"
    )
    risk_fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Outfit", color="#94a3b8"),
        xaxis_tickangle=-30
    )
    st.plotly_chart(risk_fig, use_container_width=True)

# ----------------------------
# Row 2: Scan Rate + Severity
# ----------------------------
c3, c4 = st.columns(2)

with c3:
    if "scan_rate" in df.columns:
        st.markdown("### ⚡ Scan Rate Analysis (Connections/sec)")
        scan_fig = px.bar(
            top,
            x="srcip",
            y="scan_rate",
            color="severity",
            color_discrete_map=sev_colors,
            title="Connections Per Second (Scan Rate)",
            template="plotly_dark"
        )
        scan_fig.update_layout(
            plot_bgcolor="rgba(0,0,0,0)",
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Outfit", color="#94a3b8"),
            xaxis_tickangle=-30
        )
        st.plotly_chart(scan_fig, use_container_width=True)

with c4:
    st.markdown("### 🔥 Severity Distribution")
    sev_fig = px.pie(
        df,
        names="severity",
        color="severity",
        color_discrete_map=sev_colors,
        title="Threat Severity Breakdown",
        hole=0.4,
        template="plotly_dark"
    )
    sev_fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Outfit", color="#94a3b8")
    )
    st.plotly_chart(sev_fig, use_container_width=True)

st.markdown("<hr>", unsafe_allow_html=True)

# ----------------------------
# Suspicious IPs Watchlist
# ----------------------------
st.markdown("### 🚨 Top Suspicious IPs Watchlist")

def highlight_severity(val):
    if val == "Critical":         return "background-color:rgba(239,68,68,0.2);color:#ef4444;font-weight:bold;"
    if val == "High":             return "background-color:rgba(249,115,22,0.2);color:#f97316;font-weight:bold;"
    if val == "Medium":           return "background-color:rgba(234,179,8,0.2);color:#eab308;font-weight:bold;"
    if val == "Low":              return "color:#22c55e;"
    return ""

def highlight_verdict(val):
    if val == "Backdoor/Analysis": return "color:#ef4444;font-weight:bold;"
    return "color:#3b82f6;"

cols = ["srcip", "connections", "unique_destinations", "unique_ports",
        "scan_rate", "classification", "risk_score", "severity", "final_verdict"]
available = [c for c in cols if c in top.columns]

styled_df = top[available].style \
    .map(highlight_severity, subset=["severity"]) \
    .map(highlight_verdict, subset=["final_verdict"]) \
    .format({"risk_score": "{:.2f}", "scan_rate": "{:.2f}/s"})

st.dataframe(styled_df, use_container_width=True, hide_index=True, height=400)

st.markdown("<hr>", unsafe_allow_html=True)

# ----------------------------
# Full Threat Report Table
# ----------------------------
st.markdown("### 📄 Complete Threat Report")
st.dataframe(df, use_container_width=True)

# ----------------------------
# Download Button
# ----------------------------
st.markdown("<br>", unsafe_allow_html=True)
csv = df.to_csv(index=False)
st.download_button(
    label="⬇️ Download Full Suspicious Report (CSV)",
    data=csv,
    file_name="suspicious_report.csv",
    mime="text/csv"
)