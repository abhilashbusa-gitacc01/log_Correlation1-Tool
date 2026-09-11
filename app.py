import streamlit as st
import pandas as pd


# ── Page Config ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ACLT — Automated Log Correlation Tool",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom Dark Theme CSS ───────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    .stApp {
        font-family: 'Inter', sans-serif;
    }

    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        background: linear-gradient(135deg, #3b82f6, #10b981);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0;
    }

    .subtitle {
        font-size: 1rem;
        color: #94a3b8;
        margin-top: 4px;
        margin-bottom: 24px;
    }

    .metric-row {
        display: flex;
        gap: 16px;
        margin: 20px 0;
    }

    .metric-box {
        flex: 1;
        background: rgba(15, 23, 42, 0.6);
        border: 1px solid rgba(30, 58, 138, 0.4);
        border-radius: 14px;
        padding: 18px;
        text-align: center;
        backdrop-filter: blur(8px);
    }

    .metric-box .metric-val {
        font-size: 2rem;
        font-weight: 800;
        color: #60a5fa;
    }

    .metric-box .metric-label {
        font-size: 0.78rem;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-top: 4px;
    }

    .alert-card {
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(30, 58, 138, 0.35);
        border-left: 4px solid;
        border-radius: 12px;
        padding: 16px 20px;
        margin-bottom: 12px;
        backdrop-filter: blur(8px);
    }

    .alert-card.high {
        border-left-color: #ef4444;
    }

    .alert-card.medium {
        border-left-color: #f59e0b;
    }

    .alert-card .alert-type {
        font-size: 1rem;
        font-weight: 700;
        margin-bottom: 4px;
    }

    .alert-card.high .alert-type {
        color: #fca5a5;
    }

    .alert-card.medium .alert-type {
        color: #fde68a;
    }

    .alert-card .alert-severity {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }

    .alert-card.high .alert-severity {
        background: rgba(239, 68, 68, 0.15);
        color: #fca5a5;
        border: 1px solid rgba(239, 68, 68, 0.4);
    }

    .alert-card.medium .alert-severity {
        background: rgba(245, 158, 11, 0.15);
        color: #fde68a;
        border: 1px solid rgba(245, 158, 11, 0.4);
    }

    .alert-card .alert-reason {
        font-size: 0.88rem;
        color: #94a3b8;
        margin-top: 8px;
        line-height: 1.5;
    }

    .section-header {
        font-size: 1.15rem;
        font-weight: 700;
        color: #e2e8f0;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .stDataFrame {
        border-radius: 12px !important;
    }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🔍 ACLT")
    st.markdown("**Automated Log Correlation Tool**")
    st.markdown("---")
    st.markdown("""
    **Detection Rules:**
    - 🔴 **Brute Force** — 5+ failed logins → success from same IP
    - 🟡 **Suspicious Access** — Login followed by file download
    """)
    st.markdown("---")
    st.markdown("""
    **Expected CSV Columns:**
    - `event` — login_failed, login_success, file_download
    - `ip` — Source IP address
    - `user` — Username
    """)
    st.markdown("---")
    st.caption("Built for SOC Analysts & Incident Response Teams")


# ── Main Content ────────────────────────────────────────────────────────────
st.markdown('<h1 class="main-title">🔍 Automated Log Correlation Tool</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">SOC Log Analysis Dashboard — Upload CSV logs to detect brute force attacks and suspicious file access patterns</p>', unsafe_allow_html=True)


# ── Correlation Engine ──────────────────────────────────────────────────────
def correlate_logs(df):
    alerts = []

    # Rule 1: Brute Force Detection
    failed_logins = df[df["event"] == "login_failed"]
    for ip, group in failed_logins.groupby("ip"):
        if len(group) >= 5:
            success_login = df[
                (df["ip"] == ip) &
                (df["event"] == "login_success")
            ]
            if not success_login.empty:
                alerts.append({
                    "type": "Brute Force Login Attack",
                    "severity": "High",
                    "reason": f"5+ failed logins followed by success from IP {ip}"
                })

    # Rule 2: Suspicious File Access
    for user in df["user"].unique():
        user_events = df[df["user"] == user]["event"].tolist()
        if "login_success" in user_events and "file_download" in user_events:
            alerts.append({
                "type": "Suspicious File Access",
                "severity": "Medium",
                "reason": f"Login followed by file download by user: {user}"
            })

    return alerts


# ── File Upload ─────────────────────────────────────────────────────────────
uploaded_file = st.file_uploader(
    "📂 Upload log file (CSV format)",
    type=["csv"],
    help="Upload a CSV file with columns: event, ip, user"
)

if uploaded_file is not None:
    logs = pd.read_csv(uploaded_file)

    # Normalize columns
    logs.columns = logs.columns.str.lower()
    logs["event"] = logs["event"].str.lower().str.strip()
    logs["user"] = logs["user"].str.lower().str.strip()
    logs["ip"] = logs["ip"].str.strip()

    # Log Statistics
    total_events = len(logs)
    unique_ips = logs["ip"].nunique()
    unique_users = logs["user"].nunique()
    failed_count = len(logs[logs["event"] == "login_failed"])

    st.markdown(f"""
    <div class="metric-row">
        <div class="metric-box">
            <div class="metric-val">{total_events}</div>
            <div class="metric-label">Total Events</div>
        </div>
        <div class="metric-box">
            <div class="metric-val">{unique_ips}</div>
            <div class="metric-label">Unique IPs</div>
        </div>
        <div class="metric-box">
            <div class="metric-val">{unique_users}</div>
            <div class="metric-label">Unique Users</div>
        </div>
        <div class="metric-box">
            <div class="metric-val" style="color: #ef4444;">{failed_count}</div>
            <div class="metric-label">Failed Logins</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Display logs
    st.markdown('<div class="section-header">📋 Uploaded Logs</div>', unsafe_allow_html=True)
    st.dataframe(logs, use_container_width=True, height=280)

    # Analyze
    if st.button("🔍 Analyze Logs", type="primary", use_container_width=True):
        st.markdown("---")
        st.markdown('<div class="section-header">🚨 Security Alerts</div>', unsafe_allow_html=True)

        alerts = correlate_logs(logs)

        if not alerts:
            st.success("✅ No suspicious activity detected — all clear!")
        else:
            st.info(f"🔔 **{len(alerts)} alert(s) detected** — review findings below")

            for alert in alerts:
                severity_class = "high" if alert["severity"] == "High" else "medium"
                icon = "🚨" if alert["severity"] == "High" else "⚠️"

                st.markdown(f"""
                <div class="alert-card {severity_class}">
                    <div class="alert-type">{icon} {alert['type']}</div>
                    <span class="alert-severity">{alert['severity']}</span>
                    <div class="alert-reason">{alert['reason']}</div>
                </div>
                """, unsafe_allow_html=True)

else:
    # Empty state
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div style="text-align: center; padding: 48px 0; color: #64748b;">
            <div style="font-size: 3rem; margin-bottom: 12px; opacity: 0.4;">📋</div>
            <p style="font-size: 1rem;">Upload a CSV log file to get started</p>
            <p style="font-size: 0.82rem; color: #475569;">Supports files with event, ip, and user columns</p>
        </div>
        """, unsafe_allow_html=True)