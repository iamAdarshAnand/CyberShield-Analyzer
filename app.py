"""Streamlit dashboard for defensive security event analysis."""
import pandas as pd
import streamlit as st
from analyzer import normalize_events, detect_alerts, alerts_frame, demo_events

st.set_page_config(page_title="CyberShield Analyzer", page_icon="🛡️", layout="wide")
st.title("🛡️ CyberShield Analyzer")
st.caption("Defensive log analytics • transparent detection rules • local-first processing")

with st.sidebar:
    st.header("Analysis settings")
    file = st.file_uploader("Security event CSV", type=["csv"])
    failure_threshold = st.slider("Failed logins threshold", 2, 30, 5)
    volume_threshold = st.slider("Volume threshold", 5, 200, 30)
    window_minutes = st.slider("Window (minutes)", 1, 60, 5)

try:
    events = normalize_events(pd.read_csv(file)) if file else demo_events()
except (ValueError, pd.errors.ParserError, UnicodeDecodeError) as exc:
    st.error(f"Could not parse log file: {exc}")
    st.stop()

alerts = detect_alerts(events, failure_threshold, volume_threshold, window_minutes)
findings = alerts_frame(alerts)
a, b, c = st.columns(3)
a.metric("Total events", len(events))
b.metric("Unique sources", events["source_ip"].nunique())
c.metric("Rule alerts", len(alerts))

st.subheader("Event timeline")
timeline = events.set_index("timestamp").resample("1min").size()
st.line_chart(timeline)
left, right = st.columns(2)
with left:
    st.subheader("Top source IPs")
    st.bar_chart(events["source_ip"].value_counts())
with right:
    st.subheader("Event statuses")
    st.bar_chart(events["status"].value_counts())

st.subheader("Detection findings")
if findings.empty:
    st.success("No events exceeded the configured thresholds.")
else:
    st.warning("Heuristic alerts detected; investigate before drawing conclusions.")
    st.dataframe(findings, use_container_width=True)
    st.download_button("Export alerts CSV", findings.to_csv(index=False), "cybershield_alerts.csv", "text/csv")
with st.expander("Inspect normalized events"):
    st.dataframe(events, use_container_width=True)
st.caption("Demo data is synthetic. This application does not confirm intrusions.")
