"""Defensive security event normalization and rule-based detection."""
from dataclasses import dataclass
import pandas as pd

REQUIRED = ("timestamp", "source_ip", "event_type", "status")

@dataclass(frozen=True)
class Alert:
    source_ip: str
    category: str
    count: int
    window_start: str
    window_end: str

def normalize_events(frame: pd.DataFrame) -> pd.DataFrame:
    missing = set(REQUIRED) - set(frame.columns)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
    events = frame.loc[:, REQUIRED].copy()
    events["timestamp"] = pd.to_datetime(events["timestamp"], utc=True, errors="coerce")
    if events["timestamp"].isna().any():
        raise ValueError("Some timestamps are invalid")
    for column in ("source_ip", "event_type", "status"):
        events[column] = events[column].fillna("").astype(str).str.strip()
    if (events["source_ip"] == "").any():
        raise ValueError("Source IP must not be empty")
    events["event_type"] = events["event_type"].str.lower()
    events["status"] = events["status"].str.lower()
    return events.sort_values("timestamp").reset_index(drop=True)

def _window_alerts(events: pd.DataFrame, category: str, threshold: int, window_minutes: int) -> list[Alert]:
    """One alert per IP when the first qualifying rolling window is found."""
    if threshold < 1 or window_minutes < 1:
        raise ValueError("Threshold and window must be positive")
    findings = []
    window = pd.Timedelta(minutes=window_minutes)
    for ip, group in events.groupby("source_ip", sort=True):
        times = list(group["timestamp"])
        left = 0
        for right, end in enumerate(times):
            while end - times[left] > window:
                left += 1
            count = right - left + 1
            if count >= threshold:
                findings.append(Alert(str(ip), category, count, times[left].isoformat(), end.isoformat()))
                break
    return findings

def detect_alerts(events: pd.DataFrame, failure_threshold: int = 5, volume_threshold: int = 30, window_minutes: int = 5) -> list[Alert]:
    if failure_threshold < 1 or volume_threshold < 1 or window_minutes < 1:
        raise ValueError("Thresholds and window must be positive")
    failures = events[(events["event_type"] == "login") & (events["status"] == "failure")]
    return (
        _window_alerts(failures, "Repeated login failures", failure_threshold, window_minutes)
        + _window_alerts(events, "High event volume", volume_threshold, window_minutes)
    )

def alerts_frame(alerts: list[Alert]) -> pd.DataFrame:
    return pd.DataFrame([alert.__dict__ for alert in alerts], columns=["source_ip", "category", "count", "window_start", "window_end"])

def demo_events() -> pd.DataFrame:
    """Synthetic RFC 5737 documentation IPs; no real user data."""
    base = pd.Timestamp("2026-01-01T10:00:00Z")
    rows = []
    for index in range(12):
        rows.append({"timestamp": base + pd.Timedelta(seconds=index * 20), "source_ip": "192.0.2.10", "event_type": "login", "status": "failure"})
    for index in range(40):
        rows.append({"timestamp": base + pd.Timedelta(seconds=index * 5), "source_ip": "198.51.100.20", "event_type": "request", "status": "success"})
    for index in range(8):
        rows.append({"timestamp": base + pd.Timedelta(minutes=index * 10), "source_ip": "203.0.113.30", "event_type": "login", "status": "success"})
    return normalize_events(pd.DataFrame(rows))
