import pandas as pd
import pytest
from analyzer import normalize_events, detect_alerts, demo_events, alerts_frame

def test_demo_alerts():
    events = demo_events()
    alerts = detect_alerts(events)
    assert any(a.category == "Repeated login failures" and a.source_ip == "192.0.2.10" for a in alerts)
    assert any(a.category == "High event volume" and a.source_ip == "198.51.100.20" for a in alerts)
    assert not alerts_frame(alerts).empty

def test_invalid_columns():
    with pytest.raises(ValueError, match="Missing"):
        normalize_events(pd.DataFrame({"timestamp": ["2026-01-01"]}))

def test_invalid_timestamp():
    frame = pd.DataFrame([{"timestamp": "not a date", "source_ip": "192.0.2.1", "event_type": "login", "status": "failure"}])
    with pytest.raises(ValueError, match="timestamps"):
        normalize_events(frame)

def test_no_alerts():
    events = normalize_events(pd.DataFrame([
        {"timestamp": "2026-01-01T00:00:00Z", "source_ip": "192.0.2.1", "event_type": "login", "status": "success"}
    ]))
    assert detect_alerts(events) == []

def test_threshold_validation():
    with pytest.raises(ValueError):
        detect_alerts(demo_events(), failure_threshold=0)
