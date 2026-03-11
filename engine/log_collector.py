"""
log_collector.py — AttackSight Log Collector
Captures Windows Event Log and Sysmon events generated after atomic execution.
"""

import logging
import platform
import subprocess
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger("attacksight.log_collector")


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def collect_windows_events(
    log_source: str,
    event_id: int,
    minutes_back: int = 2,
    max_events: int = 50,
) -> list[dict]:
    """
    Collect Windows Event Log / Sysmon events using PowerShell Get-WinEvent.
    Returns a list of event dicts.
    """
    if not is_windows():
        logger.warning("Windows event collection skipped (not on Windows).")
        return []

    since = (datetime.now() - timedelta(minutes=minutes_back)).strftime("%Y-%m-%dT%H:%M:%S")

    ps_script = f"""
    $events = Get-WinEvent -LogName '{log_source}' -MaxEvents {max_events} -ErrorAction SilentlyContinue |
        Where-Object {{ $_.Id -eq {event_id} -and $_.TimeCreated -gt '{since}' }};
    if ($events) {{
        $events | ForEach-Object {{
            [PSCustomObject]@{{
                EventId    = $_.Id
                TimeCreated = $_.TimeCreated.ToString('o')
                Message    = $_.Message
                LogSource  = $_.LogName
                MachineName = $_.MachineName
            }}
        }} | ConvertTo-Json -Depth 3
    }} else {{
        '[]'
    }}
    """

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=20,
        )
        raw = result.stdout.strip()
        if not raw or raw == "[]":
            return []

        # PowerShell may return a single object (dict) instead of array
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
        return parsed

    except json.JSONDecodeError as e:
        logger.warning(f"Could not parse event JSON from {log_source} EID {event_id}: {e}")
        return []
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout collecting events from {log_source}")
        return []
    except Exception as e:
        logger.error(f"Event collection error: {e}")
        return []


def collect_syslog_events(keyword: str, minutes_back: int = 2) -> list[dict]:
    """
    Collect Linux syslog entries matching a keyword (for Linux technique support).
    """
    if is_windows():
        return []

    results = []
    log_paths = ["/var/log/syslog", "/var/log/messages", "/var/log/auth.log"]

    since = datetime.now() - timedelta(minutes=minutes_back)

    for log_path in log_paths:
        path = Path(log_path)
        if not path.exists():
            continue
        try:
            with open(path, "r", errors="ignore") as f:
                for line in f:
                    if keyword.lower() in line.lower():
                        results.append({
                            "source": log_path,
                            "message": line.strip(),
                            "raw": True,
                        })
        except PermissionError:
            logger.warning(f"Permission denied reading {log_path}")

    return results


def collect_logs_for_technique(atomic: dict, minutes_back: int = 2) -> list[dict]:
    """
    Given an atomic definition, collect all expected log sources and event IDs.
    Returns a flat list of collected log events.
    """
    technique_id = atomic.get("technique_id", "unknown")
    expected_logs = atomic.get("expected_logs", [])
    all_events = []

    for expected in expected_logs:
        source = expected.get("source", "")
        event_id = expected.get("event_id")
        field_hints = expected.get("field_hints", {})

        logger.info(f"[{technique_id}] Collecting: {source} EID {event_id}")

        if is_windows() and event_id:
            events = collect_windows_events(source, event_id, minutes_back=minutes_back)
            # Tag each event with what we were looking for
            for ev in events:
                ev["_expected_source"] = source
                ev["_expected_event_id"] = event_id
                ev["_field_hints"] = field_hints
            all_events.extend(events)
        elif not is_windows():
            # Linux fallback: search syslog for technique ID as keyword
            events = collect_syslog_events(technique_id, minutes_back=minutes_back)
            all_events.extend(events)

    logger.info(f"[{technique_id}] Collected {len(all_events)} total events.")
    return all_events


def mock_logs_for_technique(atomic: dict) -> list[dict]:
    """
    Generate mock/synthetic log events for testing the sigma tester
    without needing a real Windows environment.
    Used when --mock flag is passed.
    """
    technique_id = atomic.get("technique_id", "unknown")
    expected_logs = atomic.get("expected_logs", [])
    mock_events = []

    for expected in expected_logs:
        source = expected.get("source", "MockSource")
        event_id = expected.get("event_id", 0)
        field_hints = expected.get("field_hints", {})

        mock_event = {
            "EventId": event_id,
            "LogSource": source,
            "TimeCreated": datetime.now().isoformat(),
            "MachineName": "ATTACKSIGHT-LAB",
            "Message": f"[MOCK] Technique {technique_id} simulated event. " +
                       " ".join(f"{k}: {v}" for k, v in field_hints.items()),
            "_expected_source": source,
            "_expected_event_id": event_id,
            "_field_hints": field_hints,
            "_mock": True,
        }
        mock_events.append(mock_event)

    logger.info(f"[{technique_id}] Generated {len(mock_events)} mock events.")
    return mock_events
