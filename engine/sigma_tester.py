"""
sigma_tester.py — AttackSight Sigma Rule Tester
Tests collected log events against Sigma rules to determine detection coverage.
"""

import logging
import subprocess
import json
import re
import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from enum import Enum

logger = logging.getLogger("attacksight.sigma_tester")


class DetectionStatus(str, Enum):
    DETECTED  = "DETECTED"
    MISSED    = "MISSED"
    PARTIAL   = "PARTIAL"
    NO_LOGS   = "NO_LOGS"
    NO_RULES  = "NO_RULES"
    ERROR     = "ERROR"


@dataclass
class RuleResult:
    rule_path: str
    rule_title: str
    matched: bool
    match_reason: str
    events_tested: int


@dataclass
class TechniqueResult:
    technique_id: str
    technique_name: str
    tactic: str
    status: DetectionStatus
    rule_results: list[RuleResult]
    events_collected: int
    total_rules_tested: int
    matched_rules: int
    notes: str = ""


def load_sigma_rule(rule_path: str) -> Optional[dict]:
    """Load and parse a Sigma rule YAML file."""
    path = Path(rule_path)
    if not path.exists():
        logger.warning(f"Sigma rule not found: {rule_path}")
        return None
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to parse Sigma rule {rule_path}: {e}")
        return None


def get_rule_title(rule: dict) -> str:
    return rule.get("title", "Unknown Rule") if rule else "Unknown Rule"


def keyword_match_events(events: list[dict], rule: dict) -> tuple[bool, str]:
    """
    Lightweight keyword-based Sigma matching.
    Checks if rule detection keywords appear in event messages/fields.
    This is a simplified matcher — for production use sigma-cli.
    """
    if not rule or not events:
        return False, "No events or rule to match"

    detection = rule.get("detection", {})
    keywords = []

    # Extract keywords from Sigma detection block
    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue
        if isinstance(value, list):
            keywords.extend([str(v).lower() for v in value])
        elif isinstance(value, dict):
            for v in value.values():
                if isinstance(v, list):
                    keywords.extend([str(i).lower() for i in v])
                elif isinstance(v, str):
                    keywords.append(v.lower())
        elif isinstance(value, str):
            keywords.append(value.lower())

    if not keywords:
        return False, "No keywords extracted from rule"

    # Check each event's message and fields for keywords
    for event in events:
        message = str(event.get("Message", "")).lower()
        # Also check field hints if present
        hints = str(event.get("_field_hints", "")).lower()
        combined = message + " " + hints

        matched_kws = [kw for kw in keywords if kw in combined]
        if matched_kws:
            return True, f"Matched keywords: {matched_kws[:3]}"

    return False, f"No events matched keywords: {keywords[:5]}"


def test_with_sigma_cli(events: list[dict], rule_path: str) -> tuple[bool, str]:
    """
    Use sigma-cli to test events against a rule if sigma-cli is installed.
    Falls back to keyword matching if not available.
    """
    try:
        # Check if sigma-cli is available
        result = subprocess.run(
            ["sigma", "--version"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            raise FileNotFoundError("sigma-cli not available")

        # Write events to temp file for sigma-cli
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(events, f)
            tmp_path = f.name

        try:
            result = subprocess.run(
                ["sigma", "check", rule_path, "--events", tmp_path, "--output", "json"],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout.strip()
            matched = "match" in output.lower() or result.returncode == 0
            return matched, f"sigma-cli result: {output[:100]}"
        finally:
            os.unlink(tmp_path)

    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fall back to keyword matching
        return None, "sigma-cli not found, using keyword matching"


def test_rule_against_events(
    rule_path: str,
    events: list[dict],
    mock: bool = False,
) -> RuleResult:
    """Test a single Sigma rule against collected events."""
    rule = load_sigma_rule(rule_path)
    title = get_rule_title(rule)

    if not rule:
        return RuleResult(
            rule_path=rule_path,
            rule_title="Rule not found",
            matched=False,
            match_reason="Rule file not found or could not be parsed",
            events_tested=len(events),
        )

    if not events:
        return RuleResult(
            rule_path=rule_path,
            rule_title=title,
            matched=False,
            match_reason="No events collected to test against",
            events_tested=0,
        )

    # Try sigma-cli first, fall back to keyword matching
    sigma_result, sigma_reason = test_with_sigma_cli(events, rule_path)

    if sigma_result is not None:
        matched = sigma_result
        reason = sigma_reason
    else:
        # Keyword-based fallback
        matched, reason = keyword_match_events(events, rule)
        if mock:
            # In mock mode, simulate detection based on field hints matching rule
            matched = _mock_match(rule, events)
            reason = "Mock mode: simulated detection" if matched else "Mock mode: simulated miss"

    return RuleResult(
        rule_path=rule_path,
        rule_title=title,
        matched=matched,
        match_reason=reason,
        events_tested=len(events),
    )


def _mock_match(rule: dict, events: list[dict]) -> bool:
    """In mock mode, check if field hints in events align with rule detection fields."""
    for event in events:
        hints = event.get("_field_hints", {})
        detection = rule.get("detection", {})
        for key, val in detection.items():
            if key == "condition":
                continue
            if isinstance(val, dict):
                for field, fval in val.items():
                    for hint_val in hints.values():
                        if isinstance(fval, str) and hint_val and fval.lower() in str(hint_val).lower():
                            return True
    return False


def determine_status(rule_results: list[RuleResult], events_collected: int) -> DetectionStatus:
    """Determine overall detection status for a technique."""
    if not rule_results:
        return DetectionStatus.NO_RULES
    if events_collected == 0:
        return DetectionStatus.NO_LOGS

    matched = sum(1 for r in rule_results if r.matched)
    total = len(rule_results)

    if matched == total:
        return DetectionStatus.DETECTED
    elif matched == 0:
        return DetectionStatus.MISSED
    else:
        return DetectionStatus.PARTIAL


def test_technique(
    atomic: dict,
    events: list[dict],
    mock: bool = False,
) -> TechniqueResult:
    """Run all Sigma rules for a technique against collected events."""
    technique_id = atomic.get("technique_id", "unknown")
    technique_name = atomic.get("name", "Unknown Technique")
    tactic = atomic.get("tactic", "Unknown")
    rule_paths = atomic.get("sigma_rules", [])

    logger.info(f"[{technique_id}] Testing {len(rule_paths)} Sigma rule(s) against {len(events)} event(s)...")

    rule_results = []
    for rule_path in rule_paths:
        result = test_rule_against_events(rule_path, events, mock=mock)
        rule_results.append(result)
        icon = "✅" if result.matched else "❌"
        logger.info(f"  {icon} Rule '{result.rule_title}': {result.match_reason}")

    matched_count = sum(1 for r in rule_results if r.matched)
    status = determine_status(rule_results, len(events))

    return TechniqueResult(
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        status=status,
        rule_results=rule_results,
        events_collected=len(events),
        total_rules_tested=len(rule_results),
        matched_rules=matched_count,
        notes=_build_notes(status, rule_results),
    )


def _build_notes(status: DetectionStatus, rule_results: list[RuleResult]) -> str:
    if status == DetectionStatus.DETECTED:
        return "All Sigma rules matched. Detection coverage confirmed."
    elif status == DetectionStatus.MISSED:
        missing = [r.rule_title for r in rule_results if not r.matched]
        return f"No rules matched. Missing coverage for: {', '.join(missing)}"
    elif status == DetectionStatus.PARTIAL:
        missing = [r.rule_title for r in rule_results if not r.matched]
        return f"Partial coverage. Rules without matches: {', '.join(missing)}"
    elif status == DetectionStatus.NO_LOGS:
        return "No logs were collected. Check Sysmon installation and log source config."
    elif status == DetectionStatus.NO_RULES:
        return "No Sigma rules defined for this technique."
    return ""
