"""
reporter.py — AttackSight Report Generator
Generates HTML and JSON coverage reports from technique results.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from engine.sigma_tester import TechniqueResult, DetectionStatus

logger = logging.getLogger("attacksight.reporter")

STATUS_ICON = {
    DetectionStatus.DETECTED: "✅",
    DetectionStatus.MISSED:   "❌",
    DetectionStatus.PARTIAL:  "⚠️",
    DetectionStatus.NO_LOGS:  "🔇",
    DetectionStatus.NO_RULES: "📭",
    DetectionStatus.ERROR:    "💥",
}

STATUS_COLOR = {
    DetectionStatus.DETECTED: "#22c55e",
    DetectionStatus.MISSED:   "#ef4444",
    DetectionStatus.PARTIAL:  "#f59e0b",
    DetectionStatus.NO_LOGS:  "#6b7280",
    DetectionStatus.NO_RULES: "#6b7280",
    DetectionStatus.ERROR:    "#8b5cf6",
}


def calculate_score(results: list[TechniqueResult]) -> dict:
    total = len(results)
    detected = sum(1 for r in results if r.status == DetectionStatus.DETECTED)
    partial = sum(1 for r in results if r.status == DetectionStatus.PARTIAL)
    missed = sum(1 for r in results if r.status == DetectionStatus.MISSED)
    score_pct = round((detected / total * 100) if total else 0, 1)
    return {
        "total": total,
        "detected": detected,
        "partial": partial,
        "missed": missed,
        "score_pct": score_pct,
    }


def save_json_report(results: list[TechniqueResult], output_dir: str = "reports") -> str:
    """Save results as a JSON file and return the path."""
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = Path(output_dir) / f"{timestamp}_coverage.json"

    score = calculate_score(results)
    data = {
        "generated_at": datetime.now().isoformat(),
        "score": score,
        "techniques": [
            {
                "technique_id": r.technique_id,
                "technique_name": r.technique_name,
                "tactic": r.tactic,
                "status": r.status.value,
                "events_collected": r.events_collected,
                "total_rules_tested": r.total_rules_tested,
                "matched_rules": r.matched_rules,
                "notes": r.notes,
                "rule_results": [
                    {
                        "rule_path": rr.rule_path,
                        "rule_title": rr.rule_title,
                        "matched": rr.matched,
                        "match_reason": rr.match_reason,
                        "events_tested": rr.events_tested,
                    }
                    for rr in r.rule_results
                ],
            }
            for r in results
        ],
    }

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    logger.info(f"JSON report saved: {path}")
    return str(path)


def save_html_report(results: list[TechniqueResult], output_dir: str = "reports") -> str:
    """Generate and save an HTML coverage report. Returns the file path."""
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = Path(output_dir) / f"{timestamp}_coverage.html"

    score = calculate_score(results)
    html = _build_html(results, score)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"HTML report saved: {path}")
    return str(path)


def print_console_report(results: list[TechniqueResult]):
    """Print a terminal-style coverage report."""
    score = calculate_score(results)
    width = 58

    print("\n" + "╔" + "═" * width + "╗")
    print("║" + "       AttackSight — Detection Coverage Report".center(width) + "║")
    print("╠" + "═" * width + "╣")

    for r in results:
        icon = STATUS_ICON.get(r.status, "?")
        label = f"{r.technique_id}  {r.technique_name[:28]}"
        status_str = f"{icon} {r.status.value}"
        line = f"  {label:<38} {status_str}"
        print("║" + line.ljust(width) + "║")

    print("╠" + "═" * width + "╣")
    summary = f"  Coverage Score: {score['score_pct']}%  ({score['detected']}/{score['total']} detected)"
    print("║" + summary.ljust(width) + "║")
    print("╚" + "═" * width + "╝\n")


def _build_html(results: list[TechniqueResult], score: dict) -> str:
    rows = ""
    for r in results:
        icon = STATUS_ICON.get(r.status, "?")
        color = STATUS_COLOR.get(r.status, "#6b7280")
        rule_detail = ""
        for rr in r.rule_results:
            match_icon = "✅" if rr.matched else "❌"
            rule_detail += f'<div class="rule-row">{match_icon} <code>{Path(rr.rule_path).name}</code> — {rr.match_reason}</div>'

        rows += f"""
        <tr>
          <td><code>{r.technique_id}</code></td>
          <td>{r.technique_name}</td>
          <td><span class="tactic">{r.tactic}</span></td>
          <td style="color:{color}; font-weight:700;">{icon} {r.status.value}</td>
          <td>{r.events_collected}</td>
          <td class="rule-detail">{rule_detail}</td>
          <td class="notes">{r.notes}</td>
        </tr>"""

    score_color = "#22c55e" if score["score_pct"] >= 70 else "#f59e0b" if score["score_pct"] >= 40 else "#ef4444"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AttackSight Coverage Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
    h1 {{ font-size: 1.8rem; color: #f8fafc; margin-bottom: 0.25rem; }}
    .subtitle {{ color: #94a3b8; margin-bottom: 2rem; font-size: 0.9rem; }}
    .score-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem 2rem; margin-bottom: 2rem; display: flex; gap: 3rem; align-items: center; }}
    .score-main {{ font-size: 3rem; font-weight: 800; color: {score_color}; }}
    .score-label {{ color: #94a3b8; font-size: 0.85rem; }}
    .stat {{ text-align: center; }}
    .stat-val {{ font-size: 1.6rem; font-weight: 700; }}
    .stat-label {{ font-size: 0.75rem; color: #94a3b8; }}
    .detected {{ color: #22c55e; }}
    .partial {{ color: #f59e0b; }}
    .missed {{ color: #ef4444; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 12px; overflow: hidden; }}
    th {{ background: #0f172a; padding: 0.75rem 1rem; text-align: left; font-size: 0.8rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
    td {{ padding: 0.85rem 1rem; border-top: 1px solid #1e293b; font-size: 0.88rem; vertical-align: top; }}
    tr:hover {{ background: #263148; }}
    code {{ background: #0f172a; padding: 0.2em 0.5em; border-radius: 4px; font-size: 0.82rem; color: #7dd3fc; }}
    .tactic {{ background: #1e3a5f; color: #7dd3fc; padding: 0.2em 0.6em; border-radius: 4px; font-size: 0.78rem; }}
    .rule-row {{ margin-bottom: 0.3rem; font-size: 0.82rem; color: #94a3b8; }}
    .notes {{ font-size: 0.8rem; color: #94a3b8; max-width: 200px; }}
    .footer {{ margin-top: 2rem; text-align: center; color: #475569; font-size: 0.8rem; }}
    .brand {{ color: #7dd3fc; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>🔴🔵 AttackSight</h1>
  <p class="subtitle">Purple Team Detection Validation Report · Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

  <div class="score-card">
    <div>
      <div class="score-main">{score['score_pct']}%</div>
      <div class="score-label">Detection Coverage Score</div>
    </div>
    <div class="stat"><div class="stat-val detected">{score['detected']}</div><div class="stat-label">Detected</div></div>
    <div class="stat"><div class="stat-val partial">{score['partial']}</div><div class="stat-label">Partial</div></div>
    <div class="stat"><div class="stat-val missed">{score['missed']}</div><div class="stat-label">Missed</div></div>
    <div class="stat"><div class="stat-val">{score['total']}</div><div class="stat-label">Total Techniques</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Technique ID</th>
        <th>Name</th>
        <th>Tactic</th>
        <th>Status</th>
        <th>Events</th>
        <th>Rule Results</th>
        <th>Notes</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <div class="footer">Built by <span class="brand">Farouq Hassan</span> · AttackSight Purple Team Framework</div>
</body>
</html>"""
