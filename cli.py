"""
cli.py — AttackSight Command Line Interface
Main entry point for the AttackSight Purple Team Detection Validation Framework.

Usage:
    python cli.py list
    python cli.py run --technique T1059.001
    python cli.py run --all
    python cli.py run --all --report html
    python cli.py run --technique T1059.001 --mock
"""

import click
import logging
import time
import yaml
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("attacksight")

ATOMICS_DIR = "atomics"
REPORTS_DIR = "reports"

BANNER = """
  ╔═══════════════════════════════════════╗
  ║   🔴🔵  A T T A C K S I G H T  🔵🔴  ║
  ║   Purple Team Detection Validator     ║
  ║   github.com/farouq7assan0o           ║
  ╚═══════════════════════════════════════╝
"""


def get_available_techniques() -> list[str]:
    return sorted([p.stem for p in Path(ATOMICS_DIR).glob("*.yaml")])


def load_atomic(technique_id: str) -> dict:
    path = Path(ATOMICS_DIR) / f"{technique_id}.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


@click.group()
def cli():
    """AttackSight — Purple Team Detection Validation Framework"""
    pass


@cli.command()
def list():
    """List all available ATT&CK techniques."""
    print(BANNER)
    techniques = get_available_techniques()
    if not techniques:
        click.echo("No atomics found in ./atomics directory.")
        return

    click.echo(f"  {'ID':<15} {'Name':<45} {'Tactic'}")
    click.echo("  " + "─" * 75)
    for tid in techniques:
        atomic = load_atomic(tid)
        name = atomic.get("name", "Unknown")[:43]
        tactic = atomic.get("tactic", "Unknown")[:20]
        click.echo(f"  {tid:<15} {name:<45} {tactic}")
    click.echo(f"\n  {len(techniques)} technique(s) available.\n")


@cli.command()
@click.option("--technique", "-t", default=None, help="Technique ID to run (e.g. T1059.001)")
@click.option("--all", "run_all", is_flag=True, default=False, help="Run all available techniques")
@click.option("--report", "-r", type=click.Choice(["html", "json", "both", "none"]), default="both", help="Report format to generate")
@click.option("--mock", is_flag=True, default=False, help="Use mock logs (no real execution, for testing)")
@click.option("--dry-run", is_flag=True, default=False, help="Print commands without executing them")
@click.option("--delay", default=3, type=int, help="Seconds to wait after execution before collecting logs (default: 3)")
def run(technique, run_all, report, mock, dry_run, delay):
    """Execute atomic techniques and validate detection coverage."""
    print(BANNER)

    from engine.executor import execute_technique
    from engine.log_collector import collect_logs_for_technique, mock_logs_for_technique
    from engine.sigma_tester import test_technique
    from engine.reporter import print_console_report, save_html_report, save_json_report

    # Determine which techniques to run
    if run_all:
        techniques = get_available_techniques()
    elif technique:
        techniques = [technique]
    else:
        click.echo("❌ Provide --technique <ID> or use --all")
        return

    if not techniques:
        click.echo("No techniques found.")
        return

    mode = "[DRY RUN]" if dry_run else "[MOCK]" if mock else "[LIVE]"
    click.echo(f"  Mode: {mode}")
    click.echo(f"  Techniques: {', '.join(techniques)}\n")

    all_results = []

    for tid in techniques:
        atomic_path = Path(ATOMICS_DIR) / f"{tid}.yaml"
        if not atomic_path.exists():
            click.echo(f"⚠️  No atomic found for {tid}, skipping.")
            continue

        atomic = load_atomic(tid)
        click.echo(f"▶  [{tid}] {atomic.get('name', '')}")
        click.echo(f"   Tactic: {atomic.get('tactic', 'Unknown')}")

        # Step 1: Execute
        if not mock:
            exec_results = execute_technique(tid, ATOMICS_DIR, dry_run=dry_run)
            for er in exec_results:
                status = "✅" if er.success else "❌"
                click.echo(f"   {status} Payload '{er.payload_name}' — {er.duration_seconds}s")
                if er.stdout:
                    click.echo(f"      Output: {er.stdout[:120]}")
                if er.error:
                    click.echo(f"      Error: {er.error}")

            # Step 2: Wait for logs to be written
            if not dry_run:
                click.echo(f"   ⏳ Waiting {delay}s for log propagation...")
                time.sleep(delay)

        # Step 3: Collect logs
        if mock or dry_run:
            click.echo("   📋 Using mock log events...")
            events = mock_logs_for_technique(atomic)
        else:
            click.echo("   📋 Collecting log events...")
            events = collect_logs_for_technique(atomic)

        click.echo(f"   📊 Collected {len(events)} event(s)")

        # Step 4: Test sigma rules
        result = test_technique(atomic, events, mock=(mock or dry_run))
        all_results.append(result)
        click.echo()

    # Step 5: Report
    print_console_report(all_results)

    if report in ("json", "both"):
        json_path = save_json_report(all_results, REPORTS_DIR)
        click.echo(f"  📄 JSON report: {json_path}")

    if report in ("html", "both"):
        html_path = save_html_report(all_results, REPORTS_DIR)
        click.echo(f"  🌐 HTML report: {html_path}")


@cli.command()
@click.argument("technique_id")
def info(technique_id):
    """Show details for a specific technique."""
    path = Path(ATOMICS_DIR) / f"{technique_id}.yaml"
    if not path.exists():
        click.echo(f"❌ Technique {technique_id} not found.")
        return

    atomic = load_atomic(technique_id)
    click.echo(f"\n  ID:          {atomic.get('technique_id')}")
    click.echo(f"  Name:        {atomic.get('name')}")
    click.echo(f"  Tactic:      {atomic.get('tactic')}")
    click.echo(f"  Platforms:   {', '.join(atomic.get('platforms', []))}")
    click.echo(f"  Description: {atomic.get('description', '').strip()[:120]}")
    click.echo(f"\n  Payloads ({len(atomic.get('payloads', []))}):")
    for p in atomic.get("payloads", []):
        click.echo(f"    • [{p.get('executor')}] {p.get('name')}")
    click.echo(f"\n  Sigma Rules:")
    for r in atomic.get("sigma_rules", []):
        exists = "✅" if Path(r).exists() else "❌ (missing)"
        click.echo(f"    • {r} {exists}")
    click.echo(f"\n  MITRE URL: {atomic.get('mitre', {}).get('url', 'N/A')}\n")


if __name__ == "__main__":
    cli()
