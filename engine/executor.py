"""
executor.py — AttackSight Atomic Payload Executor
Loads a YAML atomic definition and executes its payloads safely.
"""

import subprocess
import platform
import logging
import time
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("attacksight.executor")


@dataclass
class ExecutionResult:
    technique_id: str
    payload_name: str
    executor_type: str
    command: str
    stdout: str
    stderr: str
    returncode: int
    success: bool
    duration_seconds: float
    timestamp: str
    error: Optional[str] = None


def load_atomic(technique_id: str, atomics_dir: str = "atomics") -> dict:
    """Load a YAML atomic definition by technique ID."""
    path = Path(atomics_dir) / f"{technique_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No atomic found for {technique_id} at {path}")
    with open(path, "r") as f:
        return yaml.safe_load(f)


def is_platform_supported(atomic: dict) -> bool:
    """Check if current platform is supported by this atomic."""
    current = platform.system().lower()
    supported = [p.lower() for p in atomic.get("platforms", [])]
    platform_map = {"windows": "windows", "linux": "linux", "darwin": "macos"}
    return platform_map.get(current, current) in supported


def run_payload(payload: dict, technique_id: str, dry_run: bool = False) -> ExecutionResult:
    """Execute a single payload and return the result."""
    import datetime

    executor_type = payload.get("executor", "powershell").lower()
    command = payload.get("command", "").strip()
    payload_name = payload.get("name", "unnamed")
    timestamp = datetime.datetime.now().isoformat()

    logger.info(f"[{technique_id}] Running payload: '{payload_name}'")

    if dry_run:
        logger.info(f"[DRY RUN] Would execute: {command[:80]}...")
        return ExecutionResult(
            technique_id=technique_id,
            payload_name=payload_name,
            executor_type=executor_type,
            command=command,
            stdout="[DRY RUN] No execution",
            stderr="",
            returncode=0,
            success=True,
            duration_seconds=0.0,
            timestamp=timestamp,
        )

    # Build the shell command
    if executor_type == "powershell":
        shell_cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command]
    elif executor_type == "cmd":
        shell_cmd = ["cmd.exe", "/c", command]
    elif executor_type == "bash":
        shell_cmd = ["bash", "-c", command]
    else:
        shell_cmd = ["powershell.exe", "-Command", command]

    start = time.time()
    try:
        result = subprocess.run(
            shell_cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        duration = time.time() - start
        success = result.returncode == 0

        if success:
            logger.info(f"[{technique_id}] ✅ Payload completed in {duration:.2f}s")
        else:
            logger.warning(f"[{technique_id}] ⚠️  Payload exited with code {result.returncode}")

        return ExecutionResult(
            technique_id=technique_id,
            payload_name=payload_name,
            executor_type=executor_type,
            command=command,
            stdout=result.stdout.strip(),
            stderr=result.stderr.strip(),
            returncode=result.returncode,
            success=success,
            duration_seconds=round(duration, 3),
            timestamp=timestamp,
        )

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        logger.error(f"[{technique_id}] ❌ Payload timed out after 30s")
        return ExecutionResult(
            technique_id=technique_id,
            payload_name=payload_name,
            executor_type=executor_type,
            command=command,
            stdout="",
            stderr="",
            returncode=-1,
            success=False,
            duration_seconds=round(duration, 3),
            timestamp=timestamp,
            error="Timeout after 30 seconds",
        )
    except Exception as e:
        duration = time.time() - start
        logger.error(f"[{technique_id}] ❌ Execution error: {e}")
        return ExecutionResult(
            technique_id=technique_id,
            payload_name=payload_name,
            executor_type=executor_type,
            command=command,
            stdout="",
            stderr="",
            returncode=-1,
            success=False,
            duration_seconds=round(duration, 3),
            timestamp=timestamp,
            error=str(e),
        )


def run_cleanup(payload: dict, technique_id: str):
    """Run the cleanup command if defined."""
    cleanup = payload.get("cleanup", "").strip()
    if not cleanup:
        return
    logger.info(f"[{technique_id}] Running cleanup...")
    executor_type = payload.get("executor", "powershell").lower()
    if executor_type == "powershell":
        cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cleanup]
    else:
        cmd = ["cmd.exe", "/c", cleanup]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        logger.info(f"[{technique_id}] Cleanup done.")
    except Exception as e:
        logger.warning(f"[{technique_id}] Cleanup failed: {e}")


def execute_technique(technique_id: str, atomics_dir: str = "atomics", dry_run: bool = False) -> list[ExecutionResult]:
    """Load and execute all payloads for a technique. Returns list of results."""
    atomic = load_atomic(technique_id, atomics_dir)

    if not is_platform_supported(atomic):
        logger.warning(f"[{technique_id}] Not supported on this platform. Skipping.")
        return []

    results = []
    payloads = atomic.get("payloads", [])

    for payload in payloads:
        result = run_payload(payload, technique_id, dry_run=dry_run)
        results.append(result)
        # Small delay between payloads so logs have time to be written
        time.sleep(1)
        # Always run cleanup
        if not dry_run:
            run_cleanup(payload, technique_id)

    return results
