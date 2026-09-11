#!/usr/bin/env python3
"""Fail-fast structural checks for privacy, configuration, and repository hygiene."""
from __future__ import annotations

import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ERRORS: list[str] = []


def fail(message: str) -> None:
    ERRORS.append(message)


def check_tracked_secrets() -> None:
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.splitlines()
    forbidden = {".env", "data/shield.db", "data/validation-report.json"}
    for path in forbidden.intersection(tracked):
        fail(f"runtime artifact must not be tracked: {path}")


def check_production_boundaries() -> None:
    agent_files = list((ROOT / "app" / "agent").glob("*.py"))
    for path in agent_files:
        text = path.read_text(encoding="utf-8")
        if "ground_truth" in text:
            fail(f"evaluation ground truth leaked into production agent: {path.relative_to(ROOT)}")
        if "app.emulator" in text:
            fail(f"production agent imports emulator code: {path.relative_to(ROOT)}")
    if (ROOT / "app" / "qvac" / "server.py").exists():
        fail("mock QVAC server must not exist in the runtime tree")


def check_structured_files() -> None:
    for path in ROOT.rglob("*.json"):
        if any(part in {".git", ".agents", ".claude", "data"} for part in path.parts):
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
    for path in ROOT.rglob("*.xml"):
        if any(part in {".git", ".agents", ".claude"} for part in path.parts):
            continue
        try:
            ET.parse(path)
        except Exception as exc:
            fail(f"invalid XML {path.relative_to(ROOT)}: {exc}")


def check_python_compiles() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", "app", "scripts", "tests"], cwd=ROOT
    )
    if result.returncode:
        fail("Python compilation failed")


def main() -> int:
    check_tracked_secrets()
    check_production_boundaries()
    check_structured_files()
    check_python_compiles()
    if ERRORS:
        print("SHIELD quality gate: FAIL", file=sys.stderr)
        for error in ERRORS:
            print(f" - {error}", file=sys.stderr)
        return 1
    print("SHIELD quality gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
