#!/usr/bin/env python3
"""List the mutants that the last AdaMutant run did not detect.

Reads .adamutant/reports/mutation-report.json and prints the score and every
Survived or NoCoverage mutant as Markdown, also to the GitHub step summary
when there is one. With --fail, exits 1 if any mutant went undetected.
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / ".adamutant" / "reports" / "mutation-report.json"
DETECTED = {"Killed", "Timeout"}
UNDETECTED = {"Survived", "NoCoverage"}


def cell(text: str) -> str:
    return "`" + " ".join(text.split()).replace("|", "\\|").replace("`", "'") + "`"


def summary(report: dict) -> tuple[str, int]:
    counts: Counter[str] = Counter()
    rows = []
    for path, entry in sorted(report["files"].items()):
        lines = entry["source"].splitlines()
        for mutant in entry["mutants"]:
            counts[mutant["status"]] += 1
            if mutant["status"] not in UNDETECTED:
                continue
            start, end = mutant["location"]["start"], mutant["location"]["end"]
            text = lines[start["line"] - 1]
            original = (
                text[start["column"] - 1 : end["column"] - 1]
                if start["line"] == end["line"]
                else text[start["column"] - 1 :] + " ..."
            )
            rows.append(
                f"| {path}:{start['line']} | {mutant['status']} | {mutant['mutatorName']} "
                f"| {cell(original)} | {cell(mutant['replacement'])} |"
            )
    detected = sum(counts[status] for status in DETECTED)
    undetected = sum(counts[status] for status in UNDETECTED)
    scored = detected + undetected
    score = f"{100 * detected / scored:.2f}%" if scored else "n/a"
    text = [
        "## Mutation testing",
        "",
        f"Score {score}: {detected} detected, {undetected} undetected, "
        f"{counts['CompileError']} compile errors, {counts['Ignored']} ignored.",
    ]
    if rows:
        text += [
            "",
            "| Location | Status | Mutator | Original | Replacement |",
            "|---|---|---|---|---|",
            *rows,
        ]
    return "\n".join(text) + "\n", undetected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fail", action="store_true", help="exit 1 if any mutant went undetected")
    args = parser.parse_args()
    text, undetected = summary(json.loads(REPORT.read_text(encoding="utf-8")))
    sys.stdout.write(text)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as out:
            out.write(text)
    return 1 if args.fail and undetected else 0


if __name__ == "__main__":
    sys.exit(main())
