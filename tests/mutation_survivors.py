#!/usr/bin/env python3
"""List the mutants of the last AdaMutant run for a person to judge.

Reads .adamutant/reports/mutation-report.json and prints, as Markdown and to
the GitHub step summary when there is one, the score, every mutant that went
undetected (Survived or NoCoverage, a proof that ran out of time included),
and every mutant that only the proof detected, in AdaMutant's three groups:
confirmed by a counterexample run with the real code, a contract that says
too little, and undecided. Undetected mutants are not a failure; with --fail,
the script exits 1 if there is one.
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


def proof_group(reason: str) -> str:
    if reason.startswith("proof failed, confirmed: "):
        return "Confirmed"
    if reason.startswith("proof failed, a contract says too little: "):
        return "A contract says too little"
    return "Undecided"


def summary(report: dict) -> tuple[str, int]:
    counts: Counter[str] = Counter()
    rows = []
    proof_rows = []
    for path, entry in sorted(report["files"].items()):
        lines = entry["source"].splitlines()
        for mutant in entry["mutants"]:
            counts[mutant["status"]] += 1
            reason = mutant.get("statusReason", "")
            by_proof = mutant["status"] == "Killed" and reason.startswith("proof failed")
            if mutant["status"] not in UNDETECTED and not by_proof:
                continue
            start, end = mutant["location"]["start"], mutant["location"]["end"]
            text = lines[start["line"] - 1]
            original = (
                text[start["column"] - 1 : end["column"] - 1]
                if start["line"] == end["line"]
                else text[start["column"] - 1 :] + " ..."
            )
            place = f"| {path}:{start['line']} "
            change = f"| {mutant['mutatorName']} | {cell(original)} | {cell(mutant['replacement'])} |"
            if by_proof:
                proof_rows.append(f"{place}| {proof_group(reason)} {change} {cell(reason)} |")
            else:
                status = mutant["status"]
                if "the proof did not finish within the timeout" in reason:
                    status += " (proof timed out)"
                rows.append(f"{place}| {status} {change}")
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
            "Undetected by the tests and the proof:",
            "",
            "| Location | Status | Mutator | Original | Replacement |",
            "|---|---|---|---|---|",
            *rows,
        ]
    if proof_rows:
        text += [
            "",
            "Detected only by the proof (candidates for a missing test):",
            "",
            "| Location | Group | Mutator | Original | Replacement | GNATprove |",
            "|---|---|---|---|---|---|",
            *proof_rows,
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
