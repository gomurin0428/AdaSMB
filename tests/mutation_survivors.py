#!/usr/bin/env python3
"""List the mutants of the last AdaMutant run for a person to judge.

Reads .adamutant/reports/mutation-report.json and prints, as Markdown and to
the GitHub step summary when there is one, the score, every mutant that went
undetected (Survived or NoCoverage, a proof that ran out of time included),
and every mutant that only the proof detected, in AdaMutant's three groups:
confirmed by a counterexample run with the real code, a contract that says
too little, and undecided. Undetected mutants are not a failure; with --fail,
the script exits 1 if there is one.

The report does not say which mutants change a contract, which AdaMutant
leaves out of the candidates for a missing test (no test can detect a weaker
postcondition), nor where the proof proves anything. Both are in AdaMutant's
console output, which tests/adamutant_run.sh keeps in .adamutant/console.txt:
when it is there, the candidates are those the console lists, and its list
of places where the proof proves anything is added.

When there is no report, the run did not finish. tests/adamutant_run.sh
writes AdaMutant's exit status to .adamutant/status when it exits: a
non-zero status is an error (a baseline that fails, a mistake in the
configuration), and the script prints the console's errors and exits 1; no
status means the run was stopped (the step's time limit), and the script
says how far it got and exits 0.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / ".adamutant" / "reports" / "mutation-report.json"
CONSOLE = ROOT / ".adamutant" / "console.txt"
STATUS = ROOT / ".adamutant" / "status"


def write(text: str) -> None:
    """Prints text, and adds it to the GitHub step summary when there is one."""
    sys.stdout.write(text)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as out:
            out.write(text)
DETECTED = {"Killed", "Timeout"}
UNDETECTED = {"Survived", "NoCoverage"}
CANDIDATES = "Detected only by the proof"
VACUOUS = "The proof of the unmodified project proves anything here"


def console_lists(text: str) -> tuple[set[str], list[str]]:
    """The ids of the candidates for a missing test, and the places where
    the proof proves anything, from AdaMutant's console output. A section
    starts with an unindented line and ends at the next one."""
    candidates: set[str] = set()
    vacuous: list[str] = []
    section = ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = (CANDIDATES if line.startswith(CANDIDATES)
                       else VACUOUS if line.startswith(VACUOUS) else "")
            continue
        if section == CANDIDATES:
            match = re.match(r"\s+#(\d+) ", line)
            if match:
                candidates.add(match.group(1))
        elif section == VACUOUS and line.strip():
            vacuous.append(line.strip())
    return candidates, vacuous


def cell(text: str) -> str:
    return "`" + " ".join(text.split()).replace("|", "\\|").replace("`", "'") + "`"


def proof_group(reason: str) -> str:
    if reason.startswith("proof failed, confirmed: "):
        return "Confirmed"
    if reason.startswith("proof failed, a contract says too little: "):
        return "A contract says too little"
    return "Undecided"


def summary(report: dict, console: str | None = None) -> tuple[str, int]:
    counts: Counter[str] = Counter()
    rows = []
    proof_rows = []
    candidates, vacuous = console_lists(console) if console is not None else (None, [])
    for path, entry in sorted(report["files"].items()):
        lines = entry["source"].splitlines()
        for mutant in entry["mutants"]:
            counts[mutant["status"]] += 1
            reason = mutant.get("statusReason", "")
            by_proof = mutant["status"] == "Killed" and reason.startswith("proof failed")
            if by_proof and candidates is not None and str(mutant["id"]) not in candidates:
                # A mutant of a contract, which no test could detect.
                continue
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
    if vacuous:
        text += [
            "",
            "Where the proof of the unmodified project proves anything "
            "(mutants there survive the proof):",
            "",
            *(f"- {cell(place)}" for place in vacuous),
        ]
    return "\n".join(text) + "\n", undetected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fail", action="store_true", help="exit 1 if any mutant went undetected")
    args = parser.parse_args()
    console = CONSOLE.read_text(encoding="utf-8") if CONSOLE.is_file() else None
    if not REPORT.is_file():
        status = STATUS.read_text(encoding="utf-8").strip() if STATUS.is_file() else ""
        if status not in ("", "0"):
            # AdaMutant stopped with an error: show it and fail.
            errors = [line for line in (console or "").splitlines()
                      if "error" in line.lower()]
            text = ("## Mutation testing\n\nAdaMutant failed (exit status "
                    f"{status}):\n\n" + "".join(f"    {e}\n" for e in errors[-20:]))
            write(text)
            return 1
        # The run was stopped before AdaMutant wrote its report (the step's
        # time limit), or never started: say how far it got.
        done = re.findall(r"^\[(\d+)/(\d+)\] (\w+)", console or "", re.MULTILINE)
        if console is None:
            text = "## Mutation testing\n\nThe run did not start or left no output.\n"
        else:
            text = "## Mutation testing\n\nThe run did not finish, so there is no report"
            if done:
                counts = Counter(status for _, _, status in done)
                text += (f": {len(done)} of {done[-1][1]} mutants ran ("
                         + ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
                         + "); .adamutant/console.txt, kept with the report, has "
                         "their ids")
            text += ".\n"
        write(text)
        return 1 if args.fail else 0
    text, undetected = summary(json.loads(REPORT.read_text(encoding="utf-8")), console)
    sys.stdout.write(text)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as out:
            out.write(text)
    return 1 if args.fail and undetected else 0


if __name__ == "__main__":
    sys.exit(main())
