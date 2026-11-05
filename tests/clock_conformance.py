#!/usr/bin/env python3
"""Check the production FILETIME core against Python's Gregorian calendar."""

from collections import Counter
import calendar
import datetime as dt
import pathlib
import random
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
EPOCH = dt.date(1601, 1, 1)
LAST = dt.date(9999, 12, 31)
TICKS = 10_000_000


def filetime_now():
    delta = dt.datetime.now(dt.timezone.utc) - dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    return delta // dt.timedelta(microseconds=1) * 10


def time_case(year, month, day, seconds=0, ticks=0):
    result, value = "Invalid_Value", 0
    if 1601 <= year <= 9999 and 0 <= seconds <= 86400 and 0 <= ticks < TICKS:
        try:
            date = dt.date(year, month, day)
        except ValueError:
            pass
        else:
            result = "Ok"
            value = ((date - EPOCH).days * 86400 + seconds) * TICKS + ticks
    return f"T {year} {month} {day} {seconds} {ticks} {value} {result}\n"


def corpus():
    for ordinal in range(EPOCH.toordinal(), LAST.toordinal() + 1):
        date = dt.date.fromordinal(ordinal)
        yield "calendar_days", time_case(date.year, date.month, date.day)

    for year in range(1601, 10000):
        for month in range(1, 13):
            for day in (0, calendar.monthrange(year, month)[1] + 1):
                yield "invalid_month_days", time_case(year, month, day)

    for date in (EPOCH, dt.date(1700, 2, 28), dt.date(1900, 2, 28),
                 dt.date(2000, 2, 29), dt.date(2100, 3, 1),
                 dt.date(2400, 2, 29), LAST):
        for seconds in (0, 1, 3599, 3600, 86399, 86400):
            for ticks in (0, 1, TICKS - 2, TICKS - 1):
                yield "time_boundaries", time_case(date.year, date.month, date.day, seconds, ticks)

    low, high = -(2**31), 2**31 - 1
    for index, limits in enumerate(((1600, 10000), (0, 13), (-1, 32),
                                    (-1, 86401), (-1, TICKS))):
        for value in (*limits, low, high):
            fields = [2024, 1, 1, 0, 0]
            fields[index] = value
            yield "invalid_fields", time_case(*fields)
    for value in (low, high):
        yield "invalid_fields", time_case(*([value] * 5))

    for seconds in range(86400):
        hour, remainder = divmod(seconds, 3600)
        minute, second = divmod(remainder, 60)
        for leap in (False, True):
            yield "seconds", f"S {hour} {minute} {second} {leap} {seconds + int(leap)}\n"

    nanoseconds = set(range(1001))
    for tick in (1, 9, 10, 99, 100, 999, 1000, 9999, 10000, 99999, 100000,
                 TICKS - 2, TICKS - 1):
        for offset in (-1, 0, 1, 49, 50, 99):
            nanoseconds.add(tick * 100 + offset)
    rng = random.Random(0xADA5C10C)
    nanoseconds.update(rng.randrange(1_000_000_000) for _ in range(10000))
    for value in sorted(nanoseconds):
        yield "fractions", f"F 0.{value:09} {value // 100}\n"


def main():
    probe = ROOT / "build" / "bin" / ("clock_probe.exe" if sys.platform == "win32" else "clock_probe")
    counts = Counter()
    with tempfile.TemporaryFile(mode="w+", encoding="ascii", newline="\n") as fixtures:
        for category, line in corpus():
            fixtures.write(line)
            counts[category] += 1
        fixtures.seek(0)
        result = subprocess.run([str(probe)], stdin=fixtures, text=True,
                                capture_output=True, timeout=300)
    if result.returncode != 0 or result.stdout.strip() != f"PASS {sum(counts.values())}":
        print(result.stdout + result.stderr, file=sys.stderr)
        raise RuntimeError("clock conformance failed")

    # SMB.Clock reads the system clock in UTC. The bounds leave room for a
    # slow start of the probe, but not for any time zone offset.
    lower = filetime_now() - 5 * TICKS
    current = subprocess.run([str(probe)], input=f"N {lower} {lower + 40 * TICKS}\n",
                             text=True, capture_output=True, timeout=30)
    if current.returncode != 0 or current.stdout.strip() != "PASS 1":
        print(current.stdout + current.stderr, file=sys.stderr)
        raise RuntimeError("current FILETIME differs from the system clock in UTC")

    for fixture, diagnostic in (
        ("T 1970 1 1 0 0 116444736000000001 Ok\n", "FILETIME mismatch"),
        ("T 1900 2 29 0 0 0 Ok\n", "FILETIME mismatch"),
        ("S 23 59 59 True 86399\n", "seconds mismatch"),
        ("F 0.000000099 1\n", "fraction mismatch"),
        ("N 0 1\n", "current FILETIME out of bounds"),
    ):
        check = subprocess.run([str(probe)], input=fixture, text=True,
                               capture_output=True, timeout=30)
        if check.returncode == 0 or diagnostic not in check.stderr:
            raise RuntimeError("clock sensitivity check failed or could not execute")
    print(f"PASS: {sum(counts.values())} clock cases; the current time; "
          "five sensitivity checks")
    for category, count in counts.items():
        print(f"  {category}: {count}")


if __name__ == "__main__":
    main()
