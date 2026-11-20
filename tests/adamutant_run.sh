#!/bin/sh
# Run AdaMutant (ADAMUTANT, or adamutant on PATH) with the given arguments,
# keep its console output in .adamutant/console.txt and exit with its status.
# tests/mutation_survivors.py reads the lists that only the console has: the
# mutants that only the proof detected without being contract mutants, and
# the places where the proof proves anything.
mkdir -p .adamutant
# .adamutant/status appears when AdaMutant exits; a run stopped from outside
# leaves none (tests/mutation_survivors.py tells the two apart).
rm -f .adamutant/status
{ "${ADAMUTANT:-adamutant}" run "$@" 2>&1; echo $? > .adamutant/status; } \
  | tee .adamutant/console.txt
exit "$(cat .adamutant/status)"
