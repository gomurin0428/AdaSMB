# SPARK assurance design

This is the implementation target, not evidence that proofs have passed.

## Claims to establish

The executable protocol core must be SPARK, not a separate model. Within the
documented bounds, GNATprove must establish absence of language-defined run-time
errors, initialized outputs, safe packet slicing, and the written state/handle
contracts. Arbitrary peer input must produce a checked rejection, not require a
precondition that the packet is well formed. Invalid UTF encodings, DER lengths,
SMB response correlation, and authentication tokens are peer-controlled input.

Session contracts must forbid use before authentication, reuse of closed/stale
handles, and state advancement following a failed response/signature. Counters
must be checked before exhaustion rather than wrap and resurrect old identities.
Cryptographic routines need run-time-safety proofs and independent known-answer
tests. This does not prove cryptographic security or the complete SMB standard.

## Architecture

* Pure, bounded SPARK bytes/text/crypto packages implement the real runtime
  encoders, decoders and hashes. Lengths are checked before narrowing conversions.
* SPARK protocol/NTLM packages validate all peer fields, construct requests and
  produce typed results. Errors are explicit status values; no proof exemption
  for malformed input. Time and entropy are supplied as values by the adapter.
* A SPARK session/handle engine owns phases, identifiers, outstanding request
  expectations, signing keys, handle validity, and verified response acceptance.
  The Ada facade must delegate these decisions, not repeat an unproved model.
* Non-SPARK adapters are limited to GNAT socket/selector operations, OS entropy,
  clock conversion, external resource lifetime/finalization, and user-facing
  exception/string/container conversion. Document every remaining non-SPARK
  subprogram; do not call broad legacy client logic a thin trusted boundary.

Use existing public operations where possible. Bounded-memory internals may
change API implementation details but must retain working authenticated file
I/O and directory operations. Public wrappers check core preconditions and map
status to explicit errors. Operating-system failures are not proof success.

## Proof discipline

No Assume, unjustified axioms, False_Positive annotations, unproved checks hidden
by warning suppression, or SPARK_Mode Off around hard protocol logic. Split
procedures and strengthen invariants/contracts rather than hide obligations.
The proof project must enumerate actual runtime units and reject missing units.
An unproved check or excluded implementation is a release gap, never a successful
library-wide safety claim. Preserve raw GNATprove output and report proved units,
unproved items, trusted assumptions and exact reproducible commands separately.

## Boundary assumptions and non-claims

GNAT, GNATprove, SMT solvers, Ada runtime, OS socket/entropy/clock behavior,
available stack/heap, and adapter conformance are trusted. Proof does not imply
cryptographic hardness, side-channel resistance, secure key erasure, transport
availability, SMB3 encryption, or interoperability with every SMB server. Pure
Ada forbids external SMB/crypto implementations, not ordinary OS services.

Local Samba interoperation, hostile-response tests and crypto vectors remain
required alongside formal proof. CI is manual-only and is not run implicitly.
