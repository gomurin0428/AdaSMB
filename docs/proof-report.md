# GNATprove and test report

## Final SPNEGO MIC contract

`Validate_Final_Token` guarantees that an accepted nonempty token with a
nonempty `Expected_MIC` has a 16-byte expected MIC and ends with exactly those
16 bytes. An empty token is accepted only when `Expected_MIC` is empty;
otherwise its status is `SMB.Signature_Error`. The contract does not prove
HMAC correctness, all DER parser semantics, or machine-level timing behavior.
The runtime parser and constant-time MIC comparison were not changed.

The equality-bearing postcondition and loop invariant are ignored by runtime
assertion policy to avoid evaluating an early-exit array equality as an
oracle. GNATprove still proves both. The invariant states that, once the MIC
field has been accepted, `Previous_Tag` is `A3`, the expected MIC is 16 bytes,
and the parsed prefix ends in that MIC. Because accepted tags must increase,
no field can follow `A3`; the invariant therefore supports the final-token
suffix guarantee.

The mutation corpus passed **34,695 final-SPNEGO cases** across three rebased
bounds, including a token ending at `Natural'Last`. It mutates token bytes and
every expected-MIC position/value, covers empty-token expected-MIC lengths
0 through 16, and checks state-only acceptance without a MIC. The tests check
returned statuses directly and do not rely on ignored assertions.

The focused commands exited 0:

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite final-spnego
gnatprove -P proof.gpr -u smb-core_ntlm.adb --subdirs=final-mic-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

Focused GNATprove reported **219 checks** (41 flow, 178 prover), zero
unproved or justified checks, zero warnings, zero `pragma Assume` statements,
and one analyzed unit (7 subprograms/packages). It explicitly proved the
postcondition at `smb-core_ntlm.ads:42:08` and loop-invariant initialization
and preservation at `smb-core_ntlm.adb:404:13`.

The final commands exited 0:

```sh
./build/bin/test_suite authentication
make ntlm-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
gnatprove -P proof.gpr --subdirs=final-mic-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
git diff --check
```

NTLM tests passed 211 AV fixtures / 422 rebased cases and 5,896
challenge-field fixtures / 11,792 rebased cases. Samba integration passed on
`127.0.0.1:1445`. Full GNATprove reported **4,963 checks** (725 flow, 4,238
prover), zero unproved or justified checks, **69 warnings**, zero
`pragma Assume` statements, and 13 units.

The pre- and post-build disassembly texts differ (the raw unified diff is
72,987 bytes and includes instruction changes). Inspection found the
`Validate_Final_Token` call to `smb__crypto__constant_time_equal`; the
object's `memcmp` relocation is in the separate `Challenge_Slice_Valid` ghost
helper, outside this function. This comparison does not establish binary
identity or machine-level constant-time behavior. CI and Windows were not run
for this revision.

## NTLM authentication output suffix contract

`Build_Negotiate_Token` and `Authenticate` guarantee that every output byte
at or after `Used` is zero on every return; failures return `Used = 0`.
`Authenticate` clears its output before validation, and private `Build_Type3`
preserves the suffix from its entry value while writing only the used prefix.
The implementation's runtime decision and output-building statements were
not changed. This is a returned-buffer guarantee, not secure erasure of
internal temporaries or a guarantee of physical-memory erasure.

`Test_NTLM_Authenticate` passed **57 output-buffer cases**. They cover three
array lower bounds (including one ending at `Natural'Last`); zero, one-byte,
short, exact, extra, and maximum capacities; malformed input; unsupported
credentials; and success followed by failure using the same output buffer.
The buffers are prefilled with nonzero bytes so unused suffixes and failures
are checked for clearing.

The focused commands exited 0:

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite ntlm-maxlen
gnatprove -P proof.gpr -u smb-core_auth.adb --subdirs=auth-output-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

Focused GNATprove reported **453 checks** (66 flow, 387 prover), zero
unproved or justified checks, **6 warnings**, zero `pragma Assume` statements,
and one analyzed unit (20 subprograms and packages). It explicitly proved
the private `Build_Type3` suffix-preservation postcondition at
`smb-core_auth.adb:244:14` and the public postconditions at
`smb-core_auth.ads:38:14` and `smb-core_auth.ads:62:08`.

Final gates exited 0:

```sh
make ntlm-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
gnatprove -P proof.gpr --subdirs=auth-output-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
git diff --check
```

`make ntlm-test` passed 211 AV fixtures / 422 rebased cases and 5,896
challenge-field fixtures / 11,792 rebased cases. `make test` included the
57 output-buffer cases, and local Samba integration passed on
`127.0.0.1:1445`. Full GNATprove reported **4,955 checks** (725 flow,
4,230 prover), zero unproved or justified checks, **69 warnings**, zero
`pragma Assume` statements, and 13 analyzed units. An initial strict build
reported that the body-level `use type SMB.Byte` was redundant after the
specification made it visible for the new contract; removing that redundant
clause resolved the `-gnatwe` failure. CI and Windows tests were not run for
this revision.

## Unsigned SMB header signature-field contract

For `Validate_Header`, a successful non-interim result with
`Expected.Signed = False` now guarantees that all 16 signature bytes
(offsets 48 through 63) are zero. This strengthens the postcondition without
changing the runtime decision algorithm. The existing signature-field loop
maintains the invariant that `Signature_Zero` is equivalent to all
signature bytes processed so far being zero. The invariant is ignored at
runtime but is formally proved: GNATprove reports both initialization and
preservation, and proves the `Validate_Header` postcondition. This contract
does not establish HMAC correctness or authenticate pending responses.
Structurally accepted signed or interim headers are not thereby
cryptographically verified; signature verification remains separate.

`Header_Mutation_Tests` passed **77,025 cases** over three array lower bounds,
including a packet ending at `Natural'Last`. This includes **49,152**
signature-field cases: each of 16 signature-byte positions, all 256 byte
values, `Expected.Signed` true and false, `Interim` true and false, and all
three rebases. Interim fixtures carry `STATUS_PENDING` and a nonzero
`AsyncId`. The other structural, truncation, flag, and correlation mutation
cases remain covered.

The focused checks all exited 0:

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite header-mutations
./build/bin/test_suite async-responses
gnatprove -P proof.gpr -u smb-core_wire.adb --subdirs=unsigned-header-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

The focused proof reports **357 checks** (34 flow, 323 prover), zero
unproved or justified checks, zero warnings, zero `pragma Assume` statements,
and one analyzed unit (18 subprograms and packages). `Validate_Header`
discharged all 44 of its checks, including the new postcondition; the
invariant initialization and preservation checks are explicitly reported
proved.

Final-source gates all exited 0:

```sh
make signing-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
gnatprove -P proof.gpr --subdirs=unsigned-header-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
git diff --check
```

The full test suite reported 77,025 header mutation cases, and Samba
integration passed on `127.0.0.1:1445`. The full GNATprove run reported
**4,948 checks** (725 flow, 4,223 prover), zero unproved or justified
checks, 69 warnings, zero `pragma Assume` statements, and 13 units. These
are fresh explicit proof results, not a `make prove` result. CI and Windows
tests were not run for this revision.

## Crypto byte equality contract

`SMB.Crypto.Constant_Time_Equal` now specifies
`Result = (Left = Right)`, under its existing maximum-input precondition.
The length check and XOR/OR accumulator in the runtime implementation are
unchanged. A narrowly placed `Assertion_Policy (Post => Ignore)` prevents
the potentially short-circuiting array-equality oracle from being evaluated
as a runtime postcondition. The body similarly ignores the loop invariant at
runtime. These policies do not suppress formal verification: focused
GNATprove output explicitly reports
`smb-crypto.ads:35:14: info: postcondition proved`; the invariant's
initialization and preservation checks are also proved. The focused summary
reports 193 checks (39 flow, 154 prover), zero unproved or justified checks,
zero warnings, zero `pragma Assume` statements, and one analyzed unit
(16 subprograms and packages).

`Test_Crypto_Equality` compares the routine directly with Ada array equality
in **65,946 cases**: all 65,536 byte-value pairs; all 16 length combinations
from zero through three, including null arrays; equal 16- and 32-byte
inputs and every individual bit mismatch in each length (128 and 256
mismatches); two same-bit differences; shifted bounds including bounds near
`Natural'Last`; and equal, mismatching, and unequal-length inputs at
`Maximum_Hash_Input`. The negative control changed exactly one
`Difference := Difference or` to `Difference := Difference xor`. Its strict
build exited 0 and the selector exited 1 as expected with
`byte equality disagrees with Ada array equality`. The original source was
restored byte-for-byte; the strict rebuild and selector then both exited 0.

Focused verification commands (each exited 0):

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite crypto-equality
gnatprove -P proof.gpr -u smb-crypto.adb --subdirs=crypto-equality-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

The final gates also exited 0:

```sh
make crypto-test
make signing-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
gnatprove -P proof.gpr --subdirs=crypto-equality-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
git diff --check
```

Crypto conformance passed 445 hash fixtures / 890 rebased cases and 1,832
HMAC fixtures / 7,328 rebased cases; signing conformance passed 3,135
fixtures / 12,540 rebased cases. The full unit suite included the 65,946
equality cases; Samba integration passed on `127.0.0.1:1445`. The fresh full
GNATprove run reported 4,942 checks (725 flow, 4,217 prover), zero unproved
or justified checks, 69 warnings, zero `pragma Assume` statements, and 13
units. The focused and full summaries are
`build/proof-obj/crypto-equality-focused/gnatprove/gnatprove.out` and
`build/proof-obj/crypto-equality-full/gnatprove/gnatprove.out`.

The pre-change and forced-build disassemblies were compared using
`objdump -d --disassemble=smb__crypto__constant_time_equal build/obj/smb-crypto.o`.
The instruction differences are limited to five source-line arguments to
existing range, overflow, and index-check failure handlers (confirmed with
`objdump -dr` relocations). No array-equality oracle or invariant evaluation
was added to the generated comparison loop. This observation is specific to
the checked Linux GNAT 14 build, not a timing proof or a guarantee for other
compiler configurations. CI and Windows tests were not run for this revision.

## UTF-16 to UTF-8 unused output guarantee

`UTF16_To_UTF8` guarantees that every output character at or beyond `Used`
is `Character'Val (0)` on every return, including success, odd-length input,
encoding failure, and capacity failure. A partial prefix on failure does
not make the conversion successful; callers must check `Status`. This is a
returned-buffer guarantee, not secure physical-memory erasure.

The output is initialized with an array aggregate, and a bottom-of-loop
invariant maintains the zero suffix as `Used` advances. Under the existing
runtime `Loop_Invariant => Ignore` policy, this does not add per-scalar
whole-output scans. `Emit_Scalar` receives only a target slice whose length
is exactly `Encoded_Size (Value)`. Its nested byte emitter counts `Written`
and writes only within that slice; the helper proves
`UTF8_Scalar_At (Target, 0) = Value`. The outer conversion advances `Used`
explicitly after the helper returns. The helper therefore has no access to
the rest of `Output`, while the public postcondition covers the full
zero-tail guarantee.

`Test_UTF_Capacity` adds seven shifted-bound, `16#A5#`-prefilled fixtures
covering empty, BMP, and supplementary success; BMP and supplementary
capacity failures; encoding failure after a valid prefix; and odd-length
input. The Unicode probe checks ordinary and ample output tails. Its
existing generator, Python oracle, and **1,287,503-fixture** corpus are
unchanged.

The focused proof used fresh `utf8-unused-focused` output:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf8-unused-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with **730 checks** (45 flow, 685 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(27 subprograms and packages). `UTF16_To_UTF8` discharged all 97 of its
checks.

Final-source verification used these commands:

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite utf-capacity
make unicode-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
gnatprove -P proof.gpr --subdirs=utf8-unused-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
git diff --check
```

Each command exited 0. The Unicode test reported **1,287,503 fixtures**.
Fresh full-proof output contains **4,935 checks** (725 flow, 4,210 prover),
zero unproved, zero justified, 69 warnings, zero `pragma Assume` statements,
and 13 units. This is a fresh explicit GNATprove run, not a literal
`make prove` result. The proof summaries are
`build/proof-obj/utf8-unused-focused/gnatprove/gnatprove.out` and
`build/proof-obj/utf8-unused-full/gnatprove/gnatprove.out`.

CI and Windows were not run for this revision.

## UTF-8 to UTF-16 unused output guarantee

`UTF8_To_UTF16` guarantees that every output byte at or beyond `Used` is
zero, on success and on either encoding or capacity failure. Together with
the existing valid UTF-16 prefix contract, this specifies both the used and
unused parts of the returned buffer. Callers must still check `Status`;
this is not permission to treat a failed conversion as successful, nor a
secure physical-memory erasure claim.

The existing zero-initialization loop is replaced by an equivalent array
aggregate assignment. A loop invariant preserves the zero suffix while
the existing scalar writes populate the prefix. The invariant is covered
by the existing runtime `Loop_Invariant => Ignore` policy, so it does not
introduce a whole-buffer scan for each scalar. The new postcondition checks
the buffer once on return when assertions are enabled. Encoding branches,
status precedence, limits, and emitted bytes are unchanged.

`Test_UTF_Capacity` adds six shifted-bound, nonzero-prefilled buffer cases:
empty and BMP success, supplementary-scalar success, BMP and supplementary
capacity failure, and encoding failure after a valid prefix. Odd output
capacities exercise a trailing single byte. The Unicode probe also checks
the zero suffix of its ordinary and ample-capacity UTF-16 outputs. Its
existing Python oracle and fixture generator remain unchanged.

The loop invariants remain at the loop head, and the original bounded
`Emitted` Ghost slice and scalar/unit correspondence assertions are retained.
The private Ghost lemma `Lemma_Valid_UTF16_Prefix` connects valid UTF-16
units in the used prefix and the absence of a trailing high surrogate to
`Valid_UTF16_Text` for that prefix. Its null body and all call preconditions
are proved; the lemma is called at the four conversion exits, not per
iteration. This avoids rescanning the whole prefix for each scalar.

The focused proof used fresh `utf16-unused-lemma-focused` output:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf16-unused-lemma-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with **721 checks** (44 flow, 677 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(27 subprograms and packages). `Lemma_Valid_UTF16_Prefix` discharged all
11 of its checks.

The final-source build, tests, integration, and full proof commands were:

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite utf-capacity
make unicode-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
gnatprove -P proof.gpr --subdirs=utf16-unused-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
git diff --check
```

Each listed command exited 0. The Unicode run reported **1,287,503
fixtures**. The full proof used fresh `utf16-unused-full` output and discharged
**4,926 checks** (724 flow, 4,202 prover), with zero unproved, zero justified,
69 warnings, zero `pragma Assume` statements, and 13 units. This explicit
fresh-output run is not a literal `make prove` result. The focused and full
summaries are
`build/proof-obj/utf16-unused-lemma-focused/gnatprove/gnatprove.out` and
`build/proof-obj/utf16-unused-full/gnatprove/gnatprove.out`.

The strict build required marking the lemma's intentionally unused `Length`
formal with `pragma Unreferenced`; the Unicode probe required `use type
SMB.Byte` for its zero-tail comparisons. The respective final build and
Unicode-test reruns passed. CI and Windows were not run for this revision;
the separate Windows result for base PR72 is not evidence for this revision.

## UTF-8 to UTF-16 capacity outcome guarantee

`UTF8_To_UTF16` now guarantees that empty input returns `SMB.Ok`, and that
when `Output'Length >= 2 * Input'Length`, the result status is one of
`SMB.Ok` or `SMB.Invalid_Encoding`; sufficient output capacity therefore
excludes `SMB.Invalid_Length`. This is a conservative capacity guarantee,
not a theorem that status is `SMB.Ok` exactly when the entire UTF-8 input is
valid. The existing valid-output-prefix guarantee and status precedence
remain unchanged. In particular, with a smaller output, a capacity error can
precede a malformed byte later in the input.

The public `SMB.Text.To_UTF16LE` wrapper allocates output capacity of
`2 * Input'Length`, so its call satisfies the sufficient-capacity premise.
The two checked assertions at the encoder's capacity-failure returns prove
that each such return implies
`Output'Length < 2 * Input'Length`. These assertions do not alter runtime
branches, assignments, encoding behavior, status ordering, public
parameters, or limits. No whole-input UTF-8 validity iff theorem or
whole-codec roundtrip theorem is claimed.

To retain the existing emitted-scalar correspondence proof, a Ghost constant
`Emitted` names only the newly written two- or four-byte slice. Checked
assertions connect its code units to the original output units before
proving the unchanged `UTF16_Scalar_At (Emitted, 0) = Decoded_Scalar`
identity. This does not widen a model domain or scan the whole output for
each scalar.

`Test_UTF_Capacity` adds coverage for empty input with spare output, input
containing ASCII `A`, `B` followed by byte `16#FF#` with a two-byte output
(`SMB.Invalid_Length`, `Used = 2`) versus a six-byte output
(`SMB.Invalid_Encoding`, `Used = 4`), and 1 MiB of ASCII encoded into
an exact 2 MiB UTF-16 output. These cases also exercise shifted array
bounds. In the Unicode probe,
valid `Check_8` fixtures additionally convert into ample output with a
shifted lower bound and compare against the existing Python-oracle bytes.
The corpus generator, oracle, negative controls, and **1,287,503-fixture**
count are unchanged.

The focused whole-unit proof used fresh `utf8-capacity-slice-focused` output:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf8-capacity-slice-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with **699 checks** (44 flow, 655 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(26 subprograms and packages).

The final-source strict build, capacity selector, Unicode corpus, unit suite,
forced strict check, and Samba integration each exited 0:

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite utf-capacity
make unicode-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
```

The Unicode run reported 1,287,503 fixtures. The full proof used fresh
`utf8-capacity-full` output:

```sh
gnatprove -P proof.gpr --subdirs=utf8-capacity-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with **4,904 checks** (724 flow, 4,180 prover), zero unproved,
zero justified, 69 warnings, zero `pragma Assume` statements, and 13 units.
This explicit fresh-output run is not a literal `make prove` result. The
focused and full summaries are
`build/proof-obj/utf8-capacity-slice-focused/gnatprove/gnatprove.out` and
`build/proof-obj/utf8-capacity-full/gnatprove/gnatprove.out`.
CI and Windows were not run for this revision.

## UTF-16 to UTF-8 conversion outcome contract

The `UTF16_To_UTF8` postcondition now states an exact outcome under a
conservative sufficient-capacity condition: odd-length input always returns
`SMB.Invalid_Length`; for even-length input with
`Output'Length >= 2 * Input'Length`, status is `SMB.Ok` exactly when
`Valid_UTF16_Text (Input)` holds, and otherwise is `SMB.Invalid_Encoding`.
This bound is sufficient, not minimal. For smaller outputs, the existing
capacity-before-later-encoding-error behavior remains: conversion can return
`SMB.Invalid_Length` before reaching a later malformed unit. The existing
successful-input validity and output-bound guarantees remain in force.

The private Ghost procedure `Lemma_Invalid_UTF16_Unit` connects a checked
invalid-unit witness to whole-input invalidity. Its precondition bounds input
length by `2 * SMB.Maximum_Frame_Size`, requires `Index < Input'Length / 2`,
and requires `not Valid_UTF16_Unit (Input, Index)`; its postcondition is
`not Valid_UTF16_Text (Input)`. Its body is `null`, but GNATprove discharges
the body and postcondition from the quantified predicate definitions; this
is a proved lemma, not an assumption or axiom. All five lemma checks,
including the postcondition, and all four call preconditions proved.

At each of the four `Invalid_Encoding` exits, a constant-time assertion
establishes the bad-unit witness before the lemma call. Further checked
assertions establish that capacity failure implies
`Output'Length < 2 * Input'Length` and that the input is valid at normal
completion. Whole-input validity is
checked only at an outcome boundary, not once per scalar, so this adds no
per-scalar whole-input rescanning. The runtime conversion branches,
assignments, status behavior, public parameters, and limits are unchanged;
the public outcome contract is strengthened. This is not a whole-codec
equivalence or roundtrip theorem.

The Unicode corpus, generator, Python oracle, and negative controls are
unchanged. The existing `utf-capacity` selector retains short-output
precedence coverage. For valid corpus inputs, `unicode_probe.adb` additionally
converts with output capacity exactly `2 * Input'Length` and compares with
the existing oracle result; invalid corpus inputs already use ample output
capacity. The unchanged corpus contains **1,287,503 fixtures**.

The focused whole-unit proof used fresh `utf16-outcomes-lemma-focused` output:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf16-outcomes-lemma-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with **690 checks** (44 flow, 646 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(26 subprograms and packages). `Lemma_Invalid_UTF16_Unit` proved all five
checks; its postcondition and all four call preconditions proved.

The final-source build, tests, strict check, and Samba integration each exited
0:

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite utf-capacity
make unicode-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
```

The Unicode run reported 1,287,503 fixtures. The full proof used fresh
`utf16-outcomes-full` output:

```sh
gnatprove -P proof.gpr --subdirs=utf16-outcomes-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with **4,895 checks** (724 flow, 4,171 prover), zero unproved,
zero justified, 69 warnings, zero `pragma Assume` statements, and 13 units.
This explicit fresh-output run is not a literal `make prove` result. The
focused and full summaries are
`build/proof-obj/utf16-outcomes-lemma-focused/gnatprove/gnatprove.out` and
`build/proof-obj/utf16-outcomes-full/gnatprove/gnatprove.out`.
`git diff --check` exited 0 after this report section was added.

## UTF-8 to UTF-16 scalar emission contract

In `UTF8_To_UTF16`, the Ghost locals `Decoded_Scalar` and
`Scalar_Output_Start` save the successfully decoded scalar and the current
output offset before the existing BMP or supplementary-scalar writes. After
those unchanged writes, checked assertions prove that `Used` advanced exactly
two bytes for a BMP scalar or four for a surrogate pair. They also establish
that the newly written BMP unit equals the saved scalar, or that the two
newly written units are a high/low surrogate pair whose low-ten-bit
reconstruction equals it.

A further checked assertion applies the existing private Ghost
`UTF16_Scalar_At` model to only the new two- or four-byte output slice, at
position zero, and proves that it equals `Decoded_Scalar`. The slice remains
within the model's existing domain; no model precondition or public
conversion limit is widened. This model follows the previously reviewed
[RFC 2781 sections 2.2 and 3.1](https://www.rfc-editor.org/rfc/rfc2781.html).

In `UTF8_To_UTF16.Store_Unit`, checked constant-time assertions decompose the
retained `UTF16_Unit` identity check: they compare the two just-written
output bytes, converted to `Natural`, with `Unit mod 256` and `Unit / 256`.
The runtime byte assignments are unchanged. The encoder's branches,
supplementary-scalar mutation, public interface and limits, and decoding,
capacity, and status ordering are unchanged. This is a single-step scalar
emission guarantee, not a proof of output-prefix preservation, failure
position, or a whole-codec roundtrip.

The strict test-suite build and `utf-capacity` selector passed on the source
with these assertions. The focused whole-unit proof was rerun on that source
with:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf16-emission-decomposed-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 660 checks (44 flow, 616 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(25 subprograms and packages).

The unchanged Unicode corpus, test suite, forced strict check, and Samba
integration were run on the final source. The corpus run reported
**1,287,503 fixtures**. Each command exited 0:

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite utf-capacity
make unicode-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
```

The full proof used fresh `utf16-emission-full` output:

```sh
gnatprove -P proof.gpr --subdirs=utf16-emission-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 4,865 checks (724 flow, 4,141 prover), zero unproved,
zero justified, 69 warnings, zero `pragma Assume` statements, and 13 units.
This explicit fresh-output run is not a literal `make prove` result. The
focused and full summaries are
`build/proof-obj/utf16-emission-decomposed-focused/gnatprove/gnatprove.out`
and `build/proof-obj/utf16-emission-full/gnatprove/gnatprove.out`.
`git diff --check` exited 0 after the report section was added.

## UTF-16 scalar extraction contract

The private Ghost expression function `UTF16_Scalar_At` models one
little-endian UTF-16 scalar at an even byte offset, independently of the
array's lower bound. Its precondition bounds the input by
`SMB.Maximum_Frame_Size` and the position by the input length. It returns
zero for a missing or truncated scalar, NUL under the SMB no-NUL policy, or an
unpaired surrogate; otherwise it returns the BMP unit or reconstructs a
supplementary scalar from the high- and low-surrogate low ten bits.
Noncharacters remain valid. The model follows
[RFC 2781 sections 2.2 and 3.1](https://www.rfc-editor.org/rfc/rfc2781.html).

`UTF16_To_UTF8` records the current byte offset in the Ghost variable
`Scalar_Start` before its existing scalar extraction. After successful
extraction, checked assertions establish that the extracted scalar equals
`UTF16_Scalar_At (Input, Scalar_Start)` and that the offset advanced exactly
two bytes for a BMP scalar or four for a surrogate pair. Further checked
assertions establish validity of the one newly consumed UTF-16 unit, and of
the second unit for a supplementary scalar. The existing scalar extraction,
rejection ordering, output-capacity handling, runtime encoder, public limits,
and status behavior are unchanged.

The unchanged `UTF16_To_UTF8` loop invariant block and loop variant now sit
immediately after `Emit_Scalar`. This proof cutpoint exposes the validated
one- or two-unit frontier to the existing consumed-prefix invariant,
including on the final successful iteration; it adds no whole-prefix
runtime scan. `pragma Assertion_Policy (Loop_Invariant => Ignore)` retains
its existing runtime-only effect; the loop invariants remain GNATprove
obligations and are not proof suppressions.

In the existing `UTF8_To_UTF16.Store_Unit`, the checked guard now includes
even `Used`. Before the unchanged little-endian byte assignments, checked
constant-time assertions establish
`2 * (Previous_Used / 2) = Previous_Used` and exact byte reconstruction:
`Natural (SMB.Byte (Unit mod 256)) + 256 * Natural (SMB.Byte (Unit / 256)) = Unit`.
The existing identity assertion for the newly stored unit remains. These
checks separate alignment and byte reconstruction from the array update;
they do not add assumptions or change runtime byte assignments. No public
interface, failure-position guarantee, whole-string validation result, or
whole-codec roundtrip theorem is claimed by this single-step extraction
contract.

The initial strict build and targeted `utf-capacity` selector passed on the
first scalar-model revision. The later auxiliary assertions and invariant
relocation were covered by the final full unit and forced strict builds below.
The existing Unicode corpus, oracle, and negative
controls were reused without new test cases or fixtures. On the final source,
`make unicode-test` exited 0 and reported **1,287,503 fixtures** across the
unchanged scalar-pair, fixed-sequence, UTF-8 byte, UTF-16 unit, mixed, random,
and malformed-input categories. Final `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, and
`sudo -n python3 tests/samba_integration.py` also exited 0.

The focused whole-unit proof used fresh `utf16-scalar-bottom-focused` output:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf16-scalar-bottom-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 608 checks (42 flow, 566 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(25 subprograms and packages).

The full proof used fresh `utf16-scalar-full` output:

```sh
gnatprove -P proof.gpr --subdirs=utf16-scalar-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 4,813 checks (722 flow, 4,091 prover), zero unproved,
zero justified, 69 warnings, zero `pragma Assume` statements, and 13 units.
This explicit fresh-output run is not a literal `make prove` result. The
focused and full summaries are
`build/proof-obj/utf16-scalar-bottom-focused/gnatprove/gnatprove.out` and
`build/proof-obj/utf16-scalar-full/gnatprove/gnatprove.out`.

`git diff --check` was run after this section was added.

## UTF-8 scalar emission contract

The private `UTF16_To_UTF8.Emit_Scalar` precondition requires a nonzero scalar
in `1 .. 16#10FFFF#`, excludes `16#D800# .. 16#DFFF#`, bounds the output by
`2 * SMB.Maximum_Frame_Size`, and requires enough remaining capacity for
`Encoded_Size (Value)`. The existing caller proves these scalar-validity and
capacity requirements after rejecting NUL and malformed surrogate input.
Its postcondition retains the exact `Used` advance by `Encoded_Size (Value)`
and requires `UTF8_Scalar_At` to decode the slice written by this call:
`Output (Output'First + Used'Old .. Output'First + (Used - 1))` at position
zero must equal `Value`. This slice contains the newly emitted one-to-four
bytes only. The contract specifies the scalar emitted by this call; it does
not assert a quantified frame condition for preceding output or an exact
whole-codec UTF-8/UTF-16 roundtrip theorem.

`UTF8_Scalar_At` retains its original precondition of at most
`SMB.Maximum_Frame_Size` (1 MiB); its domain was not widened for emission.
The emission postcondition applies it to a slice of length `Encoded_Size`,
which is between one and four. No public conversion precondition or runtime
limit changed.

`Emit_Byte` has no modular `Pre` or `Post`. The exact former checks are
retained as body assertions: `Value <= 255` and `Used < Output'Length` before
the write, and `Used = Previous_Used + 1` after it. A constant-time body
assertion also proves `Byte_At (Output, Previous_Used) = Value`. These
assertions remain enabled; no quantified per-byte frame condition or ignored
assertion was added. The scalar encoder's branches and byte assignments are
unchanged.

The existing `utf-capacity` selector and Unicode corpus, oracle, and negative
controls were reused without new test cases, fixtures, or generator changes.
The corpus run reported **1,287,503 fixtures** across the existing scalar
pairs, fixed sequences, UTF-8 bytes and byte pairs, UTF-16 units, mixed and
random sequences, and malformed-input categories. The strict test-suite
build, `utf-capacity`, and `make unicode-test` all exited 0 before the final
slice-scoped contract refinement and restoration of the helper's original
precondition. The final source was subsequently compiled by `make test` and
the forced strict `make check` gate.

The final focused whole-unit proof used fresh `utf8-emission-slice-focused`
output:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf8-emission-slice-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 551 checks (40 flow, 511 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(24 subprograms and packages).

The final full proof used fresh `utf8-emission-full` output:

```sh
gnatprove -P proof.gpr --subdirs=utf8-emission-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 4,756 checks (720 flow, 4,036 prover), zero unproved,
zero justified, 69 warnings, zero `pragma Assume` statements, and 13 units.
This explicit fresh-output run is not a literal `make prove` result. The
focused and full summaries are
`build/proof-obj/utf8-emission-slice-focused/gnatprove/gnatprove.out` and
`build/proof-obj/utf8-emission-full/gnatprove/gnatprove.out`.

With Candidate GNAT14, final `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, and
`sudo -n python3 tests/samba_integration.py` all exited 0.
`git diff --check` was run after this section was added.

## UTF-8 scalar decoding contract

`Byte_At` now specifies both the byte-range bound and the exact mapping
`Character'Pos (Value (Value'First + Offset))`. The private Ghost expression
function `UTF8_Scalar_At` models one scalar at one position; it returns zero
for invalid or missing input, including `Position = Value'Length`. It is not
a validator for the entire remaining string. Its precondition keeps the input
within `SMB.Maximum_Frame_Size` and the position within the input length.

The model follows the canonical byte ranges in
[RFC 3629 section 4](https://www.rfc-editor.org/rfc/rfc3629#section-4):
non-NUL ASCII `01..7F`; two-byte forms `C2..DF 80..BF`; three-byte forms
`E0 A0..BF 80..BF`, `ED 80..9F 80..BF`, and
`E1..EC`/`EE..EF 80..BF 80..BF`; and four-byte forms
`F0 90..BF 80..BF 80..BF`, `F4 80..8F 80..BF 80..BF`, and
`F1..F3 80..BF 80..BF 80..BF`. Length guards precede reads of subsequent
bytes. Reconstruction uses leading-byte `mod 32`, `mod 16`, or `mod 8` and
continuation-byte `mod 64`, distinct from the runtime decoder's subtraction
arithmetic. The model enforces the existing SMB no-NUL policy; Unicode
noncharacters remain valid.

`Decode_UTF8` now guarantees that `Scalar` equals this model at the old
position; `Status` is `SMB.Invalid_Encoding` exactly when `Scalar = 0` and
`SMB.Ok` otherwise. The new position guarantee is exact: no advancement for
zero, then advancement by one, two, three, or four bytes for scalar values
`<= 16#7F#`, `<= 16#7FF#`, `<= 16#FFFF#`, or greater, respectively. Its
existing successful scalar bounds, surrogate exclusion, progress, and
four-byte supplementary-scalar guarantee remain. Thus decoding at end of
input is an invalid single-scalar operation with unchanged position, while
the whole-string `UTF8_To_UTF16` conversion of empty input remains successful.
No public interface, limit, runtime decoder assignment or branch, or codec
behavior changed. This does not claim an exact whole-codec UTF-8/UTF-16
roundtrip theorem.

The final Ghost model uses GNATprove's default expression-function treatment,
without `Inline_For_Proof`. A forced-inlining experiment left three caller
checks in the existing UTF-16 output-prefix proof unproved; that annotation
was removed, after which the whole-unit focused proof passed. The possibility
that expansion introduced irrelevant conditional and modulo terms into those
caller obligations is a hypothesis, not an established solver diagnosis.
There are no assumptions or suppressions.

The existing `utf-capacity` selector and independent Unicode corpus, oracle,
and negative controls were reused without new test cases, fixtures, or
generator changes. The corpus run reported 1,287,503 fixtures across the
existing scalar-pair, fixed-sequence, byte, UTF-16-unit, mixed, random, and
malformed-input categories. The strict test-suite build, `utf-capacity`, and
`make unicode-test` all exited 0 before the proof-annotation-only removal;
the final source was subsequently compiled by the final `make test` and
forced strict `make check` gates.

The final focused whole-unit proof used fresh `utf8-scalar-axiom-focused`
output:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf8-scalar-axiom-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 464 checks (40 flow, 424 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(24 subprograms and packages).

The final full proof used fresh `utf8-scalar-full` output:

```sh
gnatprove -P proof.gpr --subdirs=utf8-scalar-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 4,669 checks (720 flow, 3,949 prover), zero unproved,
zero justified, 69 warnings, zero `pragma Assume` statements, and 13 units.
This explicit fresh-output run is not a literal `make prove` result. The
focused and full summaries are
`build/proof-obj/utf8-scalar-axiom-focused/gnatprove/gnatprove.out` and
`build/proof-obj/utf8-scalar-full/gnatprove/gnatprove.out`.

With Candidate GNAT14, the final `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, and
`sudo -n python3 tests/samba_integration.py` all exited 0.
`git diff --check` was run after this section was added.

## UTF-8-to-UTF-16 output-prefix validity

`UTF8_To_UTF16` retains its existing bounds, even-length guarantee, and
success/empty-input equivalence. Its postcondition additionally requires
`Valid_UTF16_Text` for `Output (Output'First .. Output'First + (Used - 1))`
whenever `Used > 0`, regardless of `Status`. The empty prefix is covered
vacuously. This proves validity of the produced UTF-16 prefix, including on
failure; it does not prove exact byte correspondence with the UTF-8 input or
exact failure-status precedence. A valid partial prefix does not imply
successful conversion. The even-length guarantee predates this change.

The converter input bound remains `SMB.Maximum_Frame_Size` (1 MiB). The
preconditions of the three Ghost UTF-16 model helpers now cover
`2 * SMB.Maximum_Frame_Size` (2 MiB), matching the existing encoder output
domain. The standalone `Validate_UTF16` precondition remains 65,534 bytes.
The model retains its existing nonzero-unit and surrogate-pair rules,
including acceptance of Unicode noncharacters and the SMB policy that
rejects NUL.

`Store_Unit` intentionally has no `Pre`, `Post`, `Global`, or `Depends`
aspects. Its former precondition and postcondition are retained as body
assertions, and a constant-time body assertion identifies the little-endian
unit just written. GNATprove uses contextual analysis at the three call
sites; the body checks are proved there rather than reported as separate
checks for `Store_Unit`. This exposes byte updates without a per-scalar
quantified frame postcondition. The
`UTF16_Unit` and `Valid_UTF16_Unit` expression functions use
`Annotate => (GNATprove, Inline_For_Proof)`, so GNATprove reasons from their
expression definitions. This follows the
[AdaCore proof-inlining guidance](https://docs.adacore.com/spark2014-docs/html/ug/en/appendix/additional_annotate_pragmas.html#annotation-for-inlining-functions-for-proof)
and does not introduce assumptions or weaken a contract. The local
`Assertion_Policy (Loop_Invariant => Ignore)` disables runtime evaluation
of loop invariants only, avoiding quadratic prefix scans; GNATprove still
proves them. Body assertions and public postconditions remain enabled and
checked. The new loop invariant covers the valid produced prefix and
excludes a trailing high surrogate. No encoding
assignment, conversion branch, or status decision changed.

`Test_UTF_Capacity` adds coverage for the produced prefix:

1. `Smile & "A"` and its UTF-16 bytes exercise exact-fit and short-buffer
   behavior in both conversion directions, with a complete surrogate-pair
   prefix before the following ASCII character.
2. The maximum scalar `F4 8F BF BF` converts to `FF DB FF DF` with input and
   output arrays ending at their respective highest bounds.
3. `"A" & Smile & Character'Val (16#80#)` yields
   `SMB.Invalid_Encoding`, `Used = 6`, the complete `A`-plus-pair prefix,
   and a zero-filled output tail.

The preceding long-input and UTF-16 capacity/validity cases remain. The
independent Unicode corpus definition, generator, categories, seed, and
status controls are unchanged. `make unicode-test` reran the existing
generator and reported the same 1,287,503 fixtures; the existing oracle
continues to make 1,201,703 UTF-16 validator calls. No new corpus or
mutation control was added for this contract change.

The final focused whole-unit proof used the already completed fresh
`utf16-output-final-focused` run:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf16-output-final-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 398 checks (39 flow, 359 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(23 subprograms and packages). Its summary and logs are
`build/proof-obj/utf16-output-final-focused/gnatprove/gnatprove.out` and
`/home/ubuntu/utf16-output-final-focused.{stdout,stderr}.log`.

The final full proof used fresh `utf16-output-full` output:

```sh
gnatprove -P proof.gpr --subdirs=utf16-output-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 4,603 checks (719 flow, 3,884 prover), zero unproved,
zero justified, 69 warnings, zero `pragma Assume` statements, and 13 units.
This explicit fresh-output run is not a literal `make prove` result. Its
summary and logs are
`build/proof-obj/utf16-output-full/gnatprove/gnatprove.out` and
`/home/ubuntu/utf16-output-full-proof.{stdout,stderr}.log`.

With Candidate GNAT14, these final-source commands all exited 0:

```sh
gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe
./build/bin/test_suite utf-capacity
make unicode-test
make test
make check GPRBUILD="gprbuild -f"
sudo -n python3 tests/samba_integration.py
git diff --check
```

`git diff --check` was run after this section was added.

## UTF-16 conversion input validity

`UTF16_To_UTF8` retains its existing `Used` bounds and its success guarantees
of even input byte length and empty-input equivalence. Its success
postcondition now additionally requires `Valid_UTF16_Text (Input)`. This establishes
validity of the successful input, not exact UTF-8 output correspondence or
the exact precedence of all failure statuses. Existing partial `Used` and
output contents on failure are unchanged and are not specified more
strongly.

The Ghost model requires each UTF-16 code unit to be nonzero, and requires
high and low surrogates to be correctly paired; Unicode noncharacters remain
valid. NUL rejection is the existing SMB policy. `UTF16_Unit`,
`Valid_UTF16_Unit`, and `Valid_UTF16_Text` now have preconditions up to
`SMB.Maximum_Frame_Size` (1 MiB), covering the converter's existing input
domain. The declaration of `UTF16_To_UTF8` was moved below those helpers so
its contract can reference `Valid_UTF16_Text`. The standalone
`Validate_UTF16` precondition remains 65,534 bytes.

No conversion or validation runtime assignment or branch changed. The
converter has a local `Assertion_Policy (Loop_Invariant => Ignore)` and the
same valid-consumed-prefix and “last processed unit is not a high surrogate”
invariant used by the validator. GNATprove proves these invariants while
their quantified checks are not evaluated at runtime.

Four cases were added to `Test_UTF_Capacity` (the `utf-capacity` selector):

1. `DBFF DFFF`, the maximum Unicode scalar, converts to `F4 8F BF BF` with
   input bounds ending at `Natural'Last` and output bounds ending at
   `Positive'Last`.
2. A 65,536-byte input of 32,768 `A` code units converts successfully to
   32,768 `A` characters, exercising the converter/model beyond the
   standalone validator's 65,534-byte limit.
3. Replacing the final code unit with an orphan `D800` yields
   `SMB.Invalid_Encoding`, `Used = 32,767`, the converted prefix, and a
   zero-filled output tail.
4. With output capacity 32,766 on that input, conversion reaches
   `SMB.Invalid_Length` with `Used = 32,766` before reaching the later
   orphan surrogate.

The independent Unicode corpus definition remains unchanged at 1,287,503
fixtures, with its existing generator, seed, categories, and status controls
unchanged. `make unicode-test` reran that generator and produced the same
fixture set. The validator continues to receive 1,201,703 calls in that
oracle. No corpus was expanded, and no additional mutation control was run
for this contract-only change; the existing oracle controls are described
in the UTF-16 validator section below.

Focused whole-unit proof used a fresh `utf16-conversion-focused` output:

```sh
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=utf16-conversion-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 349 checks (39 flow, 310 prover), zero unproved, zero
justified, zero warnings, zero `pragma Assume` statements, and one unit
(23 subprograms and packages).

The fresh full proof used `utf16-conversion-full`:

```sh
gnatprove -P proof.gpr --subdirs=utf16-conversion-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 with 4,554 checks (719 flow, 3,835 prover), zero unproved,
zero justified, 69 warnings, zero `pragma Assume` statements, and 13 units.
Both proof results are from fresh output directories; the full result is
not a literal `make prove` run.

With Candidate GNAT14, the strict test-suite build and `utf-capacity`
selector passed. `make unicode-test` passed with all 1,287,503 fixtures.
The final `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, and full Samba integration all exited
0. `git diff --check` was run after this section was added.

## NTLM username uppercase contract

`Uppercase_NTLM_User` now specifies exact status priority: unequal input and
output lengths yield `SMB.Invalid_Length` before encoding is considered;
otherwise an ASCII input yields `SMB.Ok`, and a non-ASCII input yields
`SMB.Invalid_Encoding`. On success, ASCII lowercase `a` through `z` map to
`A` through `Z`; all other ASCII characters remain unchanged.
`SMB.Invalid_Length` guarantees every output character is zero. There is no
cleared-output guarantee for `SMB.Invalid_Encoding`: the existing partial
converted prefix remains, and `SMB.Text.NTLM_Username` raises
`SMB.Authentication_Error` for the failure.

The case mapper continues to accept empty input and NUL as ASCII; it is not
credential validation. `Validate_Credentials` separately rejects an empty
username, and `UTF8_To_UTF16` rejects NUL under the existing SMB policy.

The initial output zeroing is now the equivalent aggregate assignment
`Output := (others => Character'Val (0));`, replacing the zeroing loop to
provide definite initialization to GNATprove without changing behavior.
The mapping loop and runtime rejection rules are unchanged. Its proof
invariants separately describe the ASCII input prefix using input indices
and the converted output prefix using offsets. The local
`Assertion_Policy (Loop_Invariant => Ignore)` keeps quantified invariants
from being evaluated at runtime while GNATprove still proves them. No
`Relaxed_Initialization`, temporary `pragma Assert`, assumptions, or proof suppressions
remain for this contract.

`Test_NTLM_Uppercase` covers 4,100 cases: all 256 one-byte values; each byte
at each of three positions in `azm` with capacities 0 through 4 (3,840
cases); empty input at capacities 0 and 1; a 4,096-character lowercase
credential; and a one-character input/output starting at `Positive'Last`.
Successful bytes are checked against `Ada.Characters.Handling.To_Upper`,
independently of the Ghost mapping helper. Matching-length cases also check
the public `SMB.Text.NTLM_Username` adapter, including
`Authentication_Error` for non-ASCII input. The helper's output bounds are
formed without overflowing in the `Positive'Last` case.

The authorized sensitivity control used both `origin/main` Core_Text files
and changed only the mapper's `Character_Code - 32` to `-31`. On that
initial test version with baseline Core_Text sources, the strict build passed and the selector failed at
`NTLM uppercase character correspondence`. The authored files were restored
byte-for-byte; their restored hashes were spec
`d961d11bc067907622e895ab630036523f8a21fc90592bff6d0c831cbb59b002` and
body `94e9b81307083e21efc30f89652c036ff865bee4aa27d38a41b29ee51f1c653e`.
The restored build and selector passed. This control preceded the later
aggregate initialization and final proof-invariant refinements; the final
source was separately rebuilt and retested below.

The first focused proof exited 1 with 344 checks and five unproved checks
(four output-initialization checks and the status postcondition). After the
aggregate initialization rewrite, one status-postcondition check remained
unproved. Splitting the invariant into an input-indexed ASCII prefix and an
offset-indexed output mapping prefix resolved that obligation. Temporary
diagnostic assertions were removed; the final whole-unit proof below is
from the final source. A separate limited-subprogram run also passed, but
the reported whole-unit and full-project statistics are from fresh-output
runs, not extrapolated from that limited run.

Final validation:

- Candidate GNAT14 strict test-suite build:
  `gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe` — exit 0.
- `./build/bin/test_suite ntlm-uppercase` — exit 0, 4,100 cases passed.
- Fresh whole-unit proof in `ntlm-uppercase-final-focused` — exit 0, 341
  checks (39 flow, 302 prover), zero unproved, zero justified, zero
  warnings, zero `pragma Assume` statements, one unit (23 subprograms and
  packages).
- `make test` — exit 0; the full Ada test suite passed, including the
  4,100-case selector.
- `make check GPRBUILD="gprbuild -f"` — exit 0, including source dependency
  checks.
- `sudo -n python3 tests/samba_integration.py` — exit 0.
- Fresh full proof in `ntlm-uppercase-full` — exit 0, 4,546 checks (719
  flow, 3,827 prover), zero unproved, zero justified, 69 warnings, zero
  `pragma Assume` statements, 13 units.
- `git diff --check` — exit 0.

The fresh-output proof commands were:

```text
gnatprove -P proof.gpr -u smb-core_text.adb --subdirs=ntlm-uppercase-final-focused --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
gnatprove -P proof.gpr --subdirs=ntlm-uppercase-full --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

These are not reported as a literal `make prove` run.

## UTF-16 validator contract

Ghost helpers model a little-endian UTF-16 code unit, whether an individual
unit is valid, and whether the entire byte string is valid UTF-16. A unit must
be nonzero; a high surrogate must be followed by a low surrogate, and a low
surrogate must be preceded by a high surrogate. A valid text has an even byte
length and every code unit is valid; empty text is valid. Unicode
noncharacters are allowed. Rejecting NUL is the existing SMB policy, not a
Unicode validity rule. `Validate_UTF16` now specifies its exact status:
odd-length input yields `SMB.Invalid_Length`; otherwise valid text yields
`SMB.Ok`, and invalid text yields `SMB.Invalid_Encoding`.

The UTF-16 validation and conversion rejection algorithms are unchanged.
The body adds a processed-prefix loop invariant and an invariant that the
last processed code unit is not a high surrogate, allowing the proof to
reason about consuming a valid surrogate pair. The local
`Assertion_Policy (Loop_Invariant => Ignore)` follows the existing
`Validate_Path` pattern: quantified loop invariants are not evaluated at
runtime, avoiding quadratic invariant-checking cost, while GNATprove still
proves them. The model and exact status contract are not weakened.

`unicode_probe.Check_16` now calls `Validate_UTF16` on the rebased input
starting at index 29 and compares its status with the existing strict
Python-codec oracle before running the existing conversion and public-adapter
checks. The existing corpus remains unchanged at 1,287,503 fixtures; its
generator and categories were not changed. The validator receives 1,201,703 calls: 1,112,063 scalar
pairs, 4 fixed sequences, 4,096 mixed sequences, 65,536 UTF-16 code units,
20,000 random UTF-16 sequences, and 4 malformed UTF-16 sequences. Two
negative controls require the validator-specific diagnostic for valid ASCII
marked invalid (`6 4100 E`) and an orphan high surrogate marked valid
(`6 00d8 41`).

The sensitivity control used both `origin/main` Core_Text files with the
authored probe and changed only the `First = 0` rejection in
`Validate_UTF16` from `SMB.Invalid_Encoding` to `SMB.Ok`. The strict probe
build exited 0, and `6 0000 E` exited 1 with
`UTF-16 validator status mismatch: OK`. After restoring both authored
Core_Text files byte-for-byte (spec SHA-256
`09069560183755eb02046432c3f847f630c10c9dcbdd6366b3557f0fe7b98644`;
body SHA-256
`5979366846dc138dd108bf5aa6a49819a7f42b91008348fe46e05f6a527acef6`), the
strict build exited 0 and the fixture passed as `PASS 1`.

The focused proof in fresh `utf16-validator-focused` output exited 0 with
321 checks (37 flow, 284 prover), 0 unproved, 0 justified, 0 warnings,
0 `pragma Assume`, and 1 unit. The fresh-output full proof in
`utf16-validator-full` exited 0 with 4,526 checks (717 flow, 3,809 prover),
0 unproved, 0 justified, 69 warnings, 0 `pragma Assume`, and 13 units.
This was a fresh-output proof, not a literal `make prove` run.

With Candidate GNAT14, the strict probe build, Python syntax check,
`make unicode-test`, `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, and full Samba integration all exited 0.
`git diff --check` was run after this report was added.

## Request-ID continuity across Engine operations

The Ghost getter `Next_Request_Id` exposes the Engine's private request-ID
counter to contracts. The operation-level conditions complement the existing
`Begin_Request` contract: successful reservations return the old counter and
advance it by exactly one; rejection preserves the state and clears the
reservation outputs. Counter exhaustion is proof-only. Successful
`Initialize` and all `Invalidate` calls set the counter to zero.
Lifecycle transitions, `Register_Handle`,
`Close_Handle`, and `Discard_Response_Receipt` preserve it.
`Inspect_Interim_Response` preserves it on success and resets it on failure.
`Accept_Response` preserves it except on failure or successful LOGOFF, which
resets it. The Engine implementation body is unchanged from `origin/main`.

These are per-operation Engine guarantees, not a separate whole-history
temporal theorem, nor a guarantee about transport sequencing outside the
Engine. QWord exhaustion has no runtime test hook and was not exercised.

The `engine-receipts` selector verifies handshake request IDs 0 through 3.
The handle-capacity fixture then checks one local sequence from 4 through 265:
256 CREATE reservations, followed by SET_INFO, CLOSE, replacement CREATE,
TREE_DISCONNECT, TREE_CONNECT, and final CREATE. Together these are 266
consecutive reservations, 0 through 265. Capacity refusals and explicit
receipt discard are checked not to consume an ID. The signed disconnect and
connect responses are synthetic internal fixtures reusing the same TreeId;
they do not establish native-server behavior or external transport ordering.
Existing handle-ticket assertions remain in the fixture.

Two sensitivity controls used both Engine files from `origin/main` with the
authored tests. In the first, only the successful `Register_Handle` path was
mutated to set `Next_Message_Id` to zero immediately before the ticket
increment. The strict build exited 0; the selector exited 1 with
`CREATE request skipped or reused a message ID`. In the second, only the
successful TREE_DISCONNECT path was mutated to reset `Next_Message_Id` before
clearing handles. The strict build exited 0; the selector exited 1 with
`tree disconnect changed the request counter`. After each control, the
authored Engine files were restored byte-for-byte (spec SHA-256
`2c5b2de0898099a44d3d9a3dfe4be5b0e36ec26b1f8934f018b77c9ee0d7e24a`;
body SHA-256
`d7e7ea04a7df91966fdae3f2dd45d0e2958a4f4a9f0cdc9dab36cd01ee9176cc`).
The strict build and selector exited 0 after each restoration.

The focused Engine proof in fresh `request-id-focused` output exited 0 with
185 checks (71 flow, 114 prover), 0 unproved, 0 justified, one warning at
`smb-engine.adb:436` concerning `Nt_Status`, 0 `pragma Assume`, and one unit.
The fresh-output full proof in `request-id-full` exited 0 with 4,488 checks
(714 flow, 3,774 prover), 0 unproved, 0 justified, 69 warnings, 0
`pragma Assume`, and 13 units. This was a fresh-output proof, not a literal
`make prove` run.

With Candidate GNAT14, the strict build, `engine-receipts`, `make test`,
`make check GPRBUILD="gprbuild -f"`, and full Samba integration all exited 0.
`git diff --check` was run after this report was added.

## Handle ticket allocation and continuity

The Ghost getter `Last_Allocated_Handle_Ticket` exposes the private
`Next_Ticket` counter to contracts. The operation-level contracts specify
that successful `Initialize` and all `Invalidate` calls reset it to zero.
Successful `Register_Handle` calls require the old counter to be below
`SMB.QWord'Last`, advance it by exactly one, and assign that value to the
returned token. A `SMB.Counter_Exhausted` registration result implies the
counter is already at `SMB.QWord'Last`; tickets do not wrap. Other lifecycle
operations, handle close, request reservation, and receipt discard preserve
the counter. Interim-response inspection preserves it on success and resets
it on failure. `Accept_Response` preserves it except when validation failure
invalidates the state or a successful LOGOFF resets the Engine. In particular,
a successful TREE_DISCONNECT clears the handle table but retains the ticket.
The CREATE reservation contract also specifies the exact counter-exhaustion
condition without a test-only setter.

These are contracts over each Engine operation, not a separate whole-history
temporal theorem or a global ticket registry. Counter exhaustion is
proof-only; no runtime hook makes the boundary reachable.

`Test_Handle_Capacity`, selected by `engine-receipts`, verifies tickets
1 through 256 for the initial registrations. After the capacity refusal and
a CLOSE, reusing a slot receives ticket 257. It then accepts synthetic signed
TREE_DISCONNECT and TREE_CONNECT responses using the same TreeId, while
preserving owner and epoch, and verifies that the next handle receives
ticket 258. It rejects all 256 prior tokens and the earlier closed token,
while accepting the new token. This internal synthetic fixture is not a
native-server observation and does not claim that a real server permits
TreeId reuse.

Two sensitivity controls each used both Engine files from `origin/main` with
the authored tests. Changing only `Register_Handle`'s ticket increment from
`+ 1` to `+ 2` passed the strict build (exit 0), then the selector failed
(exit 1) with `handle tickets did not advance exactly once per
registration`. Adding only `State.Next_Ticket := 0;` to the successful
TREE_DISCONNECT branch passed the strict build and failed the selector with
`share reconnection recycled handle tickets or changed identity`. After each
control, both authored Engine files were restored byte-for-byte: the spec
SHA-256 was
`d2cbe79a171da4def7a906057c86544c771b03797d9b4983ef0e641f4ab17181` and the
body SHA-256 was
`d7e7ea04a7df91966fdae3f2dd45d0e2958a4f4a9f0cdc9dab36cd01ee9176cc`.
The strict rebuild and selector passed after each restoration.

The focused Engine proof in fresh `handle-ticket-focused` output exited 0
with 185 checks (71 flow, 114 prover), 0 unproved, 0 justified, one warning
at `smb-engine.adb:436` concerning `Nt_Status`, 0 `pragma Assume`, and one
unit analyzed. The fresh-output full proof in `handle-ticket-full` exited 0
with 4,488 checks (714 flow, 3,774 prover), 0 unproved, 0 justified,
69 warnings, 0 `pragma Assume`, and 13 units. This was a fresh-output proof,
not a literal `make prove` run.

With Candidate GNAT14, the strict build, `engine-receipts`, `make test`,
`make check GPRBUILD="gprbuild -f"`, and full Samba integration all exited 0.
The final `git diff --check` result is recorded with the branch changes.

## Invalidation reset contract

`Invalidate`'s runtime implementation is unchanged and matches
`origin/main`. Its postcondition now requires a complete reset of the public
connection context: disconnected phase, no handles, pending request,
validated receipt, or signing key; zero logical key bytes, session/tree/async
IDs, negotiated read/write limits, and next request ID; and default
`Response_Info`. On success it preserves the exact owner and advances the
epoch by exactly one, requiring the old epoch to be below `SMB.QWord'Last`.
At epoch exhaustion it returns `SMB.Counter_Exhausted`, clears the owner to
zero, and preserves the epoch. The established exact return-status
classification and clearing guarantees for phase, handles, pending/key state,
and session/tree/async values remain in force.

This is not a claim that the entire `Engine_State` record is erased:
`Pending_Expected` is intentionally not cleared by the existing runtime.
Signing-key zeroing describes logical Engine state only, not physical memory
erasure. Epoch exhaustion is covered by the contract and proof, not by a
runtime test; no test hook makes that boundary reachable.

`Test_Invalidation_Reset` is selected by `engine-receipts`. Its seven
synthetic fixtures cover default, transport-connected, pending NEGOTIATE,
SESSION_SETUP challenge with nonzero receipt session metadata, authenticated
with a nonzero key, live handle plus signed SET_INFO receipt, and live handle
plus a synthetic unsigned `STATUS_PENDING` with nonzero AsyncId after a
signed READ reservation. The async interim fixture is synthetic and is
distinct from a signed validated response or an observation from a native
server. The test performs eight resets, including a repeated default-state
reset, and verifies six same-owner transport/NEGOTIATE restarts reserve
message ID zero. It also checks cleared public state and limits, stale-handle
and output rejection, and that the default state does not fabricate an owner.
Existing reconnection and handle-reuse coverage remains in the suite.

Two runtime sensitivity controls used the weaker `origin/main` Engine spec
and independently changed only `Invalidate`'s body. Changing the epoch
increment from `+ 1` to `+ 2` passed the strict build (exit 0), then the
selector failed (exit 1) at the explicit diagnostic
`invalidation did not reset context or advance the same owner's epoch`.
Removing `State.Next_Message_Id := 0;` likewise passed the strict build and
failed the selector at
`invalidation did not restart message IDs at zero`. After each control, both
files were restored byte-for-byte: the spec SHA-256 was
`14a023463c9612c34183e9f0a3d24da94f4b8a3cb273a97cf2c798aa667172df` and the
body SHA-256 was
`c19631831a319934546e34b958e5d7610cd7e53f6975374b63f97027f190cf5c`.
The strict rebuild and selector passed after each restoration; the selector
reported eight resets and six message-ID restarts.

The focused Engine proof in fresh `invalidation-focused` output exited 0
with 184 checks (70 flow, 114 prover), 0 unproved and 0 justified; it
reported one warning at `smb-engine.adb:433` concerning `Nt_Status`, used
0 `pragma Assume`, and analyzed one unit. The fresh-output full proof in
`invalidation-full` exited 0 with 4,487 checks (713 flow, 3,774 prover),
0 unproved, 0 justified, 69 warnings, 0 `pragma Assume`, and 13 units.
This was a fresh-output full proof, not a literal `make prove` run.

With Candidate GNAT14, the strict build, `engine-receipts`, `make test`,
`make check GPRBUILD="gprbuild -f"`, and full Samba integration all exited 0.
The final `git diff --check` result is recorded with the branch changes.

## Reservation failure atomicity and message-ID progression

`Begin_Request` previously cleared the validated-response receipt before
checking whether a reservation could be made. A rejected command could
therefore discard an unconsumed NEGOTIATE, SESSION_SETUP challenge, or signed
CREATE receipt. The clear now occurs only after all rejection paths. Every
rejected reservation preserves the complete Engine state and returns a zero
message ID and default request expectation; a valid reservation still
supersedes the prior receipt.

The ghost `Next_Request_Id` models the Engine's next message-ID counter. The
contract specifies that successful reservations return the prior counter and
advance it by exactly one without wrapping. If no request is pending and the
prior counter is `SMB.QWord'Last`, the result is `SMB.Counter_Exhausted`;
pending-request refusal retains priority. Counter exhaustion is covered by
the contract and proof only, not a runtime test. Message IDs are not claimed
to be globally unique across reconnects.

`Test_Request_Receipt_Preservation` uses synthetic NEGOTIATE, SESSION_SETUP
challenge, and signed CREATE responses accepted through the Engine response
validation path. It checks nine rejected reservations across those receipt
fixtures, with exact statuses, full state equality, cleared poisoned outputs,
and successful consumption of the original receipt afterward. Snapshot/restore
cases verify that three valid reservations use exactly the next message ID,
supersede the receipt, and leave pending state unchanged when later receipt
consumption is rejected; the CREATE case returns no handle after supersession.
These are internal Engine fixtures, not a reproduction of a user-facing SMB
network failure or an observation from a real server.

`Test_Handle_Capacity` also fills all 256 handle slots, accepts a signed
SET_INFO receipt, and checks that direct CREATE reservation rejection with
`SMB.Resource_Limit` preserves the complete state and receipt and clears the
reservation outputs. The existing `Core_Client.Prepare_Create` rejection and
handle validation, close, and reuse checks remain in place. The existing 12
receipt-free reservation failure cases are unchanged.

The actual-old-code sensitivity control used both Engine source files from
`origin/main`. Its strict build passed; the selector failed with the expected
`rejected reservation consumed receipt or changed state/output`. Afterward,
both authored Engine files were restored byte-for-byte:

- `src/smb-engine.ads`: SHA-256
  `5017a2a8e987719ba3f401b0ef687f3a2d826f70fba9a8eabfacce7898f1343d`
- `src/smb-engine.adb`: SHA-256
  `c19631831a319934546e34b958e5d7610cd7e53f6975374b63f97027f190cf5c`

The strict rebuild and `engine-receipts` selector then passed. After the
proof-only `Core_Client.Prepare_Next` assertion below was added, the strict
build and selector passed again. The selector reported the new nine receipt
rejections, three retries, and three superseding reservations; it also passed
the existing request-metadata, authentication, lifecycle, owner-allocation,
receipt-transition, handle-capacity, and handle-failure tests.

The focused Engine proof in fresh `reservation-atomicity-focused` output
exited 0 with 184 checks (70 flow, 114 prover), 0 unproved and 0 justified,
and one warning at `smb-engine.adb:433` concerning `Nt_Status`; one unit was
analyzed.

The first fresh-output full proof, in `reservation-atomicity-full`, exited 1:
4,481 checks (713 flow, 3,767 prover), 0 justified, and one unproved assertion
at `smb-core_client.adb:2281` in `Prepare_Next`; it emitted 69 warnings, used
0 `pragma Assume`, and analyzed 13 units. A targeted replay of that line with
progressive proof and a 300-second timeout also exited 1 without discharging
the assertion.
Following review, a proof-only assertion of the common eight-byte position
predicate was added immediately before `Transfer_Packet_Matches`. This splits
the proof obligation and does not change runtime behavior or weaken a
guarantee. The focused Core_Client proof in fresh
`reservation-atomicity-client-repair` output then exited 0 with 1,293 checks
(276 flow, 1,017 prover), 0 unproved, 0 justified, 56 warnings, 0
`pragma Assume`, and one unit analyzed.

After that proof split, the fresh-output full proof in
`reservation-atomicity-final` exited 0: 4,487 checks (713 flow, 3,774
prover), 0 unproved, 0 justified, 69 warnings, 0 `pragma Assume`, and 13
units analyzed. This was a fresh-output full proof, not a literal
`make prove` run. `make test`, forced strict `make check
GPRBUILD="gprbuild -f"`, and the full Samba integration had passed before the
proof-only assertion was added; they were not rerun after it. The Candidate
GNAT14 strict build and `engine-receipts` selector were rerun after the
assertion and passed. An earlier `make test` invocation without the
Candidate14 `PATH` selected system GNAT 10.5 and failed with a GNAT compiler
bug at `smb-engine.ads:668:46`; the required Candidate GNAT14 rerun passed.
`git diff --check` passed.

## Receipt transition contracts

`Mark_Negotiated` now specifies its exact status: it returns `SMB.Ok` only for
a transport-connected state with no pending request, an unconsumed unsigned
successful NEGOTIATE receipt, limits in `1 .. SMB.Maximum_Frame_Size`, and
limits equal to those in the receipt; otherwise it returns
`SMB.Invalid_Value`. Rejection preserves the complete Engine state. Successful
transition consumes the receipt and records the negotiated limits.

`Mark_Share_Connected` returns `SMB.Ok` only for an authenticated state with no
pending request, a nonzero tree ID, and an unconsumed signed successful
TREE_CONNECT receipt matching that ID; otherwise it returns
`SMB.Invalid_State_Status`. Rejection preserves the complete Engine state.
Success consumes the receipt, connects the tree, and preserves the prior
transfer limits, identity, signing key, and handle table.

`Discard_Response_Receipt` returns `SMB.Invalid_State_Status` exactly when the
old state has a pending request, preserving the complete state on rejection.
Otherwise it returns `SMB.Ok`, clears the validated receipt and zero-defaults
the entire public `Response_Info`, while preserving connection context and
handles. No runtime implementation-body changes were made.

`Test_Receipt_Transitions` passed with 19 rejected negotiations, 9 rejected
tree transitions, 3 rejected discards, 5 successful discards, and 2 successful
transition retries. Rejections check exact status and complete state equality.
The retries use the same valid receipt after rejected attempts. The discard
cases cover default state, consumed negotiation, idempotence, a live handle,
and a signed TREE_CONNECT error response; the live directory handle's file ID,
read-only access mode, and directory flag are checked with executable
`Validate_Handle`. The signed error is a synthetic fixture accepted by the
parser/signature checks, not evidence about a real server response.

In the sensitivity control, the origin/main Engine specification was used and
the `Mark_Negotiated` rejection status was changed from `SMB.Invalid_Value` to
`SMB.Invalid_State_Status`. The strict build passed and the selector failed as
required with `rejected negotiation changed state or status`. Both Engine
files were restored byte-for-byte; their SHA-256 hashes matched the
pre-control values, and the strict rebuild and selector passed.

The focused Engine proof in fresh `receipt-transitions-focused` output exited
0: 183 checks (69 flow, 114 prover), 0 unproved, 0 justified, and 1 warning
(`smb-engine.adb:430`, `Nt_Status` after `Validate_Header`); 1 unit analyzed.
The final gates passed: `make test`, forced strict `make check
GPRBUILD="gprbuild -f"`, and the full Samba integration.

The fresh-output full proof in `receipt-transitions-full` exited 0 on its first
attempt: 4,480 checks (712 flow, 3,768 prover), 0 unproved, 0 justified,
69 warnings, 0 `pragma Assume`, and 13 units analyzed. This was a fresh-output
proof, not a literal `make prove` run. `git diff --check` passed.

## Owner allocation atomicity and monotonicity

`Last_Allocated_Owner_Id` is a ghost view of the process-local owner registry.
`Initialize` specifies that, within a single externally serialized process,
each successful call consumes exactly one owner ID and assigns that ID to the
new Engine state; the registry does not wrap. A failed call preserves both the
entire Engine state and the registry, with the existing exact failure
classification. Successful initialization requires a disconnected state with
no pending request, signing key, validated receipt, or open handles.

The runtime allocation algorithm is unchanged; the body adds only the ghost
getter. This guarantee assumes callers externally serialize owner-allocation
calls, including calls made through different `Connections`. It does not claim
concurrent correctness or persistent owner identity across process restarts.
The exhaustion boundary is covered by the contract and proof only; it was not
exercised by a runtime test.

`Test_Owner_Allocation` passed with 65 successful allocations and 32 rejected
initializations. The test observes registry preservation through the next
successful allocation and does not call the ghost getter. In the sensitivity
control, the origin/main Engine spec and body were used with a guarded registry
increment added to the first invalid-state rejection branch. The strict build
passed and the selector failed as required with
`owner allocation skipped or reused an ID`. Both Engine files were restored
byte-for-byte; their SHA-256 hashes matched the pre-control values, and the
strict rebuild and selector passed.

The focused Engine proof in fresh `owner-allocation-focused` output exited 0:
183 checks (69 flow, 114 prover), 0 unproved, 0 justified, and 1 warning
(`smb-engine.adb:430`, `Nt_Status` after `Validate_Header`); 1 unit analyzed.
The final gates passed: `make test`, forced strict `make check
GPRBUILD="gprbuild -f"`, and the full Samba integration.

The fresh-output full proof in `owner-allocation-full` exited 0 on its first
attempt: 4,480 checks (712 flow, 3,768 prover), 0 unproved, 0 justified,
69 warnings, 0 `pragma Assume`, and 13 units analyzed. This was a fresh-output
proof, not a literal `make prove` run. `git diff --check` passed.

## Lifecycle transition failure atomicity

`Initialize` now specifies its successful reset of observable connection fields:
it leaves the Engine disconnected with a nonzero owner, zero epoch/session/tree/maximum
transfer sizes and async identifier, no handles, pending request, validated
receipt or signing key, and zeroed signing-key bytes. On failure it preserves
the entire state and returns `SMB.Invalid_State_Status` when the prior state is
not disconnected or has a pending request, key, receipt or open handles;
otherwise it returns `SMB.Counter_Exhausted`.

`Mark_Connected` now specifies that success starts from a disconnected state
with a nonzero owner, changes the phase to transport-connected, and preserves
the owner, epoch, session/tree identifiers, transfer limits, signing key,
handle table, pending-request flag and receipt-valid flag. Failure preserves the
entire state and returns `SMB.Invalid_State_Status`. The runtime
implementation is unchanged. State preservation on counter-exhaustion rejection
is covered by the contract and proof, not by a runtime test.

`Test_Lifecycle_Atomicity` checks five rejected initializations and six rejected
transport transitions. Every rejection compares the complete state and exact
status. Fixtures cover the default state, transport-connected state, pending
NEGOTIATE, validated challenge receipt, authenticated state and
share-connected state, invalidating between reconnect fixtures.

The Candidate GNAT14 strict test build
(`gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe`) and
`./build/bin/test_suite engine-receipts` passed before the sensitivity control
and again after source restoration. The selector reported 11 lifecycle
rejections, as well as the existing request-metadata, authentication and
handle cases.

For the sensitivity control, I used the `src/smb-engine.ads` contract from
`origin/main` and inserted only `State.Epoch := State.Epoch + 1;` in the
`Mark_Connected` rejection branch before its error status. The mutant build
passed; the selector exited 1 with the expected diagnostic:
`rejected transport transition changed state`. Both files were restored
byte-for-byte before continuing:

- `src/smb-engine.ads`: SHA-256
  `4207cd5acd7460f34fa87c00109758d2ccc09404ba246ea39102ee9ed7c35924`
- `src/smb-engine.adb`: SHA-256
  `7e3279a57f837542d0027942c6991050b583aea619359c5ca1b69aaa7f93e4d4`

The focused Engine proof in fresh `lifecycle-focused` output exited 0 with 181
checks (67 flow, 114 prover), 0 unproved and 0 justified. It emitted one
warning at `smb-engine.adb:428` about `Nt_Status` after `Validate_Header`.

`make test`, `make check GPRBUILD="gprbuild -f"`, and
`sudo -n python3 tests/samba_integration.py` all passed.

The full proof passed on its first attempt in the fresh `lifecycle-full` output
subdirectory. No generated-ALI failure, cache repair or replay was needed.
This is a fresh-output full proof, not a literal `make prove` run:

```sh
gnatprove -P proof.gpr --subdirs=lifecycle-full --mode=all --level=2 \
  --proof=progressive --report=all --checks-as-errors=on \
  --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 after analyzing 13 units and discharging 4,478 checks (710 flow,
3,768 prover), with 0 unproved, 0 justified, 69 warnings, and 0
`pragma Assume`. Category totals were 2 data dependencies, 1 flow dependency,
545 initialization, 2 non-aliasing, 2,425 run-time checks, 299 assertions,
1,038 functional contracts, and 166 termination checks (160 flow, 6 prover).

## Authentication transition failure atomicity

`Install_Session_Key` now guarantees `SMB.Invalid_Value` and an unchanged
complete `Engine_State` on rejection. `Mark_Authenticated` likewise guarantees
`SMB.Invalid_State_Status` and an unchanged state. This includes keys, session
identity, pending requests and validated response receipts. Successful key
installation must remain in the negotiated phase; successful authentication
must preserve the installed key bytes.

Engine receipt tests exercise 18 rejected key installations and 11 rejected
authentication transitions: absent, pending, consumed and wrong-status receipts,
invalid session IDs and invalid key lengths at ordinary and near-`Natural'Last`
array bounds. Two valid 16-byte inputs with different array bounds then complete
signed authentication, preserving the expected key and consuming each receipt
once. These are internal Engine transition guarantees, not a change to the
public client's disconnect-on-authentication-failure policy. Signed server-error
receipts are synthetic unit fixtures, not observations of a real server.

The Candidate GNAT14 strict test build
(`gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe`) and
`./build/bin/test_suite engine-receipts` passed before the sensitivity control
and again after source restoration. The selector reported 29 rejected calls
(18 key-installation and 11 authentication-transition rejections) and two
successful retries, in addition to the existing request-metadata and handle
coverage.

For the sensitivity control, I used the `src/smb-engine.ads` contract from
`origin/main` and added only `State.Receipt_Valid := False;` to the
`Install_Session_Key` rejection branch before its `Invalid_Value` assignment.
The mutant build passed; the selector exited 1 with the expected diagnostic:
`rejected key installation changed state or consumed receipt`. Both files were
restored byte-for-byte before continuing:

- `src/smb-engine.ads`: SHA-256
  `7690acfccfb5bdbbf0687b504aea2aaa6720b4d7a23d7a59bf1eea8a3df13a3e`
- `src/smb-engine.adb`: SHA-256
  `7e3279a57f837542d0027942c6991050b583aea619359c5ca1b69aaa7f93e4d4`

The focused Engine proof in fresh `auth-atomicity-focused` output exited 0
with 181 checks (67 flow, 114 prover), 0 unproved and 0 justified. It emitted
one warning at `smb-engine.adb:428` about `Nt_Status` after `Validate_Header`.

`make test`, `make check GPRBUILD="gprbuild -f"`, and
`sudo -n python3 tests/samba_integration.py` all passed.

The full proof passed on its first attempt in the fresh `auth-atomicity-full`
output subdirectory. No generated-ALI failure, cache repair, or replay was
needed. This is a fresh-output full proof, not a literal `make prove` run:

```sh
gnatprove -P proof.gpr --subdirs=auth-atomicity-full --mode=all \
  --level=2 --proof=progressive --report=all --checks-as-errors=on \
  --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 after analyzing 13 units and discharging 4,478 checks (710 flow,
3,768 prover), with 0 unproved, 0 justified, 69 warnings, and 0
`pragma Assume`. Category totals were 2 data dependencies, 1 flow dependency,
545 initialization, 2 non-aliasing, 2,425 run-time checks, 299 assertions,
1,038 functional contracts, and 166 termination checks (160 flow, 6 prover).

## Complete pending-request metadata matching

`Pending_Request_Matches` now compares the complete `Request_Expectation`
record. The previous field-by-field comparison omitted `Match_Tree` and
`Match_Session`, even though these flags control response-ID correlation.
This strengthens the operation/Engine ownership checks; the existing received
header validation remains in place. This is not evidence of an observed wire
response bypass.

`Begin_Request` now specifies the exact tree/session matching policy and the
returned close token. Any failed reservation must return a default expectation
and zero message ID. Existing state-preservation conditions are unchanged;
in particular, a new reservation attempt still discards any preceding receipt.

The Engine receipt tests cover 13 valid reservations across negotiation,
pre-key and keyed SESSION_SETUP, TREE_CONNECT, every supported share command,
and authenticated LOGOFF. All 12 scalar metadata fields (including the three
close-token fields) are individually changed for each reservation, giving 156
rejections. Twelve unsuccessful reservation calls start with poisoned outputs
and verify exact errors, cleared outputs, and unchanged receipt-free state.
The all-default expectation must not match without a pending request.

The Candidate GNAT14 strict test build
(`gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe`) and
`./build/bin/test_suite engine-receipts` passed. The selector reported 13
reservations, 156 individual metadata-field mutations, and 12 rejected
reservations, along with the existing handle validation, capacity, and
failure-atomicity cases.

For the sensitivity control, I substituted only the prior fieldwise
`Pending_Request_Matches` expression from `origin/main`, retaining the new
contract and tests. The mutant build passed; the selector exited 1 with the
expected diagnostic at metadata field 4 (`Match_Tree`):
`request metadata mismatch accepted at field 4`. I restored the full-record
comparison and verified `src/smb-engine.ads` matched its pre-control SHA-256
(`7cd5217764e7592cb0c86ab86aa43c7b882e994841bb6c0bb89c3b2b87b21722`). A
strict rebuild and selector rerun then passed.

The focused Engine proof in the fresh `request-matching-focused` output
subdirectory exited 0 with 181 checks (67 flow, 114 prover), 0 unproved and
0 justified. It reported one warning at `smb-engine.adb:428` about `Nt_Status`
after `Validate_Header`.

`make test`, `make check GPRBUILD="gprbuild -f"`, and
`sudo -n python3 tests/samba_integration.py` all passed.

The full proof below used the fresh `request-matching-full` output subdirectory
and passed on its first attempt; no generated-ALI failure, cache repair, or
targeted replay was needed. This is a fresh-output full proof, not a literal
`make prove` run:

```sh
gnatprove -P proof.gpr --subdirs=request-matching-full --mode=all \
  --level=2 --proof=progressive --report=all --checks-as-errors=on \
  --prover=cvc5,z3 --timeout=120 -j4
```

It exited 0 after analyzing 13 units and discharging 4,478 checks (710 flow,
3,768 prover), with 0 unproved, 0 justified, 69 warnings, and 0
`pragma Assume`. Category totals were 2 data dependencies, 1 flow dependency,
545 initialization, 2 non-aliasing, 2,425 run-time checks, 299 assertions,
1,038 functional contracts, and 166 termination checks (160 flow, 6 prover).

## Preserving other handles after successful registration and closure

`Other_Handles_Preserved` describes preservation of the phase, owner and epoch,
and of every active handle record except a specified ticket. Its default
exception is ticket zero, which cannot designate a valid handle.
`Register_Handle` now guarantees this predicate on success for all existing
valid handles. `Close_Handle` guarantees it for every ticket other than the
closed one. Existing success and failure guarantees remain intact; the changes
to executable bodies are proof invariants and a ghost predicate only.

The 256-handle capacity test now uses distinct FileIds, all three access modes,
and both file/directory flags. It validates every slot after filling the table,
after closing the middle handle, and after reusing that slot with a new FileId,
access mode, directory flag and ticket. Other live handles must retain their
original identities and metadata; the old token must remain invalid.

The Candidate GNAT14 strict test build
(`gprbuild -p -P smb_tests.gpr test_suite.adb -cargs:Ada -gnatwe`) and
`./build/bin/test_suite engine-receipts` passed. The selector reported 74
handle-validation cases, the 256-distinct-handle capacity and slot-reuse test,
and 23 handle-failure-atomicity rejections.

The focused Engine proof exited 0 with 181 checks (67 flow and 114 prover),
0 unproved and 0 justified:

```sh
gnatprove -P proof.gpr -u smb-engine.adb \
  --subdirs=preserve-handles-focused --mode=all --level=2 \
  --proof=progressive --report=all --checks-as-errors=on \
  --prover=cvc5,z3 --timeout=120 -j4
```

`make test`, `make check GPRBUILD="gprbuild -f"`, and
`sudo -n python3 tests/samba_integration.py` all passed.

The full proof below used the fresh `preserve-handles-full` output subdirectory
and exited 0 on its first attempt; no generated-ALI failure, cache repair, or
targeted replay was needed. This is a fresh-output full proof, not a literal
`make prove` run:

```sh
gnatprove -P proof.gpr --subdirs=preserve-handles-full --mode=all \
  --level=2 --proof=progressive --report=all --checks-as-errors=on \
  --prover=cvc5,z3 --timeout=120 -j4
```

It analyzed 13 units and discharged 4,478 checks: 710 flow and 3,768 prover,
with 0 unproved, 0 justified, 69 warnings, and 0 `pragma Assume`. The category
totals were 2 data dependencies, 1 flow dependency, 545 initialization, 2
non-aliasing, 2,425 run-time checks, 299 assertions, 1,038 functional
contracts, and 166 termination checks (160 flow, 6 prover).

### Independent fresh-cache baseline before this change

The preceding version (PR #52) was also proved without using existing generated
artifacts, via a previously nonexistent `--subdirs` directory. Full proof exited
0 with 4,473 checks (709 flow, 3,764 prover), 0 unproved, 0 justified, 69 warnings
and no `pragma Assume`. Separate fresh flow runs at `-j1` and `-j4`, both full
project and focused Engine followed by full project, all exited 0. None
reproduced the previously observed malformed generated ALI. Its cause remains
unconfirmed; these results do not establish that parallelism caused it, and
the proof settings are unchanged.

## Atomic rejection of handle registration and closure

`Register_Handle` now guarantees the entire `Engine_State` remains unchanged
on failure, in addition to clearing the returned token. `Close_Handle` now
guarantees every failure returns `Invalid_Handle_Status` and leaves the entire
state unchanged. This includes handle entries, counters, pending requests and
validated response receipts. A loop invariant records the already-established
successful lookup during the CLOSE mutation pass; executable behavior and
the existing success guarantees are unchanged.

The focused test exercises 14 registration failures (disconnected, absent or
pending receipt, bad lengths and first/last FileId bytes at ordinary and near-
`Natural'Last` bounds, consumed receipt) and nine CLOSE failures (absent or
pending receipt, mismatched confirmation/receipt/token fields, consumed
receipt). Full state snapshots must match after every rejection. Valid retries
must still consume their receipts successfully, and the other live handle
must remain usable. These are internal Engine guarantees: `Core_Client`
continues to invalidate after a failed post-wire registration, and malformed
or untrusted wire responses still fail closed.

The Candidate GNAT14 strict test build and `engine-receipts` selector passed;
the selector reported 74 handle-validation cases, handle-capacity coverage,
and **23 rejected calls** in the new failure-atomicity test. The focused
`SMB.Engine` proof exited 0 and proved the strengthened registration and
closure postconditions. `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, and full Samba integration passed.

The first full `make prove` attempt exited 2 while GNAT was compiling
`smb-core_client.adb`, with `Constraint_Error bad input for 'Value: "0GG"`
from a malformed generated ALI. I preserved the failure log and affected
unit artifacts, removed only the recursive generated Core_Client proof cache,
and replayed that unit with progressive proof. The replay exited 0 and proved
the `Prepare_Next` assertion at `smb-core_client.adb:2281`. The recovered full
`make prove` exited 0 with **4,473 checks** (**709 flow**, **3,764 prover**),
**0 unproved**, **0 justified**, **69 warnings**, and **0 `pragma Assume`**.

## Handle capacity rejection and slot reuse

The existing 256-handle preflight limit is exercised through the coordinator
and public API. The coordinator test fills the table, checks exact
`Resource_Limit`/zero output/unchanged state, closes a middle slot and reuses
it with a fresh ticket, rejects the old token and validates every live handle.

The Samba case fills all 256 slots and rejects eight operations requiring
another CREATE: existing/new/truncated files, listing, directory creation,
rename, file deletion and directory deletion. Every refusal preserves the
connection, a nonzero EOF status and readable handles. Closing one file allows
listing and a replacement file. A transparent proxy counts exactly 260
CREATE/CLOSE requests overall and a peak of 256 live handles; it does not
change real Samba responses or capture credentials. The final counts were 260
CREATE, 260 CLOSE, peak 256 and zero handles at disconnect, with one SET_INFO,
TREE_DISCONNECT and LOGOFF. Filesystem checks reject unintended creation,
truncation, rename or deletion. `ADASMB_HANDLES_ONLY=1` selects this case
independently.

The corrected existing-file Action 1 uses `Read_Only`; Actions 2 and 3 retain
`Read_Write`. Its strict Candidate GNAT14 rebuild and focused
`ADASMB_HANDLES_ONLY=1` integration passed with the counts above. The earlier
unit, full `make test`, forced strict `make check GPRBUILD="gprbuild -f"`, and
full integration results remain unchanged.

For the sensitivity control, only `Begin_Request`'s `if not Free then`
preflight was replaced by `if False then`; the `Register_Handle` guard was
untouched. The mutant cleanup-client build succeeded. The corrected public
integration failed with `SMB.PROTOCOL_ERROR : SMB CREATE response was
rejected`, rather than the former permission error. This is the local
completion/registration-disconnect result after the extra existing-file CREATE
was admitted past preflight; the proxy's `EOFError` is the secondary
observation of that intentional client disconnect. The original
`src/smb-engine.adb` was restored byte-for-byte, SHA-256
`3ffb7e21eb32af62eb220ccfea6cc2c8cebd7d2508633cb5c822a10cabe4bb27`.
After restoration, `cleanup_client` was force-rebuilt with strict warnings
and the focused Samba integration passed again.

Formal proof, native Windows and CI were not run for this tests-only change.

## Exact handle validation outcomes

For a 16-byte output buffer, `Validate_Handle` retains the success equivalence:
`Status = SMB.Ok` exactly when `Valid_Handle` holds, with the existing
`Handle_Matches` guarantee on success. Other buffer lengths return
`SMB.Invalid_Length`; a failed handle check returns
`SMB.Invalid_Handle_Status`. A separate failure implication requires a zeroed
`File_Id`, `Read_Only`, and `Is_Directory = False`. The body is unchanged.

Seventy-four cases cover all access kinds, directory flags and read/write
requirements; malformed tokens; closed, disconnected and stale-after-reconnect
handles; and wrong-length buffers, at ordinary and near-`Natural'Last` bounds.
Failure outputs start with nonzero bytes and nondefault metadata.

The Candidate GNAT14 build with `-gnatwe` and `engine-receipts` selector
passed; the selector reported **74 cases**. Previously accepted `make test`,
forced strict `make check GPRBUILD="gprbuild -f"`, and full Samba integration
were not rerun for this contract-only refinement.

Proof history: an incremental `make prove` first exited 2 with a GNAT
`Constraint_Error` (`bad input for 'Value: "0GG"`) while compiling
`smb-core_client.adb`; its `.spark` was stale. Diagnostics and the affected
unit artifacts were preserved, and only recursive generated
`smb-core_client*` cache files were cleared. The isolated Core_Client replay
then exited 1 with an unproved `Transfer_Packet_Matches` assertion at
`smb-core_client.adb:2281`. A subsequent `--proof=per_path --timeout=300`
attempt on that line also exited 1. After retaining the success-equivalence
contract shape and expressing failure outputs separately, the focused
`SMB.Engine` proof proved the `Validate_Handle` postcondition, but exited 1
because `Prepare_Next` still had that one unproved assertion. The focused
progressive Core_Client retry with `--limit-line=smb-core_client.adb:2281`
and `--timeout=300` then exited 0 and proved the assertion.

The final incremental `make prove` exited 0 with **4,471 checks** (709 flow,
3,762 prover), **0 unproved**, **0 justified**, **69 warnings**, and
**0 `pragma Assume`**. The run used the repository's progressive proof
defaults without a clean rebuild. Native Windows and CI were not rerun.

## Directory name encoding rejection and recovery

Four correctly signed second-page mutations exercise an unpaired high
surrogate, an unpaired low surrogate, a high surrogate followed by a non-low
code unit, and an embedded NUL. NUL is well-formed UTF-16 but disallowed by
the existing name-validation profile. Layout, links, and total packet length
remain intact, and the original second-page signature is verified before
mutation. A nonempty first page must already have been accepted.

The public client must report the directory core's `INVALID_ENCODING`, not
merely a later conversion or signature error, then disconnect before another
query and recover listing/reading on the same connection object. Sixteen
core cases cover these four invalid names and four valid BMP/supplementary
controls at ordinary and near-`Natural'Last` array bounds, checking exact
status and cursor preservation.

Python syntax compilation and the Candidate GNAT14
`test_suite.adb`/`cleanup_client.adb` build passed. The
`directory-bounds` selector passed **6,616 cases**. Focused
`ADASMB_DIRECTORY_ONLY=1` Samba integration passed all six directory mutations:
the two existing offset cases and the four new name cases.

The sensitivity mutant built successfully. With only the
`Validate_UTF16` call in `Parse_Directory_Entry` replaced by
`Text_Status := SMB.Ok;`, `directory-bounds` failed at the exact
`directory name encoding outcome` assertion. The focused unpaired-high
Samba case also failed as intended: the later converter reported
`invalid SMB directory name encoding`, rather than the core diagnostic
required by the public-client test. Thus the test distinguishes core-boundary
rejection from later conversion failure. The original
`src/smb-core_protocol.adb` was restored byte-for-byte (SHA-256
`25917cfe388c3c2f3fb6522b08d56b0cae533275dc879a9c469bb23494e35dd3`), and a
forced build of both executables with the restored source passed.

After restoration, `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, and full root Samba integration passed;
full integration included all six directory mutations and the existing
regression scenarios. The malformed second-page cases use synthetic signed
responses after verifying the original backend signature; they test client
validation and recovery, not native Samba generation of invalid names.
Formal proof, native Windows, and CI were not rerun for this test-only change.

## Signed directory limit and recovery scenarios

Four public-API scenarios use synthetic, correctly signed directory responses
over a real Samba connection. Every request still reaches Samba and every
original directory response's signature is verified before replacement,
preserving backend credit/message-ID progression. One visible witness entry
and otherwise filtered `.` records exercise the limits without accumulating
100,000 user-visible names.

The page boundary returns 4,095 data pages and `STATUS_NO_MORE_FILES` on query
4,096. Its overflow counterpart returns data on all 4,096 queries and requires
EOF without a further request. The entry boundary returns exactly 100,000
records followed by normal termination; overflow returns exactly 100,001
records and requires EOF on query 196. Accepted listings retain their witness
and the existing file handle. Exhaustion must specifically report
`RESOURCE_LIMIT`, disconnect, reconnect the same object, enumerate/read again,
and reject the stale handle without damaging the recovered connection.

Python syntax compilation and the Candidate GNAT14 `cleanup_client.adb`
build passed. The focused `ADASMB_DIRECTORY_LIMITS_ONLY=1` integration passed all
four scenarios.

All four sensitivity controls behaved as expected. Each one-constant mutant
build succeeded; its selected mode failed on the intended boundary mismatch:
4,095 pages caused premature `RESOURCE_LIMIT`, 4,097 pages allowed an extra
query, 99,999 entries caused premature `RESOURCE_LIMIT`, and 100,001 entries
allowed an extra query. Each temporary mutation was restored byte-for-byte
from the saved original protocol spec. Its SHA-256 matched the original, and
a forced `cleanup_client` rebuild with the restored 4,096-page and 100,000-
entry limits passed.

Final `make test`, forced strict `make check GPRBUILD="gprbuild -f"`, and full
root Samba integration passed; the latter also passed all four directory
limit/recovery scenarios. The replies exercising the limits are synthetic,
correctly signed fixtures substituted only after verifying each original
backend response. All requests are forwarded to Samba, so backend
credit/MessageId progression is preserved. This validates client behavior
against the tested limits; it does not claim native Samba resource exhaustion.
No production source was changed. Formal proof, native Windows, and CI were
not rerun for this test-only change.

## Exact directory counter outcomes

`Count_Directory_Page` and `Count_Directory_Entry` now specify exact status
results: every allowed count below the limit succeeds and advances by one;
at the limit they return `Resource_Limit` and preserve the count. The existing
bounds and failure-preservation contracts remain in place. The implementation
and the limits (4,096 pages and 100,000 entries) are unchanged.

The `directory-counters` unit selector checks all **104,098** admissible
starting counts, including zero, the final successful increment, and refusal
at each limit. It compares resulting counts with saturating addition rather
than only checking that successful calls increment.

The Candidate GNAT14 build, `directory-counters` selector
(**104,098 cases**), and focused progressive proof of
`smb-core_protocol.adb` passed. `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, and full root Samba integration also
passed.

The first incremental `make prove` attempt exited 2 in the `smb-core_client`
worker with a GNAT bug:
`Constraint_Error bad input for 'Value: "0GG"`. Its generated phase-1 ALI
had adjacent `GG` records without a line break, and the Core_Client `.spark`
was stale. Although that run printed the cached **4,470-check** summary with
0 unproved checks, its nonzero exit meant it was not accepted as a proof
result. The worker stderr, ALIs, stale `.spark`, and proof summary were
preserved under `/home/ubuntu/directory-counter-*`; only the recursive
generated `smb-core_client*` cache was cleared. An isolated progressive
replay of `smb-core_client.adb` then passed and regenerated its `.spark`.
The subsequent incremental full `make prove` exited **0** and reported
**4,470 checks** (709 flow, 3,761 prover), **0 unproved**, **0 justified**,
**69 warnings**, and **0 `pragma Assume`**. No source or contract changes
were made to address the tool failure.

CI and native Windows validation were not run for this branch.

## NTLM negotiation profile combinations

The challenge-field differential fixtures now cover all 64 subsets of the
profile's six required flags (Unicode, signing, NTLM, always-sign, extended
session security, and TargetInfo), crossed with REQUEST_TARGET, 128-bit,
Version, OEM, and the mutually exclusive target-type choices. These add
3,072 fixtures: 48 accepted combinations and 3,024 rejected combinations.
Version headers and payload offsets remain structurally valid so missing
required flags are not masked by unrelated layout failures.

Accepted cases compare the complete Type 3/SPNEGO output and session key
against the Python HMAC/MD5 reference, including the negotiated flag mask
and both transcript and mechanism-list MICs. Unicode remains selected when
OEM is also offered; OEM alone cannot replace the required Unicode mode.
Rejected cases must expose neither a token nor a session key through the
core and must fail through the public API. Both array lower bounds are
exercised by the existing probe.

This is the existing signing-only NTLMv2 profile, not an implementation of
NTLM key exchange, sealing, datagram mode, or RC4. No production code,
protocol acceptance policy, or formal contracts are changed.

The Candidate GNAT14 `ntlm_av_probe.adb` build passed. The focused challenge
field script passed with **5,896 fixtures** and **11,792 rebased cases**,
including both sensitivity controls. `make ntlm-test` passed the existing AV
regression (**211 fixtures, 422 rebased cases**) and the new challenge-field
suite. `make test`, forced strict `make check GPRBUILD="gprbuild -f"`, and
`python3 -m py_compile tests/ntlm_challenge_fields.py` also passed.
Formal proof, Samba integration, TCP transport, native Windows, and CI were
not rerun for this test-only milestone; no coverage beyond these checks is
claimed.

## Exact IO progress outcomes

`Core_Protocol.Advance_Transfer` specifies exact status precedence: a missing
required progress or a count above the request/remainder returns
`Invalid_Value`; otherwise a 64-bit offset overflow returns `Invalid_Offset`;
all other inputs return `Ok`. Successful updates explicitly exclude modular
offset wrap, while failures preserve both offset and remaining length.
`Select_Transfer_Amount` and `Check_Transfer_Range` also specify exact success
and rejection conditions, including a zero-sized completed transfer.
No production implementation or protocol acceptance policy is changed.

The `transfer-progress` unit selector exercises 2,891 boundary combinations
across zero, chunk/frame limits, and offsets adjacent to `QWord'Last`.
Its overflow oracle uses modular addition and comparison, rather than the
subtraction guard used in the implementation/contracts. Both values of
`Require_Progress`, invalid-count/overflow precedence, and unchanged state on
every rejection are covered.

The Candidate GNAT14 build, `transfer-progress` selector, and focused
progressive proof of `smb-core_protocol.adb` passed. The selector reported
all 2,891 cases. `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, and full root Samba integration also
passed.

The first incremental full `make prove` run used the existing clean proof
baseline without `--clean`, with `--proof=progressive`, but its
`smb-core_client` worker failed before refreshing that unit's `.spark` report.
The stored worker stderr identified the concrete cache failure:
`Corrupted ali file detected (smb-core_client.ali): GG data after GG end
marker. Call gnatprove with "--clean".` The affected phase-1 ALI contained
two `GG EK_END_MARKER` records with GNATprove data after the first marker,
while `smb-core_client.spark` still had its pre-run timestamp. The terminal
output therefore ended with `gnatprove: error during flow analysis and proof`
and `make: *** [Makefile:55: prove] Error 1`; its repeated **4,470-check**
summary was not treated as current proof evidence.

The failing worker stderr, corrupted ALI, and stale `.spark` were preserved
as diagnostics, then only the generated
`build/proof-obj/gnatprove/**/smb-core_client*` cache was removed. No
production source, contract, or proof policy was changed. An isolated
progressive proof of `smb-core_client.adb` passed after regeneration, with a
single valid ALI end marker and a refreshed `.spark`. The subsequent
incremental full `make prove` run completed all three phases and exited 0.
Its summary reported **4,470 checks** (709 flow, 3,761 prover),
**0 unproved**, **0 justified**, **69 warnings**, and **0 `pragma Assume`**.
The focused command was
`gnatprove -P proof.gpr -u smb-core_protocol.adb --mode=all --level=2
--proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3
--timeout=120 -j4`; the repaired-unit command was
`gnatprove -P proof.gpr -u smb-core_client.adb --mode=all --level=2
--proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3
--timeout=120 -j4`; and the final full invocation was
`PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make prove`.
CI and native Windows validation were not run.

## Exact partial-transport outcomes

`Core_Transport.Receive_Chunk` and `Advance_Write` now specify exact statuses:
an already complete or out-of-range position returns `Invalid_Offset`; a
non-progressing/out-of-range native result or an oversized receive chunk
returns `Invalid_Length`; every valid transfer returns `Ok`. The existing
byte-copy, untouched-prefix/tail and failure-preservation guarantees remain.
`Prepare_Write` also specifies its canonical output index on failure.

Focused controls cover extreme native offsets, invalid positions up to
`Natural'Last`, error precedence, and empty arrays at upper permitted bounds.
The existing byte-exact partial transfers and maximum frame controls remain.
No implementation algorithm or accepted protocol policy is changed.

### Validation

The Candidate GNAT14 build, `transport-core` selector, focused proof of
`smb-core_transport.adb`, `make test`, forced strict
`make check GPRBUILD="gprbuild -f"`, `make transport-test`, and full root
Samba integration were accepted on commit `6f2bceb`; they were not rerun for
this Makefile/docs-only follow-up. To avoid a GNAT 14.1 compiler crash during
data-representation generation, the exact `Advance_Write` status mapping is
stated as equivalent status predicates instead of a conditional expression.

The initial clean full proof using per-check mode reported one unproved
grouped postcondition for `SMB.Core_Connection.Prepare_Tree_Connect`, located
at `smb-core_connection.ads:142`. GNATprove displayed the first conjunct
(`Used <= Output'Length`), but the verification condition covered the grouped
postcondition through line 173; the diagnostic did not establish that the
first conjunct alone was the failing subcondition. The grouped postcondition
was proved by the subsequent progressive full proof. No contract or assertion
was weakened, and the final `Core_Connection` body is unchanged from
`6f2bceb`.

`make prove` now uses `--proof=progressive`, retaining per-check proofs and
splitting only failed groups. The incremental full-project run used the
existing clean proof baseline, without running `--clean`, and passed all
**4,470 checks** (709 flow, 3,761 prover), with **0 unproved**, **0
justified**, **69 warnings**, and **0 `pragma Assume`**. Its effective
command was `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make
prove`, which invokes GNATprove with `-P proof.gpr`, `--mode=all`,
`--level=2`, `--proof=progressive`, `--report=all`,
`--checks-as-errors=on`, `--prover=cvc5,z3`, `--timeout=120`, and `-j4`.
CI and native Windows validation were not run.

Evidence logs are under `/home/ubuntu/transport-progress-outcomes-*`,
including the incremental progressive full-proof output and summary.

## Transport loss after an asynchronous interim response

Two additional Samba-backed async proxy modes send a valid `STATUS_PENDING`
for READ, then either half-close before the final response or send a correctly
signed final frame with its last byte missing before half-closing. The client
must observe the exact EOF transport error, not a timeout or a protocol error.
The proxy also checks that the client closes without sending another request
on the interrupted connection.

The existing public-API recovery checks apply to both modes: no READ result
escapes, the connection is closed, the interim is not published as NTSTATUS,
the same object reconnects, the old handle is rejected and a newly opened
handle reads the expected fixture byte. These tests exercise receive failure
while an AsyncId is already stored, rather than only malformed final replies
or the repeated-interim deadline path. Production source is unchanged.

### Observed validation

The focused Candidate GNAT14 build and Python syntax compilation passed. The
focused root async-only integration passed the normal client, async success,
and all eight negative modes, including both transport-loss cases. `make test`
and forced strict `make check GPRBUILD="gprbuild -f"` passed. The full root
Samba integration also passed: all six entropy recovery cases, async success
and rejection/recovery, and the existing adversarial, mutation, and
security-buffer scenarios.

GNATprove was not rerun because production source is unchanged. The **4,459
checks** (709 flow, 3,750 prover; 0 unproved, 0 justified, 69 warnings, and 0
`pragma Assume`) are inherited from PR42, not a new proof result for this
test-only change. CI and native Windows validation were not rerun; transport
and oracle suites were also outside this stage's scope.

Evidence logs: `/home/ubuntu/async-transport-loss-focused-build.log`,
`/home/ubuntu/async-transport-loss-python.log`,
`/home/ubuntu/async-transport-loss-focused-integration.log`,
`/home/ubuntu/async-transport-loss-make-test.log`,
`/home/ubuntu/async-transport-loss-strict-check.log`, and
`/home/ubuntu/async-transport-loss-full-integration.log`.

## Engine response-to-request correlation contracts

`Response_Header_Matches_Request` is a ghost predicate over the outstanding
request and the received header. `Inspect_Interim_Response` and
`Accept_Response` now expose this relationship in their successful
postconditions, rather than relying only on the lower-level
`Core_Wire.Validate_Header` contract. The predicate binds command, MessageId,
the requested SessionId/TreeId checks, response/async/signature flags and the
interim/final NTSTATUS distinction to the pre-call engine state. It interprets
bytes 32..39 as AsyncId rather than TreeId for asynchronous responses.

Repeated interim responses must retain an already recorded AsyncId. A final
response must match that saved ID, and the returned NTSTATUS must equal the
received header. Existing failure-state clearing contracts remain intact.
These are stronger proof contracts, not changes to the accepted protocol
profile or a proof of cryptographic authenticity. Three focused controls also
exercise an async final without a preceding interim, an interim for the wrong
command, and a correctly signed final for the wrong command.

### Observed validation

The focused GNAT14 build and `async-responses` unit selector passed. The
focused Engine proof passed, including 30 checks for `Accept_Response`, 9 for
`Inspect_Interim_Response`, and 10 for `Response_Header_Matches_Request`.
`make test`, forced strict `make check GPRBUILD="gprbuild -f"`, and the full
root Samba integration also passed. The integration included the entropy
recovery cases, async success and rejection/recovery cases, and existing
adversarial, mutation, and security-buffer scenarios.

The clean full proof passed across 13 units: **4,459 checks** (709 flow,
3,750 prover), **0 unproved**, **0 justified**, **69 warnings**, and **0
`pragma Assume`**. The 4,446-check PR41 result documented below remains
historical; this is the fresh result for the current branch.

The first full-proof attempt exposed an unproved assertion in
`SMB.Core_Client.Prepare_Next` at the existing WRITE-payload copy check. A
local `pragma Assert_And_Cut (Payload'Length > 0)` supplies the nonempty branch
needed to apply `Build_Write`'s existing copy postcondition. No assumption,
contract weakening, or protocol-policy change was introduced; focused
`SMB.Core_Client` proof and the clean full proof passed afterward.

Evidence logs: `/home/ubuntu/engine-correlation-focused-build.log`,
`/home/ubuntu/engine-correlation-focused-unit.log`,
`/home/ubuntu/engine-correlation-focused-proof.log`,
`/home/ubuntu/engine-correlation-core-client-proof.log`,
`/home/ubuntu/engine-correlation-make-test-final.log`,
`/home/ubuntu/engine-correlation-strict-check-final.log`,
`/home/ubuntu/engine-correlation-full-integration-final.log`, and
`/home/ubuntu/engine-correlation-full-proof-final.log`. The full proof
summary is also in `build/proof-obj/gnatprove/gnatprove.out`.

## Entropy failure rejection and same-object recovery

Six integration cases inject failures after partially filling the requested
random output: during client GUID acquisition before TCP connection, or
during nonce acquisition after a valid NTLM challenge. Each point is crossed
with `Authentication_Error`, `Invalid_State` and an unexpected `Program_Error`.
The public exception must be preserved or translated as documented by the
facade, the connection and diagnostics must be cleared, and authentication
without reconnection must fail locally.

A proxy observes no TCP connection for GUID failures, or exactly NEGOTIATE
and NTLM Type 1 followed by client EOF for nonce failures. The client pauses
at a standard-input checkpoint until the harness has verified this, so a
later reconnect or finalization cannot hide a missing failure-time close.
Only then may the same object reconnect using the default OS entropy source,
authenticate, read a signed fixture, close the file and log off. The callback
counter must remain unchanged throughout recovery. These are runtime tests,
not proof of OS entropy quality or new SPARK proof claims.

### Observed validation

The focused Ada client build passed. The root focused Samba integration passed
all six exception/call-point cases, including same-object recovery with the
default OS entropy source. The isolated failure-time-close mutant was run in
the earlier entropy stage; it was not rebuilt or rerun here.

The original pre-PR41 full-integration failure is retained as historical
evidence. That run failed during cleanup/recovery in
`malformed-signed-directory-second-page` with
`SMB.PROTOCOL_ERROR : SMB READ response: UNSUPPORTED_FEATURE`; the directory
case passed in focused runs both alone and immediately after the six entropy
cases. A separate instrumented full run reproduced a READ rejection in the
normal integration client: the actual Samba response had command 8, flags
`0x3` (server response plus async), NTSTATUS `0x103` (`STATUS_PENDING`), and
length 73. This was not a synthetic mutation. At the time, the client
explicitly excluded async responses and rejected that header. Samba's
installed defaults were `aio read size = 1` and `aio write size = 1`; they
were not overridden. The original directory failure's exact header was not
captured.

After merging [PR41](https://github.com/gomurin0428/AdaSMB/pull/41) at
`f90d1f9`, the candidate GNAT14 build, entropy-only integration, `make test`,
forced strict `make check GPRBUILD="gprbuild -f"`, Python syntax compilation,
and full root Samba integration all passed. The focused entropy run exercised
all six failure/recovery cases. The full integration exercised those six
cases, the normal client, async success, all six async rejection/recovery
modes, and the existing adversarial, mutation, and security-buffer suites.
`ADASMB_ASYNC_ONLY=1` also passed the standard integration and async scenarios
without running entropy cases; `ADASMB_ENTROPY_ONLY=1` passed the six entropy
cases and returned before the other scenarios.

GNATprove was not rerun for this entropy revalidation. The **4,446-check**
full proof (708 flow, 3,738 prover; 0 unproved, 0 justified) is inherited from
the merged PR41 `origin/main` state, not an entropy-specific proof result.
This branch's entropy-specific changes are limited to test, harness, and
documentation changes. The final merged tree passed `git diff --check`. No CI
was run.

Revalidation logs: `/home/ubuntu/entropy-revalidation-build.log`,
`/home/ubuntu/entropy-revalidation-focused.log`,
`/home/ubuntu/entropy-revalidation-make-test.log`,
`/home/ubuntu/entropy-revalidation-strict.log`,
`/home/ubuntu/entropy-revalidation-python.log`,
`/home/ubuntu/entropy-revalidation-async-selector.log`, and
`/home/ubuntu/entropy-revalidation-full-integration.log`.

Earlier entropy-stage evidence logs: `/home/ubuntu/entropy-failure-01-client-build.log`,
`/home/ubuntu/entropy-failure-02-python-syntax.log`,
`/home/ubuntu/entropy-failure-03-focused-root-integration.log`,
`/home/ubuntu/entropy-failure-05-mutant-build.log`,
`/home/ubuntu/entropy-failure-06-mutant-focused-root.log`,
`/home/ubuntu/entropy-failure-07-make-test.log`,
`/home/ubuntu/entropy-failure-08-client-rebuild.log`,
`/home/ubuntu/entropy-failure-09-strict-build.log`,
`/home/ubuntu/entropy-failure-10-full-root-integration.log`,
`/home/ubuntu/entropy-failure-11-focused-directory-repro.log`, and
`/home/ubuntu/entropy-failure-12-entropy-then-directory-focus.log`,
`/home/ubuntu/entropy-diagnostic-build.log`, and
`/home/ubuntu/entropy-diagnostic-full-1.log`. Diagnostic instrumentation remains
only in a detached worktree, not in the library or this change.


## SMB 2.1 asynchronous interim responses

The public API remains synchronous with one outstanding request. Async
interim/final handling is supported only for authenticated LOGOFF,
TREE_DISCONNECT, CREATE, CLOSE, READ, WRITE, QUERY_DIRECTORY, and SET_INFO.
The Engine records an AsyncId after validating request correlation and the
bounded `STATUS_PENDING` ERROR body. Interim responses are intentionally not
signature-verified; they are not trusted as NTSTATUS, authenticated data, or a
validated response receipt. The matching final is signature-verified over the
original raw response bytes before parsing. One absolute receive deadline
covers repeated interims and the final response.

The existing one-request credit profile is retained: first interim credit must
be positive, repeated interim credit may be zero, async final credit is zero,
and synchronous response credit remains positive. Async NEGOTIATE,
SESSION_SETUP, and TREE_CONNECT, SMB3, compounds, cancel, concurrency, and full
credit-window management are outside scope.

SMB2 references:

- [STATUS_PENDING interim response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c1692ece-7c6d-45c8-a0e3-6b53c0483030)
- [Client signature-verification requirement](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/36172e53-ac81-48fb-b2e3-caa3761b9157)
- [Record AsyncId and verify the final response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a01c6101-b94b-45c1-b7ec-cbcc94d51138)
- [Async final response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d39a64be-b8f8-424d-b8e5-a2cf5257459e)

### Observed validation

The focused async engine suite passed, covering interim retention and repeats,
signed zero-credit async finals, correlation and AsyncId failures, signature
failures, malformed interim bodies, receipt/status/data non-commitment, and
stale-handle invalidation. Python syntax compilation passed for all three
integration harnesses. The focused Samba run passed the positive workflow,
including the eight supported command transformations and signed missing-file
error, plus all six READ rejection-and-recovery modes.

`make test` passed the default suite, including the async engine cases and the
existing framing, wire, NTLM, SPNEGO, response, header, security-buffer, and
directory regression groups. `make transport-test` passed all 12 transport
scenarios. Forced strict `make check GPRBUILD="gprbuild -f"` passed with
`-gnatwe`, including runtime dependency checks. The full Samba integration
passed on `127.0.0.1:1445`; this included the async success and six rejection
scenarios, existing adversarial cases, malformed-response cleanup/recovery,
authentication diagnostics, response mutations, and security-buffer
rejections. The unrelated daemons on ports 139/445 were left untouched.

The clean full GNATprove result from merged PR41, inherited from `origin/main`
and not rerun for the entropy stage, passed across 13 units: **4,446 checks**
(**708 flow** and **3,738 prover**), with **0 unproved** and **0 justified**. The
categories were 2 data dependencies, 1 flow dependency, 545 initialization,
2 non-aliasing, 2,413 run-time checks, 292 assertions, 1,027 functional
contracts, and 164 termination checks (158 flow, 6 prover). There were **69
warnings**: 6 in `SMB.Core_Auth`, 56 in `SMB.Core_Client`, 6 in
`SMB.Core_Protocol`, and 1 in `SMB.Engine`. The per-entity summary records
**0 `pragma Assume` statements**. The proof report covers bounded state and
parsing properties only; it does not prove socket timing, OS behavior, or the
authenticity of an unsigned interim response.

One proof-only assertion in `SMB.Core_Client.Prepare_Next` now uses
`Payload'Length` as the quantified upper bound, matching the `Build_Write`
postcondition directly; the preceding assertion proves it equals `Amount`.
This does not change the transfer behavior or the public contract.

`git diff --check` passed.

Evidence logs:

- `/home/ubuntu/async-responses-focused.log` — focused async engine tests.
- `/home/ubuntu/async-responses-python.log` — Python syntax compilation.
- `/home/ubuntu/async-responses-integration-focused.log` — focused async Samba
  scenarios.
- `/home/ubuntu/async-responses-focused-proof.log` — focused GNATprove.
- `/home/ubuntu/async-responses-make-test-final.log` — default unit suite.
- `/home/ubuntu/async-responses-transport-gnat14.log` — transport scenarios.
- `/home/ubuntu/async-responses-strict-final.log` — forced strict build.
- `/home/ubuntu/async-responses-integration-final.log` — full Samba integration.
- `/home/ubuntu/async-responses-full-proof-final.log` — clean full GNATprove.
- `build/proof-obj/gnatprove/gnatprove.out` — full proof summary.

Historical proof counts are not represented as results for this stage.

## Exact wire primitive outcomes and failure preservation

The 16/32/64-bit readers and writers now specify `Ok` exactly when their
offset and complete width fit the supplied array, and `Invalid_Offset`
otherwise. Existing exact little-endian value/byte, surrounding-data
preservation and zeroed read-failure guarantees remain. Header initialization
now specifies `Invalid_Length` and an unchanged array below 64 bytes, as well
as success for sufficient capacity. No implementation body was changed.

The regression checks 7,020 integer cases, each with a write and a read,
across widths, four literal byte/value fixtures, lengths 0..12, offsets
0..13 and `Natural'Last`, and three lower-bound layouts including arrays
ending at `Natural'Last`. Another 18 cases check exact header bytes, body
preservation and short-buffer rejection at the same lower-bound layouts.
The expected bytes are literal fixtures, not the production readers or
writers; invalid reads must clear a prefilled output and invalid writes or
header initialization must preserve the prefilled array.

### Observed validation

Focused GNATprove for `smb-core_wire.adb` passed, proving the exact status
partitions and existing value, byte, and preservation postconditions.
`make test` passed, including all **7,020 integer cases** and **18 header
cases**. `make transport-test` passed all 12 scenarios. Forced strict
`make check GPRBUILD="gprbuild -f"` passed with `-gnatwe`.

The clean full proof passed across **13 units**: **4,422 checks** (700 flow,
3,722 prover), **0 unproved**, **0 justified**, and **68 warnings** (6 in
`SMB.Core_Auth`, 56 in `SMB.Core_Client`, 6 in `SMB.Core_Protocol`). It
reported **0 `pragma Assume` statements**. The check categories were 2 data
dependencies, 1 flow dependency, 539 initialization, 2 non-aliasing, 2,410
run-time checks, 292 assertions, 1,014 functional contracts, and 162
termination checks (156 flow, 6 prover).

No implementation body or acceptance behavior changed. Samba integration
was not rerun for this stage, and no CI was run.

Evidence logs: `/home/ubuntu/wire-primitive-contracts-01-focused-proof.log`,
`/home/ubuntu/wire-primitive-contracts-02-make-test.log`,
`/home/ubuntu/wire-primitive-contracts-03-transport-test.log`,
`/home/ubuntu/wire-primitive-contracts-04-strict-build.log`, and
`/home/ubuntu/wire-primitive-contracts-05-clean-full-proof.log`. The proof
summary is also in `build/proof-obj/gnatprove/gnatprove.out`.

## Exact TCP frame length and rejection contracts

`SMB.Core_Framing.Decode` previously guaranteed only a bounded length on
success and zero on failure. It now specifies both the exact three-byte
big-endian length and the complete status partition: a nonzero type is
`Unsupported_Feature`, otherwise a length outside 64..1,048,576 is
`Invalid_Length`, otherwise `Ok`. All failures return zero length. The
`Payload_Length` expression factors out the existing arithmetic without
changing the accepted wire format or the type-before-length priority.
`Encode` also promises an all-zero header on invalid lengths, matching its
existing implementation.

The unit regression crosses all 256 frame types with 15 lengths around the
minimum, byte carries, maximum and 24-bit limit: 3,840 decoding cases. It also
checks exact encoded bytes or zeroed failures for those lengths and
`Natural'Last`. This complements the real TCP maximum/coalesced/trickle tests;
neither layer claims OS socket or scheduling correctness by formal proof.

### Observed validation

The focused GNATprove run passed for `smb-core_framing.adb`: `Payload_Length`
termination and the `Encode` and `Decode` postconditions were proved.
`make test` passed, including the **3,840-case** frame-type/length matrix and
16 encoding boundary/clearing checks, as well as the existing protocol
mutation groups. `make transport-test` passed all 12 scenarios.

The Samba integration passed on `127.0.0.1:1445`. The harness requires root
to create its test-only account; the direct unprivileged invocation exited
before setup, and the passwordless root invocation completed successfully.
Existing Samba daemons on ports 139/445 were left untouched.

The clean full proof passed across **13 units**: **4,413 checks** comprising
**700 flow** and **3,713 prover** checks, **0 unproved**, **0 justified**, and
**68 warnings** (6 in `SMB.Core_Auth`, 56 in `SMB.Core_Client`, 6 in
`SMB.Core_Protocol`). It reported **0 `pragma Assume` statements**. The
check categories were 2 data dependencies, 1 flow dependency, 539
initialization, 2 non-aliasing, 2,401 run-time checks, 292 assertions, 1,014
functional contracts, and 162 termination checks (156 flow, 6 prover).
Forced strict `make check GPRBUILD="gprbuild -f"` and `git diff --check`
passed.

The only executable-source change factors the existing 24-bit length
arithmetic through `Payload_Length`; the accepted framing and status
precedence are unchanged. This is not a proof of OS socket behavior or
scheduling correctness. No CI was run.

Evidence logs: `/home/ubuntu/framing-contracts-01-targeted-proof.log`,
`/home/ubuntu/framing-contracts-02-make-test.log`,
`/home/ubuntu/framing-contracts-03-transport-test.log`,
`/home/ubuntu/framing-contracts-04-samba-integration.log` (direct
unprivileged attempt),
`/home/ubuntu/framing-contracts-05-samba-integration-root.log`,
`/home/ubuntu/framing-contracts-06-make-check.log`, and
`/home/ubuntu/framing-contracts-07-clean-full-proof.log`. The clean proof
summary is also in `build/proof-obj/gnatprove/gnatprove.out`.

## TCP frame boundaries and progress-independent receive deadline

The local transport regression adds a fragmented maximum-sized 1-MiB frame
and five coalesced frames of different lengths and byte patterns. Echoes must
preserve the exact framing and payload, without consuming bytes from the next
frame. Zero-length and 63-byte frame headers must raise `Protocol_Error`
without waiting for a body, invalidate the transport, and allow reconnection
using the same connection object.

A separate slow-trickle case sends each byte 110ms apart, completing the
header and starting the payload before the configured 500ms deadline. The
client must time out between 450ms and 750ms, rather than refreshing the
deadline after the header or after each successful partial receive. It then
checks failure invalidation, rejection of silent reuse, and reconnect/echo.
This is a scheduling-sensitive local regression, not a hard real-time proof.
DNS and multi-request API deadlines remain outside this per-frame guarantee.

### Observed validation

`make transport-test` passed the stalled-write case and all 11 receive modes,
including byte-exact echoes for the 1-MiB frame and five coalesced frames,
malformed/undersized headers, and failure/reconnect behavior. The
`trickle-read` scenario also passed five additional consecutive runs.
Python syntax compilation passed.

For the negative control, a detached worktree at `9d3e014` received the
current test files and a single mutation to `src/smb-transport.adb` that
restarted the deadline after reading the header. The mutant built, and
`trickle-read` produced the expected Ada diagnostic,
`raised PROGRAM_ERROR : stalled receive violated its deadline`. Because that
assertion aborts the client before recovery, the outer integration helper then
timed out waiting for the recovery connection; this was a consequence of the
expected rejection. The mutant remains isolated and was not committed.

`make test` passed, including the NTLM MaxLen (2,050), final SPNEGO (14,936),
challenge extraction (45,396), response mutation (35,070), header mutation
(18,838), security buffer mutation (20,124), and directory boundary (6,600)
case groups. Forced strict `make check GPRBUILD="gprbuild -f"` passed,
compiling the library, tests, and example with `-gnatwe`; runtime dependency
checks passed. `git diff --check` passed.

This stage changes tests and documentation only; no GNATprove, full Samba
integration, or CI run was performed.

Evidence logs: `/home/ubuntu/transport-framing-01-transport-test.log`,
`/home/ubuntu/transport-framing-02-trickle-repeat.log`,
`/home/ubuntu/transport-framing-03-pycompile.log`,
`/home/ubuntu/transport-framing-04-negative-build.log`,
`/home/ubuntu/transport-framing-05-negative-control.log`,
`/home/ubuntu/transport-framing-06-make-test.log`,
`/home/ubuntu/transport-framing-07-make-check.log`, and
`/home/ubuntu/transport-framing-08-diff-check.log`.

## FILETIME calendar differential regression

`make clock-test` compares the production `SMB.Core_Clock.To_Filetime` with
Python's proleptic Gregorian calendar for every accepted date, from
1601-01-01 through 9999-12-31. It also rejects day zero and the day after each
month's last day throughout that range, plus out-of-domain fields and signed
32-bit extremes. Error outputs must be zero, not a retained initial value.
Selected epoch, leap/non-leap century and maximum dates are combined with
second/tick boundaries. Expected FILETIME values use integer arithmetic;
no floating-point Unix timestamps or platform timezone conversions are used.

The helper checks cover every hour/minute/second with and without the input
leap flag, and nanosecond fractions around 100ns boundaries plus reproducible
samples. Fraction inputs are exact decimal `Duration` values; expected ticks
are integer division by 100. Four deliberately wrong expectations must fail.
Fixtures stream through a temporary file rather than requiring millions of
lines to remain in memory.

These are deterministic conversion tests, not a check of OS clock accuracy,
timezone services or historical leap-second tables. The core intentionally
maps seconds-of-day 86,400 to the next day's first second; the final accepted
date is checked with integer ticks without constructing a year-10000 Python
date. The tests do not change production/proof code or add formal proof of
the external calendar reference.

### Observed validation

`make clock-test` passed **3,453,296 cases**: 3,067,671 calendar dates,
201,576 invalid month/day combinations, 168 time boundaries, 22 invalid
fields, 172,800 seconds-of-day cases, and 11,059 fractions. All four
sensitivity checks passed. Python syntax compilation passed.

`make test` passed, including the NTLM MaxLen (2,050), final SPNEGO (14,936),
challenge extraction (45,396), response mutation (35,070), header mutation
(18,838), security buffer mutation (20,124), and directory boundary (6,600)
case groups. Forced strict `make check GPRBUILD="gprbuild -f"` passed,
compiling the library, tests (including `clock_probe`) and example with
`-gnatwe`; runtime dependency checks passed. `git diff --check` passed.

No GNATprove, Samba integration, or CI run was performed for this test-only
stage. The 4,412-check proof recorded for PR35 remains historical and is not
claimed as a fresh result here.

Evidence logs: `/home/ubuntu/clock-conformance-01-clock-test.log`,
`/home/ubuntu/clock-conformance-02-pycompile.log`,
`/home/ubuntu/clock-conformance-03-make-test.log`,
`/home/ubuntu/clock-conformance-04-make-check.log`, and
`/home/ubuntu/clock-conformance-05-diff-check.log`.

## SMB signing oracle and fail-closed status contracts

`SMB.Core_Wire.Sign` and `Verify_Signature` now specify the exact status for
short frames, empty keys and otherwise valid input sizes. Verification
additionally guarantees `Valid = False` on a non-`Ok` status. These contracts
depend only on public input lengths/status; no early-exit comparison of secret
bytes was added to an executable assertion. The signing/verification bodies
and existing buffer-preservation contracts are unchanged.

`make signing-test` compares the core and public wire APIs with Python HMAC
following [MS-SMB2 3.1.4.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0)
and [3.1.5.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5b570c0b-0854-4324-8fb5-d410692dde3e):
zero bytes 48..63, hash the entire SMB message, and copy the first 16 digest
bytes. Whole signed packets must match the oracle, including unchanged bytes
outside the signature. Error cases preserve the signing buffer and reset
verification output from an initial `True` to `False`; the public signing
API raises `SMB.Protocol_Error`, while public verification returns `False`.

Cases cover every length 0..129, larger boundaries through the maximum frame,
empty/short/long keys, independent array lower bounds 0/7, each bit of a
129-byte signed message (including all signature bits), each key bit, message
extension/truncation, and selected mutations in a maximum-sized message.
Appending zeros to a short HMAC key is correctly recognized as equivalent
padding, not incorrectly required to fail. Four sensitivity checks corrupt a
signature expectation or invert valid, invalid and error-case verification
expectations. This tests signing primitives, not whether arbitrary synthetic
bytes are valid SMB headers or whether a peer is authenticated. It does not
prove HMAC strength or constant-time execution.

### Observed validation

`make signing-test` passed **3,135 signing/verification fixtures / 12,540
rebased cases** through the core and public APIs; all four sensitivity checks
passed. The existing `make crypto-test` also passed: **445 hash fixtures /
890 rebased cases** and **1,832 HMAC fixtures / 7,328 rebased cases**, with
all five sensitivity checks. Python syntax compilation passed.

`make test` passed. Full local Samba integration passed all existing
scenarios and mutation/recovery checks. The clean full proof passed across
**13 units**: **4,412 checks**, with **699 flow** and **3,713 prover** checks,
**0 unproved**, **0 justified**, **68 warnings**, and **0 `pragma Assume`
statements**. The warnings are in `SMB.Core_Auth` (6), `SMB.Core_Client` (56),
and `SMB.Core_Protocol` (6). `SMB.Core_Wire.Sign`'s 15 checks and
`SMB.Core_Wire.Verify_Signature`'s 12 checks passed. Strict
`make check GPRBUILD="gprbuild -f"` and `git diff --check` passed.

The public signing/verification bodies are unchanged; only their contracts
in `src/smb-core_wire.ads` changed. No CI was run.

Evidence logs: `/home/ubuntu/signing-conformance-01-signing-test.log`,
`/home/ubuntu/signing-conformance-02-crypto-test.log`,
`/home/ubuntu/signing-conformance-03-pycompile.log`,
`/home/ubuntu/signing-conformance-04-make-test.log`,
`/home/ubuntu/signing-conformance-05-samba-integration.log`,
`/home/ubuntu/signing-conformance-06-clean-proof.log`,
`/home/ubuntu/signing-conformance-07-make-check.log`, and
`/home/ubuntu/signing-conformance-08-diff-check.log`.

## Hash and HMAC differential regression

`make crypto-test` checks the production `SMB.Crypto` functions against
OpenSSL 3's legacy MD4 provider and Python `hashlib`/`hmac` for MD5,
SHA-256, HMAC-MD5 and HMAC-SHA256. The MD4 reference does not reuse the
Python MD4 implementation used by the Samba proxy. Seven RFC 1320 vectors
and HMAC examples from RFC 2202/4231 check the reference outputs before
they become expected values. OpenSSL/provider failure is an explicit test
error, not a fallback to the Ada implementation or another local oracle.

Fixtures include every input length 0..129, larger block boundaries, zero,
all-one and varying-byte patterns, and the public maximum input lengths:
1,048,640 bytes for hashes and 1,048,576 bytes for HMAC keys/messages. HMAC
key lengths cover both sides of the 64-byte normalization boundary. The
Ada probe uses ordinary array equality (not `Constant_Time_Equal`) to compare
digests, repeats hash calls at lower bounds 0/7, and tests all four independent
key/message lower-bound combinations for HMAC. Corrupting each of the five
algorithm expectations must make the probe fail.

This is additional functional test evidence only. Production and proof code
are unchanged; formal proof is not rerun. It does not prove collision
resistance, authentication security, constant-time machine code or secure
erasure. OpenSSL and Python are test-only dependencies; the library remains
Pure Ada with no external cryptographic library dependency.

### Observed validation

`make crypto-test` passed **445 hash fixtures / 890 rebased cases** and
**1,832 HMAC fixtures / 7,328 rebased cases**, including the five deliberate
expectation-corruption sensitivity checks. The RFC known-answer checks passed.
Python syntax compilation, `make test`, and strict
`make check GPRBUILD="gprbuild -f"` passed.

The first probe run raised `STORAGE_ERROR` at fixture 434. The test-only Ada
probe was adjusted to heap-allocate its large input line and rebased arrays,
then release each temporary after its case, including exception paths. The
reference expectations were unchanged, and the full crypto suite then passed.
The shared input line buffer remains process-scoped. The follow-up resource
fix was also exercised by the focused crypto test, strict probe build, and
`git diff --check`.

No production or proof code was changed. GNATprove, Samba integration, and CI
were not run for this stage.

Evidence logs: `/home/ubuntu/crypto-conformance-01-crypto-test.log`,
`/home/ubuntu/crypto-conformance-02-pycompile.log`,
`/home/ubuntu/crypto-conformance-03-probe-fix.log`,
`/home/ubuntu/crypto-conformance-04-make-test.log`,
`/home/ubuntu/crypto-conformance-05-make-check.log`, and
`/home/ubuntu/crypto-conformance-06-diff-check.log`. The resource-fix
rerun logs are `/home/ubuntu/crypto-conformance-07-resource-fix.log`,
`/home/ubuntu/crypto-conformance-08-probe-strict-build.log`, and
`/home/ubuntu/crypto-conformance-09-diff-check.log`.

## NTLM Type 2 layout and public recovery

`ntlm_challenge_fields.py` adds 750 layout fixtures, each checked at two array
lower bounds through the core and public NTLM APIs. The independent complete
Type 3/SPNEGO oracle is reused without changing its output rules. Valid
cases include either payload order, padding before/between/after fields,
odd-aligned TargetInfo, optional Version storage with ignored debug contents,
ignored reserved bytes, an empty TargetName, and a bounded read-only alias
of TargetName into the domain AV value. No new blanket overlap-rejection rule
is imposed: each used slice must remain valid and within the payload.

Malformed cases place nonempty fields at every byte of the fixed header,
past the payload or at integer boundaries, and exercise oversized lengths,
empty required TargetInfo and truncated headers. Failure must publish neither
an authentication token nor a session key. Three Samba mutations separately
move TargetName into the header, set TargetInfo's offset to `0xFFFFFFFF`, or
set its length to `0xFFFF`, while retaining the original outer security-buffer
and DER lengths. The existing public recovery client requires rejection,
disconnection, cleared diagnostics and successful reconnect/read; the proxy
requires that Type 3 was not sent.

These changes add regression evidence only. They do not change production or
proof code, relax signing, establish authenticity of an unsigned challenge,
or add a cryptographic-strength proof. GNATprove and CI are not run for this
test-only stage.

### Observed validation

`make ntlm-test` passed the existing 211 AV fixtures (422 rebased cases) and
2,824 challenge-field fixtures (5,648 rebased cases). Core and public NTLM
results agreed with the expected keys and tokens; both sensitivity checks for
each fixture set passed. Python syntax compilation, `make test`, and strict
`make check GPRBUILD="gprbuild -f"` passed.

The full Samba integration passed all existing scenarios and all three new
layout modes: `challenge-layout-name-header`,
`challenge-layout-info-offset`, and `challenge-layout-info-length`. The
recovery client checked rejection, disconnect, cleared diagnostics, and
reconnect/read; the proxy required that no Type 3 was sent.

No GNATprove run was performed because production and proof sources were
unchanged. No CI was run.

Evidence logs: `/home/ubuntu/ntlm-layout-01-ntlm-test.log`,
`/home/ubuntu/ntlm-layout-02-pycompile.log`,
`/home/ubuntu/ntlm-layout-03-make-test.log`,
`/home/ubuntu/ntlm-layout-04-make-check.log`,
`/home/ubuntu/ntlm-layout-05-samba-integration.log`, and
`/home/ubuntu/ntlm-layout-06-diff-check.log`.

## Optional NTLM TargetName fields

The Type 2 receive path no longer requires `NTLMSSP_REQUEST_TARGET`.
When it is clear, `TargetNameLen`, `TargetNameMaxLen` and
`TargetNameBufferOffset` are ignored as required by
[MS-NLMP 2.2.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786).
No name slice is decoded or indexed in that case; the internal name length
and offset are zero. When the flag is set, existing bounds and UTF-16 checks
remain active. Unicode, NTLM, extended session security, signing, always-sign
and TargetInfo requirements are unchanged. Mandatory AV names are still
validated even when the separate TargetName fields are ignored.

`tests/ntlm_challenge_fields.py`, included in `make ntlm-test`, uses the
complete Python Type 3/SPNEGO oracle from the AV tests. It covers all byte
values in all eight ignored metadata bytes, invalid unused name bytes,
omitted name storage, and control cases for active name validation,
mandatory negotiation flags and TargetInfo bounds. The session key is
unchanged, but the full raw Type 2, including ignored bytes, remains in the
MIC transcript. Array lower bounds and the public exception adapter are
checked by the existing probe. This is a semantic regression test, not a
new formal claim about NTLM cryptographic strength.

### Observed validation

`make ntlm-test` passed 211 AV fixtures (422 rebased cases) and 2,074
challenge-field fixtures (4,148 rebased cases). Both the core and public APIs
agreed with the frozen expected keys and tokens. The two sensitivity checks
for each fixture set also passed: corrupted expected output and an incorrect
rejection expectation were both rejected by the probe.

The detached `477f6a0` baseline built successfully with the current shared AV
helper and challenge-field fixtures, but the new selector failed at fixture 2,
`REQUEST_TARGET clear`, with
`raised PROGRAM_ERROR : AV authentication oracle mismatch: INVALID_PROTOCOL`.
This reproduces the old required-flag rejection, rather than a setup failure.

Python syntax compilation, `make test`, and strict
`make check GPRBUILD="gprbuild -f"` passed. The full Samba integration passed
the existing regression scenarios and its three AV mutation modes:
`challenge-av-timestamp-length`, `challenge-av-name-encoding`, and
`challenge-av-terminator`. It did not test acceptance of the modified
`REQUEST_TARGET` case; that behavior is covered by the synthetic core/public
fixtures only.

The single clean full proof passed across 13 units with 4,411 checks: 699 flow
and 3,712 prover checks, 0 unproved, 0 justified, and 68 GNATprove warnings.
The totals comprise 2 data dependencies, 1 flow dependency, 539 initialization,
2 non-aliasing, 2,401 run-time checks, 292 assertions, 1,013 functional
contracts, and 161 termination checks (155 flow, 6 prover). No proof contracts
were changed, and no `pragma Assume` or `pragma Suppress` was introduced.

Evidence logs: `/home/ubuntu/ntlm-targetname-01-ntlm-test.log`,
`/home/ubuntu/ntlm-targetname-02-baseline-build.log`,
`/home/ubuntu/ntlm-targetname-03-baseline-repro.log`,
`/home/ubuntu/ntlm-targetname-04-pycompile.log`,
`/home/ubuntu/ntlm-targetname-05-make-test.log`,
`/home/ubuntu/ntlm-targetname-06-make-check.log`,
`/home/ubuntu/ntlm-targetname-07-samba-integration.log`,
`/home/ubuntu/ntlm-targetname-08-proof-clean.log`,
`/home/ubuntu/ntlm-targetname-09-make-prove.log`, and
`/home/ubuntu/ntlm-targetname-10-proof-summary.out`.

## NTLM AV-pair conformance and recovery scope

`make ntlm-test` uses a Python reference encoder and HMAC-MD5 implementation
to generate complete deterministic expected Type 3/SPNEGO tokens and session
keys. Only fixed public test-vector credentials are used. The Ada probe checks
both `SMB.Core_Auth.Authenticate` and the public `SMB.NTLM.Authenticate` with
zero and nonzero array lower bounds. Malformed AV lists must expose neither
a used output nor a session key, and must raise the public protocol exception.

The fixtures follow [MS-NLMP AV_PAIR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e)
and [client challenge processing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96):
arbitrary AV ordering, server timestamp precedence (including zero), clock
fallback when absent, zero LM response with a server timestamp, and insertion
or preservation of flags with the MIC bit set. Name encoding, fixed-width AV
lengths, missing mandatory names, duplicates, truncation and EOL rules are
covered. Nonzero channel bindings remain explicitly unsupported, not silently
accepted as verified bindings. No new channel-binding or SPN feature is added.

The Python oracle is checked against existing known-answer keys, and the
probe must reject deliberately corrupted expected output and a deliberately
incorrect rejection expectation. Separate Samba modes mutate a real
challenge's timestamp length, computer-name encoding and EOL tag without
changing the outer SMB or SPNEGO bounds. The public client must refuse to send
Type 3, disconnect/clear diagnostics and reconnect/read successfully.

This stage changes only tests and their build/documentation wiring. It does
not rerun or extend the preceding 4,411-check formal proof, and does not prove
cryptographic strength or authenticate an unsigned challenge.

### Observed validation

`make ntlm-test` passed 211 AV fixtures across 422 rebased cases, checking
both the core and public authentication APIs. Both sensitivity checks behaved
as required: the probe rejected a corrupted expected token and rejected a
deliberately incorrect rejection expectation. The initial build warned that
the probe's `Input` could be constant; it was made constant, and the focused
target passed again without that warning.

Python syntax compilation passed. `make test` and strict
`make check GPRBUILD="gprbuild -f"` passed. The full Samba integration passed
all existing scenarios and all three new modes:
`challenge-av-timestamp-length`, `challenge-av-name-encoding`, and
`challenge-av-terminator`. The public client rejected each malformed challenge
without sending Type 3, disconnected with diagnostics cleared, then reconnected
and read the fixture successfully.

No GNATprove run was performed because this stage changes no production or
proof source. No CI was run.

Evidence logs: `/home/ubuntu/ntlm-av-01-ntlm-test.log`,
`/home/ubuntu/ntlm-av-02-ntlm-test-after-constant.log`,
`/home/ubuntu/ntlm-av-03-pycompile.log`,
`/home/ubuntu/ntlm-av-04-make-test.log`,
`/home/ubuntu/ntlm-av-05-make-check.log`, and
`/home/ubuntu/ntlm-av-06-samba-integration.log`.

## Challenge extraction contract and malformed-token regression

`SMB.Core_NTLM.Extract_Challenge` now binds successful output to an in-bounds
slice of at least 48 bytes with the exact NTLMSSP marker and little-endian
message type 2. Failed extraction returns zero offset and length, including
late failures after a candidate response field was parsed. A candidate slice
is published only after the whole supported wrapper is accepted; the accepted
token language is unchanged.

`challenge-mutations` tests direct NegTokenResp and GSS-wrapped forms with
rebased arrays. It varies all prefix/header bytes, verifies accept-incomplete
and request-MIC challenge states, checks all truncations, tests late failures,
and covers canonical DER length boundaries through the 65,535-byte token limit.
The payload here is a synthetic Type 2 header fixture: acceptance by this
extractor does not assert that its credentials, flags or AV pairs are valid.
Separate Samba modes corrupt the inner NTLM marker or message type while
leaving the outer SMB security-buffer metadata valid. They must stop before
sending Type 3, disconnect, clear diagnostics and reconnect/read successfully.
These unsigned challenges do not establish server authenticity.

### Observed validation

The focused build and `challenge-mutations` selector passed with 45,396 cases.
A detached baseline at `b9a1a6132c2d47661c671ccaf90114d907f6dd9f` used the
current tests and the original `src/smb-core_ntlm.ads` and
`src/smb-core_ntlm.adb`. Its build passed; the selector exited 1 with
`PROGRAM_ERROR: failed challenge extraction published a partial slice`. This
is the expected late-error regression: the original parser had extracted the
valid response before rejecting a later field, leaving nonzero outputs. It was
not a build/setup failure.

Python syntax compilation, `make test`, and strict
`make check GPRBUILD="gprbuild -f"` passed. The full local Samba integration
passed all existing scenarios, including both public challenge modes:
`challenge-ntlm-signature` and `challenge-ntlm-type`. Each mode rejected the
mutated challenge before Type 3, disconnected with diagnostics cleared and no
additional request, then reconnected and read the fixture successfully.

The single clean full proof passed with 4,411 checks: 699 flow and 3,712 prover
checks, 0 unproved, 0 justified, and 68 GNATprove warnings. Categories: 2 data
dependencies, 1 flow dependency, 539 initialization, 2 non-aliasing, 2,401
run-time checks, 292 assertions, 1,013 functional contracts, and 161
termination checks (155 flow, 6 prover). The `Extract_Challenge` postcondition
was proved at `smb-core_ntlm.ads:27`.

Evidence logs: `/home/ubuntu/challenge-contract-01-focused-build.log`,
`/home/ubuntu/challenge-contract-02-selector.log`,
`/home/ubuntu/challenge-contract-03-baseline-build.log`,
`/home/ubuntu/challenge-contract-04-baseline-selector.log`,
`/home/ubuntu/challenge-contract-05-pycompile.log`,
`/home/ubuntu/challenge-contract-06-make-test.log`,
`/home/ubuntu/challenge-contract-07-make-check.log`,
`/home/ubuntu/challenge-contract-08-samba-integration.log`,
`/home/ubuntu/challenge-contract-09-proof-clean.log`,
`/home/ubuntu/challenge-contract-10-make-prove.log`, and
`/home/ubuntu/challenge-contract-11-proof-summary.out`.

## Final SPNEGO mutation regression scope

`test_suite final-spnego` checks each byte of the known-answer final SPNEGO
token with all byte values and rebased arrays. MIC mismatches must produce
Signature_Error; structural changes must not be accepted. Truncation, missing
or duplicate fields, reordered fields, trailing bytes, noncanonical DER lengths,
short expected MICs, and the supported optional mechanism/empty-response fields
are covered. These are selected deterministic parser tests, not full ASN.1 or
SPNEGO conformance proof.

Four Samba modes alter the final mechanism-list MIC, completion state, duplicate
state or omit the MIC. The proxy first verifies the SMB signature and checks the
original SPNEGO token against a separately constructed server-direction MIC,
then changes the token and recomputes a valid SMB HMAC. Buffer/transport lengths
are adjusted so the test reaches SPNEGO validation rather than a length guard.
The public API must reject authentication, disconnect without another request,
clear diagnostics and recover through same-object reconnect and a fixture read.
The ordinary unmodified integration remains the successful-authentication control.
No production/proof inputs change in this stage, so the prior clean full proof
is historical evidence, not a newly executed proof for these test-only changes.

### Observed validation

The focused build, `final-spnego` selector, and Python syntax compilation
passed. The selector reported 14,936 mutation cases. The first build attempt
found that the test helper used Ada's reserved word `Accept` as a parameter;
renaming it to `Should_Accept` fixed the test-only compilation error.

`make test` and strict `make check GPRBUILD="gprbuild -f"` passed. The complete
local Samba integration passed all existing scenarios and all four new modes:
`final-spnego-mic`, `final-spnego-state`,
`final-spnego-duplicate-state`, and `final-spnego-missing-mic`. The proxy
validated the original final SPNEGO token's server-direction MIC, changed the
token, adjusted buffer/frame lengths, and re-signed the SMB response. For each
mode, the client rejected the response, disconnected with cleared diagnostics,
made no further request, then reconnected with the same object and read the
fixture successfully.

No GNATprove run was performed because production and proof inputs are
unchanged; the earlier clean proof remains historical, not a result of this
test-only stage. Evidence logs: `/home/ubuntu/final-spnego-01-focused-build.log`,
`/home/ubuntu/final-spnego-02-selector.log`,
`/home/ubuntu/final-spnego-03-pycompile.log`,
`/home/ubuntu/final-spnego-04-make-test.log`,
`/home/ubuntu/final-spnego-05-make-check.log`, and
`/home/ubuntu/final-spnego-06-samba-integration.log`.

## NTLM challenge MaxLen compatibility

MS-NLMP's [CHALLENGE_MESSAGE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786)
requires recipients to ignore `TargetNameMaxLen` and `TargetInfoMaxLen`.
`SMB.Core_Auth.Authenticate` previously used both to reject otherwise valid
payloads when they were smaller than the actual length or larger than the
available bytes. It now uses the actual length and offset only. Actual range,
fixed-header overlap, string encoding, AV-pair and required-flag checks remain.
The original Type 2 bytes, including both ignored MaxLen fields, remain in the
MIC transcript; ignoring them for parsing does not remove integrity coverage.

The `ntlm-maxlen` selector exercises the public `SMB.NTLM.Authenticate` API
against the existing known-answer fixture. It varies all four MaxLen bytes,
includes an empty TargetName with maximal MaxLen, repeats with rebased arrays,
and checks the complete output token against the existing expected token with
the transcript MIC recomputed from the modified challenge and known session key.
It also requires oversized actual lengths and offsets to remain rejected.
This deterministic token regression is separate from real Samba authentication;
the server's live Type 2 transcript is not modified by this test.

### Observed validation

The focused build and `ntlm-maxlen` selector passed; the selector accepted
2,050 cases. A detached baseline at `7083acfa7f744d36df73efb2865913cc808f8318`
used the original `src/smb-core_auth.adb` with the current test suite. Its
known-answer token and session-key assertions passed before the mutation loop;
the original implementation then rejected the first modified MaxLen with
`SMB.PROTOCOL_ERROR` (expected selector exit status 1). A diagnostic marker was
added only to the disposable baseline test copy to distinguish that regression
from setup failure.

`make test`, strict `make check GPRBUILD="gprbuild -f"`, and the complete local
Samba integration passed. The integration exercised the existing authentication
and other regression scenarios; it did not mutate the live server's Type 2
message, so MaxLen acceptance is established by the deterministic token test.

The single clean full proof passed with 4,401 checks: 698 flow and 3,703 prover
checks, 0 unproved, 0 justified, and 68 GNATprove warnings. The categories were
2 data dependencies, 1 flow dependency, 539 initialization, 2 non-aliasing,
2,394 run-time checks, 292 assertions, 1,011 functional contracts, and 160
termination checks (154 flow, 6 prover). `git diff --check` passed.

Evidence logs: `/home/ubuntu/ntlm-maxlen-01-focused-build.log`,
`/home/ubuntu/ntlm-maxlen-02-selector.log`,
`/home/ubuntu/ntlm-maxlen-03-old-build-marked.log`,
`/home/ubuntu/ntlm-maxlen-04-old-selector-marked.log`,
`/home/ubuntu/ntlm-maxlen-05-make-test.log`,
`/home/ubuntu/ntlm-maxlen-06-make-check.log`,
`/home/ubuntu/ntlm-maxlen-07-samba-integration.log`,
`/home/ubuntu/ntlm-maxlen-08-proof-clean.log`,
`/home/ubuntu/ntlm-maxlen-09-make-prove.log`, and
`/home/ubuntu/ntlm-maxlen-10-proof-summary.out`.

## Authentication security-buffer contracts and regression scope

`Parse_Response` now specifies the exact NEGOTIATE security-buffer length and
nonempty offset (zero-length NEGOTIATE buffers retain normalized offset zero).
For both successful and continuing SESSION_SETUP replies it specifies the
nonzero SessionId, exact extracted offset/length and nonempty-body lower bound.
These are strengthened contracts for the existing implementation, not changed
acceptance rules. The specifications describe
[NEGOTIATE buffers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5)
as a variable-length field, separate from the fixed body; zero-length NEGOTIATE
is explicitly permitted for client-initiated authentication.

`test_suite security-buffers` crosses byte-sized offsets, the exact packet end,
and the maximum WORD offset with zero/boundary/oversized lengths in all three
phases, at array lower bounds zero and seven. It checks exact status, extracted
range and SessionId. Empty buffers are not mistaken for malformed nonempty ones.

Six Samba modes mutate offset or length in NEGOTIATE, the initial SESSION_SETUP
challenge, and final SESSION_SETUP. NEGOTIATE and challenge are preauthentication
unsigned replies; final SESSION_SETUP is verified and re-signed with a valid
HMAC. The proxy requires the client to close, without an extra request: no
SESSION_SETUP after a malformed NEGOTIATE, no Type 3 request after a malformed
challenge, and no TREE_CONNECT after a malformed final reply. The public client
requires Protocol_Error for NEGOTIATE and challenge mutations, and the
existing Authentication_Error mapping for final signed authentication
mutations. Each case also requires disconnected state and cleared diagnostics,
then reconnects/authenticates on the same object and reads a real file. A
wrong-phase exception is not accepted. This tests structural parsing and
recovery, not cryptographic authenticity of preauth data.

## Linux validation: authentication security-buffer contracts

The focused build, `test_suite security-buffers`, Python syntax compilation,
`make test`, and strict `make check GPRBUILD="gprbuild -f"` passed. The selector
passed 20,124 cases across NEGOTIATE, challenge, and final SESSION_SETUP,
including rebased arrays, offset/length boundaries, and zero-length buffers.
The changed public client also passed a forced strict build with
`gprbuild -p -f -P smb_tests.gpr security_buffer_client.adb -cargs:Ada -gnatwe`.

The first integration attempt exposed an incorrect test expectation, not a
production defect: the public facade maps a rejected final authentication
response to `SMB.Authentication_Error`, while the client initially caught only
`SMB.Protocol_Error`. The client now expects `SMB.Protocol_Error` only for
NEGOTIATE and challenge mutations and `SMB.Authentication_Error` only for the
two final-authentication mutations; a wrong-phase exception is re-raised. No
production exception behavior was changed. The corrected Samba integration
passed all existing cases and all six security-buffer modes. The proxy validated
the original preauthentication replies, verified and re-signed the final
SESSION_SETUP HMAC, and confirmed rejection without a subsequent request. In
each case the public client confirmed disconnected state and cleared
diagnostics, then reconnected on the same object, authenticated, opened the
fixture and read the expected byte.

The single clean full proof passed with 4,409 checks: 700 flow and 3,709 prover
checks, zero unproved and zero justified. Categories were 2 data dependencies,
1 flow dependency, 541 initialization, 2 non-aliasing, 2,398 run-time checks,
292 assertions, 1,013 functional contracts, and 160 termination checks (154
flow, 6 prover). GNATprove reported 68 warnings.

Evidence: `/home/ubuntu/security-buffer-17-selector-final.log`,
`/home/ubuntu/security-buffer-18-pycompile-final.log`,
`/home/ubuntu/security-buffer-19-make-test.log`,
`/home/ubuntu/security-buffer-20-make-check.log`,
`/home/ubuntu/security-buffer-21-samba-integration.log` (initial expected-
exception mismatch), `/home/ubuntu/security-buffer-22-client-build.log`,
`/home/ubuntu/security-buffer-23-samba-integration-final.log`,
`/home/ubuntu/security-buffer-24-proof-clean.log`,
`/home/ubuntu/security-buffer-25-make-prove.log`, and
`/home/ubuntu/security-buffer-26-proof-summary.out`.

## Header acceptance contracts and mutation regression scope

`SMB.Core_Wire.Validate_Header` now specifies the successful response's
protocol marker, StructureSize, credit availability, server-response and
non-async flags, absence of a compound offset, exact command/MessageId, optional
TreeId/SessionId matching and the expected SIGNED flag. Rejection must leave
NTSTATUS zero. This strengthens the declared contract without changing the
implementation. It is not a proof of HMAC verification: `Validate_Header` checks
header syntax/correlation, while `SMB.Engine.Accept_Response` separately calls
`Verify_Signature` before accepting signed data.

`test_suite header-mutations` varies each byte of the marker, StructureSize,
command, compound offset, MessageId, TreeId and SessionId through all 256 values;
checks flag bytes, truncation, optional ID matching, and unsigned signature
bytes; and repeats with rebased arrays. It checks exact rejection status and
zero NTSTATUS, not just failure. Unknown flag bits retain existing acceptance;
async and compound remain unsupported client features, not malformed SMB in
general. Command matching follows
[Processing the Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/158e87ff-e898-4e51-a8fa-18f35630929c).

Six added Samba modes change MessageId, command, TreeId, SessionId, ASYNC or
NextCommand on a real READ reply and recompute its valid HMAC. They reuse the
public-API rejection, client-caused disconnect without extra requests,
reconnect and stale-handle checks from the body-mutation tests. This distinguishes
correlation rejection from merely breaking the signature.

## Linux validation: header mutation tests

The focused build passed and `test_suite header-mutations` passed all 18,838
cases, checking exact status and NTSTATUS on the successful and rejecting
header paths. The first build reported an unused `use type SMB.QWord` clause
in the new test (`/home/ubuntu/header-mutation-01-focused-build.log`); removing
that unused clause resolved the warning. The subsequent focused build, Python
syntax compilation, `make test`, and strict
`make check GPRBUILD="gprbuild -f"` all passed.

The Samba integration passed all existing cases and all fourteen response
mutation modes. For each of the six new header modes
(`header-message-id`, `header-command`, `header-tree-id`,
`header-session-id`, `header-async`, and `header-compound`), the proxy verified
the backend signature, changed the selected header field, re-signed the valid
HMAC, and observed the client disconnect without sending another request. The
public client rejected each response, reconnected, and rejected the stale
handle.

The focused `SMB.Core_Wire` proof passed. The final per-unit proof summary
records 298 proved `SMB.Core_Wire` checks, including 32 for `Validate_Header`.
The single clean full proof passed with 4,394 checks: 700 flow and 3,694
prover checks, zero unproved and zero justified. Categories were 2 data
dependencies, 1 flow dependency, 541 initialization, 2 non-aliasing, 2,392
run-time checks, 292 assertions, 1,004 functional contracts, and 160
termination checks (154 flow, 6 prover). The strengthened `Validate_Header`
success conditions and zero-NTSTATUS-on-failure condition were proved. The
full run reported 68 GNATprove warnings: 56 in `SMB.Core_Client`, 6 in
`SMB.Core_Protocol`, and 6 in `SMB.Core_Auth`.

Raw evidence is preserved under `/home/ubuntu`: focused build
`header-mutation-02-focused-build.log`, selector
`header-mutation-03-selector.log`, focused proof
`header-mutation-04-focused-proof.log`, Python syntax
`header-mutation-05-pycompile.log`, `make test`
`header-mutation-06-make-test.log`, strict check
`header-mutation-07-make-check.log`, Samba integration
`header-mutation-08-samba-integration.log`, proof cleanup
`header-mutation-09-proof-clean.log`, full proof
`header-mutation-10-make-prove.log`, and summary
`header-mutation-11-proof-summary.out`; final whitespace check
`header-mutation-12-diff-check.log`. The change adds no implementation
behavior and makes no claim that `Validate_Header` verifies the HMAC.

## Response-body mutation regression scope

`test_suite response-mutations` checks all eleven supported successful response
layouts for fixed-body truncations and every value of each StructureSize byte,
plus ERROR ByteCount bounds across these commands. READ and QUERY_DIRECTORY
offset/length cross-products check accepted ranges exactly, not merely absence
of exceptions, and test the 64 KiB library cap with enough packet capacity.
WRITE Count bytes, ignored WRITE reserved bytes and the supported CLOSE flag
mask are also varied. Tests repeat at array lower bounds zero and seven.

The expected values distinguish wire layout rules from library policy:
- [READ response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3e3d2f2c-0e2f-41ea-ad07-fbca6ffdfd90)
- [WRITE response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7b80a339-f4d3-4575-8ce2-70a06f24f133)
- [QUERY_DIRECTORY response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4f75351b-048c-4a0c-9ea3-addd55a71956)

The 64 KiB cap, zero WRITE progress rejection and unsupported CLOSE flags are
client policy. A zero-length successful READ remains tolerated and terminates
without retry (an existing compatibility behavior); the server specification
instead requires STATUS_END_OF_FILE. Zero-length range offsets must still be
within the frame. These tests do not redefine that behavior as wire conformance.

Eight local Samba proxy modes cover malformed signed READ offset/length/body,
READ data exceeding the actual request, and WRITE zero/excessive Count or
malformed/truncated body. The proxy validates the real server HMAC, changes the
body and recomputes the HMAC, then requires the client to close without sending
another request. The public API must raise Protocol_Error, invalidate its old
handle, reconnect on the same object and read again. WRITE may have already
taken effect remotely: both client and harness check its exact contents rather
than pretending rejection rolled it back. No production code or proof contract
is changed by this test expansion. This is deterministic, selected-field
mutation coverage, not exhaustive packet-space fuzzing or a new formal proof.

## Linux validation: response-body mutation tests

The focused build and `response-mutations` selector passed all 35,070 cases.
`make test` passed, including the same selector, and strict
`make check GPRBUILD="gprbuild -f"` passed with warnings treated as errors.
Python syntax compilation passed. The final Samba integration run passed all
existing cases and all eight response-mutation modes. The proxy verified the
backend HMAC before each mutation, re-signed the changed response, and observed
the client close without another SMB request. The client rejected the malformed
response, reconnected, verified fresh data, and confirmed the exact remote
WRITE effects.

Two isolated sensitivity checks also failed as expected. Removing only the
positive-length READ offset guard produced
`buffer offset/length cross-product command 8 case 6778 length 96 status OK`;
removing only the WRITE zero-count guard produced
`WRITE Count byte mutation command 9 case 13440 length 80 status OK`.
These mutations were made only in isolated copies, not in the working branch.

The first Samba attempt exposed a missing proxy pass-through for non-target
responses during file setup. The proxy now forwards those responses; the final
full integration run passed. Evidence is preserved under `/home/ubuntu`:
`response-mutation-03-selector.log`,
`response-mutation-06-read-mutant-unit.log`,
`response-mutation-08-write-mutant-unit.log`,
`response-mutation-09-make-test.log`,
`response-mutation-10-make-check.log`,
`response-mutation-12-pycompile-after-proxy-fix.log`, and
`response-mutation-13-samba-integration-final.log`.

No `src/` or proof-project inputs differ from `origin/main` for this change, and
no new GNATprove run was performed. The 4,382-check result below is the
historical proof for the preceding Windows entropy and authentication
diagnostics change, not a proof run for these tests.

## Historical complete proof: Windows default entropy and authentication diagnostics

The focused `SMB.Core_Client` proof and the clean complete `make prove` run
passed for the Windows default entropy and unverified authentication diagnostic
changes. The Linux run selected the Unix entropy adapter. A separate Windows
native retest of `aba1508f1e47560f89022223fb4d897b369910e5` passed using the
default `BCryptGenRandom` adapter, without an entropy callback.
GNATprove analyzed all thirteen configured units:
`SMB`, `SMB.Core_Auth`, `SMB.Core_Client`, `SMB.Core_Clock`, `SMB.Core_Connection`, `SMB.Core_Framing`,
`SMB.Core_NTLM`, `SMB.Core_Protocol`, `SMB.Core_Text`, `SMB.Core_Transport`, `SMB.Core_Wire`,
`SMB.Crypto` and `SMB.Engine`.

| Category | Total | Flow | Proved by provers |
| --- | ---: | ---: | ---: |
| Data dependencies | 2 | 2 | 0 |
| Flow dependencies | 1 | 1 | 0 |
| Initialization | 541 | 541 | 0 |
| Non-aliasing | 2 | 2 | 0 |
| Run-time checks | 2,390 | 0 | 2,390 |
| Assertions | 292 | 0 | 292 |
| Functional contracts | 994 | 0 | 994 |
| Termination | 160 | 154 | 6 |
| **Total** | **4,382** | **700** | **3,682** |

There were zero unproved and zero justified checks, and no `pragma Assume`
statements. GNATprove reported 68 flow-analysis warnings (56 in
`SMB.Core_Client`, 6 in `SMB.Core_Protocol`, and 6 in `SMB.Core_Auth`).
The proof includes the bounded `Unverified_Authentication_Status` helper and
its return contract; the diagnostic remains explicitly unverified and does
not replace signed authentication or MIC validation.

The focused authentication selector passed. The complete test build,
`make test`, strict `make check GPRBUILD="gprbuild -f"` and Samba integration passed,
including unsigned final authentication error, success, and wrong-message-ID
diagnostics with rejection, disconnect, reconnect and successful reauthentication.
Python syntax compilation passed. The final clean proof summary is preserved at
`/home/ubuntu/windows-entropy-18-proof-summary.out`; raw output is at
`/home/ubuntu/windows-entropy-17-make-prove.log`.

The Windows retest passed the native build, focused and complete unit tests,
forced `-gnatwe` rebuild and dependency audit. Against the Windows SMB server,
the existing integration/cleanup tests passed with default entropy, including
large/small files, Unicode, 1,203 directory entries, rename/delete, reuse after
errors and reconnect. Header-only observation confirmed SMB 2.1 and SIGNED on
all 48 post-authentication requests and 48 responses in the observed flow;
flipping one signature bit was rejected and disconnected.

An actual wrong-password response carried `0xC000006D`, matching
`Last_Unverified_Authentication_Status`; `Last_NT_Status` stayed zero and
`Authentication_Error` explicitly labeled the peer value "unverified". The
connection closed, reconnect cleared the hint and correct authentication reused
the same connection object. All three added unsigned-auth proxy cases passed.
Temporary Windows resources were deleted and settings restored. This is tested
interoperability, not proof of OS/ABI behavior or all Windows configurations.
The non-secret reproduction and logs are packaged as
`AdaSMB-Windows-default-entropy-aba1508-evidence.zip` in the
[Windows verification session](https://app.devin.ai/sessions/dce88c0d59e74afd962e092fab69f03e).
CI was not run.

## Historical complete proof: connection reserved fields

The complete `make prove` run passed for the connection reserved-field correction
[`992f50d`](https://github.com/gomurin0428/AdaSMB/commit/992f50dbdc8db87c39fc34df588746d314ab2304).
A focused protocol proof preceded the complete run, which started
after `gnatprove --clean`.
GNATprove analyzed all thirteen configured units:
`SMB`, `SMB.Core_Auth`, `SMB.Core_Client`, `SMB.Core_Clock`, `SMB.Core_Connection`, `SMB.Core_Framing`,
`SMB.Core_NTLM`, `SMB.Core_Protocol`, `SMB.Core_Text`, `SMB.Core_Transport`, `SMB.Core_Wire`,
`SMB.Crypto` and `SMB.Engine`.

| Category | Total | Flow | Proved by provers |
| --- | ---: | ---: | ---: |
| Data dependencies | 2 | 2 | 0 |
| Flow dependencies | 1 | 1 | 0 |
| Initialization | 539 | 539 | 0 |
| Non-aliasing | 2 | 2 | 0 |
| Run-time checks | 2,390 | 0 | 2,390 |
| Assertions | 292 | 0 | 292 |
| Functional contracts | 990 | 0 | 990 |
| Termination | 159 | 153 | 6 |
| **Total** | **4,375** | **697** | **3,678** |

There were zero unproved and zero justified checks. All configured units and
subprograms were analyzed; none were reported skipped. GNATprove reported
67 flow-analysis warnings (55 in `SMB.Core_Client`, 6 in
`SMB.Core_Protocol`, 6 in `SMB.Core_Auth`), primarily unused assignments and
status/converter outputs, and
zero `pragma Assume` statements. The forced `-gnatwe` build passed.

The first full lifecycle run at the previous 30-second timeout left one CLOSE
message-ID preservation assertion unproved. A focused run proved it with Z3
in 49.74 seconds. The final clean run uses the same level-2 cvc5/z3
configuration and checks-as-errors with a 120-second timeout, now the
`make prove` default. The lifecycle proofs use checked ghost lemmas and
`Assert_And_Cut` boundaries; those assertions themselves are proved, not
assumed. No contracts were weakened or checks justified to pass.

The proof includes the typed SESSION_SETUP authentication lifecycle: negotiate
preparation and send acknowledgement, owner/epoch binding across continuations,
bounded challenge ownership and exact length/session correspondence to the
validated response, token-to-wire body preservation and SESSION_SETUP layout,
Type 3 construction from that challenge, key installation in the Engine, and
completion only after an acknowledged signed response with valid SPNEGO MIC.
Authentication ordering errors make no progress; failed completion invalidates
the Engine, preserving the received NTSTATUS where applicable. The coordinator
stores neither credentials nor the session key.

The proof also includes the bounded READ/WRITE transfer state and lifecycle:
capacity and chunk bounds, owner/epoch/token validation, actual prepared packet
fields tied to the validated handle and Engine request expectation, immutable
WRITE snapshot preservation, and READ accumulation/copying from validated
response bytes while preserving the prior prefix. Completion consumes a
matching sent-stage response receipt once; WRITE progress uses the validated
positive acknowledgement count. Empty WRITE performs no I/O, and short,
zero-length and EOF READ responses finish without retry. Zero-count and
over-count WRITE responses fail rather than advancing progress. Uncertain
transport outcomes abort the transfer and invalidate Engine state without
automatic retry. Existing CREATE/CLOSE packet, receipt, and handle contracts
remain included.

The proof also covers bounded directory enumeration. The coordinator captures
the directory handle identity and owner/epoch at start; every continuation
revalidates the readable directory handle before progressing. It binds each
signed command-14 query to the 64-KiB request limit and first-page restart
behavior, requires send acknowledgement and a matching validated response,
and copies validated nonempty page data into its fixed-size snapshot. Entry
parsing uses only that snapshot and proves cursor progress, entry metadata and
UTF-16 name correspondence, per-entry count bounds, and no progress on a short
name buffer. Page and entry caps are enforced in the core; valid terminal
statuses preserve their NTSTATUS and malformed pages invalidate the Engine.
Successful query preparation binds the stored directory identity to
`SMB.Engine.Handle_Matches` on the pre-call Engine state. The context predicate
also proves the exact stored FileId/access/directory identity using byte-wise
handle-match congruence.

The SET_INFO coordinator's preparation, packet, continuation, and response
receipt obligations are included in this analysis. The disposition and rename
builders are bounded; command-17 requests are signed and bound to the stored
handle identity, rename bytes and request expectation; successful and valid
NTSTATUS responses consume one receipt and preserve the handle.

The separate `SMB.Core_Connection` coordinator binds NEGOTIATE, TREE_CONNECT,
TREE_DISCONNECT and LOGOFF to the Engine owner, epoch, starting phase/session/
tree context and exact pending request. Preparation proves header/body fields,
GUID and path-byte preservation, signing requirements, and no state damage on
invalid input, insufficient output capacity or pre-reservation counter
exhaustion. Completion requires send acknowledgement and consumes a validated
receipt once. Negotiated read/write limits and the assigned Tree ID are bound
to the response bytes. Successful TREE_DISCONNECT clears handles and the Tree
ID while retaining the session/key; successful LOGOFF invalidates local state
and zeros the signing-key representation. Valid NTSTATUS errors preserve the
connection context; malformed or uncertain responses require reconnect.

The `SMB.Core_Transport` proof covers the actual native stream arrays used
by `SMB.Transport`: exact TCP-prefix and payload construction, exact accepted
receive-byte copies with earlier-prefix/unused-tail preservation, positive
bounded partial-I/O progress, unsent-range selection, and unchanged progress
or destination on invalid counts. Native capacity includes the four-byte
prefix beyond the 1-MiB packet limit. Nonzero buffer lower bounds are supported.
The focused proof explicitly proves initialization and preservation of all
five new loop invariants. Their local runtime `Ignore` policy avoids quadratic
prefix rescans but does not change GNATprove's analysis; no runtime bounds
checks or pre/postcondition checking are suppressed. The full socket loops,
OS return semantics, retry/deadline behavior, allocation/initialization, and
exception cleanup remain trusted and are tested rather than formally proved.

The `SMB.Core_Clock` proof covers the actual FILETIME path called during
authentication. It proves calendar-range validation, signed-64-bit timestamp
arithmetic and exact truncation of native nanoseconds to a 100-ns floor
interval. Inputs outside the supported date/seconds/tick bounds return
`Invalid_Value` and zero before conversion. The fixed-point representation is
enforced at compile time (`Duration'Small = 1ns`). OS time retrieval, UTC
splitting, the truth of leap-second flags and exception handling are not proved.

The strengthened `SMB.Core_Text` path/share contracts prove acceptance exactly
according to their lexical predicates, exact slash normalization with all other
bytes preserved, and zero output on rejected paths. The path-copy invariant's
initialization/preservation are proved; its runtime Ignore policy avoids
quadratic prefix scans without disabling bounds or pre/postcondition checks.
This does not prove server path resolution, Unicode normalization, or filesystem
containment. UTF encoder/decoder semantics remain covered by tests rather than
these new lexical contracts.

UTF conversion now uses actual per-scalar capacity, permitting valid exact-fit
buffers smaller than the former conservative `2 * Input'Length` requirement.
Strengthened contracts prove bounded `Used` even on failure, even-length
UTF-16 output, and successful empty/nonempty correspondence. The UTF-8 decoder
also proves four-byte consumption for non-BMP scalars. This remains short of a
proof of complete Unicode encoding correspondence. Public `SMB.Text` adapters
now check input limits before output-size multiplication/allocation; these
non-SPARK guards are covered by explicit exception regressions.

The proof does not establish the trusted socket/allocation/exception adapter,
complete public-facade correctness, cryptographic hardness, server rollback, or
exactly-once behavior after an uncertain write.

Raw GNATprove output is `gnatprove.out`; its summary is
`build/proof-obj/gnatprove/gnatprove.out`, both relative to the checkout root.

## Executed tests

* `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make test`:
  passed (`AdaSMB unit tests passed`). Authentication fixtures verify the
  expected NTLM Type 3 vector and key; reject foreign-engine continuations and
  aborts despite colliding message/session identifiers; reject stale epochs
  after reconnecting the same owner; preserve a challenge receipt when a fresh
  coordinator attempts to start; reject challenge/final completion before send
  acknowledgement and duplicate challenge completion; reject Success instead
  of MORE_PROCESSING_REQUIRED; distinguish malformed challenges; and reject
  tampered final signatures, bad MICs, and signed ACCESS_DENIED while checking
  Engine/key cleanup. Transfer fixtures cover partial WRITE continuation and
  payload snapshot preservation, empty WRITE, response-receipt misuse,
  NTSTATUS after partial WRITE, short/zero/EOF READ, multi-chunk READ prefix
  preservation, and invalid/overflowing transfer inputs. Directory fixtures
  cover signed multi-page enumeration and exact query fields, independent page
  snapshots, `No_More_Files` and successful zero-data termination, wrong-stage
  and duplicate completion, premature queries, short-buffer retry without
  progress, foreign/stale context, malformed records, signature failure, and
  page/entry caps.
  SET_INFO fixtures cover signed command-17 disposition packets and both
  delete-flag values, directory and file handles, nonzero-bound rename names,
  exact signed rename header/body fields,
  signed success and ACCESS_DENIED receipt consumption, completion before
  acknowledgement, duplicate completion, foreign contexts with colliding
  request IDs with completion and abort rejection, validated-receipt
  preservation, unrelated pending-request completion/abort rejection, and
  same-owner new-epoch rejection with colliding wire IDs. They also cover
  invalid short/empty/odd inputs, malformed signed structure size, and
  signature tampering.
  Connection fixtures cover exact NEGOTIATE GUID/body fields and clamped
  response limits; signed TREE_CONNECT paths with nonzero array bounds and
  wire-assigned Tree IDs; invalid inputs, short buffers, wrong phases, pending
  requests and unconsumed receipts; acknowledgement ordering, duplicate and
  foreign/stale continuations; valid error receipts and handle preservation;
  successful TREE_DISCONNECT/LOGOFF cleanup; matching aborts; and malformed,
  bad-signature and bad-correlation responses.
  Native transport fixtures cover nonzero-bound frame and receive arrays,
  maximum-size frames including the TCP prefix, insufficient output capacity,
  short packets, exact partial-read concatenation with prefix/tail preservation,
  EOF/overcount/out-of-range results with no progress, oversized positions,
  partial-write continuation, and duplicate completion rejection.
  FILETIME fixtures include the 1601/1970 epochs, the leap-century calendar,
  invalid century/day/month/range inputs, maximum accepted date, leap-second
  normalization, subsecond rounding boundaries and a public-clock smoke test.
  `gprbuild -p -P smb_tests.gpr test_suite.adb` followed by
  `./build/bin/test_suite utf-capacity` passed as the focused test. Path
  fixtures exhaustively compare strings of length 0..4 over six characters with
  the prior component-based rules, under both empty-input policies; additionally
  they cover literal rejection/normalization cases, UTF-8 byte preservation,
  maximum size, differing/nonzero/near-`Integer'Last` lower bounds, and share
  restrictions. UTF fixtures cover empty, ASCII, two-/three-/four-byte scalars,
  mixed prefixes, exact-fit and one-byte-short buffers, no partial scalar writes,
  and nonzero bounds. A 49,152-byte UTF-8 name is successfully converted into
  32,768 UTF-16 bytes in a 65,534-byte buffer. Public oversized text/username
  inputs raise the documented errors before core precondition failures.
  A focused
  `gnatprove -P proof.gpr -u smb-core_text.adb --mode=all --level=2
  --report=all --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4`
  also passed before the clean full proof.
* `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make check
  GPRBUILD="gprbuild -f"`: passed. The library, test suite, and example were
  forcibly rebuilt with warnings treated as errors; the runtime dependency
  audit passed.
* `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH gnatprove -P
  proof.gpr --clean`: passed. The subsequent
  `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make prove`
  passed across all thirteen units with the clean full-project result above.
* `sudo -n env PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH
  python3 tests/samba_integration.py`: passed against local Samba on
  `127.0.0.1:1445`. The public integration client passed normal authentication,
  wrong-password rejection, repeat authentication on an authenticated
  connection without disconnecting, and disconnect after an injected
  post-challenge entropy callback raising `SMB.Invalid_State`. All seven adversarial cases passed,
  including wrong-correlation authentication. Malformed signed CREATE and
  interrupted READ invalidation/reconnect regressions passed. In the
  lost-WRITE-response-after-progress regression, the proxy relayed the first
  positive successful WRITE response and dropped the second; it verified
  exactly two client WRITE requests and two positive successful WRITE
  responses. The client reported transport failure, rejected stale-handle
  operations, reconnected through the same public connection, and read back
  the complete deterministic 70,001-byte file. Normal directory enumeration
  returned all 1,203 entries. For the malformed signed second-page regression,
  the proxy kept the client-facing connection open and continued observing
  upstream after sending the mutated page; it required client EOF within its
  bounded 11-second join. QUERY_DIRECTORY requests are counted before
  forwarding, and any third request fails the test even if its response is not
  relayed. The test verified positive first-page progress and exactly two
  request/response pairs, followed by Protocol_Error, client-owned
  disconnection, and successful list/read after reconnecting the same
  connection to the backend. The malformed-signed-SET_INFO mode likewise
  mutated a valid signed success response from structure size 2 to 3, observed
  client EOF without a second SET_INFO request, and verified after reconnect
  that the server-side rename effect and exact fixture content existed despite
  the local Protocol_Error. The malformed-signed-TREE_DISCONNECT mode mutates
  a valid signed response from structure size 4 to 5, observes client EOF,
  exactly one TREE_DISCONNECT and zero LOGOFF requests, then verifies
  reconnect, stale-handle rejection and a successful fresh fixture read.
  A second public `Connect_Share` call on an active share is rejected without
  disconnecting or invalidating its existing handle. Invalid public paths
  (`../fixture.txt`, `/fixture.txt`, and an alternate-stream-style name) are
  rejected while an existing fixture handle remains readable. No rollback or
  exactly-once guarantee is implied.
* Prior transport milestone (not rerun for the text-only change):
  `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH
  python3 tests/transport_integration.py`: passed. A zero-reader peer exercises
  send backpressure/deadline invalidation; fragmented peer writes exercise
  header/body reception and a byte-exact frame echo. EOF during the header or
  payload, unsupported and oversized prefixes, and a stalled partial header
  are rejected with client-owned closure, invalid reuse rejection, and a new
  fragmented frame/echo after reconnecting the same Connection object. TCP
  may coalesce peer writes; deterministic unit fixtures separately exercise
  partial counts. OS scheduling and real EINTR injection are not proved/tested.
* Prior transport milestone (Python files unchanged):
  `python3 -m py_compile tests/transport_integration.py tests/adversarial_proxy.py
  tests/samba_integration.py`: passed.
* `git diff --check`: passed. A source scan found no `pragma Assume`,
  `False_Positive`, `Suppress`, or `Annotate` declarations in `src/` or
  `tests/`.

CI and Windows-native testing were not performed.

## Additional Unicode conformance regression

The test-only Unicode milestone leaves the library and proof sources unchanged
from the clean proof above. Its new Ada probe compares core output/status and
public text-adapter output/errors with fixtures authored by Python's strict
`utf-8` and `utf-16-le` codecs. SMB's NUL rejection and odd UTF-16 byte-length
error take explicit precedence in the oracle; no normalization is performed.

The run passed **1,287,503 fixtures**:

* 1,112,063 scalar pairs: every Unicode scalar except NUL, in both directions,
  with exact-size core buffers and the real public allocation adapters.
* 256 individual UTF-8 bytes, all 65,536 UTF-8 byte pairs, and all 65,536
  individual UTF-16 code units (including invalid surrogate halves).
* 4 fixed and 4,096 deterministic mixed valid sequences.
* 20,000 byte strings per direction, seed `0xADA5B021`.
* 8 explicit malformed UTF-8 and 4 malformed UTF-16 cases, including
  overlong/surrogate/out-of-range encodings, NUL, and truncation.

Negative controls confirmed that wrong expected bytes in either direction and
a wrong expected error status fail the probe. The harness also checks the exact
processed fixture count. This is differential testing, not a universal proof
for all Unicode strings or all malformed inputs.

The probe build, full unit suite, forced warnings-as-errors builds, runtime
dependency audit and Python syntax check passed. GNATprove and Samba were not
rerun for these test-only changes; their latest results above still apply to
the unchanged library. No CI was run.

## Public path preflight regression

The native facade now encodes CREATE names before entering network-failure
handlers, including the source path for rename. The private CREATE adapter
accepts encoded names; public API signatures and post-send defensive cleanup
are unchanged. Enumeration and rename initialize buffers before acquiring
their temporary remote handles.

The expanded Samba regression reproduced a real failure on the preceding
library (`39c415e`): malformed UTF-8 passed lexical validation but was rejected
before transmission inside `List_Directory`'s broad exception handler, which
disconnected the connection (`invalid path disconnected: LIST_PATH`).
The fixed library passes 42 rejection checks: seven path entry points for
three lexical errors, malformed/truncated UTF-8, and an ASCII path whose
UTF-16 encoding exceeds 65,534 bytes. Each check verifies the connection,
existing readable handle, and last NTSTATUS survive the rejection. Rename
source and target are checked separately.

The current integration suite (including malformed-response cleanup), full
unit suite, forced warnings-as-errors builds and runtime dependency audit
passed. Allocation-failure injection was not performed; initialization ordering
was reviewed. SPARK core sources are unchanged, so the previous 4,387-check
proof is retained rather than rerun; facade exception correctness remains
outside that proof. No CI was run.

## Checked buffer initialization and copying

Four growing-prefix loops in `SMB.Core_Client` now use Ada aggregate or slice
assignment: transfer/challenge clearing, WRITE snapshot creation and completed
READ result copying. The old loops rechecked every previous byte at each
iteration with assertions enabled, giving quadratic runtime verification cost.
All subprogram pre/postconditions remain unchanged. No new assertion policy,
timeout increase, suppression or proof justification was introduced.
The total decreases from 4,387 to 4,370 because the loops and their associated
checks are replaced, not because the functional contracts were weakened.
The additional warning concerns the unused initial value of the completely
overwritten `Clear_Transfer_Buffer` parameter.

This issue surfaced while testing a separate native share-name preflight fix.
The unchanged core object files in that branch and base `46cc12f` were
byte-identical. A GDB trace of the 70,001-byte lost-WRITE scenario measured
10.123678 seconds from `Start_Write` entry to the next `Prepare_Next` entry,
before any WRITE send, exceeding the proxy's unchanged 10-second idle timeout.
The snapshot loop alone checked 2,450,105,001 prefix elements.
With this fix, the same trace interval was 0.000642 seconds, both WRITE chunks
reached the backend, and the lost-response/reconnect scenario passed.
These are individual instrumented observations, not throughput benchmarks or
proved execution-time bounds.

Focused engine-receipt tests additionally use differently based WRITE input
and READ output ending at `Natural'Last`, including a short READ with a zeroed
unused tail. Empty and multi-chunk transfer cases remain covered.
Focused and full proofs, the full unit suite, all-executable builds, forced
warnings-as-errors builds, dependency audit and the complete Samba suite passed.
No CI was run.

## Public share preflight regression

`Connect_Share` completes share-name validation and UNC UTF-16 encoding in
its declaration preflight, before its communication-failure handler. The
public signature and post-send prepare/execute/status/abort policy are
unchanged, as is rejection of a repeated valid share connection.

The added integration test reproduced the previous defect at base `46cc12f`
with `invalid share preflight disconnected client`. It rejects an empty
name, a slash-containing name, malformed UTF-8 and a 256-byte name in both
authenticated and share-connected states: eight rejection checks, each
preserving the connection and last NTSTATUS. The authenticated connection
then connects to the valid share; the active-share test retains and reads its
previously opened fixture handle.

After the separate checked-buffer fix above, all test executables, the
complete Samba suite (including lost-WRITE recovery), full unit tests, forced
warnings-as-errors builds and runtime dependency audit pass. No SPARK units
changed in this preflight correction; the 4,370-check result above remains
applicable. This is native exception-ordering regression coverage, not an
extension of that proof. Allocation-failure injection was not performed.
No CI was run.

## Public transfer preflight regression coverage

Six additional Samba cases exercise public READ/WRITE rejection of a request
larger than 1 MiB, a one-byte range overflowing `QWord'Last`, and an access-kind
mismatch (READ through a write-only handle or WRITE through a read-only handle).
Each case first obtains `STATUS_OBJECT_NAME_NOT_FOUND` from a real missing-file
request. The local rejection must preserve that nonzero NTSTATUS and the
connection, with the expected `Protocol_Error` or `Invalid_State`.
Subsequent valid writes/reads exercise all three existing handles.

The unchanged library passes these tests; this is additional coverage, not a
newly discovered product fix. A separate uncommitted negative-control build
deliberately reset `Last_Status` in the READ exception handler. The new test
failed with `local transfer error changed last NTSTATUS: OVERFLOWING_READ`
after its connection-alive assertion passed, demonstrating detection of
status loss without relying on a disconnect.

All executable builds, full unit tests, strict rebuild/dependency audit and
the complete Samba suite passed. No library source changed, so the current
4,370-check SPARK result is retained; proof and Unicode-oracle runs were not
repeated. No CI was run.

## Credential preflight

`SMB.Core_Auth.Validate_Credentials` checks the existing 4,096-byte per-field
limits, nonempty ASCII username and UTF validity using the same uppercase and
conversion routines as Type 3 construction. It retains support for empty
passwords/domains and Unicode passwords/domains. It has no precondition or
global effects; run-time safety and the successful-result resource-bound
postcondition are proved. This does not add a complete Unicode semantic proof
or secure-erasure guarantee. Six proof warnings are the intentionally unused
scratch buffer/count outputs from validation-only conversions.

The public `Authenticate` checks these server-independent inputs before its
first SESSION_SETUP, outside the communication-failure handler. Local rejection
preserves the negotiated connection and last NTSTATUS so corrected credentials
can be tried. Invalid starting states retain `Invalid_State` precedence.
The original network authentication body and its cleanup are unchanged:
invalid challenges, bad passwords rejected by the server, signature/MIC failure
and transport errors still follow their existing post-send failure policy.
This public wrapper's exception ordering remains tested native adapter behavior,
not a formal proof of all facade behavior.

The preceding library at `624ca5c`, with only the new integration test copied
in, failed at `invalid credential preflight disconnected client`. The new
implementation passes eight rejection/reuse cases followed by successful
authentication, plus wrong-state precedence. Thirteen focused unit cases cover
accepted inputs, nonzero-bound maximum-length arrays and rejected credentials.
The full unit suite, complete Samba suite, strict build/dependency audit and
complete proof passed. Existing Unicode converters were unchanged, so the
Unicode oracle was not rerun. No CI was run.

## Directory-chain termination

`Parse_Directory_Entry` now rejects a nonzero `NextEntryOffset` equal to
the remaining page length. Previously, that dangling link advanced the cursor
exactly to the page end and the coordinator treated it as normal page completion.
[MS-FSCC FileIdBothDirectoryInformation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/1e144bff-c056-45aa-bd29-c13d214ee2ba)
requires the final entry's link to be zero. Alignment padding remains ignored,
including nonzero padding bytes.

The strengthened contract proves that a rejected record leaves the cursor
unchanged. On success, the cursor reaches the page end if and only if the encoded
link is zero; otherwise its advance equals that link and remains strictly inside
the page. This is a single-entry contract, not a claim that the unparsed remainder
of the page is already valid. A later truncated or invalid entry is rejected when
parsed. The full public facade and its exception/allocation behavior remain
outside the proof.

The `directory-bounds` selector passes 6,600 table cases covering truncation,
name lengths, alignment and link boundaries, nonzero array/cursor bases, and
arrays ending at `Natural'Last`. An additional two-entry control checks ignored
nonzero padding and an unpadded final record. The same tests against `6457406`
fail with `directory bounds result mismatch: available 112 name 2 next 112`.

The new `dangling-signed-directory-second-page` Samba proxy mode validates
the original server signature, forwards the first page, and changes the second
page's final link to point exactly past its padded end before re-signing it.
The public client rejects that page, disconnects without a third directory query,
then reconnects, lists and reads successfully. The earlier malformed-link mode
continues to pass. Full unit tests, Samba tests, the strict build/dependency audit
and the clean full proof passed. Unicode conversion was unchanged and its oracle
was not rerun. No CI was run.

## READ reserved-field conformance

[MS-SMB2 READ Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3e3d2f2c-0e2f-41ea-ad07-fbca6ffdfd90)
requires SMB 2.1 clients to ignore the Reserved byte and Reserved2 DWORD even
though servers must send zero. The old parser rejected nonzero values and
propagated an incorrect reserved-byte-zero postcondition through the Engine to
the transfer coordinator. Those checks and assertions are corrected, not
suppressed to pass proof. This explains the reduced check count. The READ
structure, 8-bit DataOffset, length bounds, request correlation, transfer
progress and exact data-copy contracts remain intact. SMB 3.1.1 interpretation
of the DWORD as flags does not apply to this SMB 2.1-only library.

The `read-reserved` selector accepts 256 byte values crossed with four DWORD
values (zero, one, high bit, all ones) and still rejects bad structure, length
and offset. On the preceding implementation at `548df56`, the same test fails
with `SMB2.1 READ reserved fields were not ignored`.

The new `read-reserved-fields` Samba mode verifies each original signature,
sets both reserved fields to all ones, re-signs and forwards three READ
responses. The public client checks all 70,001 bytes across two chunks, reuses
the same handle for another read, and completes CLOSE/disconnect/LOGOFF.
The interrupted-read mode now changes only the reserved byte of the second
response without re-signing: it still causes rejection, disconnect, successful
reconnect and stale-handle rejection. Ignoring a field's semantics never
excludes its bytes from MAC verification.

The full unit/Samba suites, strict forced build and dependency audit, and clean
full proof passed. This does not expand the proof to the full facade or establish
cryptographic hardness. No CI or Unicode oracle rerun was performed.

## ERROR reserved-byte conformance

[MS-SMB2 ERROR Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d4da8b67-c180-47e3-ba7a-d24214ac4aaa)
requires the client to ignore Reserved at byte 67. The preceding
ErrorContextCount byte is not interchangeable with it: nonzero context counts
remain unsupported in this SMB 2.1-only parser. The correction removes only the
Reserved-byte rejection from `Parse_Error`; structure size and ByteCount bounds
and all existing contracts remain unchanged. Removing this check accounts for
the two fewer run-time proof checks.

The `error-reserved` selector accepts all 256 Reserved values for CREATE, READ,
QUERY_DIRECTORY and SET_INFO error bodies, using nonzero array bounds. Controls
still reject a nonzero ErrorContextCount, wrong structure size, truncated body,
and oversized or overflowing ByteCount; empty ErrorData is still accepted.
The same test against `91c48dd` fails at
`SMB2.1 ERROR reserved byte was not ignored`.

The new Samba `error-reserved-field` mode verifies the original signature of a
missing-file CREATE error, changes only Reserved to all ones, and re-signs it.
The public API reports `SMB.NT_Status_Error` with
`STATUS_OBJECT_NAME_NOT_FOUND`, rather than treating the ignored byte as a
protocol fault. The connection remains live and a previously opened handle
still reads the fixture correctly before CLOSE and a complete LOGOFF exchange.
This facade exception/connection-preservation behavior is tested, not a formal
proof of the native wrapper.

Full unit/Samba tests, strict forced build/dependency audit, and the clean full
proof passed. No CI or Unicode oracle rerun was performed.

## Connection reserved-field conformance

For dialects other than 0x0311, NEGOTIATE's NegotiateContextCount/Reserved WORD
and NegotiateContextOffset/Reserved2 DWORD must be ignored; TREE_CONNECT's Reserved
byte must also be ignored. AdaSMB still accepts only dialect 0x0210, so these
fields are never interpreted as SMB 3.1.1 contexts. Minimum lengths, structure
sizes, signing-enabled mode, security-buffer bounds, transfer limits, disk share
type, nonzero TreeId and encryption refusal remain checked. The four fewer proof
checks come from deleting reserved-field reads, not from weakened contracts.

The `connection-reserved` selector covers 1,792 byte combinations (1,536
NEGOTIATE and 256 TREE_CONNECT) with nonzero array bounds, checks parsed transfer
limits and TreeId, and rejects truncation, dialect 0x0311, disabled signing,
overlapping security buffers, unsupported share type, required encryption and
zero TreeId. It fails against `3831eb2` with
`SMB2.1 connection reserved fields were not ignored`.

Samba's `connection-reserved-fields` proxy sets the unsigned NEGOTIATE reserved
fields to all ones, verifies the original TREE_CONNECT MAC, changes only its
reserved byte and re-signs it. The public client then reads the fixture and
completes LOGOFF. Full unit/Samba tests, strict forced build/dependency audit and
a clean full proof passed (0 unproved, 0 justified, 67 warnings). CI and the
Unicode oracle were not run.

## Teardown reserved-field conformance

CLOSE's reserved DWORD and TREE_DISCONNECT/LOGOFF's reserved WORD must be ignored
on receipt (MS-SMB2 sections 2.2.16, 2.2.12 and 2.2.8, linked in
`protocol.md`). Removing their reads/rejections leaves the minimum body lengths,
structure sizes, supported CLOSE flags, signatures and receipt/state transitions
unchanged. No contracts were removed or weakened; two call-site contract checks
disappear with the unnecessary reads.

The `teardown-reserved` selector covers 2,048 byte combinations: each reserved
byte varies over all 256 values while the other reserved bytes are all ones.
It uses exact-sized slices with nonzero bounds and rejects truncated bodies,
wrong structure sizes, and unsupported CLOSE flags. The same selector against
`2cb0e47` fails at `SMB2.1 teardown reserved fields were not ignored`.
The existing malformed-CLOSE Engine test now uses unsupported flags rather than
the no-longer-malformed reserved DWORD, retaining its state-invalidation check.

Samba's `teardown-reserved-fields` proxy verifies each original response MAC,
changes only reserved fields to all ones, and re-signs. It requires the complete
response sequence CLOSE, CLOSE, TREE_DISCONNECT, LOGOFF, with exactly one request
for each disconnect command. The public client closes and reopens the fixture,
reads its content, closes it again, and successfully disconnects. The native
wrapper remains a tested trust boundary rather than a completely proved facade.

Full unit/Samba tests, strict forced build/dependency audit and a clean full
proof passed. No CI or Unicode oracle rerun was performed.

## Mechanism-list MIC construction

`SMB.Core_NTLM.Mechanism_List_MIC` now has an exact functional contract in
terms of the MS-NLMP signature without key exchange: bytes 0 .. 3 are version
1, bytes 12 .. 15 are sequence number 0, and bytes 4 .. 11 are the first eight
bytes of `HMAC_MD5 (MD5 (Signing_Key_Material (Session_Key, From_Server)),
Mechanism_List_Signature_Input)`. `Signing_Key_Material` is proved to be the
16-byte session key followed by the NUL-terminated client-to-server or
server-to-client magic selected by `From_Server`; the signature input is
sequence number zero followed by the DER NTLM mechanism list. The hash
functions remain trusted primitives checked by their existing differential
tests; this contract fixes how the MIC is composed from them.

The material construction was moved into `Signing_Key_Material` without
changing the computed bytes. `make crypto-test` adds 774 fixtures (259 keys
and all 128 single-bit key changes, both directions) checked against Python
`hashlib`/`hmac`, two known vectors, and corrupted-MIC and swapped-direction
sensitivity checks.

Focused proof of `smb-core_ntlm.adb`: 243 checks (43 flow, 200 prover), zero
unproved. Full proof: 4,987 checks (727 flow, 4,260 prover), zero unproved, no
`pragma Assume`. Unit, NTLM, strict forced build/dependency audit and Samba
integration tests passed. No CI or Windows run was performed.

## Accepted SESSION_SETUP final MIC

`SMB.Engine.Accept_Response` now guarantees that when a pending SESSION_SETUP
(command 1) is accepted with `STATUS_SUCCESS`, the recorded response data
area lies inside the packet, is at least 16 bytes long, and its last 16 bytes
equal `Mechanism_List_MIC (Current_Signing_Key (State), From_Server => True)`.
The ghost function `Final_Token_MIC_Matches` states this relation and the
ghost lemma `Lemma_Final_Token_MIC` packages it inside the body.
`Bounded_Slice` now also proves element equality with the selected packet
range, so the `Validate_Final_Token` postcondition transfers to the packet.
The runtime check order and comparison primitive are unchanged.

The unit suite adds a signed final SESSION_SETUP response for each of the 16
MIC byte positions with one flipped bit; each is rejected with
`Invalid_Protocol`, disconnects, clears the signing key and leaves no pending
request.

Focused proof of `smb-engine.adb` exited successfully with zero unproved
checks. Full proof: 5,064 checks (728 flow, 4,336 prover), zero unproved, no
`pragma Assume`. Unit, NTLM, crypto, strict build/dependency audit and Samba
integration tests passed. No CI or Windows run was performed.

## Completed authentication final MIC

`SMB.Core_Client.Complete_Authenticate` now proves that a successful
`STATUS_SUCCESS` completion leaves the Engine authenticated with response
metadata whose final 16 data bytes in the supplied `Packet` equal
`Mechanism_List_MIC (Current_Signing_Key, True)` (`Final_Token_MIC_Matches`).
`Mark_Authenticated` additionally guarantees that a successful transition
preserves `Current_Response_Info` and the server-direction mechanism-list MIC.
`Response_Receipt_Matches` moved to the private part as an expression
function so callers can relate the receipt command to the accepted request.
The ghost lemma `Lemma_Final_Token_MIC_Transfer` (null body) carries the MIC
fact across equal metadata and MIC values. Runtime checks are unchanged.

The public coordinator test now checks the accepted final response's MIC bytes
against an independently computed mechanism-list MIC after authentication. Full
proof: 5,082 checks (728 flow, 4,354 prover), zero unproved, no
`pragma Assume`. Unit, NTLM, crypto, strict build/source checks and local Samba
integration tests passed. No CI or Windows run was performed.

## Failed authentication completion cleanup

When `SMB.Core_Client.Complete_Authenticate` rejects a matching final
SESSION_SETUP exchange (bad signature or MIC, verification failure, or a signed
non-success NT status), its postcondition now also proves that the Engine has
no pending request, no validated response and an all-zero signing key, and that
the authentication challenge length is 0 with every challenge buffer byte 0.
Runtime behavior is unchanged; these facts follow from the existing
`Accept_Response`, `Invalidate` and `Clear_Authentication_Buffer`
contracts. The rejection tests (signature/MIC/status faults, every final MIC
byte position, unverified-response faults) now also check the validated-response
flag and public challenge length.

Full proof: 5,083 checks (728 flow, 4,355 prover), zero unproved, no
`pragma Assume`. Unit, NTLM, crypto, strict build/source checks and local Samba
integration tests passed. No CI or Windows run was performed.

## Successful authentication completion state

On success, `SMB.Core_Client.Complete_Authenticate` now also proves that no
validated response remains, that the retained response's session ID equals the
Engine session ID, and that the Engine session ID is unchanged by completion.
The positive coordinator test additionally checks no pending request, a non-zero
session ID and equality with the authentication's recorded session ID at run
time. A follow-up adds `not Has_Pending_Request (State)` to the success branch of
`SMB.Engine.Mark_Authenticated` and to `Complete_Authenticate`, so successful
completion is also proved to leave no pending request. Stating it inside the
success branch (rather than as a top-level pending-flag frame equality) keeps
the existing final-MIC transfer provable.

Full proof: 5,089 checks (728 flow, 4,361 prover), zero unproved, no
`pragma Assume`. Unit, NTLM, crypto, strict build/source checks and local Samba
integration tests passed. No CI or Windows run was performed.

## Reproduction

With GNATprove, GPRbuild, cvc5 and z3 on `PATH`:

```sh
PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make build
PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make test
PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make unicode-test
PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make check GPRBUILD="gprbuild -f"
PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH gnatprove -P proof.gpr --clean
PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make prove
PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH python3 tests/transport_integration.py
# Requires local Linux, Samba tools and root privileges:
sudo -n env PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH python3 tests/samba_integration.py
```

`make prove` analyzes the complete explicitly enumerated `proof.gpr` project:

```sh
gnatprove -P proof.gpr --mode=all --level=2 --report=all \
  --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

Generated proof/build files are ignored by Git. [assurance.md](assurance.md)
lists the proved scope and non-SPARK adapter inventory. A successful proof
covers the stated core contracts under their bounds and trust assumptions; it
does not prove the entire public facade, operating system, or cryptographic
security.

## Successful authentication abort clears retained token state

On success, `SMB.Core_Client.Abort_Authentication` now also proves that the
retained challenge length is zero and every byte of the authentication buffer
is zero, matching the failed-completion cleanup contract. The runtime body is
unchanged. The buffer contents are ghost-only, so that part is covered by proof;
a later runtime unit test checks the observable outcome. Full proof: 5,089 checks (728 flow,
4,361 prover), zero unproved.

## Complete authentication abort outcomes

`SMB.Core_Client.Abort_Authentication` now has a total postcondition: the
result is `Ok`, `Counter_Exhausted`, or `Invalid_State_Status` for a
foreign/inactive context, and no other status is possible. On `Ok` the owner
is preserved, the epoch advances by one and the session ID is zero. On
`Counter_Exhausted` (epoch already at `QWord'Last`) the abort still
disconnects the engine, clears key, pending and validated state, sets the
owner to zero and clears the retained token. Epoch exhaustion is covered by
proof only; reaching it at runtime would need 2**64 invalidations.
A unit test aborts after a received CHALLENGE and checks the observable
success outcome: failed stage, disconnected engine, no pending or validated
response, zero key, preserved owner, epoch plus one, session ID zero and
challenge length zero. Full proof:
5,090 checks (728 flow, 4,362 prover), zero unproved.

## Failed challenge completion cleanup

`SMB.Core_Client.Complete_Challenge` no longer ends its postcondition with
`else True`. Every outcome other than an accepted CHALLENGE or an unchanged
`Invalid_State_Status` rejection now proves that the context was a
matching `Negotiate_Sent` context and that the call left stage
`Authentication_Failed`, challenge length zero, every authentication buffer
byte zero, a disconnected engine, no pending or validated response, a zero
signing key and session ID zero. A unit test drives five rejected responses
(logon failure, unsigned SUCCESS, zero session ID, inflated token length,
mismatched message ID) through the public API and checks the observable part
of that cleanup; buffer bytes are ghost-only and are covered by proof. The
`Unsupported_Feature` result for an accepted SUCCESS is covered by proof only.
Full proof: 5,091 checks (728 flow, 4,363 prover), zero unproved.

## Failed AUTHENTICATE preparation cleanup

`SMB.Core_Client.Prepare_Authenticate` no longer ends its postcondition with
`else True`. Every outcome other than a prepared AUTHENTICATE request or an
unchanged `Invalid_State_Status` rejection now proves `Used = 0`, an
all-zero output buffer, a matching `Challenge_Received` starting context,
stage `Authentication_Failed`, challenge length zero, every authentication
buffer byte zero, a disconnected engine, no pending or validated response, a
zero signing key and session ID zero.

Proving the zero output exposed a gap: after the SESSION_SETUP body (including
the NTLM AUTHENTICATE token) had been written into the caller's buffer, the
failure paths for session-key installation, request reservation and header
preparation returned with that token still in the buffer. Those paths now
clear the output before failing. They are not reachable through ordinary public
inputs, so they are covered by proof; a unit test drives three reachable
failures (output too short, invalid password encoding, invalid user encoding)
with a pre-filled output buffer and checks the observable cleanup.
Full proof: 5,096 checks (728 flow, 4,368 prover), zero unproved.

## NEGOTIATE preparation and send acknowledgement outcomes

`SMB.Core_Client.Prepare_Negotiate` and
`SMB.Core_Client.Authentication_Send_Succeeded` now have total
postconditions, so every procedure of the authentication coordinator states
all of its outcomes.

`Prepare_Negotiate` has exactly three outcomes. `Ok` proves that the call
started from a ready coordinator and a negotiated engine with session ID 0,
no pending or validated response and no signing key, and that it leaves the
coordinator `Negotiate_Prepared` with the engine's owner and epoch, session
ID 0 and challenge length 0, and the engine negotiated with the same owner
and epoch, session ID 0, a pending request, no validated response and no
signing key, in addition to the existing packet predicate.
`Invalid_State_Status` caused by any of those starting conditions failing, or
by an output that cannot hold a header, proves `Used = 0`, an all-zero output
and an unchanged coordinator and engine (`State = State'Old`). Every other
outcome proves `Used = 0`, an all-zero output, that the starting conditions
held, stage `Authentication_Failed`, challenge length zero, every
authentication buffer byte zero, the other coordinator fields unchanged, and
an unchanged engine.

Proving the zero output exposed the same gap as AUTHENTICATE preparation:
when SESSION_SETUP body construction or request reservation failed, the
partly or fully built SESSION_SETUP body was left in the caller's buffer. The
NTLM NEGOTIATE token carries no secret, but the failure paths now clear the
output and the authentication buffer through `Fail_Negotiate_Preparation`.
Reverting only the reservation-failure path to its previous body (setting the
stage without clearing) makes a focused proof of `Prepare_Negotiate` report
`postcondition might fail, cannot prove Output (Index) = 0` for the failure
outcome. The unchanged-engine result relies on `Prepare_Unsigned_Header` now stating
its exact status (`Ok` exactly when the packet holds a header): the header
failure after reservation, which invalidated the engine, is proved
unreachable.

`Authentication_Send_Succeeded` returns `Ok` exactly when the coordinator's
owner and epoch match the engine, the engine's pending request matches the
coordinator's expectation, and the stage is `Negotiate_Prepared` or
`Authenticate_Prepared`. It then maps each prepared stage to its own sent
stage, keeps every other coordinator field, and still matches the pending
request. Otherwise it returns `Invalid_State_Status` with the coordinator
unchanged; no other status is possible.

GNAT 14.2 reports the body's `with SMB.Crypto;` as a redundant with clause
since the final-MIC change added the same clause to the specification, so a
forced strict build (`make check GPRBUILD="gprbuild -f"`) failed; the body
clause is removed.

New unit cases cover three `Invalid_State_Status` rejections (output shorter
than a header, transport-only engine, repeated preparation while a NEGOTIATE
is pending, which stays acknowledgeable), the reachable `Resource_Limit`
failure for an output that holds a header but not the request (zero output,
failed coordinator, engine unchanged and reusable by a fresh coordinator,
failed coordinator not reusable), and four rejected send acknowledgements
(nothing prepared, duplicate acknowledgement, foreign engine, stale epoch).
Failures after reservation are covered by proof only.

These checks ran natively on Windows 11 with Alire 2.1.1, `gnat_native`
14.2.1, `gprbuild` 25.0.1 and `gnatprove` 14.1.1. GNATprove must be started
from PowerShell or `cmd`; started from Git Bash (MSYS2), its prover
processes fail silently and every prover check is reported unproved. On
Windows, `make transport-test` fails on `main` as well, with
`STORAGE_ERROR : EXCEPTION_STACK_OVERFLOW` in `transport_client` (1 MiB stack
buffers against the 1 MB default Windows stack); the Samba integration test
needs Linux and was not run.
On this toolchain the unchanged `main` (#89) reproduces 5,096 checks (728
flow, 4,368 prover), zero unproved.
Full proof: 5,103 checks (729 flow, 4,374 prover), zero unproved, 0
`pragma Assume`, 13 units analyzed.

## Stack usage of frame-sized buffers

GNATprove does not cover `Storage_Error`, and the buffers involved are in the
trusted facade and transport. On Windows (gnat_native 14.2.1), executables that
use `Ada.Real_Time` were linked with a 2 MiB main-thread stack reserve (the
others with 32 MiB), and `transport_client` failed in `make transport-test`
with `EXCEPTION_STACK_OVERFLOW`: three 1-MiB-class arrays were on the stack at
once — the test's own frame, the `Receive_Frame` packet and, through runtime
evaluation of `Core_Transport.Receive_Chunk`'s `Buffer'Old` postcondition, a
copy of the whole receive buffer for every socket chunk.

The trusted layer now keeps runtime-sized buffers off the stack:

- `SMB.Transport.Send_Frame` builds the frame in a heap buffer and
  `Receive_Frame` reads into one, both freed on success and failure.
- `Read_Exact` receives into a fixed 64-KiB chunk and passes
  `Core_Transport.Receive_Chunk` only the window being filled, so the runtime
  `Buffer'Old` copy is at most 64 KiB. The proved contract applies unchanged to
  the window; bytes outside it are not passed.
- `SMB.Client.Read` and `Write` allocate the `Core_Client.Transfer` (up to
  1 MiB) and the read result buffer on the heap.

No SPARK unit changed. `tests/check_stack_usage.py` (`make stack-check`, also
run by `make check`) builds `smb.gpr` with `-fcallgraph-info=su` and sums the
largest static frame chain below each public `SMB.Client` subprogram; GNAT
runtime frames and the indirect entropy callback are not counted. It enforces
896 KiB per call (a 1 MiB thread stack with 128 KiB left over) and rejects
runtime-sized frames in `SMB.Client` and `SMB.Transport` except those sized by
host, path, name or exception-message strings. Current maxima: `Authenticate`
775,424 bytes, `List_Directory` 534,320, `Connect` 529,520, `Read` 425,552,
`Write` 425,376. Run against the unchanged `main`, the check fails on exactly
`Read`, `Write`, `Send_Frame`, `Receive_Frame` and `Read_Exact`.

Most of the static stack below the `Engine` calls is runtime postcondition
checking: building with `Assertion_Policy (Post => Ignore, Contract_Cases =>
Ignore)` as a configuration pragma measured `Connect` at 55,024 bytes and
`Read` at 88,096; `Authenticate` stays at 773,392 because of `Core_Auth` work
buffers. Postconditions stay enabled, as stated
in the assurance document. Remaining known runtime-sized stack use is in the
SPARK core: `Core_Wire.Verify_Signature` copies each signed response and
`Crypto.HMAC_SHA256` concatenates the key block with it, about 2N bytes for an
N-byte response, before the signature is known to be valid.

On Windows: `transport_integration.py` now passes, including the 1-MiB
`maximum-frame` echo; unit tests, forced strict builds of all three projects
(`-f -gnatwe`), `check_sources.py` and `make stack-check` pass. The Samba
integration test needs Linux and was not run. No proof was rerun because no
unit in `proof.gpr` changed.

## Incremental HMAC-SHA256 and copy-free signature verification

`SMB.Crypto.SHA256` padded a full copy of its input, `HMAC_SHA256` built
`ipad || message` on the stack, and `Core_Wire.Verify_Signature` copied each
response to zero its signature field. For an N-byte signed response this was
about 2N bytes of stack (plus an N-byte secondary-stack copy), with N chosen by
the peer before the signature is known to be valid.

SHA-256 now runs a 64-byte block compression over a context
(`SHA256_Start`/`Update`/`Finish` in the body); `SHA256` and `HMAC_SHA256`
keep their signatures and preconditions. The new public
`HMAC_SHA256_Start`/`Update`/`Finish` take the message in pieces. Their
contracts state that a started context is ready with length zero, that each
update adds exactly the piece length and requires the total to stay within
`Maximum_Frame_Size`, and that finishing requires a ready context and leaves it
not ready (the context, including the outer pad, is cleared).
`Verify_Signature` feeds bytes 0..47, sixteen zero bytes and the bytes after the
64-byte header to the incremental HMAC; no copy of the response is made. As
before, the digest functions have no functional contract: equality with the
standard algorithms is established by tests, not proof.

Proof found one issue in the first version: slicing from `Data'First + 64` for a
64-byte packet could overflow when `Data'Last = Natural'Last`; the trailing
piece is now passed only when the packet is longer than the header.
`SHA256_Compress` carries `Global => null` so that GNATprove analyzes it
separately instead of inlining a non-scalar declaration ahead of the caller's
loop invariant.

`make stack-check` now also requires `Verify_Signature`, `SHA256`,
`SHA256_Update`, `HMAC_SHA256` and `HMAC_SHA256_Update` to have fixed-size
frames; against the previous `main` it reports `Verify_Signature` and
`HMAC_SHA256` as packet-sized. The only runtime-sized frames reachable from
`Engine.Accept_Response` are now `Signing_Key_Material`, `Padded` and
`HMAC_MD5`, all used for the mechanism-list MIC over fixed short inputs.

Tests: the existing RFC 4231 and padding-boundary vectors, `make crypto-test`
(445 hash fixtures / 890 rebased cases, 1,832 HMAC fixtures / 7,328 rebased
cases against Python and OpenSSL) and `make signing-test` (3,135
signing/verification fixtures / 12,540 rebased cases) pass on the new code. A
new unit loop splits a 200-byte message at all 201 positions and checks that
the two-piece incremental HMAC equals `HMAC_SHA256` and that a finished context
is not ready.

Focused proofs: `smb-crypto.adb` 226 checks (55 flow, 171 prover) and
`smb-core_wire.adb` 361 checks (35 flow, 326 prover), zero unproved.
On Windows the forced strict builds, unit tests, `make stack-check`,
`transport_integration.py` and the unicode, NTLM, clock, crypto and signing
conformance tests pass; the Samba integration test needs Linux and was not run.
Full proof: 5,140 checks (746 flow, 4,394 prover), zero unproved, 0
`pragma Assume`, 13 units analyzed.

## Pre-state values without whole-state copies

With runtime contract checks enabled, GNAT makes one copy of the prefix for
every `'Old` occurrence. Postconditions wrote pre-state values as
`F (State'Old)`, so each occurrence copied the whole `Engine_State` (about
10 KB, mostly the 256-entry handle table): `Engine.Accept_Response` had 27
such occurrences and a 284,272-byte frame.

Postconditions in `SMB.Engine`, `SMB.Core_Connection` and `SMB.Core_Client`
now write these values as `F (State)'Old` (164 single-argument getters such as
`Current_Phase`, `Pending_Command` and `Next_Request_Id`, and 34 multi-argument
calls whose other arguments are literals, `in` parameters or pre-state values,
such as `Response_Receipt_Matches`, `Response_Header_Matches_Request`,
`Valid_Handle` and the snapshot context predicates). The meaning is unchanged:
the function is evaluated on the pre-state either way, but the runtime check
keeps only its result. None of the hoisted functions has a precondition.
`SMB.Engine` gains `pragma Unevaluated_Use_Of_Old (Allow)`, which
`Core_Connection` and `Core_Client` already use. `State = State'Old`, two-state
relations such as `Handle_Table_Equivalent (State'Old, State)`, and four calls
whose other arguments are post-state values still copy the state.

The first full proof left three checks unproved at level 2 (they proved at
level 4 with a 300-second timeout): the lemma call and final MIC assertion in
`Complete_Authenticate` (`smb-core_client.adb:635`, `:652`) and the name-length
assertion in `Next_Directory_Entry` (`:1624`). Function-call `'Old` prefixes
are evaluated at entry, which adds their definitions to every verification
condition of the body. Keeping the original `State'Old` form for the
`Pending_Request_Matches` prefix of `Complete_Authenticate` and the
`Directory_Snapshot_Context_Matches` prefix of `Next_Directory_Entry` made all
three prove with the project settings; neither procedure is on a worst-case
stack path.

In the facade, the authentication coordinator and request buffer, the
directory enumeration and name buffer, the READ/WRITE request packet and the
UTF-16 name buffer of `Encode_Name` moved to the heap; the authentication
request buffer is zeroed before it is freed, and every buffer is freed on both
success and failure. `List_Directory` built its result array on the primary
stack with one element per server-supplied entry (up to 100,000); it now uses
an extended return, which GNAT places on the secondary stack, and its frame is
no longer runtime-sized, so it was removed from the allowed list.
`Read_Exact` reads 16-KiB chunks instead of 64 KiB. The heap buffers are
allocated after `begin`, not in declarations, so a failed later allocation
reaches the exception handler that frees the earlier ones. On the GNAT 14.2
Windows runtime, a task with a 256-KiB stack returned a 100,000-entry listing
(about 3.2 MB) through the secondary stack, while the previous form, a local
result array on the primary stack, raised an exception in the same task.

Static stack per public call, before and after: `Read` 425,568 -> 45,712,
`Write` 425,392 -> 45,552, `Open_File` 359,984 -> 45,712, `Close` 359,600 ->
45,328, `List_Directory` 534,336 -> 57,904, `Connect` 529,536 -> 111,648,
`Connect_Share` 529,312 -> 188,144, `Remove_File` 416,992 -> 146,304,
`Rename` 417,504 -> 146,880, `Authenticate` 775,424 -> 644,256. The remaining
`Authenticate` stack is mostly `Core_Auth.Build_Type3` (374,384 bytes), which
copies the NTLM AUTHENTICATE message through several 64-KiB buffers while
wrapping it in SPNEGO. `make stack-check` now enforces 256 KiB per call, with
704 KiB allowed for `Authenticate` until those buffers are reduced; against the
previous `main` it fails for every public call.

On Windows the forced strict builds, unit tests, `make stack-check`,
`transport_integration.py` and the unicode, NTLM, clock, crypto and signing
conformance tests pass; the Samba integration test needs Linux and was not run.
Full proof: 5,140 checks (746 flow, 4,394 prover), zero unproved, 0
`pragma Assume`, 13 units analyzed.

## NTLM authentication without challenge-sized stack copies

`Authenticate` was the one public call over 256 KiB (644,160 bytes static),
and its `Core_Auth` frames also grew with the server's challenge: building the
NTLM AUTHENTICATE token copied the message through four 64-KiB SPNEGO
buffers, `Build_Type3` held runtime-sized `Blob`, `Challenge_Blob`,
`NT_Response` and `Auth_Material` (Type1, Type2 and Type3 concatenated for the
MIC, up to about 128 KiB) arrays, `HMAC_MD5` concatenated its key block with
the message, and `Authenticate` and `Process_Target_Info` each decoded names
into a 128-KiB UTF-8 buffer only to reject NUL characters.

- `SMB.Crypto` gains incremental MD5 (64-byte block compression over a
  context, like SHA-256 in #94) and a public `HMAC_MD5_Start`/`Update`/`Finish`
  with the same length and readiness contracts as HMAC-SHA256. `MD5` and
  `HMAC_MD5` keep their signatures and use the context, so neither copies its
  input.
- `Build_Type3` feeds the user and domain names to the response-key HMAC
  separately, writes the NTLMv2 blob directly where the NT response lives in
  the Type3 buffer and computes the proof over the challenge and that region,
  records the NT response with a new `Reserve_Field` (Put_Field without the
  copy), and computes the MIC over Type1, Type2 and Type3 incrementally.
- The SPNEGO `NegTokenResp` is written straight into `Output` once its total
  length is known to fit, using `DER_Header_Size` and a `Put_Header` with a
  position contract; nothing is written when it does not fit. Its contract
  now requires an all-zero `Output` (which `Authenticate` establishes) and
  ensures a zero tail, instead of comparing the tail with `Output'Old`, which
  copied the whole output at run time.
- Target names and AV-pair names are checked with `Core_Text.Validate_UTF16`,
  whose contract accepts exactly valid UTF-16 without NUL code units, the same
  acceptance as decoding to UTF-8 and rejecting NUL. A 65,535-byte target name
  (odd, so previously rejected) is rejected before the call because of its
  65,534-byte precondition.
- The Type2 handling moved into `Authenticate_Challenge`, which takes the
  challenge slice as a parameter: SPARK rejects renaming a slice whose bounds
  depend on variables, and the previous constant copied it.

Proof found a missing bound: the nested `Put_Header` is analyzed with its own
precondition only, so it now states that `Output` is at most
`Maximum_Security_Token` bytes.

The generated token is unchanged: the unit test that compares a full Type3
token with a known value, `make ntlm-test` (211 AV and 5,896 challenge-field
fixtures, core/public agreement), `make crypto-test` (including MD5 and
HMAC-MD5 against Python and OpenSSL and 774 mechanism-list MIC fixtures) and
`make signing-test` pass.

Static stack: `Authenticate` 644,160 -> 234,944 bytes (`Build_Type3`
374,384-byte runtime-sized frame -> 95,424 bytes fixed, `Core_Auth.Authenticate`
197,504 -> 66,416). The only runtime-sized frame left in `Core_Auth` and
`SMB.Crypto` is `Padded`, used by MD4 on the password. `make stack-check`
drops the `Authenticate` exception, so every public call must fit 256 KiB, and
additionally requires `MD5`, `MD5_Update`, `HMAC_MD5`, `HMAC_MD5_Update` and
`Core_Auth.Authenticate`, `Process_Target_Info` and `Build_Type3` to stay
fixed-size; against the previous `main` it reports `Authenticate` over budget
and those `Core_Auth` and `HMAC_MD5` frames as runtime-sized.

Focused proofs: `smb-crypto.adb` 255 checks and `smb-core_auth.adb` 475
checks, zero unproved. On Windows the forced strict builds, unit tests,
`make stack-check`, `transport_integration.py` and the unicode, NTLM, clock,
crypto and signing conformance tests pass; the Samba integration test needs
Linux and was not run.
Full proof: 5,191 checks (754 flow, 4,437 prover), zero unproved, 0
`pragma Assume`, 13 units analyzed.

## Heap buffers freed by owners

The heap buffers and coordinators introduced to keep frames off the stack
(`Transfer`, `Authentication`, `Directory_Enumeration`, request, name, frame
and packet buffers in `SMB.Client` and `SMB.Transport`) were freed by explicit
`Unchecked_Deallocation` calls on the normal path and in each exception
handler; a missed path leaked the buffer (one such leak was found in review
earlier). They are now held by owners from the new private generic
`SMB.Heap_Owner`, a limited controlled type whose `Finalize` frees the object
whenever the subprogram is left, also when an exception propagates.
Authentication requests, which carry the NTLM token, are erased before they are
freed, as before. `Read` and `List_Directory` still release their transfer and
enumeration buffers before building the result, so peak heap use is unchanged.

A unit test instantiates the owner with an access type on a counting storage
pool and checks that the object is cleared and freed on normal exit, on an
exception, after an early `Release` (and not freed twice), and that an empty
owner does nothing; with `Finalize` disabled the test fails.

No SPARK unit changed, so the proof is unaffected. Static stack: `Authenticate`
234,976 bytes (+32), `List_Directory` 57,920 (+16), `Write` 45,520 (+48), the
rest unchanged. On Windows the strict builds, unit tests, `make stack-check`,
`transport_integration.py` and the conformance tests pass.

## AES-128 encryption (`SMB.AES`)

`SMB.AES` adds AES-128 key expansion and the encryption direction (FIPS 197)
for the SMB 3.1.1 work; nothing in the library calls it yet. The S-box is
computed on bit planes rather than looked up. A `Key_Schedule` is `Ready` only
after `Expand_Key`, and `Encrypt` requires it, so a schedule left at its zero
default cannot be used.

The first attempt at a proof did not finish: GNATprove inlined every local
helper without a contract into its callers, and with the nested calls in the
GF(2^8) inversion `gnatwhy3` grew to about 50 GB. Each helper now carries
`Post => True`, so it is proved once on its own and its callers see only the
contract. The proof target is the absence of run-time errors and the `Ready`
contracts; functional correctness comes from the tests.

```sh
gnatprove -P proof.gpr -u smb-aes.adb --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

GNATprove 14.1.1 on macOS reported **66 checks** (19 flow, 47 prover), zero
unproved or justified, zero warnings, zero `pragma Assume`, in about 35
seconds with a peak of 1.2 GB. `test_suite` checks FIPS 197 appendices B and
C.1 and a 1,000-step chain; `aes_conformance.py` compares 1,287 cases with
Python's `cryptography`, with three sensitivity checks. A changed-line
AdaMutant run left no surviving mutant. Static stack use of the public calls
is unchanged, since nothing calls the unit.

## AES-128-CMAC (`SMB.AES.CMAC`)

`SMB.AES.CMAC`, a child of `SMB.AES`, adds AES-128-CMAC (RFC 4493,
SP 800-38B), the SMB 3.1.1 signing MAC: a one-shot `MAC` and an incremental
`MAC_Context` with `Start`, `Update` and `Finish`, shaped like
`SMB.Crypto`'s incremental HMAC-SHA256 so that a frame can be fed as its
header, a zero signature and the rest without a copy. Nothing in the library
calls it yet.

`Ready` states the buffering rule as well as the expanded key and the length
bound: `(Used = 0) = (Total = 0)`, so a nonempty message always leaves its
last 1 to 16 bytes buffered and `Finish` applies K1 or the padding and K2 to
the true last block. `Finish` ends with the context `Wiped` (every component
at its default) and not `Ready`. The subkey doubling scales 16#87# by the
carried bit instead of branching on it; that is a coding rule, not a proved
property. Every local helper carries a contract, as in `SMB.AES`, and the
unit sees `Expand_Key` and `Encrypt` only through their contracts.

```sh
gnatprove -P proof.gpr -u smb-aes-cmac.adb --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

GNATprove 14.1.1 on macOS reported **43 checks** (15 flow, 28 prover), zero
unproved or justified, zero warnings, zero `pragma Assume`, in about 5
seconds. `Start` expands the key straight into the context, so it keeps no
copy of the schedule in a local of its own; nothing but `Finish` wipes. `test_suite` checks RFC 4493 examples 1 to 4, NIST's 20-byte
example, L and K1, padding look-alikes, every split point of each example,
restarted and reused contexts, and a chain over every length from 0 to 300.
`cmac_conformance.py` compares 1,073 fixtures with Python's `cryptography`,
each one-shot at four lower bounds (0, 7, one ending just below
`Natural'Last` and one ending at it) and in incremental pieces at the first
three, with five sensitivity checks. Deepest static call chains on macOS
arm64 in the default build, counting the `-gnata` wrapper frames: `MAC`
1,488 bytes, `Update` 1,184, `Start` 1,168, `Finish` 1,152. `MAC` and
`Update` must keep static frames in the stack check. A changed-line
AdaMutant run left no surviving mutant and marks none. A 64 KiB message
takes about 58 ms in the default unoptimized build and 20 ms at `-O2`,
bounded by the AES block function.

## SMB 3.1.1 key derivation (`SMB.KDF`)

`SMB.KDF.Derive (Session_Key, Purpose, Preauth_Hash)` is the SMB 3.1.1 key
derivation (MS-SMB2 3.1.4.2): SP 800-108 in counter mode with HMAC-SHA256,
one block, `HMAC-SHA256 (Session_Key, 00000001 || Label || 00 || Preauth_Hash
|| 00000080)` truncated to 16 bytes. `Purpose` (`Signing`, `Encryption`,
`Decryption`) selects one of the three NUL-terminated labels the client needs,
which only the body holds, and the 16-, 64- and 16-byte lengths are fixed by
the parameter and result subtypes, so the function has no precondition. The
parts are fed to `SMB.Crypto`'s incremental HMAC-SHA256 without assembling a
copy. Nothing in the library calls it yet.

```sh
gnatprove -P proof.gpr -u smb-kdf.adb --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4
```

GNATprove 14.1.1 on macOS reported **13 checks** (3 flow, 10 prover), zero
unproved or justified, zero `pragma Assume`, in about 5 seconds, and one flow
warning of a kind the full proof already reports in other units: the HMAC
context is set by `HMAC_SHA256_Finish` (which wipes it) and not used after.
`test_suite` checks the twelve 3.1.1 keys published in Microsoft's worked
examples (the anatomy, pre-authentication integrity and encryption blog
posts). `kdf_conformance.py` compares 330 fixtures with Python's
`cryptography` `KBKDFHMAC`, after checking that it reproduces the published
keys, with 27 sensitivity checks, including each of the twelve published keys
under the other two labels. A changed-line AdaMutant run detected all 64
mutants and marks none.

## GNATprove 16.1.0

The proof moves from gnatprove 14.1.1 (with GNAT 14.2.1 and gprbuild 25.0.1)
to gnatprove 16.1.0 with GNAT 16.1.0 and gprbuild 26.0.1, which CI has used
for builds, tests and mutation runs since #116. With the same settings,
16.1.0 left 12 of 5,272 checks unproved, also at `--level=3` with a
300-second timeout. Each site now has proof hints. No contract is weakened,
and no `pragma Assume` or justification is added:

* `smb-core_wire.adb`: `Write_U64`'s `Encoded_U64 (Data, Offset) = Value`
  needs a 64-bit value rebuilt from its eight bytes, which the ghost lemma
  `Lemma_U64_Bytes` states and proves on its own.
* `smb-core_text.adb`: in UTF-8 to UTF-16 emission, `Lemma_Slice_Units` and
  `Lemma_Emitted_Scalar` restate the units just written through the slice's
  rebased indices and show that they decode to the emitted scalar.
* `smb-core_protocol.adb`: `Build_Write` cuts the context with
  `pragma Assert_And_Cut` before the data copy. It no longer writes the zero
  Flags field (bytes 44 to 47), which `Begin_Build` already cleared; that
  write was annotated as an equivalent mutant. `Build_Rename` states the
  name slice's upper bound the way its postcondition counts it.
* `smb-core_connection.adb`: `Prepare_Negotiate` keeps a ghost snapshot of
  its inputs, cuts the success and failure paths separately, and places the
  client GUID with `Lemma_Guid_Place`.
* `smb-engine.adb` and `smb-engine.ads`: `Lemma_Token_Tail` states the final
  MIC suffix element by element, and `Final_Token_MIC_Matches` is marked
  `Inline_For_Proof`.
* `smb-core_client.adb`: `Prepare_Metadata`'s postcondition joins the whole
  Engine state with the packet bytes. The new `Seal_Request`, nested in
  it, does the header preparation and signing behind a contract that names
  only the header fields, the unchanged body and the name. A cut before it
  keeps only the facts the rest needs, and `Lemma_Slice_Equals` turns the
  element-wise name copy into the slice equality of the postcondition. z3
  and cvc5 time out on a few of these checks and alt-ergo proves them, so
  `make prove` now runs `--prover=cvc5,z3,altergo`.

The library is built with `-gnata`, so ghost code runs. `Prepare_Negotiate`'s
ghost copy of the Engine state on entry (about 10 KB, as in
`Prepare_Tree_Connect`) raises the worst-case static stack of
`SMB.Client.Connect` by about 11 KB to 122,400 bytes. That is still below
`Connect_Share`'s 187,920 and the 262,144-byte budget. `Prepare_Metadata`
ignores `Seal_Request`'s postcondition at run time
(`pragma Assertion_Policy (Post => Ignore)`), so its `Output'Old` does not
keep a second copy of the packet while `Prepare_Header` and `Sign_Packet`
make theirs.

```sh
make prove
# gnatprove -P proof.gpr --mode=all --level=2 --proof=progressive --report=all --checks-as-errors=on --prover=cvc5,z3,altergo -j4
```

The prover timeout moved from the command line to `proof.gpr`: 120 seconds,
and 300 for `smb-core_protocol.adb` and `smb-core_client.adb`. Those two
hold the only checks that take 40 seconds or more in one prover attempt on
the Mac: 60 seconds for `Build_Rename`'s postcondition and 83 for one
`core_client` check. A timeout given on the command line overrides
`proof.gpr`, so a per-unit command with `--timeout=120` can still fail on
them.

`smb-core_text.adb` had three more, all in `UTF8_To_UTF16`: the loop
invariant, the `Lemma_Valid_UTF16_Prefix` call after the loop and an
assertion in the loop (55, 83 and 76 seconds on the Mac). The first
`proof.yml` run left the first two unproved at 120 seconds after 81
minutes, and a second run at 300 seconds still left the lemma call. The
loop was proved from the inlined byte stores of `Store_Unit`, and the check
after a while loop also sees the last iteration's body. `Store_Unit` now
has a contract. Its postcondition says that the units before the new one
keep their values, and that a valid unit stays valid unless it is a high
surrogate whose low half was overwritten. The unit now proves in 71
seconds on the Mac, no attempt takes over 16 seconds, and it is back to the
120-second default. The postcondition is ignored at run time
(`pragma Assertion_Policy (Post => Ignore)`), so `Output'Old` costs
nothing; AdaMutant does not mutate contracts, so the change adds no
mutants. Two other changes were tried and dropped. Stating the prefix
property as an assertion at the end of the loop body took 138 seconds on
its own, and would scan the prefix for every unit at run time. Moving the
exit test after the invariants made the invariant take 234 seconds. With
the contract, the third `proof.yml` run proved every check in 50 minutes.

GNATprove 16.1.0 on an Apple M4 Mac mini with 16 GB of RAM reported
**5,494 checks** (799 flow, 4,695 prover, most of them by z3), zero
unproved or justified, zero `pragma Assume`, and 16 units. The run took 84
minutes with builds and tests running alongside; one on its own, before the
`Store_Unit` contract, took about 67. The prover processes together peaked
near 9.6 GB.
None of the 81 warnings is on a changed line. `make check` (with
`GPRBUILD="gprbuild -f"`) and `make test` passed with the new toolchain. A
changed-line AdaMutant run detected all 4 mutants (three statement deletions
and an equality operator in `smb-core_client.adb`) and marks none; the other
changed lines are contracts, assertions and ghost code, which AdaMutant does
not mutate.

## AES-128-CCM (`SMB.AES.CCM`)

`SMB.AES.CCM` adds AES-128-CCM (NIST SP 800-38C, RFC 3610) with SMB's
parameters (MS-SMB2 3.1.4.3): an 11-byte nonce, so a four-byte length field,
and a 16-byte tag. `Seal` and `Open` work on `Data` in place; associated
data may be up to 65,279 bytes and data up to `Maximum_Frame_Size`. `Open`
compares the recomputed tag with `SMB.Crypto.Constant_Time_Equal` and, on a
mismatch, zeroes `Data`, which its postcondition states:
`(if not Authentic then (for all I in Data'Range => Data (I) = 0))`. The
counter and the length field depend only on lengths; that is a coding rule,
not a proved property. Nothing in the library calls the package yet.

```sh
gnatprove -P proof.gpr -u smb-aes-ccm.adb --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3,altergo --timeout=120 -j4
```

GNATprove 16.1.0 on macOS reported **70 checks** (15 flow, 55 prover, all
by z3 or trivially), zero unproved or justified, zero `pragma Assume`, in
about 10 seconds. `test_suite` seals and opens the four AES-CCM messages of
Microsoft's SMB 3.1.1 encryption examples (appendix A.2), each also at
bounds that end at `Natural'Last`, and checks that `Open` rejects a
one-bit change in every byte of the tag and of the associated data, three
changed ciphertext bytes, another nonce and a truncated message, leaving
only zeros. SMB always passes associated data and a nonempty message, so
three messages generated with Python's `AESCCM` (no associated data, no
data, neither) cover B0 without the Adata flag and empty data: 226 checks
in all, 215 of them rejections. `ccm_conformance.py` compares 487 fixtures with Python's
`cryptography` `AESCCM`, after checking that it reproduces the four
published messages; `crypto_probe` seals and opens each at four lower
bounds of the data, with the associated data at two, and checks the
rejection of a changed tag and ciphertext. Six sensitivity checks change
the key, the nonce, the associated data, the plaintext, the ciphertext or
the tag of a published message.

A changed-line AdaMutant run detected all 113 mutants and marks none. The
first run left seven: the redundant top byte and `mod` of the four-byte
encoding, the zero initializer that every byte then overwrote, and an
Adata flag of `16#41#`, which `16#3B# or` absorbs. `Nonce_Block` is now one
aggregate with a precondition that bounds the value, and B0's two flags
bytes are separate constants. `Seal` and `Open` are on the stack check's
list of static frames; their deepest static chains are 1,840 and 2,064
bytes, down through `Absorb_AAD` into AES's S-box. Sealing 64 KiB takes
about 109 ms in the default unoptimized build and 37 ms at `-O2`, twice
AES-CMAC's time: two AES blocks per 16 bytes.

## AES-128-GCM (`SMB.AES.GCM`)

`SMB.AES.GCM` adds AES-128-GCM (NIST SP 800-38D) with SMB 3.1.1's parameters
(MS-SMB2 3.1.4.3): a 12-byte nonce and a 16-byte tag. `Seal` and `Open` have
`SMB.AES.CCM`'s shape: `Data` in place, and `Open` compares tags with
`SMB.Crypto.Constant_Time_Equal` and zeroes `Data` on a mismatch, which its
postcondition states. Associated data and data may each be up to
`Maximum_Frame_Size`. GHASH multiplies in GF(2^128) bit by bit on two 64-bit
words (algorithm 1 of the standard); adding a term and reducing by R use
masks made from a bit. That no branch or table index depends on the key,
the data or the tag is a coding rule, not a proved property. Nothing in the
library calls the package yet.

```sh
gnatprove -P proof.gpr -u smb-aes-gcm.adb --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3,altergo -j4
```

GNATprove 16.1.0 on macOS reported **126 checks** (23 flow, 103 prover, all
by z3 or trivially), zero unproved or justified, zero `pragma Assume`, in
about 10 seconds. The first version filled `To_Block` in a loop, which flow
analysis could not see as complete. A zero initializer would have been an
equivalent mutant, so `To_Block` and `To_Element` are now expressions that
name every byte.

`test_suite` seals and opens the four AES-GCM messages of Microsoft's SMB
3.1.1 encryption examples (appendix A.1), each also at bounds that end at
`Natural'Last`, with the same rejection checks as CCM: a one-bit change in
every byte of the tag and of the associated data, three changed ciphertext
bytes, another nonce and a truncated message, each leaving only zeros. Test
cases 1 to 4 of McGrew and Viega's GCM paper (empty data, no associated
data, a partial last block with associated data) and one message with
associated data only, generated with Python's `AESGCM`, cover the cases SMB
does not produce: 230 checks in all. `gcm_conformance.py` compares 681
fixtures with `cryptography`'s `AESGCM`, after checking that it reproduces
the four published messages. They cover every data length up to five
blocks and the lengths around larger block boundaries, the counter carries
up to the frame limit, the bit-length carries at 32 and 8,192 bytes,
associated data of every length up to three blocks and up to the frame
limit, single-bit changes at both ends of each GHASH word, and seeded random
messages. `crypto_probe`'s CCM check is now the generic `Check_AEAD`, with a
CCM and a GCM instance, so both ciphers get the same four lower bounds and
rejection checks; CCM's 487 fixtures still pass through it.

An AdaMutant run on `smb-aes-gcm.adb` detected all 188 mutants (three more
did not compile) and marks none. `Seal` and `Open` are on the stack check's
list of static frames; their deepest static chains are 1,632 and 1,856
bytes. Sealing 64 KiB takes about 56 ms in the default unoptimized build
and 18 ms at `-O2`, half of CCM's time: one AES block per 16 bytes, plus a
128-step multiplication.

## SMB 3.1.1 negotiate contexts (`SMB.Core_Negotiate`)

`SMB.Core_Negotiate` builds the SMB 3.1.1 NEGOTIATE request body with its
preauth integrity context (SHA-512 and a 32-byte salt) and encryption
context (AES-128-GCM, then AES-128-CCM), and checks the negotiate contexts
of a response that selected 3.1.1 (MS-SMB2 2.2.3, 2.2.4 and 3.2.5.2, with
the rules of `docs/smb3-design.md`). `Check_Response_Contexts`'s
postcondition names the four statuses it returns and gives `No_Cipher`
whenever the status is not `Ok`. `Request` is completed in the private
part of the spec, so callers' proofs see every byte. Nothing in the library
calls the package yet.

```sh
gnatprove -P proof.gpr -u smb-core_negotiate.adb --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3,altergo -j4
```

GNATprove 16.1.0 on macOS reported **72 checks** (10 flow, 62 prover),
zero unproved or justified, zero `pragma Assume`, in about 10 seconds.

`test_suite` builds the request with the GUID and salt of the A.1 example
in Microsoft's SMB 3.1.1 encryption blog, with and without 2.1, and checks
every byte, and that the two contexts equal the A.1 request's. The A.1 and
A.2 NEGOTIATE responses, which reproduce the blog's preauth integrity
hashes, select GCM and CCM. Forty-one more, built from A.1's response,
cover each rule. Contexts in either order, an empty salt, longer preauth
data, ignored kinds, an empty last context, contexts right after the fixed
body and A.1 at index 1,000 pass. Duplicate preauth and encryption
contexts, a missing preauth context, hash counts of 0 and 2, another hash,
an oversized salt, short contexts, cipher counts of 0 and 2, cipher 3, a
compression, transport, RDMA or signing context, and no contexts fail as
protocol errors. A short packet, a context or header past the end, a count
above 2**8 and offsets that are misaligned, inside the fixed body, at or
past the end, above 2**16 or above `Natural'Last` fail as length or offset
errors.

An AdaMutant run on `smb-core_negotiate.adb` detected all 132 mutants (one
more did not compile) and marks none. AdaMutant mutates bodies only, so
`Request`, in the spec, is covered by the byte-for-byte test instead. The
first run, with `Request` still in the body, left twenty: the upper
bytes of a four-byte encoder whose values are all below 2**16, a length
check that only a 128-byte packet tells apart, and a bound the loop
checked again. The request now writes those fields as two bytes and two
zeros, bounds are additions, the loop checks only the positions it
advances to, and the offset tests past the end use a packet whose length
is a multiple of 8, so the alignment check does not reject them first.

## SMB 3.1.1 preauth integrity hash (`SMB.Core_Preauth`)

`SMB.Core_Preauth.Update` replaces a 64-byte hash value with SHA-512 of
that value followed by a message, the preauth integrity step of MS-SMB2
3.2.5.2 and 3.2.5.3.1. Nothing in the library calls it yet.

```sh
gnatprove -P proof.gpr -u smb-core_preauth.adb --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3,altergo -j4
```

GNATprove 16.1.0 reported **4 checks** (1 flow, 3 prover), zero unproved,
and one warning: `Context` is set by `SHA512_Finish` but not used after the
call, as for the HMAC contexts elsewhere. `test_suite` replays the five
hashed messages of Microsoft's A.1 and A.2 examples, checks each value
against Python's `hashlib`, and derives both sessions' three keys with
`SMB.KDF` from the final value: all six are the published keys. An empty
message is checked too: 17 checks. AdaMutant detected all 4 mutants.

## AES-CMAC message signing (`SMB.Core_Wire`)

`SMB.Core_Wire` gains `Sign_CMAC` and `Verify_Signature_CMAC`, the SMB 3.1.1
signature (MS-SMB2 3.1.4.1): the AES-128-CMAC tag of the whole message
with its Signature field zeroed. Their contracts are those of `Sign` and
`Verify_Signature`, except that the key is an `SMB.AES.Key_128`. Nothing in
the library calls them yet, and the existing procedures are unchanged.

```sh
gnatprove -P proof.gpr -u smb-core_wire.adb --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3,altergo -j4
```

GNATprove 16.1.0 proved all **415 checks** of `smb-core_wire.adb` (37 flow,
378 prover). The first version passed the empty rest of a bare header to
the incremental CMAC as `Data (Data'First + 64 .. Data'Last)`, whose lower
bound overflows when the header ends at `Natural'Last`; GNATprove reported
the overflow, and the empty rest is now skipped as `Verify_Signature`
skips it.

`test_suite` verifies the final SESSION_SETUP responses of Microsoft's A.1
and A.2 examples with each session's derived signing key, re-signs them
from a garbled Signature field, rejects one-bit changes at seven positions,
another key and verification as HMAC, rejects a message shorter than a
header, and signs and verifies a bare header that ends at `Natural'Last`:
26 checks. `make signing-test` adds AES-128-CMAC fixtures compared with
Python's `cryptography`: two keys over the lengths up to 129 bytes and
around CMAC's block boundaries, 64 KiB and the frame limit, and one-bit
changes in a message and its key. With the HMAC fixtures that makes 3,990
fixtures, each at two lower bounds of the key and of the data, and six
sensitivity checks. A changed-line AdaMutant run detected all 43 mutants.

## SMB 3.1.1 in the engine

The library now negotiates SMB 3.1.1 by default and signs with AES-128-CMAC
under the key derived from the preauth integrity hash (MS-SMB2 3.2.5.2,
3.2.5.3 and 3.1.4.1); `SMB.Client.Connect` offers 2.1 too only with
`Dialects => SMB_311_Or_21`. `SMB.Core_Negotiate`, `SMB.Core_Preauth`,
`SMB.KDF` and the CMAC procedures of `SMB.Core_Wire` are now called from the
library; the AES-CCM and AES-GCM ciphers still are not.

* `Core_Protocol.Parse_Response` accepts a NEGOTIATE response for 2.1 or
  3.1.1 and returns the dialect; the SMB 3 capability bits are rejected only
  with 2.1. `Engine.Accept_Response` passes the dialect fact on.
* `Engine.Mark_Negotiated` records the dialect, the cipher (only with
  3.1.1) and the connection's preauth hash, and clears any SMB 3 key.
  `Derive_SMB3_Signing_Key` succeeds only on 3.1.1 with a session key and
  no SMB 3 key yet; its postcondition states the key,
  `SMB.KDF.Derive (Current_Signing_Key, Signing, Preauth)`, and lists every
  other accessor as unchanged. With 3.1.1 a signed response must carry a
  valid CMAC under that key, or it fails as `Signature_Error` and the
  engine is invalidated.
* `Core_Connection.Prepare_Negotiate` sends `SMB.Core_Negotiate.Request`
  and starts the preauth hash with it. `Complete` checks a 3.1.1
  response's negotiate contexts, extends the hash with the response, and
  fails a 2.1 response that was not offered with `Unsupported_Feature`. Its
  postcondition proves that the dialect after a successful NEGOTIATE is
  3.1.1, or 2.1 only when 2.1 was offered.
* `Core_Client` extends the hash with the first SESSION_SETUP request, the
  challenge response and the final request, then derives the key. Every
  request is signed with HMAC-SHA256 or AES-CMAC according to the dialect.

Two checks in `smb-core_connection.adb` were left unproved by the first
run. `Prepare`'s precondition on the NEGOTIATE body timed out: the provers
had to index into the 30-piece concatenation of `Core_Negotiate.Request`.
`Request` now has a postcondition with the fixed fields byte by byte,
proved once in `smb-core_negotiate.adb`. `Complete`'s postcondition could
not show that a dialect other than 3.1.1 is 2.1, because nothing said the
Engine's response information held one of the two; `Accept_Response`'s
postcondition now says so for a successful NEGOTIATE, as it already did for
the I/O limits.

```sh
gnatprove -P proof.gpr -u <unit> --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3,altergo -j4
```

GNATprove 16.1.0 on the Mac, one unit at a time with the `proof.gpr`
timeouts, proved every check, with no `pragma Assume` or justification:

| Unit | Checks | Time |
| --- | ---: | ---: |
| `smb-core_negotiate.adb` | 73 | 25 s |
| `smb-core_protocol.adb` | 912 | 14 min |
| `smb-engine.adb` | 282 | 5 min |
| `smb-core_connection.adb` | 479 | 8 min |
| `smb-core_client.adb` | 1,486 | 42 min |

`test_suite` adds:

* the parse of NEGOTIATE responses for every dialect: 2.1 and 3.1.1 are
  accepted, 2.0.2, 3.0, 3.0.2 and the neighbours of 2.1 and 3.1.1 are
  `Unsupported_Feature`, and SMB 3
  capability bits are accepted with 3.1.1 and rejected with 2.1;
* six NEGOTIATE exchanges through `Core_Connection`: the A.1 and A.2
  responses of Microsoft's SMB 3.1.1 encryption blog with 3.1.1 alone and
  with 2.1 allowed (GCM and CCM, and the blog's preauth hash after the
  request and response), 2.1 when it was offered, 2.1 when it was not
  (`Unsupported_Feature`), and 3.1.1 responses without contexts or with a
  signing context (`Invalid_Protocol`);
* a 3.1.1 authentication through `Core_Client`, whose derived key equals
  `SMB.KDF` over an independently computed hash of the three SESSION_SETUP
  messages; the final response signed with that key's CMAC is accepted,
  and one signed with HMAC is rejected as `Signature_Error` and
  disconnects;
* 17 checks on 3.1.1 after authentication. TREE_CONNECT, CREATE and
  CLOSE requests carry the CMAC of the derived key, not the HMAC of the
  session key. Derivation is refused on 2.1, without a session key and a
  second time, and 2.1 records no cipher. A signed response before the
  derivation fails even with the CMAC of the all-zero key the engine
  holds, an HMAC-signed CLOSE response fails, and both report no
  NTSTATUS and clear the dialect, cipher, preauth hash and 3.1.1 key.

The Samba integration test now runs twice. The first run is the SMB 2.1
test as before, since its proxies re-sign responses with SMB 2.1 HMAC.
The second limits Samba to SMB3_11 with signing required and runs
`integration_client` with `Dialects => SMB_311_Only`, which checks that
`Negotiated_Dialect` is 3.1.1. Both passed on GitHub Actions (Ubuntu
24.04's Samba): Samba accepted the CMAC-signed requests, so it derived the
same key from the same preauth hash, and the client verified Samba's
signed responses, the final SESSION_SETUP response included.

The review before merging found that drawing the salt as a second entropy
request moved the integration tests' injected failure, meant for the
authentication nonce, onto the salt. `Connect` now draws the GUID and the
salt in one 48-byte request.

`make check`, `make test`, and the CMAC, CCM, GCM, KDF, signing, crypto,
AES, NTLM, Unicode, clock and transport tests passed. The stack check
passed: `SMB.Client.Connect` is now 124,032 bytes and `Authenticate`
235,120, below the 262,144-byte budget.

A changed-line AdaMutant run on GitHub Actions detected all 148 mutants.
The first run left eleven. Eight became tests: the three conditions of
`Derive_SMB3_Signing_Key`'s guard, the cipher dropped on 2.1, the
missing-key check (an absent key is all zero, so only a response signed
with the zero key's CMAC tells the check apart), and the cleared NTSTATUS
after a signature failure, which the earlier tests could not see because
their responses reported success. Three are equivalent and annotated: the
session's preauth hash is read only on 3.1.1, so updating it on 2.1
changes nothing, and only a fresh operation, which already holds the
initial hash, can prepare a NEGOTIATE. `Fail_Connection` and the 3.1.1
fields that `Invalidate` resets were suppressed as unreachable; hostile
input reaches them now, so they are mutated and tested.

## SMB 3.x transform header (`SMB.Core_Transform`)

`SMB.Core_Transform` seals a message into an SMB2 TRANSFORM_HEADER with
AES-128-CCM or AES-128-GCM, and checks and opens a received one (MS-SMB2
2.2.41, 3.1.4.3, 3.2.4.1.8 and 3.2.5.1.1.1). Nothing in the library calls
it yet; the engine will in the second half of phase 4.

* `Seal`'s postcondition gives the result's length, the ProtocolId, the
  Nonce field (the bytes of the given nonce that the cipher uses, then
  zeros), OriginalMessageSize, Reserved, Flags, SessionId and zeros after
  the result. An output too short fails with `Invalid_Length` and is all
  zero.
* `Unwrap`'s postcondition names its five statuses. On `Ok` it gives the
  checked header fields and the ProtocolId and SessionId of the decrypted
  SMB2 header (the tag check is not a property a contract can state); on
  any failure, every byte after the transform header is zero.
* `Counter_Nonce` writes a 64-bit counter in little-endian order, then
  zeros, which is the same nonce under either cipher.

```sh
gnatprove -P proof.gpr -u smb-core_transform.adb --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3,altergo -j4
```

GNATprove 16.1.0 proved all **138 checks** in about two and a half minutes
on the Mac, with no `pragma Assume` or justification. The AEAD calls get the nonce, the
associated data and the tag as copies, so no in-out slice of the packet
aliases an input.

`test_suite`:

* `Check_Transform_Vector` reproduces each of the eight transformed
  messages of Microsoft's SMB 3.1.1 encryption blog (A.1 with GCM, A.2
  with CCM: a WRITE and a READ, each request and response) byte for byte
  from its plaintext, key, Nonce field and SessionId. The output is placed
  at bounds from 0, at bounds that end at `Natural'Last`, and with spare
  bytes, which must be zero. It then opens each message again.
* `Test_Transform` runs, for each cipher:
  * the nonce field and header fields of a message sealed with a nonce
    whose every byte is set;
  * a round trip that ends at `Natural'Last`, and the 64-byte minimum
    message;
  * an output one byte short;
  * 43 rejections, each of which must also leave the header and zero
    the rest:
    * an empty packet, a bare header, and a bare header with an SMB2
      ProtocolId (length is checked first);
    * each ProtocolId byte;
    * Flags 0 and `0x0101`;
    * OriginalMessageSize one larger, one smaller and above 2**24;
    * a truncated message;
    * another SessionId outside, and outside alone;
    * every tag byte, the nonce, the last byte of the Nonce field (which
      neither cipher uses, but the tag covers), Reserved, the ciphertext,
      another key and the other cipher;
    * a decrypted message shorter than an SMB2 header, another transform,
      each other ProtocolId byte, and another SessionId inside.

That is 8 published messages and 86 rejections.

An AdaMutant run on `smb-core_transform.adb` detected all 126 mutants (20
more did not compile) and marks none. The first run left two. Both are now
tests: a bare header with an SMB2 ProtocolId, which shows that length is
checked first, and a message whose header alone carries another SessionId,
which shows that the header's SessionId is checked, not just the one
inside.

## SMB 3.1.1 encryption in the engine

With a cipher negotiated, the client now encrypts every request after the
final SESSION_SETUP response and accepts only encrypted responses (MS-SMB2
3.1.4.3, 3.2.4.1.8 and 3.2.5.1.1.1).

* `Derive_SMB3_Keys` (renamed from `Derive_SMB3_Signing_Key`) also derives
  the encryption and decryption keys with `SMB.KDF` and sets the nonce
  counter to 1. Its postcondition states both keys and the counter. With
  no cipher, it states that none of them changed.
* `Mark_Authenticated`'s postcondition: encryption is on exactly when the
  cipher keys exist.
* `Seal_Request`'s postcondition: on `Ok`, encryption was on, the counter
  was below `QWord'Last` and advanced by one, nothing else changed, and the
  output's Nonce field is `Counter_Nonce` of the old counter. Otherwise the
  state is unchanged.
* `Unwrap_Response`'s postcondition: on `Ok`, encryption was on, a request
  was pending and no decrypted response was held; now one is held and
  nothing else changed. Otherwise the engine is invalidated and no message
  bytes are left.
* `Accept_Response` and `Inspect_Interim_Response`'s postconditions:
  * while encrypting, `Ok` means the response had been decrypted;
  * the decrypted mark is consumed;
  * only a successful LOGOFF stops encryption or moves the counter.
* `Initialize` and `Invalidate` state that the keys are zero, the counter is
  0 and encryption is off.

The first Samba run with `server smb encrypt = required` failed after
TREE_CONNECT: Samba copies the request's flags into the response, so an
encrypted response claimed a signature. Microsoft's published examples
clear the flag. A decrypted response is now taken with either flag, and its
signature field is not read. `Parse_Response` first also stated the
accepted SessionFlags in its postcondition; that contract case timed out at
300 seconds, and the rule is left to the tests.

```sh
gnatprove -P proof.gpr -u <unit> --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3,altergo -j4
```

GNATprove 16.1.0 on the Mac proved every check of the changed units, with
no `pragma Assume` or justification:

| Unit | Checks | Time |
| --- | ---: | ---: |
| `smb-engine.adb` | 323 | 12 min |
| `smb-core_protocol.adb` | 912 | 19 min |
| `smb-core_connection.adb` | 479 | 9 min |
| `smb-core_client.adb` | 1,486 | 26 min |

The full proof workflow (`proof.yml`) on GitHub Actions also passed on
this branch: every unit at its `proof.gpr` timeouts, in 91 minutes, with
nothing unproved.

`test_suite`'s 3.1.1 test now has 114 checks. With each cipher it covers:

* the derived cipher keys and the start of encryption;
* sealed TREE_CONNECT, CREATE and CLOSE requests under nonces 1, 2 and 3,
  which the server side opens with the encryption key;
* sealed responses that clear the SIGNED flag, and an async CREATE
  response that sets it with a meaningless signature, with an encrypted
  STATUS_PENDING interim before it;
* the session and share ENCRYPT_DATA flags, which are accepted;
* rejections, each of which invalidates the engine:
  * a plaintext interim response;
  * a plaintext response;
  * `Unwrap_Response` without encryption, without a pending request,
    twice, on a plaintext frame, under the wrong key and on a changed
    message;
* refused seals, which leave the state and the output untouched;
* short frames that end at `Natural'Last`.

Without a cipher, the session and share flags are refused, and an unsigned
response that claims a signature fails. `Parse_Response` accepts only
SessionFlags 0 and 4, and reports the share flag.

CI's Linux job runs Samba four times: 2.1 with the proxy tests, and 3.1.1
with `server smb encrypt` set to `off`, `default` and `required`. The
integration client checks `Is_Encrypted` in each run. It passes
`Require_Encryption` when encryption is required, and checks that the
option refuses the servers without a cipher. All four passed.

`make check` (including the stack check) and `make test` passed.
`Receive_Response` decrypts the received frame in place. The frame is a
variable initialized by `Receive_Frame`, which GNAT keeps on the secondary
stack. An earlier version returned a slice of a heap copy from inside the
copy's owner, and the stack check rejected it: the result had to be copied
to a runtime-sized frame before the owner freed the buffer.

A changed-line AdaMutant run on GitHub Actions detected all 118 mutants.
Earlier runs left eleven survivors, and each was resolved:

* tests now cover:
  * the cleared cipher keys after invalidation;
  * the zeroed output of a refused seal;
  * short frames at `Natural'Last`;
  * an unsigned response that claims a signature (which
    showed that the SIGNED flag of a plaintext response is still checked);
* two are equivalent and annotated:
  * the cleared NTSTATUS of a flag rejection, which only success responses
    reach;
  * the length guard before reading a decrypted response's flags.

Defensive checks that no test can reach were annotated from the start:
the cipher-key check in `Derive_SMB3_Keys` (the keys exist only with the
signing key), the cipher check in `Seal_Request` and `Unwrap_Response`
(encryption needs the keys), and the counter at `QWord'Last` (2**64
requests).

## Windows SMB server interoperability

The Windows CI job now runs `tests/windows_integration.py` against the
runner's own SMB server (Windows Server 2025). The harness adds a test-only
local account, with a random password that it generates and never prints,
and a share holding the Samba test's fixture. It runs `integration_client`
over SMB 3.1.1 three times: with a cipher negotiated but not required; then
with `EncryptData` on and only `AES_128_GCM` allowed; then with only
`AES_128_CCM` allowed. Afterwards it restores the server settings and
removes the account and the share.

The first run passed unchanged, `Disconnect` included: Windows encrypts the
LOGOFF response. The required run failed in authentication. Windows sets
SMB2_SESSION_FLAG_ENCRYPT_DATA in the challenge response already, and
`Accept_Response` refused that flag whenever the cipher keys did not exist
yet. Samba sets it only in the final response, after the keys exist. The
rule now refuses the flag only when no cipher was negotiated, which was its
intent. The `Nt_Status := 0` of that rejection had been annotated as
unreachable for a non-success response; that annotation was wrong.
`test_suite` now covers both cases: each cipher's encrypted run takes the
flag in the challenge response, and without a cipher the flag in the
challenge response is refused with NTSTATUS 0. That brings the 3.1.1 test
to 115 checks.

GNATprove 16.1.0 on the Mac proved every check of `smb-engine.adb` (323, in
10 minutes), the only unit whose body changed, with no `pragma Assume` or
justification. No specification changed.

The facade gains `Negotiated_Cipher`. The integration client prints it,
checks that a cipher was negotiated exactly when the run encrypts, and in
the required runs checks that it is the one cipher the server allows
(`SMB_TEST_CIPHER`). On GitHub Actions all three runs passed. The server's
own cipher list was `AES_128_GCM, AES_128_CCM, AES_256_GCM, AES_256_CCM`.
So the client and Windows agree on each cipher: the keys, the nonce, the
transform header and the tag. Windows accepted encrypted requests that keep
SMB2_FLAGS_SIGNED and a CMAC signature inside, and a NEGOTIATE without
NETNAME.

The review before merging found that the CCM run did not check which
cipher was used, which `Negotiated_Cipher` now does. It also found that the
harness switched `EncryptData` off instead of restoring it, and that a
failure in one cleanup step could skip the others. The harness now refuses
to start when its account or share already exists or the server has no
`EncryptionCiphers` setting. It restores both settings to their old values
and runs each cleanup step even if an earlier one fails.

A changed-line AdaMutant run on GitHub Actions detected all 4 mutants of
`smb-engine.adb`, including the `Nt_Status := 0` whose annotation was
removed.
