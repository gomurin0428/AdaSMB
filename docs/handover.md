# Handover

State of the SMB 3.1.1 work as of 2026-11-08, for whoever picks it up. Fold
what stays useful into the other documents, and delete this file, once it is
out of date.

## Where things stand

* 0.1.0 (SMB 2.1) is released and on Alire as the crate `smb`.
* The work toward 0.2.0 follows [smb3-design.md](smb3-design.md); read it
  first. The maintainer approved its decisions:
  * SMB 3.1.1 only (no 3.0 or 3.0.2).
  * 3.1.1 is required by default. The client offers 2.1 only when the
    caller explicitly allows it, because offering both lets a
    man-in-the-middle strip 3.1.1.
  * The client encrypts whenever the server supports a cipher, and a
    "require encryption" option refuses servers that do not.
  * AES-128 only; AES-256 is not offered in 0.2.0.
  * Out of scope: AES-GMAC signing, compression, multichannel, Kerberos,
    and raising the 64 KiB I/O chunk.
* Phase status (the phases are listed in the design document):

| Phase | Item | State |
| --- | --- | --- |
| 1 | Design document | merged (#101) |
| 2 | SHA-512 | merged (#112) |
| 2 | AES-128, encryption direction | open pull request from `claude/aes` (see below) |
| 2 | AES-128-CMAC | not started |
| 2 | SP 800-108 KDF (counter mode, HMAC-SHA256) | not started |
| 2 | AES-128-CCM | not started |
| 2 | AES-128-GCM | not started |
| 3 | 3.1.1 negotiation, preauth integrity, CMAC signing | not started |
| 4 | Encryption | not started |
| 5 | Windows server interop, release 0.2.0 | not started |

* Mutation testing: [AdaMutant](https://github.com/gomurin0428/AdaMutant)
  came in with #103. The first full run over `src/*.adb` was triaged in
  #104 to #111, so `main` had no known surviving mutants after #112.

## The open AES-128 pull request

New unit `SMB.AES` (`src/smb-aes.ads`, `src/smb-aes.adb`): key expansion
and the encryption direction of FIPS 197 AES-128. CMAC, CCM and GCM never
run the cipher backwards, so there is no decryption.

* The S-box is computed, not looked up. The sixteen state bytes are
  transposed into eight 16-bit bit planes, inverted in GF(2^8) as x^254
  (four multiplications and seven squarings, reduced modulo
  x^8 + x^4 + x^3 + x + 1), then put through the affine transform.
  MixColumns multiplies by x with a mask. No table index or branch depends on
  the key or the data. This is a coding rule, not a proved property.
* Tests:
  * `test_suite` checks FIPS 197 appendices B and C.1 and a 1,000-step
    chain in which each ciphertext is fed back as the next plaintext and
    folded into the key.
  * `tests/aes_conformance.py` (`make aes-test`) compares 1,287 cases with
    Python's `cryptography` through `crypto_probe` (record type `A`).
    The cases are the published vectors, every single-bit key and
    plaintext, every repeated-byte key and plaintext, and 512 seeded random
    pairs. Three sensitivity checks confirm that the probe rejects a
    corrupted key, plaintext or ciphertext.
* Wiring:
  * `proof.gpr` and `tests/check_sources.py` include the new unit.
  * `tests/mutant_tests.py` gives `smb-aes.adb` a second stage (`aes`).
  * There is a `make aes-test` target.
  * CI installs `cryptography`: `python3-cryptography` from apt on Linux,
    including both mutation workflows, and a pinned `pip install` on
    Windows.
  * `README.md`, `README.ja.md`, `docs/protocol.md` and
    `docs/assurance.md` mention the unit.

Verified locally on Windows before the push:

* `gprbuild` with `-gnatwe` for `smb.gpr`, `smb_tests.gpr` and
  `smb_example.gpr`;
* `test_suite`, `aes_conformance.py`, `check_sources.py`, and the stack
  check.

Not done yet:

1. **The proof does not finish.** GNATprove on `smb-aes.adb` ran for about
   two hours. By then `gnatwhy3` had grown to about 50 GB of memory, and the
   run was stopped. The likely cause is GNATprove's contextual analysis.
   Its output had separate entities only for `Column_Sum`, `Encrypt` and
   `Expand_Key`. Their `.gnat-json` files were 22 to 34 MB. So the local
   helpers without contracts were inlined into their callers, and the
   nested calls in `Inverse` (`Square (Square (Multiply (...)))`) multiply
   the size of the inlined terms. The fix to try first is to give each
   helper a contract so that it is proved on its own and its callers see
   only the contract. The helpers are `To_Planes`, `From_Planes`,
   `Reduce`, `Multiply`, `Square`, `Inverse`, `Sub_Bytes`, `Shift_Rows`,
   `Mix_Columns` and `Add_Round_Key`. A trivial `Post => True` is enough,
   because the proof target is only the absence of run-time errors.
   `--no-inlining` on the command line is a quick way to confirm the
   diagnosis.
2. **Changed-line mutation run.** The CI job "Mutation testing (changed
   lines)" runs it on the pull request and fails on any survivor. Triage
   survivors with the rules under "Conventions". Equivalents are likely
   where a loop overwrites a whole local before reading it, as with the
   `Result : Block := State` and `S : Planes := B` initial values. The
   two `(others => 0)` initializers in `Expand_Key` are already marked.
3. **Independent review** of the diff. None has been done.
4. Merge once CI is green. CI does not run GNATprove on pull requests, only
   the weekly `proof.yml` does, and that run would include the new unit
   after the merge. Fix item 1 before merging.

## Next steps after AES

Each primitive is its own pull request with no protocol behavior change,
following the checklist below.

1. **AES-128-CMAC** (RFC 4493, SP 800-38B), on top of `SMB.AES`. It is
   needed for 3.1.1 signing. Use the RFC 4493 vectors, plus a comparison
   with `cryptography`'s CMAC over random lengths, including 0, 16, and
   lengths around the block boundaries.
2. **SP 800-108 KDF** in counter mode with HMAC-SHA256. HMAC-SHA256
   already exists in `SMB.Crypto`. Use the session and signing keys from
   Microsoft's worked examples (linked in the design document's Testing
   section) and `cryptography`'s `KBKDFHMAC`.
3. **AES-128-CCM** (11-byte nonce, 16-byte tag) and **AES-128-GCM** (12-byte
   nonce, 16-byte tag). The GHASH multiply must use masks, not tables.
   Verifying a tag must be constant-time and must not release plaintext
   on failure.
4. Then phase 3, which changes `SMB.Engine` contracts and is expected to
   carry most of the proof cost.

## Checklist for a new primitive

The AES pull request touches each of these. Its diff is the template.

* `src/`: the unit with `pragma SPARK_Mode (On)`, bounded inputs, and no heap.
* `proof.gpr` and `tests/check_sources.py` (`PROOF_UNITS`, `PROOF_BODIES`).
* `tests/test_suite.adb`: the published known answers.
* `tests/crypto_probe.adb`: a record type for the differential test.
* `tests/<name>_conformance.py`: the oracle comparison and sensitivity checks.
* `tests/mutant_tests.py`: `CONFORMANCE` and `SECOND_STAGE`, so mutants of
  the unit also run the comparison test.
* `tests/check_stack_usage.py`, when a subprogram will process peer-sized
  messages (SHA-512 did this).
* `Makefile`, `.github/workflows/ci.yml` (Linux and Windows), and
  `.github/workflows/mutation.yml` if a new test dependency is needed.
* `README.md`, `README.ja.md`, `docs/protocol.md` and `docs/assurance.md`.

## Conventions

* One topic per branch, squash-merged. Commit messages and pull request
  descriptions are in English.
* The repository does not allow GitHub auto-merge, so merge by hand once
  the checks are green. The Codex and Devin review bots stopped reviewing
  (out of quota), so ask for a human review or run your own.
* Before opening a pull request, all of these should pass:
  * `-gnatwe` builds;
  * `test_suite`, the conformance scripts, `check_sources.py` and the stack
    check;
  * GNATprove on the changed units with no unproved checks;
  * a changed-line mutation run with no survivors.
* `smb.gpr` compiles with `-gnat2012`, so `src/` cannot use Ada 2022
  features such as iterated component aggregates. `proof.gpr` uses
  `-gnat2022`.
* Mutation triage rules, followed since #104:
  * A real gap gets a test.
  * Dead code, and a check that only duplicates another layer's check, is
    removed if the unit still proves. Re-prove it.
  * A remaining equivalent mutant gets
    `--  adamutant:disable-next-line <Mutators>: <reason>`, or a
    disable/enable block for an `or else` chain whose operators are on
    following lines.
  * Confirm each fix with `adamutant run --mutate <id>`.

## Windows environment notes

* The toolchain comes from Alire 2.1.1 and matches CI: gnat_native 14.2.1,
  gprbuild 25.0.1, gnatprove 14.1.1.
* There is no GNU make on Windows, so run each Makefile recipe's commands
  directly.
* Run GNATprove from PowerShell or cmd. Started from Git Bash (MSYS), it
  silently reports every prover check as unproved.
* Prove one unit at a time. The large core units (`core_auth`,
  `core_client`) take about four minutes each:

  ```powershell
  gnatprove -P proof.gpr -u smb-aes.adb --subdirs=aes-check --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j8
  ```

* AdaMutant:
  * Build it at the commit pinned in `ADAMUTANT_COMMIT` (in the workflows).
    Earlier commits report false kills on Windows because of ALI time
    stamps.
  * Run it with `adamutant run --since origin/main --concurrency 8`, then
    list the survivors with `python tests/mutation_survivors.py`.
  * Do not redirect its output into a file inside the repository during a
    run. AdaMutant copies the tree into its sandbox, and a file held open
    makes that fail with "cannot copy".
  * A full run of `src/*.adb` takes about four hours on a fast machine.
    The weekly `mutation.yml` splits it into eight jobs.
* `make aes-test` needs `pip install cryptography`. CI pins 50.0.2 on
  Windows.

## Open items

* The design document's open questions: SMB2_FLAGS_SIGNED inside encrypted
  requests, and whether `Connect` should send NETNAME.
* One AdaMutant survivor seen on macOS did not reproduce on Windows and was
  never investigated. The weekly mutation run shows whether it comes back.
