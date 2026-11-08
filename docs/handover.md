# Handover

State of the SMB 3.1.1 work after #113, for whoever picks it up. Fold what
stays useful into the other documents, and delete this file, once it is out
of date.

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
| 2 | AES-128, encryption direction | merged (#113) |
| 2 | AES-128-CMAC | next |
| 2 | SP 800-108 KDF (counter mode, HMAC-SHA256) | not started |
| 2 | AES-128-CCM | not started |
| 2 | AES-128-GCM | not started |
| 3 | 3.1.1 negotiation, preauth integrity, CMAC signing | not started |
| 4 | Encryption | not started |
| 5 | Windows server interop, release 0.2.0 | not started |

* Mutation testing: [AdaMutant](https://github.com/gomurin0428/AdaMutant)
  came in with #103. The first full run over `src/*.adb` was triaged in
  #104 to #111, so `main` had no known surviving mutants after #112. Each
  pull request since then has ended its changed-line run with none.

## AES-128 (#113)

`SMB.AES` (`src/smb-aes.ads`, `src/smb-aes.adb`) has key expansion and the
encryption direction of FIPS 197 AES-128. CMAC, CCM and GCM never run the
cipher backwards, so there is no decryption.

* The S-box is computed, not looked up. The sixteen state bytes are
  transposed into eight 16-bit bit planes, inverted in GF(2^8) as x^254
  (four multiplications and seven squarings, reduced modulo
  x^8 + x^4 + x^3 + x + 1), then put through the affine transform.
  MixColumns doubles a byte by multiplying the reduction constant 0x1B by
  the byte's top bit. No table index or branch depends on the key or the
  data. This is a coding rule, not a proved property.
* A `Key_Schedule` is `Ready` only after `Expand_Key`, and `Encrypt`
  requires `Ready`, as `SMB.Crypto`'s contexts do.
* Every helper in the body has a contract, if only `Post => True`. The first
  version had none, and GNATprove inlined each helper into its callers
  (contextual analysis). With the nested calls in `Inverse`, `gnatwhy3`
  grew to about 50 GB on Windows without finishing. With the contracts the
  unit proves in about 35 seconds with 1.2 GB (66 checks, none unproved).
  `--no-inlining` on the command line is a quick way to check whether
  inlining is the cause of a slow proof.
* Tests: `test_suite` checks FIPS 197 appendices B and C.1 and a 1,000-step
  chain. `tests/aes_conformance.py` (`make aes-test`) compares 1,287 cases
  with Python's `cryptography` through `crypto_probe` (record type `A`),
  with three sensitivity checks.
* The CI changed-line mutation run found two equivalent survivors.
  The affine term is now written `(4 + I) mod 8`, because the mutant of
  `(I + 4) mod 8` to `(I - 4) mod 8` is the same index. The substituted
  word in `Expand_Key` is a four-byte array, so its loop bound is checked.
  The two `(others => 0)` initializers in `Expand_Key` stay marked as
  equivalent.

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
  Give every helper in the body a contract, if only `Post => True`, so that
  GNATprove does not inline it into its callers (see the AES section). A
  type that must be set up before use gets a `Ready` function, required by
  the subprograms that use it.
* `proof.gpr` and `tests/check_sources.py` (`PROOF_UNITS`, `PROOF_BODIES`).
* `tests/test_suite.adb`: the published known answers.
* `tests/crypto_probe.adb`: a record type for the differential test.
* `tests/<name>_conformance.py`: the oracle comparison and sensitivity checks.
* `tests/mutant_tests.py`: `CONFORMANCE` and `SECOND_STAGE`, so mutants of
  the unit also run the comparison test.
* `tests/check_stack_usage.py`, when a subprogram will process peer-sized
  messages (SHA-512 did this).
* `Makefile`, and for a new test dependency `.github/workflows/ci.yml` (the
  Linux, Windows and changed-line mutation jobs) and
  `.github/workflows/mutation.yml`: the mutation baseline runs every
  comparison test.
* `README.md`, `README.ja.md`, `docs/protocol.md` and `docs/assurance.md`.

## Conventions

* One topic per branch, squash-merged. Commit messages and pull request
  descriptions are in English.
* The repository does not allow GitHub auto-merge, so merge by hand once
  the checks are green. The Codex and Devin review bots no longer review
  this repository, so run an independent review of your own before each
  merge.
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

## macOS environment notes

* GNATprove 14.1.1 installs with alr 2.1.1, as CI's
  `.github/scripts/install-ada.sh` does:
  `alr -n install --prefix=<dir> gnatprove=14.1.1`. Its bundled alt-ergo
  needs Homebrew's `gmp`, but the proofs use only cvc5 and z3.
* With 16 GB of RAM, prove one unit at a time with `-j4` and watch
  `gnatwhy3`'s memory.
* `make aes-test` and the mutation runs need `cryptography` for the
  interpreter behind `python`; `python -m pip install --user
  cryptography==50.0.2` matches the Windows CI pin.
* GNU make is available, so the Makefile targets work directly. A
  changed-line AdaMutant run of the AES unit took about three minutes with
  `--concurrency 8`.

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
