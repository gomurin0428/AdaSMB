# Handover

State of the SMB 3.1.1 work after #115, for whoever picks it up. Fold what
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
| 2 | AES-128-CMAC | merged (#114) |
| 2 | SP 800-108 KDF (counter mode, HMAC-SHA256) | merged (#115) |
| 2 | AES-128-CCM | merged (#118) |
| 2 | AES-128-GCM | merged (#119) |
| 3 | 3.1.1 negotiate contexts (`SMB.Core_Negotiate`) | merged (#120) |
| 3 | Preauth integrity hash (`SMB.Core_Preauth`) | merged (#121) |
| 3 | AES-CMAC message signing in `SMB.Core_Wire` | merged (#122) |
| 3 | Engine: 3.1.1 negotiation, keys, CMAC signing, dialect policy | merged (#123) |
| 4 | Encryption | next |
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

## AES-128-CMAC (#114)

`SMB.AES.CMAC` (`src/smb-aes-cmac.ads`, `src/smb-aes-cmac.adb`) is a child of
`SMB.AES`, so its private part sees `Key_Schedule`'s default, and it uses only
the public `Expand_Key`, `Encrypt` and `Ready`. It has a one-shot `MAC` and a
`MAC_Context` with `Start (Context, Key)`, `Update` and `Finish (Context,
Tag)`, whose `Ready`/`Length` contracts match `SMB.Crypto`'s incremental
HMAC-SHA256. `Ready` also states the buffering rule `(Used = 0) = (Total =
0)`, and `Finish` leaves the context `Wiped`. It proves with 43 checks in
about 5 seconds.

Decisions worth keeping for phase 3:

* The engine keeps the raw 16-byte signing key, and each message calls
  `Start` with it. No prepared key is cached: the per-message cost is two
  AES blocks, and the engine's key contracts stay as they are.
* `Core_Wire.Verify_Signature` can feed the header (48 bytes), a zero
  signature and the rest, as it does for HMAC-SHA256; the `Update`
  preconditions discharge the same way.
* AES bounds the speed: a 64 KiB CMAC takes about 58 ms in the default
  unoptimized build and 20 ms at `-O2`. Phases 3 and 4 will sign or encrypt
  every 64 KiB chunk, so a faster constant-time AES (several blocks per
  bit-sliced pass) or an optimized default build may be needed later.

## Key derivation (#115)

`SMB.KDF.Derive (Session_Key, Purpose, Preauth_Hash)` derives the 3.1.1
signing, encryption (client to server) and decryption (server to client)
keys. `Purpose` selects the label, so a caller cannot pass a label without
its NUL, an SMB 3.0 label or the ApplicationKey label, and every length is
fixed by the types. Phase 3 calls it once per key after the final
SESSION_SETUP response, with the NTLM ExportedSessionKey and the session's
final preauth hash. The tests use Microsoft's twelve published 3.1.1 keys;
the same posts also give 3.0 and ApplicationKey vectors, which this API
deliberately cannot produce.

## AES-128-CCM (#118)

`SMB.AES.CCM` (`src/smb-aes-ccm.ads`, `src/smb-aes-ccm.adb`) has
`Seal (Key, Nonce, AAD, Data, Tag)` and `Open (Key, Nonce, AAD, Data, Tag,
Authentic)` with SMB's parameters fixed by the types: an 11-byte nonce
(`Nonce_88`), so a four-byte length field, and a 16-byte tag. Both work on
`Data` in place. `Open` decrypts, recomputes the tag and compares it with
`SMB.Crypto.Constant_Time_Equal`; on a mismatch it zeroes `Data`, which its
postcondition states. Associated data may be up to 65,279 bytes (the
two-byte length encoding) and data up to `Maximum_Frame_Size`. It proves
with 70 checks in about 10 seconds.

Decisions worth keeping for phase 4:

* The caller passes the transform header's 32 bytes from the Nonce field on
  as the associated data and the first 11 bytes of the Nonce field as the
  nonce, and the tag is the header's Signature field. The tests take all
  three from Microsoft's four A.2 messages.
* Each call expands the key, as `SMB.AES.CMAC.MAC` does. A message costs one
  key expansion and two AES blocks per 16 bytes, about twice CMAC's time.
* `Open` returns `Authentic`, not a status. Phase 4 maps a rejected message
  to its own error and must not use `Data` then.
* Passing the nonce, the associated data, the tag and `Data` as slices of
  one frame buffer proves without aliasing warnings only with literal
  offsets on a 0-based buffer (`Frame (20 .. 51)`, `Frame (52 ..
  Frame'Last)`). With offsets from `Frame'First`, GNATprove 16.1.0 reports
  that the formals might be aliased; copy the 52-byte header into a local
  then.

## AES-128-GCM (#119)

`SMB.AES.GCM` (`src/smb-aes-gcm.ads`, `src/smb-aes-gcm.adb`) has the same
`Seal` and `Open` as `SMB.AES.CCM`, with a 12-byte nonce (`Nonce_96`) and a
16-byte tag. Associated data and data may each be up to
`Maximum_Frame_Size`. It proves with 126 checks in about 10 seconds.

* GHASH multiplies bit by bit (SP 800-38D algorithm 1) on two 64-bit words.
  Adding V to the product and reducing by R use masks made from a bit, so
  no branch or table index depends on the hash subkey or the data. A
  message costs one AES block and one 128-step multiplication per 16 bytes:
  64 KiB takes about 18 ms at `-O2`, half of CCM's time.
* The caller passes the transform header's 32 bytes from the Nonce field on
  as the associated data and the first 12 bytes of the Nonce field as the
  nonce; the tag is the Signature field. The tests take all three from
  Microsoft's four A.1 messages.
* `Open` decrypts as it hashes and zeroes `Data` on a mismatch, as CCM's
  does, so both ciphers have one shape for phase 4. GCM could check the tag
  before decrypting, at the cost of a second pass over the data; a rejected
  message would then never put plaintext in `Data` or key stream on the
  stack. Consider it if phase 4 needs that.
* `crypto_probe`'s CCM check became the generic `Check_AEAD`, with a CCM and
  a GCM instance.
* The library is built as Ada 2012 (`smb.gpr`) and the proof as Ada 2022
  (`proof.gpr`). An Ada 2022 construct such as an iterated component
  association proves but does not build, so `To_Block` is a positional
  aggregate.

## SMB 3.1.1 negotiate contexts (#120)

`SMB.Core_Negotiate` (`src/smb-core_negotiate.ads`, `.adb`) is the first
part of phase 3. Nothing calls it yet.

* `Request (Guid, Salt, Allow_21)` returns the 102-byte NEGOTIATE request
  body: SecurityMode 3 as today, Capabilities `0x40` (encryption) only,
  dialect `0x0311` and, with `Allow_21`, `0x0210`, then the preauth
  integrity context (SHA-512 and the 32-byte salt) and the encryption
  context (GCM, then CCM). The contexts start at body offset 40 (104 from
  the header) with one dialect or two, so the layout does not depend on
  `Allow_21`. The contexts are byte for byte those of Microsoft's A.1
  request, which the test checks. `Request` is completed in the spec's
  private part, so the engine's proofs can see the bytes it sends.
* `Check_Response_Contexts (Packet, Cipher, Status)` takes the whole
  response, header included, because the offset fields count from the
  header. It applies the design document's rules and returns the cipher,
  or `No_Cipher` with any failure. A compression, transport, RDMA or
  signing context fails it, since we offer none. It also requires the
  first context at or after offset 128, the end of the fixed response body
  (ours).
* It does not check DialectRevision or call anything; the engine pull
  request does that, takes the salt from the entropy source and hashes the
  messages.
* Mutation testing shaped the code: every four-byte field holds a value
  below 2**16, so they are written as two bytes and two zeros; bounds are
  written as additions (`Position + 8 > Packet'Length`) so that `>` and
  `>=` differ in some test; and only positions the loop advances to are
  checked inside it, since the first is checked before.

## Preauth integrity hash (#121)

`SMB.Core_Preauth.Update (Value, Message)` sets `Value` to SHA-512 of
`Value` followed by `Message`; `Initial` is the 64 zero bytes. The test
replays Microsoft's A.1 and A.2 chains, from the NEGOTIATE request to the
second SESSION_SETUP request, and derives each session's signing,
encryption and decryption keys with `SMB.KDF` from the final value: they
are the published keys. The A.1 and A.2 messages are shared constants in
`tests/test_suite.adb`, for the engine tests to reuse.

* Hash every message whole, from its header, without the TCP framing, and
  not the final, successful SESSION_SETUP response.
* The hash state is 64 bytes per connection and per session in progress;
  the engine pull request decides where it lives.

## AES-CMAC message signing (#122)

`SMB.Core_Wire.Sign_CMAC` and `Verify_Signature_CMAC` are the SMB 3.1.1
forms of `Sign` and `Verify_Signature`: AES-128-CMAC over the whole message
with the Signature field zeroed, under a 16-byte key typed as
`SMB.AES.Key_128`. Nothing calls them yet.

* They are separate procedures, not an algorithm parameter of `Sign`, so
  the contracts that `core_connection`, `core_client` and the engine prove
  against stay as they were. The engine pull request picks one by dialect.
* `Verify_Signature_CMAC` feeds the header, a zero signature and the rest
  to the incremental CMAC. The rest is skipped when empty: for a bare
  header that ends at `Natural'Last`, its first index would overflow,
  which GNATprove reported and a test now covers.
* Like `Sign`, `Sign_CMAC` has a postcondition with `Data'Old`, which
  `-gnata` copies at run time, so it is not on the stack check's list of
  static frames; `Verify_Signature_CMAC` is.
* The final SESSION_SETUP responses of Microsoft's A.1 and A.2 examples
  are the published vectors: each verifies with its session's derived
  signing key.

## SMB 3.1.1 in the engine (#123)

Phase 3 is complete: `Connect` offers SMB 3.1.1 by default and signs a
3.1.1 session with AES-128-CMAC.

* `SMB.Client.Connect` has `Dialects : Dialect_Policy := SMB_311_Only`.
  `SMB_311_Or_21` also offers 2.1. `Negotiated_Dialect` reports the result.
  This changes behavior: a 2.1-only server now needs `SMB_311_Or_21`.
* `SMB.Core_Connection.Prepare_Negotiate` takes the salt and `Allow_21`,
  sends `SMB.Core_Negotiate.Request` and keeps the request's preauth hash.
  `Complete` accepts 3.1.1 only with valid negotiate contexts, and 2.1 only
  when it was offered; its postcondition proves that downgrade rule.
  `Parse_Response` accepts both dialects, records the one chosen in
  `Response_Info.Dialect`, and rejects SMB 3 capabilities only from a 2.1
  server (Samba sends multichannel with 3.1.1).
* The engine records the dialect, the cipher and the connection's preauth
  hash (`Mark_Negotiated`). `Current_Signing_Key` stays the NTLM session
  key, which also keys the SPNEGO mechListMIC; a 3.1.1 session signs with a
  separate key, `Current_SMB3_Signing_Key`, that
  `Derive_SMB3_Signing_Key` sets to `SMB.KDF.Derive` of the session key and
  the session's preauth hash. Its postcondition proves that provenance and
  lists every other accessor as unchanged, because the accessors are
  completed in the body and callers cannot see that they depend only on
  other fields.
* The session's preauth hash lives in `SMB.Core_Client`'s `Authentication`
  record, so hashing does not change the engine state. `Prepare_Negotiate`
  starts it from the connection's, `Complete_Challenge` adds the challenge,
  and `Prepare_Authenticate` adds the second request once its header is
  written, then derives the key. The engine verifies the final response
  with AES-CMAC under it.
* Every request signer (`Sign_Packet` in both units, and the direct call in
  `Prepare_Close`) picks HMAC-SHA256 or AES-CMAC by `Current_Dialect`.
* The cipher is negotiated and recorded but not used; a share or session
  the server wants encrypted is refused. Because the request now offers
  encryption, that includes servers that only prefer it (Samba's
  `server smb encrypt = desired`, Windows' `EncryptData` without
  `RejectUnencryptedAccess`), which accepted this client unencrypted over
  2.1: the session flag fails SESSION_SETUP as `Invalid_Protocol`, the
  share flag fails TREE_CONNECT as `Unsupported_Feature`. Phase 4 encrypts
  and removes this regression.
* Samba runs twice in CI: as before with 2.1 for the proxy tests (their
  proxies re-sign with the 2.1 key, and every integration client passes
  `Test_Dialects.Policy`), and with `ADASMB_SMB311_ONLY=1`, a 3.1.1-only
  server with mandatory signing, for `integration_client` in its default
  policy.

## Next steps

Phase 4 of `docs/smb3-design.md`: the transform header, AES-128-GCM/CCM
encryption of every request after the final SESSION_SETUP response, a
nonce counter that never wraps, and the response checks listed under
Encryption. The engine already holds the cipher; the encryption and
decryption keys come from `SMB.KDF` with the same preauth hash as the
signing key. Samba with `smb encrypt = required` and hostile transform
headers are the tests.

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

## Toolchain

* CI builds, tests, mutates and proves with GNAT 16.1.0, gprbuild 26.0.1
  and gnatprove 16.1.0. `make prove` runs cvc5, z3 and alt-ergo: z3 and
  cvc5 time out on a few checks in `smb-core_client.adb`, whose context
  carries the whole Engine state, and alt-ergo proves them.
* The prover timeout is in `proof.gpr`, not on the command line: 120
  seconds, and 300 for `core_protocol` and `core_client`, whose slowest
  checks take up to 83 seconds on an M4. The GitHub runner can be four
  times slower on one check. A `--timeout` on the command line overrides
  it.
* `UTF8_To_UTF16`'s nested `Store_Unit` has a postcondition: the units
  before the new one keep their values, and a valid unit stays valid. The
  loop is proved from it, not from the inlined byte stores, for which the
  check after the loop ran past 300 seconds on the GitHub runner. The
  postcondition is ignored at run time, so `Output'Old` is not copied.
* Moving the proof from gnatprove 14.1.1 to 16.1.0 left 12 checks
  unproved, which now have proof hints: byte-slice equalities and
  bit-vector reconstructions in `smb-core_text.adb` (UTF-8 to UTF-16
  emission), `smb-core_wire.adb` (`Write_U64`), `smb-core_client.adb`
  (`Prepare_Metadata`), `smb-engine.adb` (the final MIC suffix),
  `smb-core_protocol.adb` (`Build_Write`, `Build_Rename`) and
  `smb-core_connection.adb` (`Prepare_Negotiate`'s client GUID). The hints
  are ghost lemmas, `pragma Assert_And_Cut`, and a `Seal_Request` helper
  that takes the signing step out of `Prepare_Metadata`'s context.
  `Build_Write` no longer writes the zero Flags field (bytes 44 to 47),
  which `Begin_Build` already cleared.
* alr 2.1.1 installs every one of these versions. When GitHub's release
  downloads fail (HTTP 504), `gh release download` through the API still
  works; check the archive against the Alire index's SHA-256.

## macOS environment notes

* `alr -n install --prefix=<dir> gnat_native=16.1.0 gprbuild=26.0.1` and,
  in another prefix, `gnatprove=16.1.0` install the toolchain, as CI's
  `.github/scripts/install-ada.sh` does. The bundled alt-ergo needs
  Homebrew's `gmp`.
* With 16 GB of RAM, prove one unit at a time with `-j4` and watch
  `gnatwhy3`'s memory. The full gnatprove 16.1.0 proof with cvc5, z3 and
  alt-ergo took 67 to 84 minutes on an M4 Mac mini, and the prover
  processes together peaked near 9.6 GB. On the GitHub runner it took 50
  minutes.
* `make aes-test`, `make cmac-test`, `make ccm-test`, `make gcm-test`,
  `make kdf-test` and the mutation runs need `cryptography` for the
  interpreter behind `python`; `python -m pip install --user cryptography==50.0.2` matches the
  Windows CI pin.
* GNU make is available, so the Makefile targets work directly. A
  changed-line AdaMutant run of the AES unit took about three minutes with
  `--concurrency 8`.

## Windows environment notes

* The toolchain comes from Alire 2.1.1. Builds and tests used gnat_native
  14.2.1 and gprbuild 25.0.1 before #116, and the proof used gnatprove
  14.1.1 before #117; see "Toolchain" above for what CI uses now.
* There is no GNU make on Windows, so run each Makefile recipe's commands
  directly.
* Run GNATprove from PowerShell or cmd. Started from Git Bash (MSYS), it
  silently reports every prover check as unproved.
* Prove one unit at a time. With gnatprove 14.1.1, the large core units
  (`core_auth`, `core_client`) took about four minutes each; 16.1.0 has not
  been timed on Windows. Use the provers `make prove` uses:

  ```powershell
  gnatprove -P proof.gpr -u smb-aes.adb --subdirs=aes-check --mode=all --level=2 --proof=progressive --report=fail --checks-as-errors=on --prover=cvc5,z3,altergo --timeout=120 -j8
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
* `make aes-test`, `make cmac-test`, `make ccm-test`, `make gcm-test` and
  `make kdf-test` need `pip install cryptography`. CI pins 50.0.2 on Windows.

## Open items

* The design document's open questions: SMB2_FLAGS_SIGNED inside encrypted
  requests, and whether `Connect` should send NETNAME.
* One AdaMutant survivor seen on macOS did not reproduce on Windows and was
  never investigated. The weekly mutation run shows whether it comes back.
