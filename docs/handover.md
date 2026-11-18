# Handover

State of the SMB 3.1.1 work since release 0.3.0, for whoever picks it up. Fold what
stays useful into the other documents, and delete this file, once it is out
of date.

## Where things stand

* 0.1.0 (SMB 2.1) is released and on Alire as the crate `smb`. 0.2.0 (SMB
  3.1.1 with signing and encryption) is tagged `v0.2.0` with a GitHub
  release and on the Alire index (alire-project/alire-index#2340, merged
  on 2026-11-14). 0.3.0 (the AES-256 ciphers and AES-GMAC signing) is
  tagged `v0.3.0` with a GitHub release and on the Alire index
  (alire-project/alire-index#2357, merged on 2026-11-16).
* After 0.3.0 the maintainer approved three pieces, in this order: file
  information (`Query_Information`, #134, and `Set_Size`, #135), reads and
  writes larger than 64 KiB per request (#137 and #138), and teaching the
  adversarial proxy SMB 3.1.1. A release that includes them (0.4.0), and
  its Alire submission, wait for the maintainer's word.
* The work toward 0.2.0 followed [smb3-design.md](smb3-design.md); read it
  first. The maintainer approved its decisions:
  * SMB 3.1.1 only (no 3.0 or 3.0.2).
  * 3.1.1 is required by default. The client offers 2.1 only when the
    caller explicitly allows it, because offering both lets a
    man-in-the-middle strip 3.1.1.
  * The client encrypts whenever the server supports a cipher, and a
    "require encryption" option refuses servers that do not.
  * AES-128 only in 0.2.0; AES-256 is offered since #130.
  * Out of scope: compression, multichannel and Kerberos. AES-GMAC
    signing and READs and WRITEs above 64 KiB, first out of scope, came in
    with #132, #137 and #138.
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
| 4 | Transform header (`SMB.Core_Transform`) | merged (#124) |
| 4 | Engine: encryption keys, nonce counter, encryption policy | merged (#125) |
| 5 | Windows server interop (`tests/windows_integration.py`) | merged (#126) |
| 5 | Release 0.2.0 (`alire.toml`, tag, GitHub release) | merged (#127) |
| after 0.2.0 | AES-256 primitives (`SMB.AES`, CCM, GCM, `SMB.KDF.Derive_256`) | merged (#129) |
| after 0.2.0 | AES-256 in negotiation, the transform and the engine | merged (#130) |
| after 0.2.0 | AES-GMAC signing (GMAC, the signing context, the engine) | merged (#132) |
| after 0.2.0 | Release 0.3.0 (`alire.toml`, tag, GitHub release) | merged (#131) |
| after 0.2.0 | 0.3.0 on the Alire index | merged (alire-project/alire-index#2357) |
| after 0.3.0 | File information: QUERY_INFO (`SMB.Core_Query`), directory entry times, `To_Time` | merged (#134) |
| after 0.3.0 | Setting a file's size: SET_INFO FileEndOfFileInformation (`SMB.Core_Resize`, `SMB.Core_Request`) | merged (#135) |
| after 0.3.0 | The proof cache in `proof.yml` (`make prove PROOF_CACHE=`) | merged (#136) |
| after 0.3.0 | Multi-credit READs: LARGE_MTU, the engine's credit count, READs up to 960 KiB | merged (#137) |
| after 0.3.0 | Multi-credit WRITEs: WRITEs up to 960 KiB, built and signed in place | #138 |

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
  signing context fails it, since we offer none. (#132 offers and accepts
  a signing context.) It also requires the
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
  `Derive_SMB3_Signing_Key` (now `Derive_SMB3_Keys`) sets to `SMB.KDF.Derive` of the session key and
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
  (Since #132, `Sign_Packet` picks by `Current_Signing`.)
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

## The transform header (#124)

`SMB.Core_Transform` seals a message into a TRANSFORM_HEADER and checks and
opens a received one. It is a stateless SPARK unit, like
`SMB.Core_Negotiate`, and nothing calls it yet.

* `Seal` takes the whole 16-byte Nonce field and keeps only the bytes the
  cipher uses (11 for CCM, 12 for GCM), with zeros after them, so
  Microsoft's examples, whose nonces are random, test it. `Counter_Nonce`
  is the nonce the engine will use: a 64-bit counter in little-endian
  order, then zeros.
* `Unwrap` applies every check that `docs/smb3-design.md` lists under
  Encryption, except that it asks the decrypted message to start with
  `FE 'SMB'`, not just not to start with `FD 'SMB'`. On any failure every
  byte after the header is zero, so a caller cannot use the ciphertext or
  a forged plaintext by mistake.
* `Test_AES_CCM` and `Test_AES_GCM` pass each of Microsoft's eight
  transformed messages to `Check_Transform_Vector`, which seals the
  plaintext back into the published bytes and opens them.

## Encryption in the engine (#125)

* `Derive_SMB3_Keys` (renamed from `Derive_SMB3_Signing_Key`) also derives
  the encryption (`SMBC2SCipherKey`) and decryption (`SMBS2CCipherKey`)
  keys when a cipher was negotiated, and sets the nonce counter to 1.
  `Mark_Authenticated` turns encryption on (`Is_Encrypting`), so the final
  SESSION_SETUP exchange is the last one in the clear.
* `Seal_Request` seals with `Counter_Nonce (Next_Nonce)` and advances the
  counter; `Counter_Exhausted` at `QWord'Last`. The counter is assigned in
  four places only (`Initialize`, `Invalidate`, `Derive_SMB3_Keys`,
  `Seal_Request`).
* `Unwrap_Response` decrypts a frame in place and sets
  `Holds_Decrypted_Response`. `Accept_Response` and
  `Inspect_Interim_Response` refuse anything else while encrypting, and
  consume the flag. A decrypted response may claim a signature or not:
  Windows clears SMB2_FLAGS_SIGNED in encrypted responses, while Samba copies
  the request's flags (`smbd_smb2_request_setup_out`) and so claims one it
  never computes. The first Samba run failed on exactly that. So
  `Validate_Header` gets the packet's own flag, no signature is read, and
  `Response_Header_Matches_Request` does not constrain the flag of a
  decrypted response. `Receipt_Signed` still records the request's
  expectation, so the phase transitions are unchanged.
* Requests stay CMAC-signed inside the transform: MS-SMB2 3.2.4.1.1 requires
  signing unless both the session and the share are encrypted, and does not
  forbid it then; servers check signatures only on unencrypted requests.
* `Response_Info.Encrypt_Data` reports SESSION_SETUP's ENCRYPT_DATA session
  flag (the only nonzero SessionFlags accepted; guest and null still fail)
  and TREE_CONNECT's ENCRYPT_DATA share flag. The engine refuses either with
  `Unsupported_Feature` when no cipher was negotiated. (#125 tested for the
  cipher keys instead, which Windows broke; see #126.)
* The facade: `Receive_Response` declares the received frame as a variable
  initialized by `Receive_Frame`. GNAT leaves that object on the secondary
  stack, so it can be decrypted in place without a frame-sized primary
  stack frame. A heap copy that was returned from inside its owner's scope
  made the frame runtime-sized, because the result had to be copied before
  the owner freed it. `Send_Request` replaces every direct `Send_Frame` and
  seals into a heap buffer once the engine encrypts. `Connect` gains
  `Require_Encryption` and the client `Is_Encrypted`.
* Samba runs four times in CI. The 3.1.1 runs set
  `server smb encrypt = off` (signing only; the integration client also
  checks that `Require_Encryption` refuses the server), `= default` (a
  cipher is negotiated but not required, and the client encrypts anyway)
  and `= required` (the client passes `Require_Encryption`). The client
  checks `Is_Encrypted` in each.

## Windows server interop (#126)

* The Windows CI job runs `tests/windows_integration.py` against the
  runner's own SMB server (Windows Server 2025; the job is an
  administrator on a disposable VM). The harness adds a local account with
  a random password it generates and never prints, and a share with the
  Samba test's fixture. It runs `integration_client` (3.1.1 only) three
  times:
  * a cipher negotiated but not required;
  * `EncryptData` on and only `AES_128_GCM` allowed;
  * the same with only `AES_128_CCM`.
  Then it restores the server settings and removes the share and account.
  It refuses to run without `ADASMB_WINDOWS_SERVER=1`.
* The first run passed as it was. The required run failed: Windows sets
  SMB2_SESSION_FLAG_ENCRYPT_DATA in the challenge response already, and the
  engine refused that flag whenever the cipher keys did not exist yet. The
  rule now tests for a negotiated cipher. Its `Nt_Status := 0` had been
  annotated as unreachable for a non-success response; a unit test now
  covers an encrypted challenge without a cipher.
* Windows encrypts the LOGOFF response, as Samba does, so `Disconnect`
  passes; the watch item from #125 is closed. Windows accepts encrypted
  requests that keep SMB2_FLAGS_SIGNED and a CMAC signature, and a
  NEGOTIATE without NETNAME.
* With its default settings, a Windows server negotiates a cipher whenever
  a 3.1.1 client offers one, so the signing-only 3.1.1 path is tested
  against Samba only, as is 2.1.

## Next steps

* Next, in the order the maintainer approved: the adversarial proxy over
  3.1.1 (below). The maintainer will say whether 0.4.0 comes before or
  after it.
* Submit a release to the Alire index only when the maintainer says so.
  * The index manifest is `alire.toml` at the release tag with an
    `[origin]` section added: `commit` is the tag's commit and `url` is
    `git+https://github.com/gomurin0428/AdaSMB.git`, as in the index's
    `index/sm/smb/smb-0.2.0.toml`.
  * `alr publish` wrote that file for 0.1.0. Later ones were written by
    hand in the same form, on a branch of the fork gomurin0428/alire-index
    cut from the index's `stable-1.4.0`.
  * The index is a third-party repository: leave the Claude session URL
    and any `Claude-Session:` commit trailer out of pull requests and
    commits there.
* Hostile transform headers are covered by unit tests through the engine;
  the adversarial proxy still speaks 2.1 only. Teaching it 3.1.1 would let
  the proxy tests run against the 3.1.1 Samba.

## File information (#134)

* `SMB.Core_Query` is a new SPARK unit for QUERY_INFO, rather than another
  operation in `SMB.Core_Client`, so that a change to it re-proves a small
  unit. Since #135 it shares `Prepare_Header` and `Sign_Packet` with
  `SMB.Core_Resize` through `SMB.Core_Request`; `SMB.Core_Client` and
  `SMB.Core_Connection` keep copies of their own.
* One request shape: FileNetworkOpenInformation (class 34), 56 bytes, on
  an open handle. Every access mode the client opens with includes
  FILE_READ_ATTRIBUTES (`Core_Client.Access_Mask`), so any handle can be
  queried; the integration client queries through write-only and
  read-write handles and a read-only one.
* The response has QUERY_DIRECTORY's layout, so `Parse_Response` takes
  command 16 on QUERY_DIRECTORY's branch, and the engine accepts command 16
  where it accepts 14 and 17 (requests, interim responses, and the
  postcondition that the phase and handles are unchanged). A success
  response whose OutputBufferLength is not 56 invalidates the connection;
  an error status finishes the operation with a zero result and keeps it.
* `Directory_Info` gains the four times at offsets 8 to 32 of
  FileIdBothDirectoryInformation, and `Parse_Directory_Entry`'s
  postcondition states them. `Next_Directory_Entry`'s postcondition does
  not repeat them; the facade copies them.
* `To_Time` is facade code. It splits the day count into a civil date
  (H. Hinnant's civil_from_days, from 1600-03-01) and calls
  `Ada.Calendar.Formatting.Time_Of` with the time of day, so it does not
  depend on how the runtime adds days or counts leap seconds. GNAT accepts
  times in 2400; the function refuses them, because the language guarantees
  only 1901 to 2399. A unit test steps through every day of the range.
* `Complete` states three outcomes, as `Complete_Metadata` does: success,
  `Invalid_State_Status` with nothing changed, or the operation failed and
  the connection invalidated. The stronger form of `Core_Connection` (a
  call made in flight never reports `Invalid_State_Status`) would need the
  engine to state that `Handle_Matches` implies `Validate_Handle` succeeds.
* The adversarial proxy mutates QUERY_DIRECTORY and SET_INFO responses but
  not QUERY_INFO; add it when the proxy learns 3.1.1.
* Not done: a path-based query that opens and closes a handle itself (it
  would need to tell files from directories first).

## Multi-credit READs (#137)

* The NEGOTIATE request offers SMB2_GLOBAL_CAP_LARGE_MTU (`0x04`, with
  encryption's `0x40`). `Parse_Response` records the server's bit as
  `Response_Info.Large_MTU`, clamps MaxReadSize to `Maximum_Read_Chunk`
  (fifteen credits, 960 KiB) with it and to 64 KiB without, and
  `Mark_Negotiated` copies it into the engine (`Has_Large_MTU`).
* The engine counts credits (`Current_Credits`): one on `Mark_Connected`, the
  charge taken off in `Begin_Request`, each response's CreditResponse added
  in `Accept_Response` and `Inspect_Interim_Response`, at most
  `Maximum_Credits` (8,192); `Invalidate` and a LOGOFF reset it.
* Only a READ (and, since #138, a WRITE), and only with LARGE_MTU, takes
  more than one credit: `Core_Protocol.Credit_Charge` (one per 64 KiB
  started). `Begin_Request`
  refuses a multi-credit READ the count does not cover (`Resource_Limit`)
  and advances the message id by the charge; a one-credit request goes as
  before even with no credit counted, so a gap in the count costs speed,
  not a connection.
* `Request_Expectation` carries `Credit_Charge` and `Credit_Request`, which
  every `Prepare_Header` copy writes at offsets 6 and 14
  (`Core_Wire.Initialize_Header`'s new `Charge`). The CreditRequest is 1
  without LARGE_MTU, as before, and otherwise the charge plus what brings
  the count back to `Credit_Target` (32).
* `Core_Client.Prepare_Next` asks for at most `Engine.Current_Read_Chunk`:
  the negotiated limit, and no more than the credits on hand pay for, one
  credit at least. WRITE stayed at 64 KiB here: its body was built in a
  stack buffer and copied (`Body_Buffer`, `Payload`); #138 builds it in the
  output.
* Tests: `tests/credit_tests.adb` (counting, the reset on `Invalidate`,
  charges, the CreditRequest on the wire, the chunk limit, a 1 MiB READ in
  two requests or, without LARGE_MTU, sixteen, and chunks that shrink with
  small grants), and the integration client reads a 1 MiB file back in one
  call. The adversarial proxy clears LARGE_MTU in the SMB 2.1 NEGOTIATE
  response for `interrupted-read-after-progress`, `read-reserved-fields`
  and `lost-write-response-after-progress`, which need a transfer in
  several 64 KiB requests.
* `Credit_Target` (32) is what the CreditRequest asks to be back at; a
  server may grant more. Samba 4.19 grants the charge plus the request
  minus one, so the count grows by about fourteen per 960 KiB READ until
  Samba's limit. Credits in responses that are not authenticated (an
  interim response under signing alone, and the NEGOTIATE and first
  SESSION_SETUP responses of SMB 2.1) are counted as they are: an on-path
  attacker could inflate the count and get the connection dropped, a
  denial of service it can cause anyway.
* One receive deadline (`Timeout_Seconds`, 10 s by default) still covers a
  whole response, now up to 960 KiB. On a link slower than about
  0.8 Mbit/s, raise it.

## Multi-credit WRITEs (#138)

* A WRITE takes credits as a READ does: with LARGE_MTU, one per 64 KiB
  started, up to fifteen (`Maximum_Write_Chunk`, 960 KiB, which with the
  headers and a transform header fits a 1 MiB frame). `Parse_Response`
  clamps MaxWriteSize to it with the bit and to 64 KiB without;
  `Engine.Current_Write_Chunk` is `Current_Read_Chunk`'s twin, and
  `Begin_Request` charges a WRITE by its amount. A WRITE response's Count
  may now be up to 960 KiB.
* `Core_Client.Prepare_Next` builds the request body straight into
  `Output`, a WRITE's data straight from the transfer's buffer (no
  `Body_Buffer` or `Payload` copy any more).
* The library is built with `-gnata`, so postconditions are checked at run
  time, and a postcondition with `X'Old` copies X onto the stack. Every
  step that took the whole request `in out` (`Prepare_Header` and its
  `Core_Wire` calls, `Sign_Packet` and `Core_Wire.Sign`, and
  `Core_Protocol`'s field writers in `Build_Write`) kept such a copy, nested
  several deep: with 960 KiB WRITEs `Credit_Tests` needed 10 to 12 MiB of
  stack and overflowed the 8 MiB main thread. Now:
  * `Build_Write` writes the 48 fixed bytes through `Build_Write_Fixed`, on
    their own slice, and puts the data after them with one assignment.
  * `Prepare_Next` passes `Prepare_Header` the 64-byte header slice.
  * `Prepare_Next` signs with `Request_Signature`, which reads the request
    (`in`) and returns the signature through `Core_Wire.Compute_Signature`
    or `Compute_Signature_SMB3`; `Prepare_Next` zeroes the Signature field
    first and puts the result in place. `Sign` and `Sign_SMB3` are now
    built on the same two procedures.
* Measured with GNAT's task stack usage (`gnatbind -u`), `Credit_Tests`
  peaks at 4,931,212 bytes with this change and its 1 MiB WRITEs, and
  `main`'s at 4,931,036 with only 1 MiB READs: the WRITEs add nothing. The
  4.9 MB comes from before (see "Open items").
* Tests: `Credit_Tests` adds WRITE charges (fifteen credits for 960 KiB,
  three for 128 KiB and a byte, refusals past fifteen credits, of nothing,
  with too few credits and past 64 KiB without LARGE_MTU),
  `Current_Write_Chunk`, the MaxWriteSize clamp, and 1 MiB WRITEs through
  `SMB.Core_Client` (two requests with LARGE_MTU, sixteen without, and a
  512 KiB one whose chunks follow grants of 4, 2, 1 and 1), checking each
  request's data, signature, charge and CreditRequest on the wire.
  `Response_Mutation_Tests` accepts a WRITE Count up to 960 KiB and tests
  the cap. The integration client's 1 MiB write now goes in two WRITEs.

## Setting a file's size (#135)

* `SMB.Client.Set_Size` sends SET_INFO FileEndOfFileInformation (class 20,
  an eight-byte EndOfFile) through the new SPARK unit `SMB.Core_Resize`,
  built like `SMB.Core_Query` rather than as a third `Metadata_Kind` in
  `SMB.Core_Client`, whose proof takes about 40 minutes on the Mac.
* `Prepare` asks the engine for a handle that may write
  (`Validate_Handle (..., Need_Write => True)`), so a read-only handle is
  refused with `Invalid_State_Status` before any I/O, and refuses a size
  past 2**63 - 1 (EndOfFile is signed) with `Invalid_Value`, which the
  facade raises as `SMB.Protocol_Error`, as it does for a READ that is too
  long.
* `SMB.Core_Request` holds the header and signing steps that
  `SMB.Core_Query` kept its own copy of; both new units use it.
* The integration client truncates the 70,001-byte file to 1,000 bytes,
  extends it to 5,000 and reads zeros past 1,000, and checks the two local
  refusals. The async proxy's success workflow calls `Set_Size` as well.

## AES-256 primitives (#129)

* `SMB.AES.Expand_Key` takes a 16- or 32-byte `SMB.Bytes` key (its
  precondition) and expands it word by word as FIPS 197 5.2 does, so one
  loop serves both lengths: every Nk-th word takes SubWord (RotWord) and a
  round constant, and with AES-256 the word halfway between takes SubWord.
  The branches depend on the key's length, not its bytes. `Key_Schedule`
  holds 240 bytes and the round count; `Ready` is a count of 10 or 14.
* `SMB.AES.CCM` and `SMB.AES.GCM` take `Key : SMB.Bytes` with the same
  length precondition; their bodies were already independent of the key
  length. CMAC keeps `Key_128`: 3.1.1 signing is AES-128-CMAC under every
  cipher.
* `SMB.KDF.Derive_256` returns the whole HMAC-SHA256 block with L = 256
  (`00000100`). Both `Derive` and `Derive_256` call one `PRF_Block`.
* No AES-256 test vectors exist for SMB. The unit tests use FIPS 197 C.3,
  SP 800-38A F.1.5 and a 1,000-step chain for AES, test cases 13 to 16 of
  the GCM specification for GCM, and one CCM message and three L = 256 keys
  computed with `cryptography`, so `make test` covers AES-256 without
  Python. `gcm_conformance.py` checks `cryptography` against the same GCM
  test cases before using it; for CCM and the KDF it is the only reference.
* `crypto_probe` tells the key length from the fixture: a 32-byte AES key,
  a 32-byte key before the AEAD nonce, or a 32-byte expected KDF result.

## AES-256 in the protocol (#130)

* `SMB.Core_Negotiate.Cipher_Id` gains `AES_256_CCM` and `AES_256_GCM`; the
  enumeration's positions are the wire IDs 1 to 4. The request offers
  AES-128-GCM, AES-128-CCM, AES-256-GCM, AES-256-CCM, the Windows client's
  default order, so `Request_Length` grows from 102 to 106 and the
  NEGOTIATE packet from 166 to 170 bytes. A response may select 3 or 4.
* `SMB.Core_Transform.AEAD_Cipher` covers all four ciphers.
  `Key_Length (Cipher)` is 16 or 32, and `Seal` and `Unwrap` take
  `Key : SMB.Bytes` of that length (precondition).
* The engine stores the cipher keys as `SMB.AES.Key_256`. `Cipher_Key`
  (in the spec, so contracts can name it) is `Derive_256` under an AES-256
  cipher and `Derive` followed by 16 zero bytes otherwise; `Seal_Request`
  and `Unwrap_Response` pass the first `Key_Length` bytes. The signing key
  is `Derive` (L = 128) under every cipher.
* Tests: the transform tests loop over all four ciphers and add a check
  that the same mode under the other key length fails; the engine's
  encryption tests loop over all four with keys derived independently in
  the test; the negotiate tests accept cipher IDs 3 and 4 and refuse 5 and
  0xFFFF. Microsoft's A.1 request offers only the AES-128 ciphers, so only
  its preauth context is compared with ours now.
* Integration: `ADASMB_SMB_CIPHER` makes the Samba harness set
  `server smb3 encryption algorithms` to one cipher, and CI runs Samba with
  AES-256-GCM only and AES-256-CCM only. The Windows harness runs all four
  ciphers as the only one allowed. All passed on the first try.
* The signing key under AES-256 is L = 128, although MS-SMB2 3.1.4.2 reads
  as L = 256 for every key: Windows Server 2025 and Samba both sign the
  final SESSION_SETUP response with the L = 128 key, which the client
  verifies. Requests after authentication are encrypted, so the servers
  never check the client's signature under that key.

## AES-GMAC signing (#132)

* `SMB.AES.GCM.MAC` is GMAC, GCM with no data, and `MAC_Context`
  (`Start`, `Update`, `Finish`) its incremental form. GHASH pads only the
  last block, so `Update` requires the length so far to be a multiple of
  16; the pieces `Core_Wire` verifies (48 bytes, the 16-byte zero
  signature, the rest) meet that. The context keeps the hash subkey, the
  GHASH state and the encrypted first counter block, not the key schedule,
  and `Finish` wipes it.
* `SMB.Core_Negotiate.Signing_Id` is `HMAC_SHA256`, `AES_CMAC`,
  `AES_GMAC` (wire IDs 0 to 2), and `SMB3_Signing_Id` the last two. The
  request gains a SIGNING_CAPABILITIES context offering AES-GMAC, then
  AES-CMAC: `Request_Length` grows from 106 to 126 and the NEGOTIATE packet
  from 170 to 190 bytes, with `Request_Context_Count` 3.
  `Check_Response_Contexts` returns the algorithm, `AES_CMAC` without a
  signing context or on failure, and refuses HMAC-SHA256, unknown IDs, a
  count other than one and a second signing context.
* `SMB.Core_Wire.Sign_CMAC` and `Verify_Signature_CMAC` became `Sign_SMB3`
  and `Verify_Signature_SMB3` with an `Algorithm` parameter, with the same
  contracts. `GMAC_Nonce` builds the nonce from the header: the MessageId,
  then bit 0 from SMB2_FLAGS_SERVER_TO_REDIR (as Samba does) and bit 1 for
  command 12 (CANCEL), which the client never sends.
* The engine records the algorithm in `Mark_Negotiated`, which gained a
  `Signing` parameter. `Current_Signing` is the recorded algorithm under
  3.1.1 and `HMAC_SHA256` otherwise; its postcondition says so, which lets
  `Prepare_Close` pass it where it has just checked the dialect. Resets
  leave the field alone, because they set the dialect to 0, which hides
  it. `SMB.Client.Negotiated_Signing` reports it.
* No SMB message signed with AES-GMAC is published. GMAC is checked
  against the GCM specification's test case 1 and the first no-plaintext
  vectors of NIST's CAVP for AES-128 and AES-256, which
  `gcm_conformance.py` also checks `cryptography` against; SMB signing
  against `cryptography`, with a nonce built from the header as MS-SMB2
  3.1.4.1 says, and a signature over A.1's final SESSION_SETUP response
  computed with it.
* Integration: `ADASMB_SMB_SIGNING` makes the Samba harness set
  `server smb3 signing algorithms` to one algorithm, and the client must
  report it (`SMB_TEST_SIGNING`). CI runs the signing-only 3.1.1 Samba
  configuration with AES-128-GMAC only and with AES-128-CMAC only. The
  Windows harness requires AES-GMAC: Windows Server 2025 chooses it. With
  encryption on, Windows signs only the final SESSION_SETUP response, so
  the requests signed with AES-GMAC are tested against Samba.

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
  * a changed-line mutation run (CI runs it), whose undetected mutants and
    proof-only detections the pull request lists with a judgement for each.
* `smb.gpr` compiles with `-gnat2012`, so `src/` cannot use Ada 2022
  features such as iterated component aggregates. `proof.gpr` uses
  `-gnat2022`.
* Mutation triage rules, since #137 (AdaMutant with the proof, no
  exclusion comments; the maintainer's decision: survivors are not a
  failure, a person judges them):
  * The tests run first, and a mutant they miss goes to GNATprove
    (`tests/mutant_prove.py`). The job summary lists what neither detects
    and what only the proof detects, the latter in AdaMutant's groups:
    confirmed (a counterexample ran with the real code), a contract that
    says too little, and undecided. A proof that runs out of time counts
    as undetected.
  * A real gap that the tests can observe gets a test, also when only the
    proof detected it.
  * A contract that says too little is made stronger where that is worth
    it.
  * Dead code, and a check that only duplicates another layer's check, may
    be removed if the unit still proves.
  * What remains, such as an equivalent mutant the object-code comparison
    does not catch, is left as it is and judged in the pull request. There
    are no `adamutant:disable` comments any more: #137 removed all 706.

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

* A 1 MiB `Read` or `Write` through `SMB.Client` takes several MB of stack
  in a `-gnata` build: `Credit_Tests` peaks at about 4.9 MB, before and
  after #138. Where it goes has not been broken down; the likely source is
  the postconditions that copy the whole transfer buffer for
  `Transfer_Buffer_Of (Value)'Old` (`Prepare_Next`,
  `Transfer_Send_Succeeded`, `Complete_Read`, `Complete_Write`). A task
  that calls them needs a stack to match.

* The design document's open question: whether `Connect` should send
  NETNAME. Samba and Windows Server 2025 do not need it.
* One AdaMutant survivor seen on macOS did not reproduce on Windows and was
  never investigated. The weekly mutation run shows whether it comes back.
