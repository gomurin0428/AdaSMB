# GNATprove and test report

## Latest complete proof: Windows default entropy and authentication diagnostics

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
