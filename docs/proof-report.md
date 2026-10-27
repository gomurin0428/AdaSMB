# GNATprove and test report

## Final clean proof

`gnatprove -P proof.gpr --clean` and the subsequent complete `make prove`
run passed for the UTF-capacity implementation
[`429c98d`](https://github.com/gomurin0428/AdaSMB/commit/429c98d4072a20aa6fbbe35f409d6a9a0c159e2e).
GNATprove analyzed all thirteen configured units:
`SMB`, `SMB.Core_Auth`, `SMB.Core_Client`, `SMB.Core_Clock`, `SMB.Core_Connection`, `SMB.Core_Framing`,
`SMB.Core_NTLM`, `SMB.Core_Protocol`, `SMB.Core_Text`, `SMB.Core_Transport`, `SMB.Core_Wire`,
`SMB.Crypto` and `SMB.Engine`.

| Category | Total | Flow | Proved by provers |
| --- | ---: | ---: | ---: |
| Data dependencies | 1 | 1 | 0 |
| Flow dependencies | 1 | 1 | 0 |
| Initialization | 538 | 538 | 0 |
| Non-aliasing | 2 | 2 | 0 |
| Run-time checks | 2,398 | 0 | 2,398 |
| Assertions | 301 | 0 | 301 |
| Functional contracts | 987 | 0 | 987 |
| Termination | 159 | 153 | 6 |
| **Total** | **4,387** | **695** | **3,692** |

There were zero unproved and zero justified checks. All configured units and
subprograms were analyzed; none were reported skipped. GNATprove reported
60 flow-analysis warnings (54 in `SMB.Core_Client`, 6 in
`SMB.Core_Protocol`), primarily unused assignments and status outputs, and
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
