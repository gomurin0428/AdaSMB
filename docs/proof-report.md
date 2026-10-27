# GNATprove and test report

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

Candidate GNAT14 Python syntax compilation and the combined
`test_suite.adb`/`cleanup_client.adb` build passed. The
`directory-bounds` selector passed **6,616 cases**. Focused
`ADASMB_DIRECTORY_ONLY=1` Samba integration passed all six directory mutations:
the two existing offset cases and the four new name cases.

The single requested sensitivity mutant built successfully. With only the
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
