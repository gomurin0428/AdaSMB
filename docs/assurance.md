# SPARK assurance

This is a **proved-core / trusted-adapter architecture**, not a proof of every
public Ada API statement or of the operating system. See the exact run results
in [proof-report.md](proof-report.md) and the intended properties in
[assurance-design.md](assurance-design.md). A green build or Samba test does not
replace a successful GNATprove run.

## Executable proof scope

`proof.gpr` explicitly includes thirteen units (twelve bodies plus `SMB`'s types).
These are the implementations called by `SMB.Client` and `SMB.Transport`, not a
parallel model.

| Unit | Runtime responsibility |
| --- | --- |
| `SMB` | Fixed-width integers, bytes, frame limit and statuses |
| `SMB.Crypto` | MD4, MD5, SHA-256, SHA-512, HMACs and digest comparison; run-time safety, not cryptographic hardness |
| `SMB.AES` | AES-128 encryption with a computed S-box, for SMB 3.1.1; run-time safety, not cryptographic hardness or timing |
| `SMB.Core_Text` | Strict UTF-8/UTF-16 conversion, NTLM ASCII username uppercase; exact lexical path/share acceptance, byte-preserving slash normalization, and zeroed invalid-path output |
| `SMB.Core_NTLM` | Strict DER/SPNEGO challenge extraction, directional mechanism-list MIC and final-token validation |
| `SMB.Core_Auth` | Bounded credential preflight, Type 2/security-buffer/AV validation, NTLMv2 proof, Type 3 and its MIC, session key and SPNEGO output |
| `SMB.Core_Wire` | Exact integer read/write success and rejection with zeroed read failures and unchanged write failures; header initialization, correlation validation and signing |
| `SMB.Core_Framing` | Exact 24-bit big-endian TCP frame length encoding/decoding, 64-byte through 1-MiB bounds, type/length status precedence, and zero outputs on failure |
| `SMB.Core_Transport` | Native stream frame construction, exact receive-prefix copying with prefix/tail preservation, bounded partial-read/write progress and unsent-slice selection |
| `SMB.Core_Clock` | Validated Gregorian date-to-FILETIME arithmetic, seconds-of-day/leap-second normalization, and exact 100-ns subsecond truncation |
| `SMB.Core_Protocol` | Operation request builders and response-body parsers, directory entry/UTF validation, exact directory-link progress and termination, transfer arithmetic and pagination limits |
| `SMB.Core_Client` | Typed SESSION_SETUP authentication lifecycle; CREATE/CLOSE lifecycle; bounded READ/WRITE transfer state; bounded directory-query lifecycle, owned page snapshot, pagination and entry progress; bounded SET_INFO disposition/rename lifecycle; packet construction/signing, send acknowledgement, validated completion and handle identity/receipt updates |
| `SMB.Core_Connection` | Bounded NEGOTIATE, TREE_CONNECT, TREE_DISCONNECT, and LOGOFF lifecycle; request construction/signing, send acknowledgement, response correlation, receipt consumption, and phase-specific transitions |
| `SMB.Engine` | Phases, pending requests, signed final-response acceptance, SMB 2.1 async-interim correlation, single-use response receipts and handle identity/lifetime |

Supported response bodies are parsed in the core after header/correlation and
required signature validation. A successful final Session Setup also needs the
server-to-client SPNEGO MIC. The first unsigned challenge cannot authenticate a
connection. CREATE and CLOSE state updates are coupled to the matching receipt;
malformed responses invalidate the engine and its handles. Core procedures return
status values for malformed input. Inputs must meet documented **resource/array
bounds**, not an assumption that a peer packet is well formed. The transport caps
received allocations before invoking the core. Public CREATE/CLOSE and READ/WRITE
paths use `SMB.Core_Client` for packet construction, signing and request
lifecycles. Authentication sequencing, challenge-token ownership, session-key
installation, and completion based on the Engine's signed response receipt are
in the proved core. The facade supplies entropy and clock input, pumps socket
frames, translates exceptions, and closes the transport when the engine is
invalidated. The bounded transfer state owns progress, the immutable WRITE
snapshot, and accumulated READ bytes; each chunk is at most 64 KiB and a transfer
is at most 1 MiB. READ short/zero responses finish normally, while positive
partial WRITE counts advance only by the validated response count. Reserved
fields in NEGOTIATE, TREE_CONNECT, READ, ERROR, CLOSE, TREE_DISCONNECT and LOGOFF
are ignored as required for SMB 2.1. Except for the unsigned SMB 2.1 NEGOTIATE
response, their bytes remain covered by response MAC verification. No zero-value
property is claimed for these ignored fields. Nonzero ERROR context counts and
unsupported CLOSE flags remain rejected. An uncertain
send/receive or malformed response aborts the Engine state without retry; the
facade closes its transport. The adapter still owns socket I/O, forwarding the
exact returned packet slice, allocation, exception translation and public
container lifetime. The directory coordinator owns the QUERY_DIRECTORY
sequence, restart flag, bounded 64-KiB validated page snapshot, entry cursor,
and page/entry limits. It validates and copies each page before parsing entries
from the owned snapshot. `List_Directory` pumps socket frames and extracts
owned UTF-16 names; decoding, dot-entry filtering, vector insertion, folder
lifetime, and cleanup remain trusted facade responsibilities.

`SMB.Client` disposition and rename paths now use the separate
`SMB.Core_Client.Metadata_Operation` lifecycle for SET_INFO request construction,
signing, response validation, and receipt consumption. `Execute_Metadata`
remains a trusted socket pump; path validation and UTF-16 conversion,
allocation, temporary-handle lifetime, cleanup, and exception/NTSTATUS
translation stay in the facade. Engine access flags do not prove DELETE
authorization, and no server-side effect, rollback, or exactly-once guarantee
is claimed. The public `Open_File`, `Close`, `Make_Directory`, `Remove_File`,
and `Remove_Directory` wrappers use typed CREATE/CLOSE/SET_INFO flows while
retaining trusted path and object-lifetime orchestration.

The connection lifecycle uses the separate `SMB.Core_Connection` operation
coordinator for bounded NEGOTIATE, TREE_CONNECT, TREE_DISCONNECT, and LOGOFF
construction, signing, response validation, receipt handling, and Engine
transitions. `Execute_Connection` is the trusted socket pump. OS socket setup,
entropy, share-path validation/encoding, allocation, exception handling, and
public facade correctness remain outside the proof. Successful TREE_DISCONNECT
and LOGOFF use the Engine transitions performed by response acceptance; valid
NTSTATUS errors consume one receipt while preserving the connection context.
Malformed or uncertain responses invalidate local state. No remote rollback or
exactly-once behavior is claimed.

For authenticated LOGOFF, TREE_DISCONNECT, CREATE, CLOSE, READ, WRITE,
QUERY_DIRECTORY, and SET_INFO commands, the Engine records a nonzero AsyncId
only after validating the correlated `STATUS_PENDING` header and bounded ERROR
body. The interim is intentionally not signature-verified as required by SMB2;
it does not create a receipt, expose its status, or advance transfer progress.
The matching async final is validated and signature-verified over the original
received bytes before parsing. A missing interim, changed AsyncId, mismatched
request/session correlation, or invalid final signature fails closed and
invalidates local handles. This behavior does not authenticate an unsigned
interim.

The facade remains synchronous and keeps one outstanding request. One absolute
receive deadline covers all interim frames and the final response; an interim
does not renew it. Credit handling remains the existing single-request profile:
first interim credit must be positive, a repeat may grant zero, an async final
must grant zero, and synchronous responses must grant positive credit. This is
not a full credit-window implementation. Async NEGOTIATE, SESSION_SETUP, and
TREE_CONNECT, SMB3, compounds, cancellation, concurrent requests, and transport
timing guarantees are outside this proof boundary.
Normative references and observed validation results are listed in the
[proof report](proof-report.md#smb-21-asynchronous-interim-responses).

The transport's real `Read_Exact`, `Write_Exact`, and `Send_Frame` paths use
`SMB.Core_Transport`. The core builds the native `Ada.Streams` array directly,
binding every payload byte and all four TCP prefix bytes to the input packet.
Receive copying accepts only a positive count within both the supplied native
chunk and the destination's remaining capacity. It preserves previous bytes
and the unused tail; rejected counts change neither the buffer nor progress.
Write progress accepts only a last index within the current unsent slice and
computes the cumulative offset without resending a confirmed prefix. Core
resource bounds allow the 1-MiB packet plus its four-byte prefix and nonzero
array lower bounds. This is not a proof of the socket result itself: the
adapter must supply the actual returned index and valid initialized bytes.
Socket pumps, retry decisions, deadlines and exception cleanup remain trusted.

Prefix-processing loop invariants in `Core_Transport` and `Core_Text` use
runtime assertion policy `Ignore` to avoid repeatedly rescanning a growing prefix. This does **not**
remove them from GNATprove: their initialization and preservation are proved,
as specified by [AdaCore's assertion-policy documentation](https://docs.adacore.com/spark2014-docs/html/ug/en/source/assertion_pragmas.html).
Compiler run-time checks and pre/postcondition checking remain enabled in the
project builds; no proof assumption or check-suppression pragma is introduced.

`Validate_Path` now binds status to the executable `Lexically_Valid_Path`
predicate: empty input is allowed only on request; NUL, colon, leading/trailing
or repeated separators, and exact `..` components are rejected. Success changes
only forward slashes to backslashes, preserving every other byte and its
relative position even with different array lower bounds. Failure clears the
entire output rather than exposing a partial normalized name. Single-dot
components and names merely containing dots retain their existing acceptance.
`Validate_Share` similarly binds status to nonempty input without NUL, colon,
or separators. The path copy's prefix invariant is proved by GNATprove and
locally ignored at runtime to avoid quadratic scans; runtime bounds and
pre/postconditions remain enabled. These are lexical byte rules, not proof of
Unicode conversion semantics, server canonicalization, symlink/DFS behavior,
or filesystem containment.

Public path APIs now complete lexical validation and UTF-16 encoding in their
declaration preflight before entering communication/cleanup handlers.
`Create_Internal` accepts the resulting bounded encoded name instead of
encoding raw input inside an outer operation's handler. Thus local malformed
UTF-8 or encoded-length errors do not accidentally trigger the disconnect
policy for protocol/transport failures during enumeration or rename. Temporary
folder/file acquisition also follows buffer initialization. This is reviewed
and regression-tested native adapter ordering, not an extension of the SPARK
proof or a proof of allocation/exception behavior.

`Connect_Share` likewise validates the share name and encodes the UNC path in
declaration preflight. Local syntax, length or UTF errors preserve the
authenticated/share-connected session and last NTSTATUS; regression tests
also check that an existing handle remains usable. The post-send abort and
disconnect policy is unchanged. This remains native adapter testing, not a
formal proof of the facade's exception semantics.

`Authenticate` similarly invokes `Core_Auth.Validate_Credentials` before
SESSION_SETUP and outside its communication handler when the session is ready
for authentication. That stateless core helper proves run-time safety and
accepted credential size bounds; the existing text converters determine
supported encodings. A local credential rejection leaves the negotiated
connection available for corrected input. Other starting states retain
`Invalid_State` precedence. Server-dependent failures and post-send cleanup
are unchanged. Wrapper ordering, complete Unicode semantics and secure erasure
of credential scratch storage remain outside the proof.

UTF conversion checks capacity for each decoded scalar rather than requiring a
worst-case-size buffer before decoding. The contracts bound `Used` by both the
output capacity and twice the input length, including on failure; UTF-16 output
is always word-aligned. Successful conversion is empty exactly when its input
is empty, and successful UTF-16 input is even-length. Scalar-atomic short-buffer
behavior and exact encoding bytes are tested, not a complete Unicode semantic
proof. Callers must discard partial output on error. The public text adapters
check the 1-MiB input bound before allocating worst-case-sized result buffers;
these adapter guards are reviewed/tested rather than GNATprove-verified.

Proof covers language-defined run-time checks, initialization, flow analysis and
the contracts actually written in the source. It does not prove that every
encoded bit matches SMB, or that a hash has the mathematical/security properties
of its standard. Known-answer vectors and interoperation tests supply different
evidence.

## Remaining non-SPARK code: complete subprogram inventory

These bodies are **not** GNATprove-verified. Their correct use of the core is a
trusted assumption checked by review and tests. The facade still owns operation
sequencing and buffer copying; calling it just an OS syscall shim would
understate this boundary.

`SMB.Clock.Current_Filetime` now calls `SMB.Core_Clock` for all calendar,
seconds-of-day and subsecond arithmetic. The core accepts Gregorian dates in
1601..9999, seconds in 0..86400 and ticks in 0..9999999, rejects invalid parts
before arithmetic, and binds successful output to the explicit signed-64-bit
FILETIME formula. The fractional contract proves the floor interval, including
the last nanoseconds before a new second; it never rounds up to 10000000 ticks.
The build explicitly requires `Duration'Small = 1ns`. A leap-second flag from
Ada.Calendar is normalized by adding one second, as before (86400 maps to the
next day). No validation of historical leap-second dates, OS clock correctness,
or monotonicity is claimed. Clock retrieval, UTC splitting and exception dispatch
remain trusted.

| Package | Subprograms | Trusted responsibility |
| --- | --- | --- |
| `SMB.Transport` | `Wait_For`, `Read_Exact`, `Write_Exact`, `Connect`, `Send_Frame`, `Receive_Frame`, `Close`, `Is_Open` | GNAT sockets/selectors, nonblocking I/O, deadlines, allocation/initialization, slice dispatch, retry and exception cleanup. Native frame copying and progress use `Core_Transport`; frame type/length use `Core_Framing`. DNS resolution is outside the deadline. |
| `SMB.Heap_Owner` | `Release`, `Finalize` | Frees the heap buffers and coordinators of `SMB.Client` and `SMB.Transport` when their subprogram is left, also by an exception, and erases authentication requests first. Ada finalization and deallocation are trusted. |
| `SMB.Clock` | `Current_Filetime` | OS calendar retrieval/UTC splitting, core dispatch and exception translation; date/seconds/subseconds arithmetic uses `Core_Clock` |
| `SMB.NTLM` | `Negotiate_Token`, `Authenticate` | Allocation, `Core_Auth` dispatch and exceptions |
| `SMB.Text` | `Check`, `Output_Capacity`, `To_UTF16LE`, `From_UTF16LE`, `NTLM_Username` | Public input-limit checks before multiplication/allocation, allocation/exception adapters to `Core_Text` |
| `SMB.Wire` | `Check`, `U16`, `U32`, `U64`, `Put_U16`, `Put_U32`, `Put_U64`, `Initialize_Header`, `Validate_Header`, `Sign`, `Verify_Signature` | Public exception adapters to `Core_Wire` |
| `SMB.Client` | `Slice`, `Encode_Name`, `Decode_Name`, `Read.Checked_Length`, `Write.Checked_Length` | Allocation, checked copying/slicing and text-container conversion |
| `SMB.Client` | `Last_NT_Status`, `Last_Unverified_Authentication_Status`, `Is_Connected` | Accessors to engine state or facade diagnostics |
| `SMB.Entropy`, `SMB.Client` | `Generate`, `Get_Entropy` | Unix Stream_IO or Windows BCryptGenRandom OS binding, ABI and OS CSPRNG or caller-provided callback; no deterministic fallback |
| `SMB.Client` | `Clear_State`, `Clear_State_Preserving_Status`, `Require_Status`, `Require_Transfer_Status`, `Require_Authentication_Status`, `Cleanup_Close`, `Finalize` | Cleanup and exception/NTSTATUS translation; finalization cannot report exceptions |
| `SMB.Client` | `Check_Handle`, `Validated_Path`, `Require_Relative_Share` | Core dispatch for handle/path validation and error translation |
| `SMB.Client` | `Disposition_Value` | Public enum mapping |
| `SMB.Client` | `Create_Internal`, `Close_Internal` | Socket send/receive orchestration around the typed coordinator, exact returned packet slicing, status/exception translation and abort cleanup |
| `SMB.Client` | `Read`, `Write` | I/O pump around the typed coordinator, exact returned packet forwarding, allocation, exception/NTSTATUS translation, and cleanup of invalidated transports |
| `SMB.Client` | `Authenticate` | I/O pump for `SMB.Core_Client` authentication steps; caller/OS entropy, clock input, exception/NTSTATUS translation and transport cleanup |
| `SMB.Client` | `List_Directory` | Trusted folder lifetime and cleanup, UTF-16 decoding, dot-entry filtering, vector allocation/insertion, exception translation and socket pumping around the typed directory coordinator. |
| `SMB.Client` | `Open_File`, `Close`, `Make_Directory`, `Remove_File`, `Remove_Directory` | Public wrappers over typed CREATE/CLOSE/SET_INFO flows; path validation/conversion, local object and temporary-handle lifetime, cleanup, and exception/NTSTATUS translation remain trusted. |
| `SMB.Client` | `Connect`, `Connect_Share`, `Disconnect`, `Execute_Connection` | Trusted OS socket/entropy setup, share path encoding, exact returned packet slicing and socket pumping, exception/NTSTATUS translation, best-effort TREE_DISCONNECT/LOGOFF ordering, and transport cleanup. |
| `SMB.Client` | `Execute_Metadata`, `Set_Disposition`, `Rename` | Trusted SET_INFO socket orchestration, path validation and UTF-16 encoding, allocation, temporary-handle lifetime, cleanup, and exception/NTSTATUS translation. DELETE authorization and server-side disposition/rename effects are outside the proof. |

Tests and the example are outside the proof project. Their successful execution
does not make the above bodies formally verified.

## Preconditions and non-claims

* Calls allocating owner IDs (including `Client.Connect` for different
  connections) must be externally serialized. Each connection is single-task-at-
  a-time; connection/handle objects are limited and not copyable. No concurrency
  proof is claimed.
* GNAT/GNATprove, SMT solvers, Ada runtime, compiler translation, OS socket,
  clock and entropy behavior, available stack/heap, and adapter conformance are
  trusted. A finite resource bound does not guarantee allocation will succeed.
* Stack usage is outside GNATprove's scope. `make stack-check` sums the largest
  static frame chain below each public `SMB.Client` subprogram from GCC
  call-graph data (GNAT runtime frames and the indirect entropy callback are not
  counted) and enforces 256 KiB per call (the largest is `Authenticate` at
  about 229 KiB), all with runtime contract checks enabled. `Core_Auth` writes
  the SPNEGO wrapping and the NTLMv2 blob in place and computes HMAC-MD5 over
  the challenge, the blob and the Type1/Type2/Type3 messages incrementally, so
  no stack frame on the NTLM path grows with the server's challenge or target
  information. Postconditions keep pre-state values as
  `F (State)'Old` rather than `F (State'Old)`, so the runtime check stores a
  function result instead of a copy of the whole engine state; only two-state
  relations and `State = State'Old` copy it. The check also rejects
  runtime-sized frames in `SMB.Client` and `SMB.Transport` other than those
  sized by host, path, name or exception-message strings: frame-, packet-,
  transfer-, request- and directory-sized buffers there are heap-allocated and
  held by `SMB.Heap_Owner` owners, which free them on every exit path, the
  directory listing result is built on the secondary stack, and sockets are
  read in 16-KiB chunks. The secondary stack (unconstrained function results
  such as received frames and directory listings) is not counted; on the
  native GNAT 14.2 runtime it grows from the heap, and a 100,000-entry listing
  (about 3.2 MB) returned this way succeeded in a task with a 256-KiB stack. SHA-256 and
  HMAC-SHA256 absorb input in 64-byte blocks, and `Core_Wire.Verify_Signature`
  feeds the response to an incremental HMAC in three pieces (before, zeroed,
  after the signature field) instead of copying it; the check also requires
  those frames, the MD5/HMAC-MD5 frames and `Core_Auth.Authenticate`,
  `Process_Target_Info` and `Build_Type3` to stay fixed-size, because the peer
  chooses those lengths (for responses, before the signature is known to be
  valid).
* An entire read/write API operation is capped at 1 MiB, each wire I/O chunk at
  64 KiB, encoded names at 65,534 bytes, open handles at 256, directory pages at
  4,096 and directory entries at 100,000. Exhaustion is reported, not wrapped.
* For each request, one absolute receive deadline covers interim frames and the
  final response; multi-request API operations keep their existing per-frame
  budget. Timeout/backpressure behavior is tested, not proved.
* Cryptographic hardness, generated machine code's timing/side-channel resistance,
  secure key erasure, FIPS certification, complete SMB conformance, all servers
  and all Windows versions/configurations are not established.
* The SET_INFO coordinator proves bounded disposition/rename body construction,
  signed command-17 request framing, validated response correlation and
  single-use receipt consumption while preserving validated file/directory
  handle identity. The facade pump remains trusted. Integration demonstrates a
  remote rename effect even when a deliberately malformed signed response
  causes local `Protocol_Error` and disconnect; rollback and exactly-once
  semantics are not claimed.
* No `Assume`, `False_Positive`, or SPARK-off body substitutes for proof.
  `make prove` uses checks-as-errors. GitHub Actions runs the builds, unit,
  conformance and transport tests (Linux and Windows) and the Samba
  integration test (Linux) on pushes to `main` and pull requests, and the full
  proof weekly and on demand; see `.github/workflows`.
* Mutation testing (AdaMutant, configured in `adamutant.toml`) measures how
  much of the executable library code the unit and conformance tests
  constrain. It mutates only executable code, not contracts or ghost code, and
  runs `test_suite` and the conformance tests of the mutated unit, so a mutant
  that only the Samba integration test would catch is reported as surviving.
  The socket facade (`SMB.Client`, `SMB.Transport`) is left out for that
  reason. It says nothing about the proofs.

## Unverified authentication diagnostics

`Core_Client.Unverified_Authentication_Status` is a read-only SPARK helper. It
requires the current sent authentication context, matches the unsigned response
header against the pending request, parses the error body and returns only an
error-severity NTSTATUS (or zero). Its contract establishes bounded access and
correspondence to the packet status, not authenticity. It never creates a receipt,
changes Engine state or marks a session authenticated. Normal `Complete_Authenticate`
still rejects the response and invalidates keys/state. The trusted facade saves
the hint separately across that failure cleanup and labels the exception text
"unverified". `Last_NT_Status` semantics and all signature/MIC requirements remain
unchanged. Connect/Disconnect clear the hint. This is not a verified server error.

The Windows OS binding is outside SPARK, like the Unix entropy adapter. The source
audit permits only that named `BCryptGenRandom` import rather than permitting
foreign calls throughout the protocol/crypto implementation.
