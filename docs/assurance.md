# SPARK assurance

This is a **proved-core / trusted-adapter architecture**, not a proof of every
public Ada API statement or of the operating system. See the exact run results
in [proof-report.md](proof-report.md) and the intended properties in
[assurance-design.md](assurance-design.md). A green build or Samba test does not
replace a successful GNATprove run.

## Executable proof scope

`proof.gpr` explicitly includes ten units (nine bodies plus `SMB`'s types).
These are the implementations called by `SMB.Client`, not a parallel model.

| Unit | Runtime responsibility |
| --- | --- |
| `SMB` | Fixed-width integers, bytes, frame limit and statuses |
| `SMB.Crypto` | MD4, MD5, SHA-256, HMACs and digest comparison; run-time safety, not cryptographic hardness |
| `SMB.Core_Text` | Strict UTF-8/UTF-16 conversion, NTLM ASCII username uppercase, path/share validation |
| `SMB.Core_NTLM` | Strict DER/SPNEGO challenge extraction, directional mechanism-list MIC and final-token validation |
| `SMB.Core_Auth` | Type 2/security-buffer/AV validation, NTLMv2 proof, Type 3 and its MIC, session key and SPNEGO output |
| `SMB.Core_Wire` | Bounded integer readers/writers, SMB header construction/correlation validation and signing |
| `SMB.Core_Framing` | Direct TCP session header encoding/decoding and 64-byte through 1-MiB frame bounds |
| `SMB.Core_Protocol` | Operation request builders and response-body parsers, directory entry/UTF validation, transfer arithmetic and pagination limits |
| `SMB.Core_Client` | Typed SESSION_SETUP authentication lifecycle; CREATE/CLOSE lifecycle; bounded READ/WRITE transfer state; bounded directory-query lifecycle, owned page snapshot, pagination and entry progress; bounded SET_INFO disposition/rename lifecycle; packet construction/signing, send acknowledgement, validated completion and handle identity/receipt updates |
| `SMB.Engine` | Phases, pending requests, signed response acceptance, single-use response receipts and handle identity/lifetime |

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
partial WRITE counts advance only by the validated response count. An uncertain
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
retaining trusted path and object-lifetime orchestration. `Connect`,
`Connect_Share`, and `Disconnect` remain on the legacy `Exchange` adapter.

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

| Package | Subprograms | Trusted responsibility |
| --- | --- | --- |
| `SMB.Transport` | `Wait_For`, `Read_Exact`, `Write_Exact`, `Connect`, `Send_Frame`, `Receive_Frame`, `Close`, `Is_Open` | GNAT sockets/selectors, nonblocking I/O, deadlines, allocation and copying. Frame type/length use `Core_Framing`. DNS resolution is outside the deadline. |
| `SMB.Clock` | `Is_Leap_Year`, `Current_Filetime` | OS calendar and FILETIME conversion |
| `SMB.NTLM` | `Negotiate_Token`, `Authenticate` | Allocation, `Core_Auth` dispatch and exceptions |
| `SMB.Text` | `Check`, `To_UTF16LE`, `From_UTF16LE`, `NTLM_Username` | Public allocation/exception adapters to `Core_Text` |
| `SMB.Wire` | `Check`, `U16`, `U32`, `U64`, `Put_U16`, `Put_U32`, `Put_U64`, `Initialize_Header`, `Validate_Header`, `Sign`, `Verify_Signature` | Public exception adapters to `Core_Wire` |
| `SMB.Client` | `Copy_Bytes`, `Slice`, `Encode_Name`, `Decode_Name`, `Read.Checked_Length`, `Write.Checked_Length` | Allocation, checked copying/slicing and text-container conversion |
| `SMB.Client` | `Session_Identifier`, `Tree_Identifier`, `Last_NT_Status`, `Is_Connected` | Accessors to engine state or facade diagnostics |
| `SMB.Client` | `Generate_Entropy`, `Get_Entropy` | OS CSPRNG or caller-provided entropy callback; no deterministic fallback |
| `SMB.Client` | `Clear_State`, `Clear_State_Preserving_Status`, `Require_Status`, `Require_Transfer_Status`, `Require_Authentication_Status`, `Cleanup_Close`, `Finalize` | Cleanup and exception/NTSTATUS translation; finalization cannot report exceptions |
| `SMB.Client` | `Exchange`, `Check_Handle`, `Validated_Path`, `Require_Relative_Share` | Core dispatch, frame assembly/copying, socket invocation and error translation |
| `SMB.Client` | `Disposition_Value` | Public enum mapping |
| `SMB.Client` | `Create_Internal`, `Close_Internal` | Socket send/receive orchestration around the typed coordinator, exact returned packet slicing, status/exception translation and abort cleanup |
| `SMB.Client` | `Read`, `Write` | I/O pump around the typed coordinator, exact returned packet forwarding, allocation, exception/NTSTATUS translation, and cleanup of invalidated transports |
| `SMB.Client` | `Authenticate` | I/O pump for `SMB.Core_Client` authentication steps; caller/OS entropy, clock input, exception/NTSTATUS translation and transport cleanup |
| `SMB.Client` | `List_Directory` | Trusted folder lifetime and cleanup, UTF-16 decoding, dot-entry filtering, vector allocation/insertion, exception translation and socket pumping around the typed directory coordinator. |
| `SMB.Client` | `Open_File`, `Close`, `Make_Directory`, `Remove_File`, `Remove_Directory` | Public wrappers over typed CREATE/CLOSE/SET_INFO flows; path validation/conversion, local object and temporary-handle lifetime, cleanup, and exception/NTSTATUS translation remain trusted. |
| `SMB.Client` | `Connect`, `Connect_Share`, `Disconnect` | Legacy operation sequencing and recovery through the trusted `Exchange` adapter. |
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
* An entire read/write API operation is capped at 1 MiB, each wire I/O chunk at
  64 KiB, encoded names at 65,534 bytes, open handles at 256, directory pages at
  4,096 and directory entries at 100,000. Exhaustion is reported, not wrapped.
* Timeouts apply per complete sent/received frame, not to an entire multi-request
  API call. Timeout/backpressure behavior is tested, not proved.
* Cryptographic hardness, generated machine code's timing/side-channel resistance,
  secure key erasure, FIPS certification, complete SMB conformance, all servers
  and Windows-native operation are not established.
* The SET_INFO coordinator proves bounded disposition/rename body construction,
  signed command-17 request framing, validated response correlation and
  single-use receipt consumption while preserving validated file/directory
  handle identity. The facade pump remains trusted. Integration demonstrates a
  remote rename effect even when a deliberately malformed signed response
  causes local `Protocol_Error` and disconnect; rollback and exactly-once
  semantics are not claimed.
* No `Assume`, `False_Positive`, or SPARK-off body substitutes for proof.
  `make prove` uses checks-as-errors. CI is not run automatically.
