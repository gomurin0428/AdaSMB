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
| `SMB.Core_Client` | Typed, receipt-gated CREATE/CLOSE preparation, signing, send acknowledgement, completion, handle registration and close-token consumption |
| `SMB.Engine` | Phases, pending requests, signed response acceptance, single-use response receipts and handle identity/lifetime |

Supported response bodies are parsed in the core after header/correlation and
required signature validation. A successful final Session Setup also needs the
server-to-client SPNEGO MIC. The first unsigned challenge cannot authenticate a
connection. CREATE and CLOSE state updates are coupled to the matching receipt;
malformed responses invalidate the engine and its handles. Core procedures return
status values for malformed input. Inputs must meet documented **resource/array
bounds**, not an assumption that a peer packet is well formed. The transport caps
received allocations before invoking the core. The CREATE/CLOSE facade path now
uses `SMB.Core_Client` for the complete bounded packet and lifecycle; the adapter
still owns socket I/O, exact-slice forwarding, allocation, exception translation
and container lifetime. Other public operation paths remain on the legacy
`SMB.Client.Exchange` adapter and are not claimed as migrated by this stage.

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
| `SMB.Client` | `Copy_Bytes`, `Slice`, `Encode_Name`, `Decode_Name`, `Read.Checked_Length` | Allocation, checked copying/slicing and text-container conversion |
| `SMB.Client` | `Session_Identifier`, `Tree_Identifier`, `Read_Limit`, `Write_Limit`, `Last_NT_Status`, `Is_Connected` | Accessors to engine state or facade diagnostics |
| `SMB.Client` | `Generate_Entropy`, `Get_Entropy` | OS CSPRNG or caller-provided entropy callback; no deterministic fallback |
| `SMB.Client` | `Clear_State`, `Clear_State_Preserving_Status`, `Require_Status`, `Cleanup_Close`, `Finalize` | Cleanup and exception/NTSTATUS translation; finalization cannot report exceptions |
| `SMB.Client` | `Exchange`, `Check_Handle`, `Validated_Path`, `Require_Relative_Share` | Core dispatch, frame assembly/copying, socket invocation and error translation |
| `SMB.Client` | `Disposition_Value` | Public enum mapping |
| `SMB.Client` | `Create_Internal`, `Close_Internal` | Socket send/receive orchestration around the typed coordinator, exact returned packet slicing, status/exception translation and abort cleanup |
| `SMB.Client` | `Set_Disposition`, `Connect`, `Authenticate`, `Connect_Share`, `Open_File`, `Read`, `Write`, `Close`, `List_Directory`, `Make_Directory`, `Remove_File`, `Remove_Directory`, `Rename`, `Disconnect` | Legacy operation sequencing, local object/collection lifetime and recovery. These paths remain unmigrated; their existing `Exchange` adapter is outside this CREATE/CLOSE proof scope. |

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
* No `Assume`, `False_Positive`, or SPARK-off body substitutes for proof.
  `make prove` uses checks-as-errors. CI is not run automatically.
