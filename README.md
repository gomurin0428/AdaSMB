# AdaSMB

English | [日本語](README.ja.md)

AdaSMB is a synchronous SMB 2.1 (dialect `0x0210`) client library implemented
with only GNAT's regular Ada runtime. It is not a sample that merely builds SMB
packets: it implements NTLMv2 authentication, signed sessions, file I/O and
directory operations.

## Scope

* SMB 2.1 only, over TCP port 445 (the API can change the port).
* NTLMv2 inside SPNEGO only. User names are limited to ASCII, because the
  library does not carry the complete Windows upper-case table for Unicode
  user names. Passwords, domains and file names are converted strictly from
  UTF-8 to UTF-16LE, including surrogate pairs for non-BMP characters.
* SMB signing is required for the final Session Setup response and for all
  traffic after authentication, and the first 16 bytes of the SMB 2.1
  HMAC-SHA256 are verified. A frame that fails signature verification or
  carries a wrong correlation number tears the connection down.
  Signing detects tampering; it does not encrypt file contents.
* One share per connection and one outstanding operation. Connections and
  handles are not thread-safe. Calls to `Connect` on different connections
  must also be serialized by the caller, because they share the allocation of
  owner IDs. Handles record a monotonic integer owner ID, an epoch and an open
  ticket, and foreign, stale or closed handles are rejected before any network
  I/O.
* Frames are limited to 1 MiB and single read/write requests to 64 KiB, and
  received offsets, lengths and their sums are range-checked. SMB1, SMB3,
  encryption, compression, compound requests, Kerberos, guest/null fallback
  and large-MTU negotiation are not implemented.
* Stack usage is outside the proofs. Frame, transfer, request and directory
  listing buffers live on the heap, and the socket is read 16 KiB at a time.
  Response signature verification and NTLM authentication compute
  HMAC-SHA256 / HMAC-MD5 incrementally in 64-byte blocks and copy no
  peer-sized data onto the stack. `make stack-check` checks that the worst-case
  stack use of each public API (a static estimate that excludes the GNAT
  runtime) stays within 256 KiB (the largest is `Authenticate`, about
  230 KiB). Call the library from a thread or task with a stack of at least
  1 MiB.

The public API is synchronous and sends one request at a time. After
authentication, LOGOFF, TREE_DISCONNECT, CREATE, CLOSE, READ, WRITE,
QUERY_DIRECTORY and SET_INFO handle SMB 2.1 `STATUS_PENDING` interim responses
and the matching async final responses. As the specification says, interim
responses are not signature-checked; only their correlation with the request,
a non-zero AsyncId and the mandatory fields of the ERROR body are checked. An
interim response is never taken as success, authenticated data or an NTSTATUS.
The final response is signature-checked as usual over the original bytes
received. References to the official specification and the verification
results are in the
[proof report](docs/proof-report.md#smb-21-asynchronous-interim-responses).

Credit handling keeps the existing single-request profile. The first interim
response must grant a positive CreditResponse, interim responses after the
AsyncId has been recorded may grant zero, the async final response must grant
zero and a synchronous response a positive credit. Interim responses do not
extend the wait: each request gets one absolute receive deadline, set once.
Async responses to NEGOTIATE, SESSION_SETUP and TREE_CONNECT, SMB3, compound
requests, cancel, concurrent requests and full credit-window management are
out of scope.

"Pure Ada" means that the implementation is written in Ada and links no C
crypto library or `libsmbclient`; it does not refer to the Ada package
property `pragma Pure`. The library depends on GNAT.Sockets, Ada Stream_IO and
GNAT's regular runtime. The default entropy source is `/dev/urandom` on Unix
and `BCryptGenRandom` (the OS standard CSPRNG) on Windows. Only the Windows
build links `bcrypt`, to obtain OS random numbers, and calls it directly from
an Ada OS adapter. Hashes, HMAC, NTLM and SMB signing remain pure Ada. The
existing entropy callback of `Connect` can still be used. When the CSPRNG
fails, the library fails closed and does not fall back to another source. The
project is experimental.

On Windows the adapter is selected automatically from `OS=Windows_NT`. For
cross builds, pass `-XADASMB_OS=Windows_NT` or `-XADASMB_OS=Unix` explicitly in
addition to the compiler's target.

An unsigned final authentication failure is also rejected and the connection
closed, but an error that matches the request and is well formed can be
diagnosed through `Last_Unverified_Authentication_Status` and the exception
message. This is a **claim by an unauthenticated peer**. It is kept apart from
`Last_NT_Status` and is never used to decide that authentication succeeded or
to retry automatically. The value 0 means no diagnosis; `Connect` and
`Disconnect` clear it.

## What SPARK covers

The crypto computations, UTF conversions, NTLMv2/SPNEGO authentication,
parsing and building of SMB headers, operation bodies and frames, transfer
progress, and state and handle management that the public API actually uses
are in the SPARK core. The proofs are not about a separate model. What is
proved is the absence of run-time errors and the stated boundary and state
contracts.

The real `SMB.Client` paths for CREATE/CLOSE and READ/WRITE go through the
typed coordinator in `SMB.Core_Client`. The core builds and signs complete
packets from the Engine's request expectations and accepts a response only
after the send has been confirmed. The transfer state holds up to 1 MiB, and
each READ/WRITE request is at most 64 KiB. WRITE copies its input once into a
private snapshot at the start, and a partial write advances only by the
verified count. READ accumulates verified data in the state and extracts the
final result with a bounded copy in the core. On an uncertain send or receive
or an invalid response, the Engine is invalidated without a retry and the
facade closes the Channel. Socket I/O, transfer of the returned slices,
allocation, exception handling and container lifetime are trust boundaries.
Authentication, directory enumeration and DISPOSITION/RENAME also go through
typed cores, and `SMB.Core_Connection` manages the state updates of connect,
share connect and disconnect from requests and responses.

The socket path uses `SMB.Core_Transport`, which proves the bytes of the whole
frame in the native array actually sent, the copy of partial receives that
keeps the data already received, and the remaining slice and progress of
partial sends. The meaning of the byte counts returned by the OS, the socket
loops, the deadlines, and allocation, initialization and exception handling
are not proved.

The calendar calculation of the FILETIME passed to authentication and its
truncation to 100 ns units are proved in `SMB.Core_Clock`. Reading the OS clock
and splitting UTC time are trust boundaries.

For relative paths and share names, the string-level rejection rules, the
exact separator conversion on success and the clearing of the output on
failure are also under contract. This does not prove what a path means on the
server, such as link resolution or Unicode normalization.

The call order, buffer allocation and exception handling of the public
`SMB.Client`, the sockets, OS random numbers and clock, the runtime and memory
allocation remain trust boundaries. **This does not mean that unconditional
safety of the whole public API, cryptographic security or full SMB conformance
has been proved.** Proof results and commands to reproduce them are in
[`docs/proof-report.md`](docs/proof-report.md), and every non-SPARK part and
assumption is listed in [`docs/assurance.md`](docs/assurance.md).

## API and build

The main API of `SMB.Client` is `Connect`, `Authenticate`, `Connect_Share`,
`Open_File`, `Read`, `Write`, `Close`, `List_Directory`, `Make_Directory`,
`Remove_File`, `Remove_Directory`, `Rename` and `Disconnect`. Paths are
relative to the share; absolute paths, `..` escapes and embedded NULs are
rejected.

You need GNAT, GPRbuild and GNU Make. Time conversion requires GNAT's
`Duration` with a 1 ns step, and a runtime with a different precision is
rejected at compile time.

```sh
make build                  # static library build/lib/libsmb.a
make test                   # crypto, wire, UTF-8/UTF-16 and SPNEGO tests
make unicode-test           # all Unicode scalars against Python's standard codecs
make ntlm-test              # NTLM challenge handling and authentication output
make crypto-test            # hashes and HMAC against OpenSSL / Python
make signing-test           # SMB signing and tamper rejection against Python
make clock-test             # FILETIME for every day, second and 100 ns fraction
make check                  # warnings as errors and dependency checks (with stack-check)
make stack-check            # worst-case stack use per public API from GCC call graphs
make example                # build/bin/smb_example
make prove                  # needs GNATprove + cvc5/z3; fails on any unproved check
make transport-test         # TCP fragmentation, send/receive timeouts, disconnects, recovery
make integration            # opt-in test that explicitly starts a local Samba
```

`make unicode-test` uses Python 3's standard codecs as an independent
reference and checks all 1,112,063 Unicode scalars except NUL, every
combination of short byte sequences, and composite strings and fixed-seed
inputs. NUL is rejected by SMB policy. This differential test is not a formal
proof of Unicode semantics. Python is used only for testing and is not a
run-time dependency of the library.

`make crypto-test` needs Python 3 and the legacy provider of OpenSSL 3. MD4 is
compared with OpenSSL, and MD5/SHA-256 and HMAC with Python's
`hashlib`/`hmac`, covering block boundaries, long keys, the maximum input
length and differing array lower bounds. These are test-only dependencies. The
test does not prove cryptographic strength or constant-time behavior, and
MD4/MD5 are not recommended for new designs beyond NTLM compatibility.

The example takes the host, share and path as arguments, but not the
password. It reads the `SMB_USER`, `SMB_DOMAIN` and `SMB_PASSWORD` environment
variables. Environment variables may be readable through the process
environment, so take care on shared hosts.

```sh
SMB_USER=alice SMB_PASSWORD='...' SMB_DOMAIN=WORKGROUP \
  build/bin/smb_example 127.0.0.1 public README.txt
```

Run `make integration` only on a local Linux machine with root privileges. It
creates a dedicated temporary Samba configuration, a share and an
`ada_smb_test_only` user (with a known, test-only password), and removes them
at the end. It does not connect to remote hosts. It needs `smbd`, `smbpasswd`
and Python 3.

## CI

GitHub Actions (`.github/workflows`) runs the following. The toolchain (GNAT
14.2.1, gprbuild 25.0.1 and gnatprove 14.1.1) is installed with Alire 2.1.1
(`alr` is checked against the release's SHA-256, and the installation is
cached).

* `ci.yml` (pushes to main, pull requests and manual runs; not run for
  documentation-only changes)
  * Linux: `make check` (including `stack-check`), `make test`, the comparison
    tests, `make transport-test` and the Samba integration test on the
    disposable VM
  * Windows: build with warnings as errors, source and stack checks, unit
    tests, the comparison tests and the TCP transport test
  * macOS (ARM64): build with warnings as errors
* `proof.yml` (every Sunday 18:00 UTC, which is Monday 03:00 JST, and manual
  runs): the full proof with `make prove`. GitHub stops scheduled runs in
  repositories without activity for 60 days.

## Protocol references

Signing follows
[MS-SMB2 signing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0):
HMAC-SHA256 over the whole SMB2 message with the signature field zeroed. The
NTLMv2 NTOWFv2, response and session base key follow
[MS-NLMP NTOWFv2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3),
and the timestamp, zero LM response and MIC/AV flags follow
[MS-NLMP timestamp and MIC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96).
These links do not widen the implemented scope; the SMB 2.1/NTLMv2-only
profile above still applies.

See [`docs/protocol.md`](docs/protocol.md) (in Japanese) for the detailed state
transitions, rejected inputs and limitations, and
[`docs/assurance.md`](docs/assurance.md) for what SPARK covers and what is
unproved.

An Ada project uses the client by referring to the library from its GPR
project:

```gpr
with "/path/to/AdaSMB/smb.gpr";
project Example is
   for Source_Dirs use ("src");
   for Main use ("client.adb");
end Example;
```

## Alire

The Alire crate is named `smb` ([`alire.toml`](alire.toml)) and is published
in the Alire community index. Add it to a project as a dependency with:

```sh
alr with smb
```

Builds through Alire require GNAT 14 or later and set `ADASMB_OS` to
`Windows_NT` or `Unix` according to the OS. No Alire crate configuration files
(`config/`) are generated.

## License

Dual-licensed under `MIT OR Apache-2.0`; you may use it under either license.
See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE) for the
texts.
