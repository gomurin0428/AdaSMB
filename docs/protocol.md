# AdaSMB protocol design notes

English | [日本語](protocol.ja.md)

This document records the wire profile that the implementation in `src/`
accepts, and the inputs it deliberately does not accept.

## Connection state

The client moves from `Disconnected` through TCP connect, SMB 2.1 negotiate,
NTLMv2 session setup and tree connect, in that order. The transition does not
complete if negotiation selects a dialect other than `0x0210`, signing is not
enabled, an I/O maximum is 0, or the share requires encryption. The successful
session setup response must be signed as well, and guest, null and session
encryption are rejected.

Each request is sent with a monotonic message id and 1 credit. Responses are
checked for magic, structure size, command, message id, session/tree id, zero
credit, response flag, async flag and `NextCommand`. An SMB 2 transform header,
compression, a compound response or an unimplemented async response discards
the state and raises `SMB.Protocol_Error`. After authentication, an NTSTATUS
reaches the caller as `SMB.NT_Status_Error` only after its signature has been
verified. The negotiate response and the first challenge response come before
the signing key is established, so they are unsigned; they alone can never
move the client into an authenticated state.

## Signing

The 16 bytes of the session base key are the signing key. HMAC-SHA256(message)
is computed with the signature field of the SMB2 header zeroed, and its first
16 bytes are stored and compared. Every request after authentication is
signed, and every expected response must be signed too. The comparison uses
`SMB.Crypto.Constant_Time_Equal`. A signature mismatch, a correlation mismatch
or invalid packet bounds close the socket.

Official specification:

* [MS-SMB2 3.1.4.1 Signing](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3e9ea1e-53c8-4cff-94bd-d98fb20417c0)

## Reserved fields in responses

The `Reserved` (1 byte) and `Reserved2` (4 bytes) fields of the SMB 2.1 READ
response are ignored even when non-zero, following the specification's rules
for the receiver. The sender must set them to zero, but that is not a rule for
the receiver to reject on their values. SMB 3.1.1, which reads the latter as
flags, is out of scope. The structure size, DataOffset (1 byte), DataLength
and the match with the request are still checked, and the signature
verification over the whole message, reserved fields included, is kept.

Official specification:

* [MS-SMB2 2.2.20 READ Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/3e3d2f2c-0e2f-41ea-ad07-fbca6ffdfd90)

The `Reserved` field (1 byte) of the ERROR response is ignored too. The
adjacent `ErrorContextCount` is a separate field, and since SMB 3.1.1 error
contexts are out of scope, a non-zero value is still rejected. After checking
the bounds of the error body's structure size and ByteCount, the signature and
the match with the request, the received NTSTATUS is returned to the caller.

* [MS-SMB2 2.2.2 ERROR Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d4da8b67-c180-47e3-ba7a-d24214ac4aaa)

The reserved DWORD of CLOSE and the reserved WORD of TREE_DISCONNECT and LOGOFF
are also ignored on receipt. The CLOSE flags (0 or POSTQUERY_ATTRIB), the
minimum length and structure size of each response, the signature and the
match with the request are still checked. A correct closing response is never
turned into a protocol error because of reserved fields alone.

* [MS-SMB2 2.2.16 CLOSE Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/c0c15c57-3f3e-452b-b51c-9cc650a13f7b)
* [MS-SMB2 2.2.12 TREE_DISCONNECT Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/aeac92de-8db3-48f8-a8b7-bfee28b9fd9e)
* [MS-SMB2 2.2.8 LOGOFF Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7539feb4-6fbb-4996-81ac-06863bb1a89e)

`NegotiateContextCount/Reserved` and `NegotiateContextOffset/Reserved2` of
NEGOTIATE and `Reserved` of TREE_CONNECT are also ignored on receipt. Only
dialect 0x0210 is accepted, so they are never read as SMB 3.1.1 contexts.
Signing enabled, the security buffer bounds, the share type, the TreeId and
the rejection of encryption requests are still checked.

* [MS-SMB2 2.2.4 NEGOTIATE Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5)
* [MS-SMB2 2.2.10 TREE_CONNECT Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/dd34e26c-a75e-47fa-aab2-6efc27502e96)

## NTLMv2/SPNEGO

The SPNEGO token the client sends contains only the NTLM OID. Responses have
their DER lengths and nesting checked, and a GSS wrapper or a NegTokenResp is
recognized. A supportedMech other than NTLM, duplicate or out-of-order fields,
non-minimal DER and an unexpected negState are rejected. accept-incomplete or
request-mic is accepted with the challenge, and accept-completed with the
final success. Type 3 carries the client-to-server `mechListMIC`, and the
final response must carry a server-to-client `mechListMIC`, which is verified.
This check is separate from the MIC of the NTLM message itself. Authentication
never works by searching a string for `NTLMSSP`.

The valid security buffers and AV pairs of Type 2 are bounds-checked, and
Unicode, NTLM, ESS, signing and target-info are required. The server timestamp
is preferred for the NTLMv2 blob, and when that AV pair is present the LM
response is all zeros. Only when there is no timestamp is the current FILETIME
used. The 8-byte client challenge always comes from the entropy source. The
MIC-present bit of MsvAvFlags is kept or added, and the MIC is computed over
Type 1, Type 2 and the whole Type 3 with a zeroed MIC. A non-zero channel
binding is rejected instead of making up a value. KEY_EXCH/RC4, NTLMv1 and LM
authentication are not offered.

When `NTLMSSP_REQUEST_TARGET` is clear, the length, maximum length and offset
of TargetName are ignored as the specification says, and the name is not read.
When it is set, the existing bounds and UTF-16 checks apply. The checks of
TargetInfo and its required AV names stay, and the MIC covers the whole Type 2,
ignored fields included.

Official specification:

* [MS-NLMP NTOWFv2 and session base key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3)
* [MS-NLMP timestamp, LM response and MIC AV flag](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96)
* [MS-NLMP CHALLENGE_MESSAGE fields](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786)

## Crypto and input limits

MD4, MD5, SHA-256, HMAC-MD5 and HMAC-SHA256 are implemented with Ada integer
arithmetic only. The default entropy source is `/dev/urandom` on Unix and
`BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG)` on
Windows. Short reads and OS API failures are never treated as success, and
there is no fallback to a pseudo-random generator. Overlong UTF-8, surrogates,
out-of-range scalars and embedded NULs are rejected, as are odd-length UTF-16
and invalid surrogates.

The maximum frame is 1 MiB, and a single read/write credit chunk is 64 KiB.
The TCP header and payload are sent and received completely under one
deadline, so a dribbling peer cannot hold the socket forever. Absolute, UNC,
drive-qualified, empty-component and `..`-escaping share-relative paths are
rejected at the API boundary. Name resolution happens synchronously before
the socket connects and is not covered by the connect and I/O deadlines. The
socket deadlines apply to the TCP connect after name resolution and to the
complete read or write of each SMB frame.

This document and the library guarantee no certification such as FIPS and no
resistance to attacks. OS random numbers and the GNAT socket environment are
trust boundaries. The Windows default random source is isolated in an Ada
adapter that uses the OS standard API, and it is not used for any other
cryptographic processing.

An unsigned error in the final SESSION_SETUP still counts as an authentication
failure and disconnects. After the request ID, SessionId, TreeId, command and
error structure have been checked, only an NTSTATUS of error severity is kept
in `Last_Unverified_Authentication_Status` for diagnosis. Its authenticity is
not guaranteed, and it is kept apart from `Last_NT_Status`, which comes from
signed responses. Success, more-processing-required, broken signatures,
correlation mismatches and invalid structures are never taken as diagnostic
values.

* [BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)
* [MS-SMB2 3.2.5.1.3 Verifying the Signature](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/36172e53-ac81-48fb-b2e3-caa3761b9157)
