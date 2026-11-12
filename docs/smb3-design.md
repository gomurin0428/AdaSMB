# SMB 3.1.1 design

This is the plan for adding SMB 3.1.1 signing and encryption (target
release 0.2.0). It is a design target, not evidence that anything below is
implemented or proved. Section numbers refer to
[MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962).

## Decisions

* **Dialect 3.1.1 (`0x0311`) only.** SMB 3.0 and 3.0.2 are not offered. They
  need FSCTL_VALIDATE_NEGOTIATE_INFO to detect a downgrade, while 3.1.1
  protects the negotiation with the preauth integrity hash instead.
* **3.1.1 is required by default.** A connection offers only `0x0311` unless
  the caller explicitly allows SMB 2.1. When both are allowed, the client
  offers both and accepts either, and the caller accepts that an active
  attacker can strip `0x0311` from the request and force 2.1.
* **Encrypt whenever the server supports a cipher.** After authentication,
  every request is encrypted if a cipher was negotiated, whether or not the
  server marked the session or share as requiring encryption. A
  `Require_Encryption` option makes the connection fail when no cipher is
  negotiated.
* **Not planned:** SMB 3.0/3.0.2, AES-GMAC signing (SMB2_SIGNING_CAPABILITIES),
  compression, multichannel, RDMA/QUIC transports, Kerberos, and raising the
  64 KiB read/write chunk.

## Protocol profile

What follows is the client behavior to implement. Where MS-SMB2 is silent
or ambiguous, the choice is marked as ours.

### NEGOTIATE (§2.2.3, §3.2.4.2.2.2, §3.2.5.2)

* Dialects: `0x0311`, plus `0x0210` only when 2.1 is allowed. The response's
  DialectRevision must be one of the offered dialects, or the connection is
  closed.
* SecurityMode stays 3 (signing enabled and required), as today. Capabilities is
  SMB2_GLOBAL_CAP_ENCRYPTION (`0x40`) and nothing else. A server encrypts its
  responses only if the client set this bit (§3.3.4.1.4).
* Negotiate contexts start at the first 8-byte-aligned offset after the
  dialects (offsets count from the SMB2 header), and each context starts
  8-byte aligned:
  * PREAUTH_INTEGRITY_CAPABILITIES (`0x0001`): one algorithm, SHA-512
    (`0x0001`), and a 32-byte salt from the entropy source.
  * ENCRYPTION_CAPABILITIES (`0x0002`): AES-128-GCM (`0x0002`),
    AES-128-CCM (`0x0001`), AES-256-GCM (`0x0004`) and AES-256-CCM
    (`0x0003`), in that order, as a Windows client offers them by default.
    0.2.0 offered only the first two.
  * No NETNAME (a SHOULD that servers ignore) and no SIGNING_CAPABILITIES,
    so 3.1.1 signing is always AES-128-CMAC.
* Response checks for 3.1.1, all failing the connection:
  * exactly one preauth context, with HashAlgorithmCount = 1, SHA-512, and a
    DataLength that covers the count and salt;
  * at most one encryption context, with CipherCount = 1 and a cipher that
    is 0 or was offered;
  * a compression, transport, RDMA or signing context is rejected (ours):
    a server sends one only in answer to the client's, and we offer none;
  * every context lies inside the message, and other context types are
    ignored.
* A missing encryption context, or cipher 0, means no encryption.

### Preauth integrity (§3.2.5.2, §3.2.5.3.1)

The hash input is each whole SMB2 message from the `FE 'SMB'` header, with
no 4-byte TCP framing:

```
H := 64 zero bytes
H := SHA-512 (H || NEGOTIATE request)             -- connection
H := SHA-512 (H || NEGOTIATE response)
H := SHA-512 (H || SESSION_SETUP request 1)       -- session
H := SHA-512 (H || SESSION_SETUP response 1)      -- MORE_PROCESSING_REQUIRED
H := SHA-512 (H || SESSION_SETUP request 2)
```

The final, successful SESSION_SETUP response is not hashed. The final H is
the KDF context.

### Keys (§3.1.4.2, §3.2.5.3.1)

`KDF (Key, Label, Context)` is SP 800-108 in counter mode with HMAC-SHA256,
r = 32 and L = 128. Its one block is

```
HMAC-SHA256 (Key, 00000001 || Label || 00 || Context || 00000080)
```

truncated to 16 bytes, where Label includes its terminating NUL. Key is the
NTLM ExportedSessionKey (16 bytes) and Context is H:

| Key | Label |
| --- | --- |
| SigningKey | `"SMBSigningKey\0"` |
| EncryptionKey (client to server) | `"SMBC2SCipherKey\0"` |
| DecryptionKey (server to client) | `"SMBS2CCipherKey\0"` |

The cipher keys are derived only when a cipher was negotiated. The
ApplicationKey is not needed.

### Signing (§3.1.4.1, §3.2.4.1.1, §3.2.5.3.1)

* AES-128-CMAC with SigningKey over the whole message with the Signature
  field zeroed, as for HMAC-SHA256 today.
* The final SESSION_SETUP response must carry SMB2_FLAGS_SIGNED, and the
  client always verifies its CMAC with the new SigningKey before the session
  counts as authenticated. The spec requires the flag; verifying the
  signature too is ours, and it is what detects tampering with the preauth
  messages.
* Without a cipher, every later request is signed and every response must be
  signed, as in the 2.1 profile. The 3.1.1 rule that TREE_CONNECT is always
  signed when not encrypted is then met.

### Encryption (§2.2.41, §3.1.4.3, §3.2.4.1.8, §3.2.5.1.1.1)

* Transform header, 52 bytes: ProtocolId `FD 'SMB'`, Signature (the 16-byte
  AEAD tag), Nonce (16), OriginalMessageSize (4), Reserved (2) = 0, Flags (2)
  = `0x0001`, SessionId (8). The additional authenticated data is bytes
  20..51; the plaintext is the whole SMB2 message.
* Nonce: GCM uses the first 12 bytes and CCM the first 11; the rest are zero
  when sending. Ours: the first 8 bytes are the little-endian request
  counter, which starts at 1 for each session, and the remaining used bytes
  are zero. Client and server use different keys, so their nonces cannot
  collide.
* With a cipher negotiated, every request after the final SESSION_SETUP
  response is encrypted, TREE_CONNECT included. Inside an encrypted request
  we keep SMB2_FLAGS_SIGNED and the AES-CMAC signature. MS-SMB2 3.2.4.1.1
  requires signing unless both the session and the share are encrypted, and
  does not forbid it then; the Windows client sets the flag with a zero
  signature. Samba and Windows Server 2025 accept such requests.
* Every response to an encrypted request must arrive encrypted. The
  connection is torn down when any of these holds:
  * a plaintext response arrives once encryption is active (ours; the spec
    is silent);
  * the message is not longer than the transform header;
  * Flags is not `0x0001`;
  * SessionId is not the session's;
  * OriginalMessageSize does not equal the ciphertext length;
  * the tag does not verify;
  * the decrypted message is not an SMB2 message (`FE 'SMB'`), such as a
    nested transform (`FD 'SMB'`);
  * the decrypted header's SessionId differs.
* Signatures inside a decrypted message are not checked; the AEAD tag
  already authenticates it.
* The server's SMB2_SESSION_FLAG_ENCRYPT_DATA (`0x0004`) and
  SMB2_SHAREFLAG_ENCRYPT_DATA (`0x00008000`) change nothing for us, because
  we already encrypt everything. Without a cipher, either flag fails the
  connection, since the server would reject our unencrypted requests.
  Windows Server 2025 sets the session flag in the challenge response
  already, before the keys exist, so the rule tests for a cipher, not for
  the keys.

### AES-256

0.2.0 offered only AES-128-GCM and AES-128-CCM. Microsoft publishes no
AES-256 test vectors for SMB, and the spec leaves open which key length
applies to the signing key under an AES-256 cipher, so AES-256 waited for a
server to test against. With the Windows CI runner's own SMB server
available, the client now offers AES-256-GCM and AES-256-CCM after the
AES-128 ciphers, and the server chooses. Under an AES-256 cipher:

* the encryption and decryption keys are 32 bytes, derived with L = 256
  (`SMB.KDF.Derive_256`, MS-SMB2 3.1.4.2), and the transform uses AES-256
  in CCM or GCM with the same nonce lengths and tag;
* the signing key stays 16 bytes, derived with L = 128, because 3.1.1 signs
  with AES-128-CMAC under every cipher. Samba derives it the same way, and
  Windows and Samba both accept the client's signatures under each AES-256
  cipher in CI;
* the key derivation key is the session key. MS-SMB2 takes the full
  session key under AES-256; with NTLM it is the same 16 bytes.

The primitives are checked against FIPS 197, SP 800-38A, the GCM
specification's AES-256 test cases and Python's `cryptography`; the
protocol against Samba and Windows, each with one AES-256 cipher as the only
one allowed.

## New cryptography

All of it is written in Ada, in SPARK, in the style of `SMB.Crypto`: bounded
inputs, no heap, incremental interfaces where messages are large, and
known-answer plus differential tests. Python's `cryptography` package joins
OpenSSL and `hashlib` as a test-only reference.

| Primitive | Used for | Reference vectors |
| --- | --- | --- |
| SHA-512 | preauth integrity hash | FIPS 180-4 examples, `hashlib` |
| AES-128 and AES-256 (encryption direction only) | CMAC (AES-128 only), CCM, GCM | FIPS 197, SP 800-38A (AES-256), NIST CAVP (AES-128), `cryptography` |
| AES-128-CMAC | 3.1.1 signing | RFC 4493, SP 800-38B |
| SP 800-108 KDF (counter mode, HMAC-SHA256, L = 128 or 256) | signing and cipher keys | Microsoft vectors (L = 128), `cryptography` |
| AES-128-CCM and AES-256-CCM (11-byte nonce, 16-byte tag) | encryption | SP 800-38C (AES-128), `cryptography` |
| AES-128-GCM and AES-256-GCM (12-byte nonce, 16-byte tag) | encryption | SP 800-38D, the GCM specification's test cases 13 to 16 (AES-256), `cryptography` |

AES and GHASH are written without secret-dependent table indices or
branches: the S-box is computed, not looked up, and the GF(2^128) multiply
uses masks. This is a coding rule, not a proved property; the existing
non-claim about side channels still applies.

Proof target for the primitives: absence of run-time errors and the stated
length/initialization contracts, as for the existing hashes. Functional
correctness comes from the vectors, not from proof.

## Engine changes

`SMB.Engine` keeps owning every security decision. New state:

* the negotiated dialect (2.1 or 3.1.1) and cipher (none, or AES-128-CCM,
  AES-128-GCM, AES-256-CCM or AES-256-GCM);
* the connection and session preauth hash values (64 bytes each);
* the 3.1.1 signing key, encryption key and decryption key, replacing the
  2.1 use of the session key as the signing key;
* whether the current session and tree require encryption, and whether
  encryption is active;
* a 64-bit request nonce counter.

Properties to prove, in addition to the existing ones:

* **No nonce reuse.** Each encrypted request uses a nonce derived from a
  counter that only increases, and the engine refuses to encrypt once the
  counter is exhausted instead of wrapping. Keys change only on a new
  session, and the counter is never reset while a key is in use.
* **No plaintext after encryption starts.** Once encryption is active, a
  response that did not arrive in a transform header is rejected and tears
  the connection down, the same way a bad signature does today.
* **Only the negotiated cipher and dialect.** A transform header with another
  algorithm, a different SessionId, an OriginalMessageSize that does not
  match, or a failed tag tears the connection down.
* **Downgrade policy.** When the caller did not allow 2.1, a negotiate
  response selecting 2.1 is rejected.
* **Signing key provenance.** The 3.1.1 signing key is the KDF output from
  the session key and the session's final preauth hash; a 2.1 session keeps
  using the session key.

Encryption sits between the transport and the existing response pipeline.
`SMB.Client.Receive_Response` is already the only place where response
frames enter; it gains a SPARK `Unwrap` step before
`Inspect_Interim_Response`. Requests get a single send helper in the facade
that calls a SPARK `Seal` step, replacing the direct `Send_Frame` calls.
Both steps use heap buffers like the existing frame buffers, so stack use
stays within the `make stack-check` budget.

## Public API

```ada
type Dialect_Policy is (SMB_311_Only, SMB_311_Or_21);

procedure Connect
  (Client : in out Connection;
   Host : String;
   Port : Positive := 445;
   Timeout_Seconds : Duration := 10.0;
   Entropy : Entropy_Source := null;
   Dialects : Dialect_Policy := SMB_311_Only;
   Require_Encryption : Boolean := False);
```

Existing calls keep compiling. Their behavior changes, because the default
now requires 3.1.1: a caller that needs a 2.1-only server passes
`Dialects => SMB_311_Or_21`. `Negotiated_Dialect` reports the outcome after
`Connect`, and `Is_Encrypted` after `Authenticate`. With
`Require_Encryption`, `Connect` fails when the server selects 2.1 or offers
no common cipher.

## Phases

Each phase is one or more pull requests, each with its proofs passing.

1. This document.
2. Cryptographic primitives, one pull request per row of the table above. No
   protocol behavior changes.
3. 3.1.1 negotiation, preauth integrity and AES-CMAC signing, without
   encryption. The Samba integration test gains a 3.1.1-only configuration
   with mandatory signing.
4. Encryption: transform header, CCM/GCM, nonce counter, the encryption
   policy above. Samba with `smb encrypt = required`, plus hostile tests for
   plaintext, wrong algorithm, wrong SessionId and corrupted tags.
5. Interoperability with a Windows SMB server on the Windows CI runner, if a
   local share can be set up there, then release 0.2.0.

## Testing

* Primitives: the published vectors in the table above, plus differential
  tests against Python's `cryptography` over random lengths and the block
  boundaries, as `make crypto-test` does for the hashes today.
* Protocol: Microsoft's worked examples become unit tests. They give full
  NEGOTIATE and SESSION_SETUP bytes, every intermediate SHA-512 value, the
  session, signing, encryption and decryption keys, the final SESSION_SETUP
  response signature, and encrypted WRITE/READ requests and responses for
  AES-128-GCM and AES-128-CCM:
  * [SMB 3.1.1 Pre-authentication integrity in Windows 10](https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-3-1-1-pre-authentication-integrity-in-windows-10)
  * [SMB 3.1.1 Encryption in Windows 10](https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-3-1-1-encryption-in-windows-10)
  * [the anatomy of signing and cryptographic keys](https://learn.microsoft.com/en-us/archive/blogs/openspecification/smb-2-and-smb-3-security-in-windows-10-the-anatomy-of-signing-and-cryptographic-keys),
    whose NTLMv2 example connects a password to the first exchange above, so
    one test can run from the password to the final signature.
* Hostile input: the existing mutation tests and adversarial proxy gain the
  3.1.1 cases: malformed or duplicate negotiate contexts, an unoffered
  dialect or cipher, a final SESSION_SETUP response that is unsigned or
  wrongly signed, a plaintext response after encryption starts, and every
  transform-header rejection listed above.
* Interoperability: Samba with `server min protocol = SMB3_11`, once with
  signing only and once with `smb encrypt = required`; then a Windows server
  if the CI runner allows it.
* Mutation testing (`make mutation-diff`) runs on every pull request, so the
  new code starts without surviving mutants.

## Open questions

* Whether `Connect` should send NETNAME, which Windows 10 1809 and earlier
  omit and servers ignore. Samba and Windows Server 2025 accept a NEGOTIATE
  without it.
