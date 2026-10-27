# GNATprove and test report

## Final clean proof

`gnatprove -P proof.gpr --clean` and the subsequent complete `make prove`
run passed. GNATprove analyzed all eleven configured units:
`SMB`, `SMB.Core_Auth`, `SMB.Core_Client`, `SMB.Core_Connection`, `SMB.Core_Framing`,
`SMB.Core_NTLM`, `SMB.Core_Protocol`, `SMB.Core_Text`, `SMB.Core_Wire`,
`SMB.Crypto` and `SMB.Engine`.

| Category | Total | Flow | Proved by provers |
| --- | ---: | ---: | ---: |
| Data dependencies | 1 | 1 | 0 |
| Flow dependencies | 1 | 1 | 0 |
| Initialization | 527 | 527 | 0 |
| Non-aliasing | 2 | 2 | 0 |
| Run-time checks | 2,228 | 0 | 2,228 |
| Assertions | 281 | 0 | 281 |
| Functional contracts | 967 | 0 | 967 |
| Termination | 145 | 139 | 6 |
| **Total** | **4,152** | **670** | **3,482** |

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
* `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make check
  GPRBUILD="gprbuild -f"`: passed. The library, test suite, and example were
  forcibly rebuilt with warnings treated as errors; the runtime dependency
  audit passed.
* `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH gnatprove -P
  proof.gpr --clean`: passed. The subsequent
  `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make prove`
  passed across all eleven units with the clean full-project result above.
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
  disconnecting or invalidating its existing handle. No rollback or
  exactly-once guarantee is implied.
* `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH
  python3 tests/transport_integration.py`: passed, including send backpressure
  timeout behavior.
* `python3 -m py_compile tests/adversarial_proxy.py
  tests/samba_integration.py`: passed.
* `git diff --check`: passed. A source scan found no `pragma Assume`,
  `False_Positive`, `Suppress`, or `Annotate` declarations in `src/` or
  `tests/`.

CI and Windows-native testing were not performed.

## Reproduction

With GNATprove, GPRbuild, cvc5 and z3 on `PATH`:

```sh
PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make build
PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make test
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
