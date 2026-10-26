# GNATprove and test report

## Final clean proof

The complete `make prove` run passed after clearing generated proof intermediates
with `gnatprove -P proof.gpr --clean`. GNATprove analyzed all ten configured
units: `SMB`, `SMB.Core_Auth`, `SMB.Core_Client`, `SMB.Core_Framing`,
`SMB.Core_NTLM`, `SMB.Core_Protocol`, `SMB.Core_Text`, `SMB.Core_Wire`,
`SMB.Crypto` and `SMB.Engine`.

| Category | Total | Flow | Proved by provers |
| --- | ---: | ---: | ---: |
| Data dependencies | 1 | 1 | 0 |
| Flow dependencies | 1 | 1 | 0 |
| Initialization | 372 | 372 | 0 |
| Non-aliasing | 2 | 2 | 0 |
| Run-time checks | 1,620 | 0 | 1,620 |
| Assertions | 137 | 0 | 137 |
| Functional contracts | 606 | 0 | 606 |
| Termination | 87 | 81 | 6 |
| **Total** | **2,826** | **457** | **2,369** |

There were zero unproved or justified checks. All configured subprograms were
analyzed; no core subprograms were skipped and no `pragma Assume` statements
were reported. Six non-fatal “initialization ... has no effect” warnings remain
on local parser variables in `SMB.Core_Protocol`.

The proof includes the bounded READ/WRITE transfer state and lifecycle:
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

The proof does not establish the trusted socket/allocation/exception adapter,
complete public-facade correctness, cryptographic hardness, server rollback, or
exactly-once behavior after an uncertain write.

Raw GNATprove output is `gnatprove.out`; its summary is
`build/proof-obj/gnatprove/gnatprove.out`, both relative to the checkout root.

## Executed tests

* `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make test`:
  passed (`AdaSMB unit tests passed`), including bounded transfer fixtures for
  partial WRITE continuation and payload snapshot preservation, empty WRITE,
  response-receipt misuse, NTSTATUS after partial WRITE, short/zero/EOF READ,
  multi-chunk READ prefix preservation, and invalid/overflowing transfer inputs.
* `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make check`:
  passed, including warnings-as-errors builds of the library, tests and example,
  plus the runtime dependency audit.
* `PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH make prove`:
  passed with the clean full-project result above.
* `python3 -m py_compile tests/adversarial_proxy.py tests/samba_integration.py`:
  passed.
* `sudo -n env PATH=/home/ubuntu/.local/share/ada/candidate-14/bin:$PATH
  python3 tests/samba_integration.py`: passed against local Samba on
  `127.0.0.1:1445`. The normal public integration and all seven existing
  adversarial cases passed. Malformed signed CREATE and interrupted READ
  invalidation/reconnect regressions passed. In the lost-WRITE-response-after-
  progress regression, the proxy relayed the first positive successful WRITE
  response and dropped the second; it verified exactly two client WRITE
  requests and two positive successful WRITE responses. The client reported
  transport failure, rejected stale-handle operations, reconnected through the
  same public connection, and read back the complete deterministic 70,001-byte
  file.

The unchanged transport-backpressure test was not rerun for this migration; its
previous passing result is baseline evidence, not part of these current test
results. CI and Windows-native testing were not performed.

## Reproduction

With GNATprove, GPRbuild, cvc5 and z3 on `PATH`:

```sh
make build
make test
make check
gnatprove -P proof.gpr --clean
make prove
python3 -m py_compile tests/adversarial_proxy.py tests/samba_integration.py
# Requires local Linux, Samba tools and root privileges:
sudo env "PATH=$PATH" python3 tests/samba_integration.py
```

`make prove` analyzes the complete explicitly enumerated `proof.gpr` project:

```sh
gnatprove -P proof.gpr --mode=all --level=2 --report=all \
  --checks-as-errors=on --prover=cvc5,z3 --timeout=10 -j4
```

Generated proof/build files are ignored by Git. [assurance.md](assurance.md)
lists the proved scope and non-SPARK adapter inventory. A successful proof
covers the stated core contracts under their bounds and trust assumptions; it
does not prove the entire public facade, operating system, or cryptographic
security.
