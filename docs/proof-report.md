# GNATprove report

## Result (2026-10-26)

The complete `make prove` run passed with **2,146 checks and zero unproved**:
380 flow checks and 1,766 prover checks. All ten configured units were analyzed,
with no skipped core subprograms, justified checks or `pragma Assume` statements.

| Category | Total | Flow | Proved by provers |
| --- | ---: | ---: | ---: |
| Data dependencies | 1 | 1 | 0 |
| Flow dependencies | 1 | 1 | 0 |
| Initialization | 320 | 320 | 0 |
| Run-time checks | 1,239 | 0 | 1,239 |
| Assertions | 55 | 0 | 55 |
| Functional contracts | 466 | 0 | 466 |
| Termination | 64 | 58 | 6 |
| **Total** | **2,146** | **380** | **1,766** |

The units were `SMB`, `SMB.Crypto`, `SMB.Core_Wire`, `SMB.Core_Text`,
`SMB.Core_NTLM`, `SMB.Core_Auth`, `SMB.Core_Framing`, `SMB.Core_Protocol`,
`SMB.Core_Client` and `SMB.Engine`. Receipt-based transitions prove that success
requires the matching old-state receipt; they do not assume that receipt as a
semantic precondition. CREATE/CLOSE packet correspondence, signing preservation,
typed operation lifecycle, and Engine handle metadata contracts are included.

GNATprove reported six non-fatal "initialization ... has no effect" warnings on
local parser variables in `SMB.Core_Protocol`; they do not correspond to
unproved checks. The full raw run is at
`/home/ubuntu/repos/AdaSMB/gnatprove.out`, with the GNATprove summary at
`/home/ubuntu/repos/AdaSMB/build/proof-obj/gnatprove/gnatprove.out`.

### Executed tests

* `make test`, `make build`, `make example`, `make check`: passed. Checks include
  warnings-as-errors compilation and the source dependency/proof-scope audit.
* Crypto/NTLM frozen vectors, DER/UTF rejection, nonzero-bound wire preservation,
  request-layout and response-body tests, coordinator CREATE/CLOSE packet and
  receipt lifecycle, receipt misuse, and signed-malformed-body invalidation: passed.
* `make transport-test`: passed against a real TCP peer that never reads. The
  0.5-second stalled-write deadline closed the connection and prevented reuse.
* Python syntax check for the transport harness: passed.
* Local Samba at `127.0.0.1:1445`, mandatory signing, SMB2.1: passed. Includes
  authentication, 70,001-byte I/O, Unicode names, directory pagination,
  rename/delete, error and stale/foreign-handle cases.
* Seven adversarial proxy modes: truncated, oversized,
  wrong-correlation-negotiate, dribble-timeout, unsigned, tampered-signature,
  wrong-correlation-auth: all rejected as expected.

CI was not run. These results do not include a Windows-native client/server run.

## Reproduction

With GNATprove, GPRbuild, cvc5 and z3 on PATH:

```sh
make build
make test
make example
make check
make prove
make transport-test
# Requires local Linux, Samba tools and root privileges:
sudo env "PATH=$PATH" python3 tests/samba_integration.py
```

The session's toolchain is in
`/home/ubuntu/.local/share/ada/candidate-14/bin`; prepend it to PATH in this
environment. That local installation path is not an installer or a portable
toolchain lockfile. Reported versions: GNATprove `0.0w`, Why3 `1.6.0+git`,
cvc5 `1.1.2`, z3 `4.13.0`.

`make prove` runs the complete explicitly enumerated `proof.gpr` (no `-u`
selection):

```sh
gnatprove -P proof.gpr --mode=all --level=2 --report=all \
  --checks-as-errors=on --prover=cvc5,z3 --timeout=10 -j4
```

Raw output is retained locally as `gnatprove.out`; the GNATprove summary is
`build/proof-obj/gnatprove/gnatprove.out`. Generated proof/build files are ignored
by Git. [assurance.md](assurance.md) lists the scope and every non-SPARK adapter
subprogram. A successful proof covers the stated core contracts under their
bounds and trust assumptions, not the entire public facade, OS, or cryptographic
security.
