# SPARK Platinum design

This is the plan for taking AdaSMB's SPARK core from its current level to
SPARK's Platinum level: a complete functional specification, written in
SPARK, for every proved subprogram, with the implementation proved against
it. It is a design target, not evidence that anything below is specified or
proved. The current state comes from a survey of the contracts on `main` at
0.4.0 (1225e38).

## Where the core is now

The core is proved free of run-time errors (Silver) in every unit of
`proof.gpr`, and many contracts state functional properties (Gold in places),
but much of what the code computes is "tested, not stated"
([assurance.md](assurance.md)). No specification is written as ghost code of
its own today: postconditions state properties directly (this byte holds
that field), the few ghost functions (`Transfer_Packet_Matches` and the
other packet matchers) restate the builders rather than the standard, and
the cryptography's contracts track only bookkeeping such as `Ready` and
`Length`, never the digest, tag or ciphertext.

| Level reached | Units |
| --- | --- |
| Complete already | `Core_Framing`, `Core_Transport`, `Core_Clock`; in `Core_Text` the path, share and UTF-16 validators; in `Core_Wire` the integer readers and writers; in `Core_Protocol` the transfer arithmetic, `Credit_Charge` and `Network_Open_Information` |
| Fields stated, gaps left | `Core_Wire`'s header, `Core_Request`, `Core_Protocol`'s builders (CREATE's name bytes, READ/WRITE/CLOSE fixed bytes) and `Parse_Response` (which packets are accepted, the failure status, CREATE and CLOSE fields), `Core_Transform`'s header, `Core_Negotiate`'s response checks, `Core_Query`, `Core_Resize` |
| Outputs not stated at all | every digest, MAC, cipher and key: `Crypto` (MD4, MD5, SHA-256, SHA-512, both HMACs), `AES`, `AES.CMAC`, `AES.CCM`, `AES.GCM`, `KDF`; `Core_Preauth.Update` has no postcondition; the NTLMv2 response, Type 3 message and session key in `Core_Auth` |
| Large state, partial frames | `Engine` (about 45 fields and a 256-slot handle table behind about 55 functions), `Core_Connection`, `Core_Client` |

## What Platinum means here

* **Every output determined.** For each subprogram of a unit in `proof.gpr`,
  the postcondition fixes every output (`out` and `in out` parameters,
  function results and the status) from the inputs, in terms of
  specification functions. Where the code deliberately leaves something
  open, the contract says so, and that is the exception.
* **Specifications from the standards, not from the code.** Specification
  functions are expression or ghost functions that transcribe the standard
  (FIPS 180-4, FIPS 197, SP 800-38B/C/D, SP 800-108, RFC 1320/1321/2104,
  MS-NLMP, MS-SPNG, MS-SMB2, MS-FSCC, Unicode), citing the section. They do
  not call the implementation, and the implementation does not call them
  except as ghost code.
* **Exact failure statuses.** When several checks fail, the status is the
  one the specification's order of checks gives; the order is part of the
  specification, not a comment.
* **The boundary stays where it is.** The trusted facade (`SMB.Client`,
  sockets, entropy, allocation) is not part of this plan; Platinum covers
  the SPARK core.

## Decisions

The maintainer approved all of these on 2026-11-18.

* **Specifications are ghost packages.** Each area gets a child package
  that is ghost as a whole (`package SMB.Spec.SHA2 with Ghost`), written from
  the standard and `with`ing nothing from the implementation;
  `tests/check_sources.py` enforces that. For SHA-256, for example,
  `SMB.Spec.SHA2.SHA256 (Message)` transcribes FIPS 180-4 section 6.2, and
  the implementation's postcondition becomes
  `Digest = SMB.Spec.SHA2.SHA256 (Message)`.
* **The specifications are tested too.** A specification is only as good as
  its reading of the standard, so every specification function is
  executable, and a new test program (`spec_test`) runs the specifications
  alone on published vectors: the FIPS examples and NIST CAVP files, RFC
  4231, SP 800-38B/C/D's examples, and Microsoft's worked SMB 3.1.1 and
  NTLMv2 examples already in `test_suite`. The proof ties the code to the
  specification; these tests tie the specification to the standard.
* **Run-time checking in the library build.** Today `smb.gpr` builds with
  `-gnata`, so every postcondition also runs in production. A
  specification-level postcondition such as "the digest equals SHA-256 of
  the message" would recompute the hash recursively over up to 1 MiB on
  every call. The proposal: the library build keeps preconditions and
  assertions checked but ignores postconditions and ghost code
  (`Assertion_Policy (Post => Ignore, Ghost => Ignore)`), because GNATprove
  proves them; the test build checks everything on the small inputs tests
  use. This changes what runs in production and needs the maintainer's
  agreement. (Phase 4 found an exception: a whole-input specification
  that recurses over the input cannot run on the megabyte some tests
  convert, so the two converters' postconditions are proved and never
  run, and tests check them on every short input instead. Phase 5 found
  another: the stack check rejects recursion reachable from `SMB.Client`
  in every build, so the hashes' postconditions, whose specifications
  recurse over a block's schedule and rounds, are proved and never run
  either.)
* **Ada 2022 in the build.** The proof already runs as Ada 2022, the build as
  Ada 2012. Specifications need Ada 2022 features (big integers for
  arithmetic in GF(2^128) and modular reductions, iterated aggregates),
  and GNAT 14, which the crate already requires, supports them. The build
  moves to `-gnat2022`.
* **One model of the SMB2 messages.** `SMB.Spec.SMB2` describes the header
  and each request and response body as records with an encoding function
  and a validity predicate. The six packet matchers that now restate the
  builders field by field (`Transfer_Packet_Matches`,
  `Metadata_Packet_Matches`, `Packet_Matches_Prepared`, ...) are replaced by
  "the packet is the encoding of this record".
* **One model of the engine.** `SMB.Spec.Engine` is a record of what the
  client knows (MS-SMB2 3.2.1: connection, session, tree and open state);
  each engine transition is stated as a function on it, as the three
  `Only_*` functions already do for key derivation, sealing and opening.

## The work, by area

| Area | Specification | Implementation units | Effort | Main obstacle |
| --- | --- | --- | --- | --- |
| SMB2 header and bodies | MS-SMB2 2.2 | `Core_Wire` (header), `Core_Request`, `Core_Protocol` builders, `Core_Transform` header, `Core_Query`, `Core_Resize` packets | Low | Many fields; exact statuses for short outputs |
| Text | Unicode 3.9 (UTF-8, UTF-16) | `Core_Text` conversions | Medium | Input and output advance at different widths over up to 1 MiB |
| Hashes and HMAC | FIPS 180-4, RFC 1320, RFC 1321, RFC 2104 | `Crypto`, `KDF`, `Core_Preauth`, HMAC signing | High | Rounds over 64/80 steps; a model of the absorbed message for the incremental contexts |
| AES and its modes | FIPS 197, SP 800-38B/C/D | `AES`, `AES.CMAC`, `AES.CCM`, `AES.GCM`, SMB 3.1.1 signing, `Core_Transform` | High | The S-box is computed on bit planes; GHASH's masked bit-serial multiply against the polynomial definition |
| Response acceptance | MS-SMB2 2.2 and 3.2.5 | `Core_Protocol.Parse_Response`, `Parse_Directory_Entry`, `Core_Negotiate` contexts | Medium to high | Per-command validity predicates in what is already a 47-minute unit |
| NTLM and SPNEGO | MS-NLMP 3.3.2, MS-SPNG, DER | `Core_Auth`, `Core_NTLM` | High | The largest specification to write: NTOWFv2, NTProofStr, the blob and AV pairs, the Type 3 layout, the MIC, the SPNEGO grammar |
| Engine and coordinators | MS-SMB2 3.2 | `Engine`, `Core_Connection`, `Core_Client` | High | Breadth: about 45 state fields, 30 coordinator procedures |

## Phases

Each phase is one or more pull requests, with the proofs and the
specification tests passing.

1. This document.
2. **Infrastructure** (#149). The Ada 2022 build, the run-time policy above,
   the `SMB.Spec` root, `spec_test`, the independence check, and a Platinum
   section in [assurance.md](assurance.md) that each later phase fills in.
   Two adjustments while doing it: ghost code stays enabled in the library
   build, because some preconditions call ghost functions and SPARK does not
   allow a checked precondition to use ignored ghost code (it runs only
   where a precondition or an assertion uses it; postconditions, where the
   costly specifications go, are ignored as decided); and the test project
   compiles the library's sources itself, so that the tests check every
   contract while the library build checks preconditions and assertions.
3. **SMB2 messages.** `SMB.Spec.SMB2`; complete contracts for the header,
   `Core_Request`, the `Core_Protocol` builders, the transform header and
   the QUERY_INFO and SET_INFO packets, with exact statuses. The cheapest
   tier, done first to settle the patterns. The header writers came first
   (#150); a specification is stated as fields read at their offsets.
4. **Text.** Whole-string UTF-8 and UTF-16 specifications, and exact
   outputs and statuses for both conversions.
5. **Hashes and HMAC**, with the incremental model (SHA-256's
   compression function came first, #168); then `KDF`,
   `Core_Preauth` and HMAC signing follow.
6. **AES, then CMAC, CCM, GCM and GMAC**; then SMB 3.1.1 signing and the
   transform's tag and plaintext.
7. **Response acceptance.** Exact acceptance and failure statuses for
   `Parse_Response`, directory entries, negotiate contexts and a received
   transform header (`Core_Transform.Unwrap`).
8. **NTLM and SPNEGO.**
9. **Engine model, then the coordinators** (`Core_Connection`,
   `Core_Client`, `Core_Query`, `Core_Resize`) in terms of it.
10. **Release**, with [assurance.md](assurance.md) stating the result unit
    by unit.

The order puts the cheap, pattern-setting work first and the cryptography,
whose proofs carry the most risk, in the middle, so that the protocol layers
can be specified in terms of it before the engine is.

## Risks

* **Cryptographic proofs may not close.** Proving a bit-plane S-box or a
  bit-serial GF(2^128) multiply equal to its definition is research-grade
  work in SPARK. Mitigation: lemmas in units of their own, small steps, and
  rewriting the implementation in a form that is easier to prove where the
  cost is acceptable. If a primitive still cannot be proved, the plan
  records it as the one exception, with its specification still tested on
  the published vectors.
* **Proof time.** The whole proof takes about 67 minutes uncached on GitHub
  Actions, and some units already reach their per-check limits. Specification
  lemmas go in separate units so the proof cache keeps them; heavy goals are
  split, as #138 did for `Core_Connection.Complete`.
* **The specification can be wrong.** A wrong specification proved against
  a matching implementation is the main way Platinum can mislead. That is
  why the specifications are executable and tested on published vectors,
  and reviewed against the standard's text in each pull request.

## Mutation testing as a measure

With complete specifications, a mutant of a proved unit that changes what
the code computes must fail its proof. After each phase, the mutants of the
units it covers that survive both the tests and the proof should be
equivalent ones only; any other survivor marks a gap in the specification.
AdaMutant's proof-only detections, which today point at missing tests,
then also confirm that the specifications constrain the code.

## Open questions

* Whether to keep a few error codes apart where the standard does not
  order the checks, or to collapse them (the proposal keeps them apart and
  fixes an order).
* Whether `Core_Clock`'s closed form should get a lemma tying it to
  Gregorian day counting, or stay as its own specification.
* The release number: the plan does not change the public API, so 0.5.0
  would mark the assurance change, not new features.
