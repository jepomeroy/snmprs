# snmprs production readiness roadmap

Tracks the work needed to turn snmprs into a production-ready SNMP v2c/v3 library.

Starting point (2026-10-30): about 1,270 lines that can encode v2c requests, but can't
read a response. v3 has only a `ScopedPdu` encoder and two unused enums.

Each phase depends on the one before it. Start the fuzzing and net-snmp integration
tests during Phases 1–2 rather than waiting for Phase 5.

## Phase 0: Foundations and existing problems

- [x] Commit the current work.
- [x] **Choose the codec.** Chose a small in-house BER codec (`message/ber.rs`) and removed `asn1-rs`. It mishandled OIDs with a second arc of 40 or more (rejecting them on encode and misreading them on decode) and added 16 crates, while SNMP's application types and device-quirk handling needed custom code either way.
  - [x] Delete the leftovers: the commented-out `asn1-rs` line in `snmprs_lib/Cargo.toml`, and the unused `Class` enum and `Tag::class()`.
- [x] **Fix `SnmpMessageBuilder`.** It returns only bytes, so the caller never learns the request ID and can't match the reply. Return a typed request and encode it separately.
- [x] **Fix OID limits.** Valid OIDs like `2.999.1` are rejected.
  - [x] Encode them: `ber::oid` writes the merged first value in base 128, so `2.999.1` encodes as `06 03 88 37 01`.
  - [x] Accept them: `ObjectIdentifier::new` still rejects any second arc above 39. Limit the second arc only under first arcs 0 and 1, and update `test_invalid_prefix_values`, which expects `2.40` to fail.
- [x] **Stop hiding bad values.**
  - [x] `BulkPdu::new` silently clamps its values; use a checked input instead. It now returns `SnmpMessageError::BulkFieldOutOfRange` for values above 2147483647.
  - [x] `ErrorStatus::from_int` turns unknown codes into `GenErr`; preserve the unknown code. Unknown codes now become `ErrorStatus::Unknown(code)`, and `to_int` returns them unchanged.
- [ ] **Fix the socket setup.**
  - [x] Support IPv6 and hostnames; `BaseClient` is IPv4 only.
  - [ ] Add a configurable policy for source addresses. The connected socket drops replies that a multihomed agent sends from a different IP.
  - [x] Reuse the receive buffer; each receive allocates 65 KB.
- [ ] **Protect secrets.** Derived `Debug` on `SnmpV2MessageBuilder` and `V2cMessage` prints the community string. Redact it there and accept communities as bytes.
- [x] **Rework the error types.** All error types now live in `errors.rs` and use `thiserror`. Variants carry structured fields instead of strings, OS failures keep their `io::Error` as the source, and the enums are `#[non_exhaustive]`. The CLI prints the full chain of causes.
- [x] **Tighten the public API.** Use one consistent `encode` visibility, and add `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`. Only whole messages (`V2cMessage`) have a public `encode`; PDUs, varbinds and values use `pub(crate)`, because they can't be sent alone. Every public item is now documented.

## Phase 1: Decoding (RFC 3416, 3417, 2578)

- [x] Add a BER reader that handles short and long definite lengths and rejects indefinite lengths. `ber::read` returns a borrowed `Tlv` (tag, value and the raw bytes for v3 HMAC checks) plus the remaining input, and `ber::expect` checks the tag.
- [ ] Decode every type: integers, octet strings, OIDs, all application types, and the exception values.
- [ ] Decode all PDU types and the v2c message wrapper.
- [ ] Make hostile input safe: no panics, with limits on depth, lengths, varbind count and integer overflow.
  - [x] Header level: `read` checks every declared length against the input, limits length fields to 4 bytes, and rejects multi-byte tags.
  - [ ] Typed decoders: nesting depth, varbind count and integer overflow (`DecodeError::IntegerOverflow` is defined but not used yet).
- [ ] Tolerate common device quirks, such as odd integer padding, behind a defined policy.
  - [x] Non-minimal lengths such as `81 05` are accepted, and the policy is documented on `read_length`.
  - [ ] Decide the policy for integer padding and other value-level quirks.
- [ ] Add round-trip and property tests, plus fuzz targets. Fixed encoding and decoding vectors exist in `ber.rs`; property tests and fuzz targets don't yet.

## Phase 2: A working v2c client

**Request handling**

- [ ] Match request IDs and discard replies that don't match.
- [ ] Add timeouts and retries with configurable backoff.
- [ ] Don't retry `SET` automatically unless the caller opts in.

**Async design**

- [ ] Make Tokio the core, with a blocking wrapper.
- [ ] Ensure cancellation safety and clean shutdown.
- [ ] Run many concurrent requests over one socket, with concurrency limits for polling large fleets.

**Operations**

- [ ] Support multi-varbind `get`, `get_next`, `get_bulk` and `set`.
- [ ] Add `walk` and `bulk_walk`.
- [ ] Make walks safe: stop on `endOfMibView` or on leaving the subtree, and detect non-increasing OIDs so a buggy agent can't cause an infinite loop.

**Size limits**

- [ ] Handle `tooBig` by splitting requests or lowering `max-repetitions`.
- [ ] Cap message sizes.

**Result API**

- [ ] Map `error-status` and `error-index` to the failing varbind.
- [ ] Add typed value accessors and `Display`.
- [ ] Add OID ordering, prefix checks and a compile-time `oid!` macro.

## Phase 3: SNMPv3 (RFC 3412, 3414, 3417, 3826, 7860)

**Message format**

- [ ] Add the `msgGlobalData` header: ID, max size, flags and security model.
- [ ] Add USM security parameters and encrypted `ScopedPdu` handling.
- [ ] Validate engine ID length (5–32 bytes), context name length (32 bytes or less), and security levels, including rejecting privacy without auth.

**Authentication**

- [ ] Implement password-to-key and key localization.
- [ ] Implement HMAC-MD5-96 and HMAC-SHA-96, with MD5 behind a legacy feature flag.
- [ ] Implement HMAC-SHA-2 with RFC 7860's truncated output lengths: 128, 192, 256 and 384 bits for SHA-224, 256, 384 and 512.
- [ ] Sign and verify over the exact message bytes with the auth field zeroed, using constant-time comparison.

**Privacy**

- [ ] Implement AES-128-CFB (RFC 3826).
- [ ] Implement DES-CBC behind a legacy feature flag.
- [ ] Generate salts and IVs correctly, and never reuse them.
- [ ] Support AES-192/256 through the Blumenthal and Reeder key-extension variants. These aren't RFC standards and vendors differ, so the variant must be explicit, which means replacing today's `Aes192` and `Aes256` enum values.

**Engine state**

- [ ] Discover the engine ID, and cache engine ID, boots and time per agent.
- [ ] Enforce the 150-second time window, and resync once on `notInTimeWindows`.
- [ ] Handle all `usmStats` reports as distinct errors: unsupported security level, not in time window, unknown user, unknown engine, wrong digest and decryption error.
- [ ] Discover the context engine ID (RFC 5343).
- [ ] Generate a fresh `msgID` on every retransmission.
- [ ] Reject replies whose security level or user doesn't match the request.

**Secret handling and crypto review**

- [ ] Use maintained crypto crates, such as RustCrypto. Don't write custom primitives.
- [ ] Use `zeroize` on keys and passwords, and redact them from `Debug` and logs.
- [ ] Offer localized keys as an alternative to passwords, and cache them because the key derivation is deliberately slow.
- [ ] Get an independent security review of the USM code before calling it production-ready.

## Phase 4: Notifications

- [ ] Send v2c traps and informs, with the required `sysUpTime.0` and `snmpTrapOID.0` varbinds added automatically.
- [ ] Send v3 traps, where the sender is the authoritative engine, so it needs persistent boots and time.
- [ ] Send v3 informs, including the receiver's engine discovery.
- [ ] Add a listener with a handler or stream API, and acknowledge informs.
- [ ] Add a v3 listener with a user table keyed by engine ID, plus replay protection.

## Phase 5: Testing and interoperability

- [ ] **RFC vectors:** add the published key-derivation and localization test vectors.
- [ ] **Integration tests:** run against a containerized net-snmp `snmpd`, covering every auth and privacy combination.
- [ ] **Other implementations:** test against SNMP4J or another independent stack.
- [ ] **Real captures:** build a sanitized packet corpus from Cisco, Juniper, Windows and similar devices.
- [ ] **Failure tests:** cover loss, duplicates, reordering, late replies, spoofed replies and agent reboots (boots increment).
- [ ] **Fuzzing:** run decoders and USM processing continuously, with the corpus committed.
- [ ] **Coverage:** measure it, and require it on the security-critical paths.
- [ ] **Load and soak tests:** poll thousands of targets, check for memory growth over long runs, and add benchmarks.

## Phase 6: Production operation

- [ ] Add `tracing` instrumentation with secrets redacted.
- [ ] Expose stats for timeouts, retries, auth failures and malformed packets.
- [ ] Provide documented config defaults, a builder API and per-request overrides.
- [ ] Add optional `serde` support for values and OIDs.
- [ ] Support source address and interface binding.

## Phase 7: CLI

- [ ] Add `get-next`, `bulk`, `walk`, `set` with typed values, and trap and inform sending.
- [ ] Parse protocols and security levels into enums, and wire up the v3 flags, which are currently ignored.
- [ ] Accept secrets through an environment variable or prompt, because command-line arguments are visible in process listings.
- [ ] Print decoded output, with a JSON option, and define exit codes.
- [ ] Make the argument layout friendlier: `-i` must currently come before the subcommand.

## Phase 8: Release

**Packaging**

- [ ] Move the crates to `crates/` and use workspace dependencies.
- [ ] Add crates.io metadata, and check the crate name is available.
- [ ] Declare an MSRV and feature flags (`tokio`, `blocking`, `legacy-crypto`, `serde`).

**CI**

- [ ] Build and test on Linux, macOS and Windows, on stable and MSRV.
- [ ] Run fmt, clippy, docs, `cargo-audit`, `cargo-deny` and `cargo-semver-checks`.

**Docs**

- [ ] Write rustdoc for all public items, with runnable examples.
- [ ] Write a v3 setup guide and security notes, including that v2c communities travel in plaintext.
- [ ] Add `SECURITY.md`, a changelog and a versioning policy.

**Release path**

- [ ] Publish 0.x and run it against real networks.
- [ ] Go to 1.0 only after the API settles.

## Suggested non-goals for 1.0

These are large enough to be separate projects, so leave them out unless they're needed:

- Agent or responder functionality, including VACM (RFC 3415)
- A MIB parser or compiler, which fits better as a separate crate
- TLS/DTLS transport (RFC 6353)
- SNMPv1, unless legacy devices have to be supported
