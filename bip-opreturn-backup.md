```
  BIP: ?
  Layer: Applications
  Title: On-Chain Encrypted Wallet Descriptor Backups
  Authors: Oliver Gugger <gugger@gmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Requires: 32, 157, 158, 340, 380
```

## Abstract

This BIP specifies a compact, encrypted backup format for wallet output
script descriptors ([BIP 380]) and wallet policies ([BIP 388]) that is
published inside an `OP_RETURN` output on the Bitcoin blockchain itself, and
a discovery mechanism that lets a wallet find and decrypt its backup with
nothing but a quorum of its seeds and access to a compact block filter
index. The published output is indistinguishable from uniformly random data:
without the required quorum of the wallet's extended public keys, a third
party can neither decrypt the backup, nor locate it, nor even tell that any
given `OP_RETURN` output is a backup at all.

## Motivation

For a multisig or miniscript wallet, losing the wallet descriptor is almost
as catastrophic as losing the seeds: the keys alone cannot reconstruct the
script, so funds become unspendable even with a spending quorum of seeds
intact. This risk is unintuitive and, in practice, under-backed-up: seed
phrases get stamped into steel, while the descriptor lives in a coordinator
app or a cloud folder.

An emerging class of wallets uses multisig not for shared custody but for
**single-user redundancy**: one person or entity splits control across, for
example, a mobile app key, a hardware signing device and a co-signing
service, in a 2-of-3 arrangement, so that no single device is a single point
of failure or attack. For such wallets, the natural disaster-recovery story
is: *any spending quorum of seeds must suffice to recover everything else* —
including the descriptor. Losing one seed also loses that seed's extended
public key, so the backup must be recoverable without it.

The blockchain itself is a uniquely suitable backup medium for this data: it
is highly replicated, always available to any wallet that can sync, cannot
silently lose or corrupt the data, and — crucially — can be searched by a
recovering wallet that starts from nothing but its seeds. What the chain
does not offer is confidentiality or deletion, so the scheme must remain
secure with the ciphertext permanently public and potentially linkable to
the wallet's own transactions.

[BIP 138] specifies an encryption scheme for the same payload class, aimed
at storage on untrusted media, where any *single* participant's extended
public key decrypts the backup. That trade-off is appropriate for private
storage (an attacker needs the xpub *and* access to the medium) but not for
a public ledger, where the storage-access factor disappears and every
published backup is trivially collectable forever. This proposal therefore
replaces BIP 138's access structure with a threshold one, adds a discovery
beacon mechanism, and hardens the construction for a public, permanent,
linkable ciphertext — while remaining compatible with BIP 138's payload
content encoding.

## Design Overview

All secrets derive from the wallet's **root extended public keys** — no
private key material is ever required, so a watch-only coordinator can
publish backups, and hardware signers are not involved.

* A wallet-wide secret `s` commits to all `n` participating xpubs. A
  per-version content key is derived from `s` and a version counter `v`.
* The content key is *wrapped* for every recovery subset of `r` of the `n`
  xpubs (or shared via a Shamir construction for large quorums), so any `r`
  key holders can unwrap it, and fewer cannot.
* Short *beacons* — 4-byte tags derived from discovery subsets of `j ≤ r`
  xpubs — are placed in a fixed 64-byte slot field at the start of the
  `OP_RETURN` data. A recovering wallet derives its own beacon candidates
  and matches them against a compact filter index of `OP_RETURN` data
  chunks, then downloads only the matching blocks.
* Everything is published in a **single `OP_RETURN` output** whose bytes are
  all either hash outputs, XOR-masked keys or AEAD ciphertext — i.e.
  indistinguishable from random. There is no magic value, no plaintext
  version byte, and no visible structure.

Recovery, starting from `r` seeds and nothing else: derive the root xpubs at
standard derivation paths, derive beacon candidates over a version window,
match them against the filter index, fetch matching blocks, unwrap, decrypt,
and take the highest version that authenticates.

## Specification

The scheme is defined for any `n ≥ 1` (single-signature wallets included).

Notation: `hash_tag(m)` is the
[BIP 340] tagged hash `SHA256(SHA256(tag) || SHA256(tag) || m)` with
`tag = "BIPXXX/<keyword>"`, where `XXX` is the number assigned to this BIP.
`ser32(i)` is the 4-byte big-endian serialization of an unsigned integer.
`||` is byte concatenation. `⊕` is bitwise XOR. `GROUP_N` is the order of
the secp256k1 group. `C(a, b)` is the binomial coefficient ("a choose b"):
the number of distinct b-element subsets of an a-element set.

### Parameters

Every backup is published under three parameters, chosen per wallet:

* `n` — the number of qualifying root extended public keys (see below).
* `r` — the **recovery threshold**: the number of xpubs required to decrypt,
  with `1 ≤ r ≤ n`. `r` MUST NOT exceed the minimum number of keys that can
  spend from the wallet under any script path at any time (otherwise a party
  able to spend could be unable to recover the descriptor that lets them do
  so). For a plain k-of-n multisig, `r = k`. For a policy that decays over
  time (e.g. a 2-of-2 that becomes 1-of-2 after a timeout), `r` is the
  *decayed* minimum, here `r = 1`.
* `j` — the **discovery subset size**: the number of xpubs required to
  locate the backup, with `1 ≤ j ≤ r`. RECOMMENDED default: `j = min(r,
  2)`. `C(n, j)` MUST NOT exceed 16; if the default exceeds 16, use
  `j = 1`.

The recovering party knows its own wallet's `(n, r, j)`; none of them are
encoded on chain.

### Qualifying Keys and Normalization

The key set is derived from the descriptor's key expressions using the same
requirements as [BIP 138]: only extended-public-key expressions with a
trailing derivation step or wildcard qualify, so that the root public key
used for secret derivation never equals any on-chain key.[^trailing] Literal
public keys, bare xpubs without trailing derivation, and provably public
keys (such as the [BIP 341] NUMS point) MUST be excluded from the key set;
they may still appear in the encrypted payload. Implementations MUST warn
the user about every excluded expression and MUST refuse to encode if the
resulting set is empty.

For each qualifying expression, the key material is the **full 78-byte
[BIP 32] serialization of the root extended public key** — including the
chain code — with the 4-byte network version bytes normalized to the
mainnet `xpub` prefix `0x0488B21E` regardless of network.[^fullxpub] Let
`x_1 < x_2 < … < x_n` be these serializations in increasing lexicographic
order; this order also assigns each key its canonical index `i`.

### Derivations

For a wallet key set `x_1 … x_n` and version counter `v` (starting at 0):

* `s` = `hash_BIPXXX/secret(x_1 || x_2 || … || x_n)`
* `K_v` = `ser256( int(hash_BIPXXX/key(s || ser32(v))) mod GROUP_N )`
* `W(S, v)` = `hash_BIPXXX/wrap(x_a || x_b || … || ser32(v))`
* `B(S, v)` = `hash_BIPXXX/beacon(W(S, v))[0..4)`
* `h(i, v)` = `int(hash_BIPXXX/share(x_i || ser32(v))) mod GROUP_N`
* `nonce` = `hash_BIPXXX/nonce(K_v || plaintext)[0..12)`

where `S` ranges over subsets of the key set (keys within a subset in
lexicographic order), `K_v` is the 32-byte content key,[^modn] `B(S, v)` is
the 4-byte beacon of subset `S`, and `h(i, v)` is key `i`'s Shamir share
value.

### Key Wrapping

Two wrapping modes are defined. A wallet uses exactly one, chosen by its
parameters; the mode is not signaled on chain (the recoverer knows its own
wallet's shape).[^modes]

**Subset mode** (RECOMMENDED when `C(n, r) ≤ n`): for each of the `C(n, r)`
subsets `S` of size `r`, in lexicographic order of their concatenated keys,
the wrap entry is

```
wrap_S = K_v ⊕ W(S, v)
```

A recoverer holding the `r` keys of subset `S` computes `W(S, v)` and
unwraps `K_v` directly.

**Shamir mode** (RECOMMENDED when `C(n, r) > n`): choose a polynomial `P` of
degree `r − 1` over the scalar field mod `GROUP_N` with `P(0) = int(K_v)`
and uniformly random higher coefficients. The `n` wrap entries, in canonical
key order, are the 32-byte serializations of

```
d_i = ( P(i) − h(i, v) ) mod GROUP_N
```

A recoverer holding any `r` keys computes the points `(i, h(i, v) + d_i)`
and interpolates `P(0)` via Lagrange interpolation.[^shamir]

### Beacon Slot Field

The slot field is a fixed **64-byte** area holding sixteen 4-byte slots. The
publisher places the `C(n, j)` beacons `B(S, v)` of all size-`j` subsets
into slots, **sorted lexicographically**, and fills every remaining slot
with uniformly random bytes.[^slots] Decoders MUST NOT ascribe meaning to
slot positions; a recoverer matches its single expected beacon value against
all slots.

### Encryption

The payload is encrypted with ChaCha20-Poly1305 ([RFC 8439]):

```
ciphertext = ChaCha20-Poly1305-Encrypt(
    key   = K_v,
    nonce = nonce,                     (payload-derived, see Derivations)
    aad   = slot_field || wrap_entries,
    data  = plaintext,
)
```

The nonce is deterministic and payload-bound (an SIV-style
construction).[^nonce] The associated data binds the ciphertext to the exact
slot field and wrap entries it was published with. The plaintext MUST NOT
contain private key material.

### Payload

The plaintext SHOULD use the content encoding of [BIP 138] (a sequence of
`CONTENT_TYPE || CONTENT_LENGTH || CONTENT` items), carrying a [BIP 380]
descriptor backup or a [BIP 388] wallet policy backup, so that an extracted
payload is interoperable with BIP 138 tooling. The payload SHOULD include a
birth height or `birth_time`, which lets the recovered wallet bound its
subsequent funds rescan. The plaintext SHOULD be padded with zero bytes
(after a `0x00` end-of-content item) to a multiple of 64 bytes.[^padding]

### Envelope and Publication

The complete `OP_RETURN` script is:

```
OP_RETURN <push:  slot_field (64)
                  || wrap_entries (C(n,r)·32 or n·32)
                  || nonce (12)
                  || ciphertext (len(plaintext) + 16) >
```

There is no magic value, no format version byte and no length field; every
byte of the push is a hash output, an XOR-masked key, a scalar difference or
AEAD output, making the push indistinguishable from uniformly random
data.[^nomagic] The push length is implied by the script. Future format
versions use distinct tag names (e.g. a version suffix), which changes all
derived values including the beacons, so scanners for one version never
match blobs of another.

Publication rules:

* Exactly one backup output per version; a transaction MAY carry other
  outputs of any kind. The funding of the transaction is out of scope (note
  the linkability consideration under Security).
* The version counter `v` MUST be incremented for every newly published
  backup of the same key set. Publishers without local state SHOULD
  discover the current maximum `v` by running the discovery procedure below
  before publishing (`v_new = v_max + 1`).
* A different account (different hardened account derivation, hence
  different root xpubs) forms a different key set with its own independent
  secret, beacons and version counter starting at 0.
* Re-publishing the byte-identical backup (same key set, `v` and plaintext)
  yields a byte-identical output and is harmless.

### Discovery Index

Discovery uses a compact filter index over `OP_RETURN` data, built with the
same parameters as [BIP 158] basic filters (`P = 19`, `M = 784931`, SipHash
key = first 16 bytes of the block hash) and committed to a [BIP 157]-style
filter header chain, so clients can verify served filters against a header
chain they trust.

For every `OP_RETURN` output in a block, let `data` be the concatenation of
the script's data pushes. The filter elements contributed by that output are
the **complete 4-byte chunks** `data[4·i .. 4·i+4)` for `i = 0 … 15` (at
most sixteen chunks, covering the first 64 bytes).[^chunks] Elements are
deduplicated per block as usual for GCS filters.

Because the slot field occupies the first 64 bytes of the backup push, every
beacon is one of these indexed chunks, and a recoverer can test its beacon
candidates against a block's filter with a single `MatchAny` query,
regardless of which slot the beacon occupies.

### Recovery Procedure

Given `r` seeds (or the corresponding root xpubs directly) and access to
block data plus the discovery index:

1. Derive candidate root xpubs: for each seed, derive the account-level
   xpubs at the standard derivation paths and account indexes given in
   [BIP 138]'s recovery path list (or the wallet product's known paths).
2. For each candidate key-set hypothesis, compute the recoverer's discovery
   subset `S` (its `j` keys, sorted) and the beacon candidates
   `B(S, v)` for `v = 0 … v_gap` (RECOMMENDED `v_gap = 20`).
3. Match all candidates against the discovery index from the wallet's birth
   height (or from the earliest possible height). For every matching block,
   download the block and locate `OP_RETURN` outputs that contain a
   candidate beacon in their first 64 bytes.
4. For each located output, parse the envelope using the recoverer's known
   `(n, r)` shape, unwrap `K_v` (subset mode: XOR with `W(S, v)`, trying
   each wrap entry; Shamir mode: interpolate), read the nonce from the
   envelope and attempt AEAD decryption with
   `aad = slot_field || wrap_entries`.
5. Collect all outputs that authenticate. The valid backup is the one with
   the **highest `v`**; on-chain position MUST NOT be used for
   ordering.[^replay] Outputs that fail authentication are false positives
   and MUST be ignored.
6. Parse the payload, restore the descriptor/policy, and rescan for funds
   from the embedded birth height.

## Rationale

### Why full xpubs, including chain codes

BIP 138 derives its secrets from x-only root public keys. This scheme uses
the full 78-byte xpub serialization because chain codes never appear
anywhere on chain: even a hypothetical adversary who could relate observed
child public keys to a root *public key* would still lack the chain code.
Since the recovering party derives full xpubs from seeds anyway, the extra
hardening is free. Normalizing the version bytes makes the derivation
network-independent.

### Why a threshold access structure

Under BIP 138's per-key individual secrets, any single participant xpub
decrypts. On a private backup medium that is acceptable: the adversary needs
the xpub *and* the medium. On a public chain the medium is free, so the
xpub becomes the entire security boundary — and single xpubs leak through
many channels (co-signing service databases, hardware vendor telemetry,
coordinator configuration files, and every multisig PSBT, which carries all
participant xpubs in its `GLOBAL_XPUB` fields). Wrapping to `r`-subsets
means a single leaked xpub reveals nothing — neither the content nor the
existence of a backup — while any party that could spend can still recover.

### Why deterministic keys and a payload-bound nonce

Deterministic derivation makes publishing stateless and idempotent and
requires no randomness source for keys. Per-version keys make nonce
management trivial — except for the failure mode where a publisher reuses a
version for a *different* payload, which with a fixed nonce would be a
catastrophic two-time pad. Deriving the nonce from `(K_v, plaintext)`
reduces that failure to a harmless linkage: identical payloads produce
identical outputs, differing payloads under a reused `v` produce
independently secure ciphertexts.

### Beacon length: why 4 bytes

There are two independent sources of false positives during discovery, and
only one of them depends on beacon length:

1. **GCS filter false positives**: `≈ 2^-19` per queried candidate per
   block (a property of the `M` parameter, independent of element length).
   Over a full scan of `B` blocks with `C` candidates this costs
   `B · C · 2^-19` unnecessary block downloads.
2. **Genuine chunk collisions**: some unrelated `OP_RETURN` chunk equals a
   candidate beacon. With `U` total indexed chunks on the chain and `b`-bit
   beacons, this costs `U · C / 2^b` downloads over a full scan.

With conservative estimates `U = 2^30` chunks (order 10^9; hundreds of
millions of `OP_RETURN` outputs at a few chunks each), `C = 100` candidates
(paths × accounts × version window) and `B = 10^6` blocks:

| Beacon length | Collision downloads `U·C/2^b` | GCS downloads `B·C·2^-19` | Dominant source | Verdict          |
|--------------:|------------------------------:|--------------------------:|-----------------|------------------|
|       8 bytes |                      ~0.000006 |                       ~190 | GCS             | wasteful size    |
|   **4 bytes** |                        **~25** |                   **~190** | **GCS**         | **chosen**       |
|       3 bytes |                         ~6,400 |                       ~190 | collisions      | ~10 GB junk      |
|       2 bytes |                    ~1,600,000 |                       ~190 | collisions      | unusable         |

At 4 bytes the beacon-dependent term hides below the GCS noise floor that
exists at *any* beacon length, so nothing is gained above 4 bytes; at 3
bytes collisions dominate by more than an order of magnitude and worsen as
`U` grows. False positives never affect correctness — every candidate is
verified by the AEAD tag — so the choice is purely a bandwidth trade-off.

### Slot count and quorum coverage: why 16 slots

The slot field must hold `C(n, j)` beacons. Wrap size depends on the mode.
For common configurations:

| Configuration        | `r` | wraps: subset mode | wraps: Shamir mode | beacons at `j = min(r,2)` | fits 16 slots |
|----------------------|----:|-------------------:|-------------------:|--------------------------:|:--------------|
| single-sig (1-of-1)  |   1 |         1 (32 B)   |          1 (32 B)  |                         1 | yes           |
| 2-of-2               |   2 |         1 (32 B)   |          2 (64 B)  |                         1 | yes           |
| 2-of-3               |   2 |         3 (96 B)   |          3 (96 B)  |                         3 | yes           |
| 3-of-3               |   3 |         1 (32 B)   |          3 (96 B)  |                  C(3,2)=3 | yes           |
| 2-of-2 → 1-of-2 decay|   1 |         2 (64 B)   |          2 (64 B)  |                    j=1: 2 | yes           |
| 3-of-4               |   3 |         4 (128 B)  |          4 (128 B) |                  C(4,2)=6 | yes           |
| 3-of-5               |   3 |        10 (320 B)  |          5 (160 B) |                 C(5,2)=10 | yes           |
| 4-of-6               |   4 |        15 (480 B)  |          6 (192 B) |                 C(6,2)=15 | yes           |
| 5-of-7               |   5 |        21 (672 B)  |          7 (224 B) |          C(7,2)=21 → j=1: 7 | via `j = 1`  |

Sixteen slots cover every `j = 2` configuration up to `n = 6` and every
configuration whatsoever at `j = 1` (for `n ≤ 16`). Larger windows were
considered and rejected: covering `C(7,2) = 21` natively would require 24
slots, growing every backup and the index for a rare configuration that
degrades gracefully to `j = 1`. A fixed field (rather than one sized to
`C(n, j)`) makes all configurations with up to 16 subsets byte-identical in
this region of the output.

### The `j` parameter

Discovery and decryption have different natural thresholds. `j = r` gives
maximal locate-privacy but makes a partial quorum unable to even confirm a
backup exists; `j = 1` lets any single key holder locate (but not decrypt),
which also means any single leaked xpub reveals backup existence, count and
timing. `j = 2` is the recommended balance: locating requires two
cooperating keys, which in the single-user-redundancy model means the user
themselves.

### Why one output and no marker

Compact filter elements are derived per output, so an earlier design used
one output per discovery subset (a data output plus small marker outputs).
Indexing multiple aligned chunks per output removes that need: all beacons
share one output, position-independently matchable — and the output count
no longer leaks the quorum shape (three marker outputs would have advertised
"2-of-3" to any observer).

### Why no magic value

A magic prefix would only help third parties enumerate protocol outputs —
an anti-goal. The beacons themselves are the discovery mechanism, and the
index covers all `OP_RETURN` outputs regardless of content, so a magic
value adds nothing for the owner and subtracts deniability. Without it (and
without any plaintext version or length byte), the entire push is
indistinguishable from random data, and the set of "possible backups" is
every `OP_RETURN` output on the chain.

### XOR subsets versus Shamir

Subset XOR wraps are trivially simple (pure hashing, per BIP 138's
implementability goal) but scale as `C(n, r)`. Shamir sharing over the
secp256k1 scalar field scales as `n` and reuses scalar arithmetic every
wallet already ships; it needs no new primitives. Keeping both, with the
size-based recommendation, lets simple wallets stay hash-only while heavy
quorums stay compact. Because the recoverer always knows its own wallet
parameters, no on-chain mode signaling is needed.

## Security Considerations

**Extended public keys are the key material.** Whoever holds `r` of the `n`
root xpubs can locate and decrypt the backup; whoever holds `j` can locate
it. This is by design — recovery must work from public key material — but
it upgrades xpubs to secrets, permanently, because the ciphertext can never
be deleted:

| Adversary knows                                     | Locate | Decrypt |
|-----------------------------------------------------|:------:|:-------:|
| nothing (chain observer)                            | no     | no      |
| all on-chain child keys and the full spend history  | no     | no      |
| fewer than `j` root xpubs                           | no     | no      |
| `j ≤ · < r` root xpubs                              | yes    | no      |
| `r` or more root xpubs                              | yes    | yes     |

Implementations MUST treat multisig PSBTs as descriptor-equivalent secrets
(their `GLOBAL_XPUB` fields carry the full key set) and SHOULD avoid
sending participant xpubs to third-party services. The [BIP 138] warning
about single-signature account xpubs known to vendor servers applies with
full force: such a key SHOULD NOT be reused as a participant of a backed-up
multisig, or the vendor's database becomes `1` of the `r` required shares.

**`r = 1` configurations** (required for policies that decay to
single-key spending) have exactly BIP 138's single-xpub security floor, on
a public medium. Publishers SHOULD make this trade-off explicit to users.

**Child keys reveal nothing.** Spends reveal child public keys (even full
witness scripts), but deriving a parent public key from a child requires the
parent chain code, which never appears on chain; the qualifying-key rules
additionally guarantee the root key itself is never an on-chain key.

**Linkability.** The transaction publishing the backup may be funded from
the wallet itself, publicly linking "this wallet published a backup" —
this has no cryptographic effect on the scheme. Publishers wanting
unlinkability SHOULD fund the transaction from unrelated coins. Version
counters are folded into every derivation, so multiple backups of the same
wallet are mutually unlinkable to observers.

**Replay.** An attacker can re-publish an old (superseded) backup output in
a new transaction. Recoverers select by highest authenticated `v`, never by
chain position, which defeats rollback; forging a higher `v` requires the
content key.

**Beacon griefing.** Anyone can copy the (public) beacon bytes of an
observed backup into their own outputs, adding false positives for that
specific wallet's recovery. The recovery outcome is unaffected (AEAD
verification rejects them); the cost is bounded extra downloads.

**Availability.** The scheme depends on `OP_RETURN` relay policy for the
envelope size (188 bytes plus payload for a 2-of-3). Where policy
constrains data carrier size below the envelope size, publication requires
miner cooperation or policy-relaxed relays; this affects publication only,
never recovery of already-confirmed backups.

## Backward Compatibility

This BIP defines a new format and changes no existing one. The payload
content encoding is shared with [BIP 138], so recovered payloads are
interoperable with BIP 138 tooling; the envelope, access structure and all
derivation tags are deliberately distinct (no derived value is shared
between the two schemes, so publishing both for the same wallet does not
create cross-scheme key reuse).

## Test Vectors

To be added: derivation vectors (secret, keys, wraps in both modes, beacons,
nonce) for 1-of-1, 2-of-3 and 3-of-5 key sets, a complete 2-of-3 envelope,
and a discovery-index vector (block with known `OP_RETURN` outputs and the
resulting chunk filter).

## Reference Implementation

To be added. A prototype of the discovery index (the 4-byte-chunk
`OP_RETURN` compact filter set, served with BIP 157-style header chains
over HTTP) exists in [block-dn].

## Acknowledgements

This proposal builds on the backup scheme of [BIP 138] by Pyth
(@pythcoiner), which in turn builds on work by @bigspider; the threshold
adaptation, discovery mechanism and on-chain profile were developed to suit
a public, permanent storage medium.

## Changelog

* **0.1.0** (2026-08-23): Initial draft.

## Copyright

This BIP is licensed under the BSD 2-Clause License.

[^trailing]: Any trailing derivation step (or the implicit child derivation
    of a wildcard) breaks the identity between the root public key used for
    secret derivation and the public keys that appear on chain; see BIP 138
    for the full rationale and the allowed expression forms.

[^fullxpub]: Including the chain code costs nothing (recoverers derive full
    xpubs from seeds regardless) and adds a defense layer: chain codes are
    never published on chain in any protocol.

[^modn]: Reducing the key derivation output modulo the group order unifies
    the two wrap modes: Shamir interpolation recovers a scalar, whose
    32-byte serialization is exactly `K_v`. The reduction bias is
    negligible (< 2^-128) and irrelevant for a symmetric key.

[^modes]: Because the recoverer necessarily knows its own wallet's
    parameters `(n, r, j)` before it can derive any candidate xpubs, mode
    and layout information on chain would only help third parties.

[^shamir]: The share values `h(i, v)` are derived from the xpubs, so no
    per-participant state is needed; the published corrections `d_i` shift
    those deterministic values onto the random polynomial. Any `r` points
    reconstruct `P(0)`; fewer points reveal nothing about it
    (information-theoretically, for uniformly random higher coefficients).

[^slots]: Sorting removes any information from beacon order; random filler
    makes every configuration with up to 16 discovery subsets produce an
    identically-shaped field. Fillers collide with a real beacon only with
    probability ~2^-32 per slot, and such a collision is harmless (the AEAD
    step rejects).

[^nonce]: A random nonce would require a CSPRNG at publish time and would
    make identical re-publications distinguishable; a zero nonce would make
    an accidental version reuse catastrophic. The payload-bound nonce is
    the standard SIV compromise: deterministic, and secure under nonce-reuse
    up to revealing payload equality.

[^padding]: Padding coarsens the only remaining observable, the output
    size. 64-byte buckets keep overhead under one filter chunk row while
    grouping typical descriptor payloads into few size classes.

[^nomagic]: Indistinguishability is load-bearing for the threat model: a
    chain observer cannot even enumerate which outputs are backups, so
    bulk-collection attacks must treat every `OP_RETURN` output as a
    candidate against every stolen xpub set.

[^chunks]: Only complete 4-byte chunks become elements: the backup slot
    field always occupies 64 bytes, so all sixteen chunks exist for backup
    outputs; short foreign outputs simply contribute fewer elements.
    Sixteen chunks bound the index growth to at most 16 elements per
    `OP_RETURN` output regardless of payload size.

[^replay]: Confirmation depth of the *highest-version* backup is still
    relevant: recoverers SHOULD prefer a confirmed backup over an
    unconfirmed one and MAY require a minimum depth before acting on it.

[BIP 32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[BIP 138]: https://github.com/bitcoin/bips/pull/1951
[BIP 157]: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
[BIP 158]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
[BIP 340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[BIP 341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
[BIP 380]: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
[BIP 388]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki
[RFC 8439]: https://www.rfc-editor.org/rfc/rfc8439
[block-dn]: https://github.com/guggero/block-dn
