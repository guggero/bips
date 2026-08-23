```
  BIP: ?
  Layer: Applications
  Title: On-Chain Encrypted Wallet Descriptor Backups
  Authors: Oliver Gugger <gugger@gmail.com>
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Requires: 32, 157, 158, 324, 340, 380
```

## Abstract

This BIP specifies a compact, encrypted backup format for wallet output
script descriptors ([BIP 380]) and wallet policies ([BIP 388]) that is
published inside an `OP_RETURN` output on the Bitcoin blockchain itself, and
a discovery mechanism that lets a wallet find every backup it participates in
with nothing but **one** of its seeds and access to a compact block filter
index. Each participating seed derives a dedicated *backup key pair* at a
hardened path. The published output is encrypted to the backup public keys
of all participants in two layers: any single backup private key reveals the
*shape* of the wallet (the quorum, and which other keys are needed), while a
recovery quorum of backup private keys reveals the full descriptor. The
output is indistinguishable from uniformly random data, and no extended
public key of the wallet is ever an input to any derivation, so a leaked
xpub, PSBT or coordinator database cannot decrypt a backup.

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
is: *any spending quorum of seeds must suffice to recover everything else*,
including the descriptor. And the natural recovery *experience* is: plug in
one device, or restore one seed into an app, and be told which wallets that
key is part of and what else is needed to open them. A user who has lost
their coordinator should not need to remember how many wallets they had,
what their quorums were, or which other devices to look for.

The blockchain itself is a uniquely suitable backup medium for this data: it
is highly replicated, always available to any wallet that can sync, cannot
silently lose or corrupt the data, and can be searched by a recovering
wallet that starts from nothing but a seed. What the chain does not offer is
confidentiality or deletion, so the scheme must remain secure with the
ciphertext permanently public and potentially linkable to the wallet's own
transactions.

[BIP 138] specifies an encryption scheme for the same payload class, aimed
at storage on untrusted media, where any *single* participant's extended
public key decrypts the backup. That trade-off is appropriate for private
storage (an attacker needs the xpub *and* access to the medium) but not for
a public ledger: the storage-access factor disappears, every published
backup is trivially collectable forever, and account xpubs leak through many
channels (every multisig PSBT carries all of them, as do co-signing service
databases and coordinator configuration files). This proposal therefore
moves the key material from extended public keys to **private keys at a
dedicated hardened path**, uses public-key encryption so that the publisher
never holds anything that decrypts, splits the content into a single-key
layer and a quorum layer, and adds a discovery mechanism, while remaining
compatible with BIP 138's payload content encoding.

## Design Overview

Every seed derives one **backup key pair** `(b, B)` at a fixed hardened
path, independent of network and account. The public key `B` is exported to
the coordinator once, at wallet setup, exactly like an account xpub. The
private key `b` never leaves the device.

* The publisher (a watch-only coordinator holding the `n` backup public
  keys) chooses an ephemeral key pair `(e, E)` and derives one shared
  secret per participant by ECDH: `Z_i = e·B_i`. The recoverer computes the
  same value as `b_i·E`, reading `E` from the output. This is
  multi-recipient ECIES: the publisher needs only public keys, the
  recoverer only its own private key.
* **Layer 1 (schema)**: a fixed-size record holding the quorum shape, a
  wallet identifier and a publication version, encrypted under a key that
  is wrapped once per participant. Any single backup private key opens it.
* **Layer 2 (content)**: the descriptor or policy payload, encrypted under
  a key that is Shamir-shared across the `n` participants with threshold
  `r`, each share masked with that participant's ECDH secret. Any `r` backup
  private keys open it; fewer reveal nothing.
* **Beacons**: a 4-byte tag per participant, derived from that participant's
  backup public key and a block-height epoch, placed in a fixed 64-byte slot
  field at the start of the `OP_RETURN` data. A recovering wallet derives
  its own beacon per epoch and matches it against a compact filter index of
  `OP_RETURN` data chunks, then downloads only the matching blocks.
* Everything is published in a **single `OP_RETURN` output** whose bytes
  are all hash outputs, an [ElligatorSwift] point encoding, XOR-masked keys,
  scalar differences or AEAD ciphertext, and therefore indistinguishable
  from random. There is no magic value, no plaintext version byte, and no
  visible structure.

Recovery, starting from one seed and nothing else: derive `(b, B)`, derive
the beacon for every epoch since the wallet's birth, match against the
filter index, fetch matching blocks, unwrap the schema with `b`, and show
the user every wallet this key participates in together with what is still
needed. With `r` keys present, unwrap the content and restore the
descriptor.

## Specification

The scheme is defined for any `1 ≤ r ≤ n ≤ 16` (single-signature wallets
included).

Notation: `hash_tag(m)` is the [BIP 340] tagged hash
`SHA256(SHA256(tag) || SHA256(tag) || m)` with `tag = "BIPXXX/<keyword>"`,
where `XXX` is the number assigned to this BIP. `ser32(i)` is the 4-byte
big-endian serialization of an unsigned integer; `ser256(k)` the 32-byte
big-endian serialization of a scalar. `int(m)` interprets a byte string as
a big-endian integer. `||` is byte concatenation. `⊕` is bitwise XOR.
`GROUP_N` is the order of the secp256k1 group, `G` its generator, `x(P)`
the 32-byte x-coordinate of point `P`, and `ser_comp(P)` its 33-byte
compressed serialization. `stretch_tag(m)` is the memory-hard key
derivation defined below.

### Backup Key Pair

Each participating seed derives its **backup private key** `b` as the
private key at the [BIP 32] path

```
m / XXX' / 0'
```

with both steps hardened, where `XXX` is the number assigned to this
BIP.[^path] The **backup public key** is `B = b·G`, serialized as
`ser_comp(B)`. The path is independent of network, script type and account:
one seed has exactly one backup key pair, which is what lets a single key
find every wallet the seed participates in.

The backup public key is exported to the wallet coordinator at setup, along
with the participant's account xpub, and is stored as part of the wallet
configuration. It MUST NOT be included in PSBTs and SHOULD NOT be shared
with parties other than the coordinator(s) of wallets it participates in
(see Security Considerations on what a leaked backup public key enables).

Signing devices supporting this BIP MUST implement two operations:

1. **Export**: return `ser_comp(B)` for the path above.
2. **Decrypt**: given a 33-byte compressed or 64-byte ElligatorSwift-encoded
   point `E`, return `x(b·E)`. Devices MUST require explicit user
   confirmation on the device before performing this operation, since it
   otherwise turns the device into a decryption oracle for any backup
   addressed to it.[^oracle]

### Parameters

Every backup is published under two parameters, chosen per wallet:

* `n` — the number of participants that contributed a backup public key,
  `1 ≤ n ≤ 16`. Participants whose signing device cannot export a backup
  public key are not part of the key set; they still appear in the payload.
  Implementations MUST warn the user about every such participant.
* `r` — the **recovery threshold**, `1 ≤ r ≤ n`. Consider every set of
  participants that can spend from the wallet under any script path at any
  time; `r` MUST NOT exceed the smallest number of key-set members contained
  in any such set (otherwise a party able to spend could be unable to
  recover the descriptor that lets them do so). For a plain k-of-n multisig
  in which every participant is in the key set, `r = k`. For a policy that
  decays over time (e.g. a 2-of-2 that becomes 1-of-2 after a timeout), `r`
  is the *decayed* minimum, here `r = 1`. A participant outside the key set
  further lowers `r` by one for every spending set it belongs to.

Unlike the extended-public-key based design this proposal replaces, the
recoverer does **not** need to know `n` or `r` in advance: both are carried
in the schema layer.

### Canonical Order and Wallet Identifier

Let `B_1 < B_2 < … < B_n` be the participants' backup public keys in
increasing lexicographic order of their compressed serializations; this
order assigns each participant its canonical index `i` (1-based, used as the
Shamir evaluation point). The **wallet identifier** is

```
wallet_id = hash_tag("BIPXXX/wallet-id", ser_comp(B_1) || … || ser_comp(B_n))[0..8)
```

Two backups with the same `wallet_id` are versions of the same wallet.

### Key Stretching

`stretch_tag(m)` is [Argon2id] ([RFC 9106]) with password `m`, salt
`SHA256("BIPXXX/" || tag)[0..16)`, time cost `t = 3`, memory cost
`m = 65536` KiB (64 MiB), parallelism `p = 1` and a 32-byte output. It is
applied exactly twice per participant during recovery: once to the backup
public key (for beacons) and once to the ECDH secret (for unwrapping). Its
purpose is to raise the per-candidate cost of brute-force attacks against
weak seeds; see Rationale.

### Epochs and Versions

Block heights are grouped into **epochs** of 2016 blocks:
`epoch(h) = floor(h / 2016)`.

Each publication carries a 4-byte **version** `v`. Versions of the same
wallet MUST be strictly increasing. `v` RECOMMENDED to be the block height
of the chain tip at the time the publisher constructs the backup, which
makes versions monotonic without publisher state as long as a wallet
publishes at most once per block.[^version] The beacons of a publication are
bound to `epoch(v)`, and the publication MUST confirm at a height `h` with
`epoch(h) ≤ epoch(v) + 1`; a publisher whose transaction remains
unconfirmed past that point MUST rebuild it with a fresh `v`.

### Schema Record

The **schema** is the fixed 80-byte layer-1 plaintext:

| Offset | Size | Field        | Content                                              |
|-------:|-----:|--------------|------------------------------------------------------|
|      0 |    4 | `v`          | `ser32(v)`                                           |
|      4 |    1 | `r`          | recovery threshold                                   |
|      5 |    1 | `n`          | key set size                                         |
|      6 |    1 | `flags`      | bit 0: hints present; other bits MUST be zero        |
|      7 |    1 | reserved     | MUST be zero                                         |
|      8 |    8 | `wallet_id`  | as defined above                                     |
|     16 |   64 | `hints`      | sixteen 4-byte hint slots                            |

If `flags` bit 0 is set, hint slot `i − 1` (for `i = 1 … n`) holds the
[BIP 32] master key fingerprint of participant `i`'s seed and the remaining
slots are zero; otherwise all hint slots are zero.[^hints] Hints let a
recovering wallet tell the user *which* of their devices to connect next;
without hints the wallet simply tries whatever device is connected. Hints
are OPTIONAL because they reveal the identity of all co-signers to any
single-key holder (see Rationale).

### Derivations

For a key set `B_1 … B_n`, a schema record `schema` and a payload plaintext
`payload`, the publisher derives:

* `e` = `int(hash_tag("BIPXXX/ephemeral", ser_comp(B_1) || … || ser_comp(B_n) || schema || payload)) mod GROUP_N`
  (the negligible case `e = 0` MUST be rejected)
* `E` = `e·G`
* `E_enc` = the 64-byte [ElligatorSwift] encoding of `E`, using
  `hash_tag("BIPXXX/ellswift", ser256(e))` as the encoding's auxiliary
  randomness[^ellswift]
* `Z_i` = `x(e·B_i)` (publisher) `= x(b_i·E)` (recoverer)
* `secret_i` = `stretch_secret(Z_i || ser_comp(B_i))`
* `K_1` = `hash_tag("BIPXXX/schema-key", ser256(e))`
* `wrap_i` = `K_1 ⊕ hash_tag("BIPXXX/schema-wrap", secret_i)`
* `k_2` = `int(hash_tag("BIPXXX/content-key", ser256(e))) mod GROUP_N`, and
  `K_2 = ser256(k_2)`
* `a_j` = `int(hash_tag("BIPXXX/coefficient", ser256(e) || ser32(j))) mod GROUP_N`
  for `j = 1 … r − 1`
* `P(x)` = `k_2 + a_1·x + … + a_{r−1}·x^{r−1} mod GROUP_N`
* `h_i` = `int(hash_tag("BIPXXX/share-mask", secret_i)) mod GROUP_N`
* `d_i` = `(P(i) − h_i) mod GROUP_N`
* `filler_s` = `hash_tag("BIPXXX/filler", ser256(e) || ser32(s))[0..4)`
  for slot `s`
* `beacon_i` = `hash_tag("BIPXXX/beacon", stretch_beacon(ser_comp(B_i)) || ser32(epoch(v)))[0..4)`

Every value is a deterministic function of the key set and the plaintexts,
so publishing requires no randomness source and is idempotent: identical
inputs produce a byte-identical output.[^deterministic]

### Layer 1: Schema Encryption

```
schema_ct = ChaCha20-Poly1305-Encrypt(
    key   = K_1,
    nonce = 0x000000000000000000000000,
    aad   = slot_field || E_enc,
    data  = schema,                        (80 bytes)
)                                          (96 bytes)
```

A recoverer holding `b_i` computes `secret_i`, unwraps
`K_1 = wrap_i ⊕ hash_tag("BIPXXX/schema-wrap", secret_i)` and decrypts.

### Layer 2: Content Encryption

```
ciphertext = ChaCha20-Poly1305-Encrypt(
    key   = K_2,
    nonce = 0x000000000000000000000000,
    aad   = slot_field || E_enc || schema_ct || entries,
    data  = payload,
)
```

A recoverer holding `r` backup private keys computes, for each, the point
`(i, h_i + d_i mod GROUP_N) = (i, P(i))` and interpolates `P(0) = k_2` via
Lagrange interpolation over the scalar field.[^shamir] The fixed nonces are
safe because both keys are single-use by construction: `e`, and hence `K_1`
and `K_2`, change whenever any bit of either plaintext changes.[^nonce]

### Payload

The payload plaintext SHOULD use the content encoding of [BIP 138] (a
sequence of `CONTENT_TYPE || CONTENT_LENGTH || CONTENT` items), carrying a
[BIP 380] descriptor backup or a [BIP 388] wallet policy backup, so that an
extracted payload is interoperable with BIP 138 tooling. The payload SHOULD
include a birth height or `birth_time`, which lets the recovered wallet
bound its subsequent funds rescan. The plaintext SHOULD be padded with zero
bytes (after a `0x00` end-of-content item) to a multiple of 64
bytes.[^padding] The plaintext MUST NOT contain private key material.

### Beacon Slot Field

The slot field is a fixed **64-byte** area holding sixteen 4-byte slots. The
publisher places the `n` beacons `beacon_1 … beacon_n` into slots, **sorted
lexicographically**, and fills every remaining slot `s` with
`filler_s`.[^slots] Decoders MUST NOT ascribe meaning to slot positions; a
recoverer matches its expected beacon value against all slots.

### Envelope and Publication

The complete `OP_RETURN` script is:

```
OP_RETURN <push:  slot_field (64)
                  || E_enc (64)
                  || schema_ct (96)
                  || entries (n · 64)
                  || ciphertext (len(payload) + 16) >
```

where `entries` is the concatenation, in canonical order, of one 64-byte
entry per participant:

```
entry_i = wrap_i (32) || ser256(d_i) (32)
```

There is no magic value, no format version byte and no length field; every
byte of the push is a hash output, an ElligatorSwift encoding, an XOR-masked
key, a scalar difference or AEAD output, making the push indistinguishable
from uniformly random data.[^nomagic] The push length is implied by the
script. Future format versions use distinct tag names (e.g. a version
suffix), which changes all derived values including the beacons, so scanners
for one version never match blobs of another.

Publication rules:

* Exactly one backup output per publication; a transaction MAY carry other
  outputs of any kind. The funding of the transaction is out of scope (note
  the linkability consideration under Security).
* A publisher MUST use a `v` strictly greater than every version it has
  published for the same `wallet_id`. A publisher without local state
  SHOULD use the current tip height, which satisfies this whenever the
  previous publication has confirmed.[^statelesspub]
* Re-publishing the byte-identical backup (same key set and plaintexts)
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

Given one or more seeds (or signing devices) and access to block data plus
the discovery index:

1. For each seed, derive the backup key pair `(b, B)` and compute
   `stretch_beacon(ser_comp(B))` once.
2. For every block at height `h` from the earliest height to scan (the
   wallet's known birth height, the activation height of this BIP, or the
   user's best guess), the candidate set is
   `{ hash_tag("BIPXXX/beacon", stretched_B || ser32(ep))[0..4) : ep ∈ {epoch(h), epoch(h) − 1} }`
   for each held key. Match the candidates against the block's filter. For
   every matching block, download it and locate `OP_RETURN` outputs of at
   least 288 bytes[^minlen] that contain a candidate beacon in their first
   64 bytes.
3. For each located output, decode `E` from bytes `[64, 128)`. For each
   held key, obtain `Z = x(b·E)` from the device and compute `secret`.
   Then for each entry position `k = 0 … 15` with
   `224 + 64·(k + 1) ≤ len(push)`, read `wrap` from bytes
   `[224 + 64k, 224 + 64k + 32)`, unwrap a candidate `K_1`, and attempt to
   decrypt `schema_ct` (bytes `[128, 224)`) with
   `aad = slot_field || E_enc`. At most one position authenticates; if none
   does, the output is a false positive and MUST be ignored.
4. Parse the schema. Check `flags` and the reserved byte, check
   `1 ≤ r ≤ n ≤ 16`, check that `k + 1 ≤ n` for the position that
   authenticated, and check `v ≤ h`; reject otherwise. Record
   `(wallet_id, v, r, n, hints, k + 1)`: the held key is participant
   `k + 1`.
5. Group all authenticated schemas by `wallet_id`. For each wallet, the
   current backup is the one with the **highest `v`**; on-chain position
   MUST NOT be used for ordering.[^replay] Present every wallet found to the
   user, including how many further keys are needed (`r` minus the number
   of held keys that are participants) and the hints, if present.
6. When `r` participant keys are held for a wallet: for each, compute
   `P(i) = h_i + d_i mod GROUP_N` from its entry, interpolate `k_2`, and
   decrypt `ciphertext` (everything after the `n` entries) with
   `aad = slot_field || E_enc || schema_ct || entries`. Outputs that fail
   authentication MUST be ignored and the next-highest `v` for that
   `wallet_id` considered.
7. Parse the payload, restore the descriptor/policy, verify that the
   held keys' account xpubs appear in it, and rescan for funds from the
   embedded birth height. If more than one authenticated backup exists for a
   `wallet_id`, or the highest-version backup describes a wallet with no
   on-chain history while a lower one does, implementations SHOULD surface
   this to the user (see the forgery discussion under Security).

### Obtaining the Remaining Keys (Informative)

When a recovering wallet holds fewer than `r` participant keys, the missing
contributions come from one of three places. None of them requires a
protocol beyond this BIP:

* **Another device of the same user.** In the single-user-redundancy model
  this is the common case; the user connects the next device and step 3
  repeats for it.
* **A co-signing service that is itself a participant.** The service holds
  its own backup private key and can locate and unwrap its own share
  `P(i)` for any backup it participates in. It can release that 32-byte
  share to a requester who proves possession of another participant's key
  (for instance by signing a challenge with their backup key), after
  applying whatever policy it sees fit: rate limits, delays, notifications
  or additional authentication. This is the one place in the system where
  policy, rather than cryptography, can stand between a brute-forced weak
  seed and a decrypted backup.
* **Another person.** Their wallet locates the same output via their own
  beacon and can display or export their share `P(i)` together with the
  index `i`. The share is specific to this one backup output and reveals
  nothing about any other publication. Transport of the share (QR code,
  message, in person) is out of scope.

## Rationale

### Why private keys instead of extended public keys

The design this proposal replaces derived all secrets from the wallet's
account xpubs, on the grounds that recovery must work from public key
material and that a watch-only coordinator should be able to publish. Both
goals survive here, but the xpub-as-secret model has two flaws that became
apparent in implementation review. First, account xpubs are not secrets in
practice: they are in every PSBT, in every co-signing service's database, in
coordinator configuration files and, for many hardware wallets, on the
vendor's servers. Second, any threshold over xpubs requires a quorum of
xpubs even to *find* a backup, which prevents the desired recovery
experience of plugging in one device and being shown everything it belongs
to.

A dedicated hardened path fixes the first flaw: nothing derived at
`m/XXX'/0'` is ever needed for signing, so nothing about it appears in
PSBTs, on chain or in vendor telemetry. Public-key encryption fixes the
tension in the second: discovery can be single-key without the publisher
ever holding a decryption key.

### Why public-key encryption

A tempting simpler design would use the *hash* of the obscure-path xpub as a
symmetric key, in the manner some hardware wallets derive encryption keys
for wallet software. That works when the encrypting and decrypting parties
are the same, but here the publisher is a coordinator and the recoverer a
device. Under a symmetric scheme the coordinator must hold every
participant's decryption secret, and because that secret is per *seed*
rather than per wallet, the coordinator of one wallet, or anyone who steals
its database, could decrypt every backup of every wallet that seed is ever
part of.

With ECIES the coordinator holds only public keys. The ephemeral key `E` in
the envelope is what makes this possible: publisher and recoverer arrive at
the same `Z_i` from different sides (`e·B_i` versus `b_i·E`) without either
ever knowing the other's scalar, and `e` is discarded after publishing. A
single ephemeral key serves all recipients, as in age and HPKE
multi-recipient modes; domain separation between recipients comes from
including `B_i` in the stretched secret.

### Why two layers

Nobody recovers a multisig wallet only to look at it. Recovery is a prelude
to spending, and spending needs `r` keys anyway, so requiring `r` keys for
the *descriptor* adds no devices to the flow the user must complete
regardless. What it does cost is ordering: the user would see nothing until
the second device is connected. The schema layer removes that friction by
letting the first key answer "which wallets am I in, and what else do I
need?" immediately.

The layers also have very different exposure. In the heterogeneous setups
this BIP targets (phone key, hardware device, service), the realistic
failure is that *one* key is compromised while the others are strong: a
breached service database, a stolen hardware device with an extracted seed,
phone malware. Under single-key full decryption, each of those events would
disclose complete descriptors, balances and co-signer identities for every
affected wallet, which is a targeting list. Under the two-layer split, the
same events disclose only quorum shapes.

### Why single-key discovery, and what it costs

Single-key beacons are what make the intended recovery experience possible.
They also change the security picture for one specific adversary, and this
BIP prefers to state that plainly.

Consider a hardware wallet product with a weak entropy source whose entire
seed space, say `2^32` seeds, an attacker can enumerate, and a user whose
multisig consists entirely of such devices. Without any on-chain backup, the
attacker cannot find that wallet: they would have to guess *pairs* of weak
seeds and script templates, about `2^63` attempts. Under the previous
xpub-based design with two-key discovery, the same held. With single-key
discovery, the attacker derives one beacon per weak seed, locates the
output, and then searches for the second weak seed *against a known
ciphertext*, a linear `2^32` search. Whatever layer 2 contains, it falls,
and two weak seeds that were safe by combinatorics become a spending quorum.

No construction avoids this while keeping single-key discovery: once an
output is located, every quorum layer is a function of the located bytes and
the remaining keys, and the remaining keys are enumerable by assumption. The
available mitigations are cost (key stretching, below), policy (a service
participant that rate-limits share release) and, above all, heterogeneity:
a wallet with at least one participant that is not from the weak population
is not affected, because that participant's key is not enumerable.
Implementations SHOULD discourage building a multisig entirely from devices
of one vendor and model for reasons that predate this BIP.

### Why key stretching

Argon2id in both derivations makes every brute-force candidate cost one
memory-hard evaluation instead of one hash or one point multiplication. At
the chosen parameters (about a quarter second on a phone), a `2^32`
candidate space costs on the order of `2^32` core-seconds with limited GPU
and ASIC advantage: roughly a hundred years of a single core, or a
substantial cloud bill. This does not rescue a `2^20` seed space and it is
not a substitute for a good entropy source. It is included because it is
cheap for the legitimate user, who performs exactly two evaluations per key
per recovery, and because it raises the price of exactly the attack that
single-key discovery makes cheaper. The parameters are a knob; the
reference implementation will document the measured cost on common
hardware.

### Why epoch-bound beacons

Beacons must be computable both by the publisher (who holds `B_i`) and by
the recoverer (who holds `b_i` and therefore also `B_i`) *before* the output
is located, so they cannot depend on `E`. A constant beacon per key would
link every backup of every wallet a key participates in. The previous design
folded the wallet's version counter into the beacon, which works when the
recoverer already knows the wallet but not when one key participates in an
unknown number of wallets each with its own counter.

Binding the beacon to `epoch(v)` instead needs no counter anywhere: the
publisher uses the epoch of its own `v`, the recoverer tests two candidates
per key per block (the block's epoch and the one before, allowing for
confirmation delay), and two publications of the same key in different
epochs are unlinkable. Two publications of the same key in the same epoch
share a beacon, which links them to each other but to nothing else; an
observer already sees their timing. The epoch length of 2016 blocks matches
the difficulty period and gives publishers about two weeks of confirmation
slack.

An alternative considered was a per-key counter across all of a key's
wallets, discovered by the publisher via the index before publishing. It
gives full unlinkability at the cost of a mandatory publisher-side scan and
a recovery window that grows with the number of wallets and versions per
key. Either choice is compatible with the rest of the design.

### Why ElligatorSwift

A compressed point begins with `0x02` or `0x03`, and even an x-only
coordinate is a valid field element for only about half of all 32-byte
strings, so either encoding would let an observer rule out half of all
`OP_RETURN` outputs as backups with certainty and mark the rest as
candidates. [ElligatorSwift], specified in [BIP 324] and implemented in
libsecp256k1, encodes any point as 64 bytes that are computationally
indistinguishable from uniform. The cost is 32 extra bytes per backup.

### Why a fixed-size schema in a fixed position

The recoverer does not know `n` before decrypting layer 1, so layer 1 must
be parseable without it. Placing the schema ciphertext at a fixed offset
with a fixed size, *before* the variable-length entries, lets the recoverer
try each of the at most sixteen entry positions against a fixed target. The
64-byte hint area makes the record larger than strictly necessary, but a
fixed size is required for both parseability and shape-hiding, and 96 bytes
of ciphertext is small next to a typical descriptor.

### Hints

Master key fingerprints in the schema let a wallet say "connect the device
with fingerprint `a1b2c3d4`" rather than "connect another device". They also
tell any single-key holder exactly who the co-signers are, which is a
privacy loss in shared-custody setups and, for the weak-seed adversary, a
cheap join key (though that adversary can find weak partners without it, as
discussed above). Because the trade-off depends on the deployment, hints are
optional and signaled by a flag. Single-user-redundancy wallets will
typically include them; shared-custody wallets may prefer to omit them.

### Beacon length: why 4 bytes

There are two independent sources of false positives during discovery, and
only one of them depends on beacon length:

1. **GCS filter false positives**: `≈ 2^-19` per queried candidate per
   block (a property of the `M` parameter, independent of element length).
   Over a full scan of `B` blocks with `c` candidates per block this costs
   `B · c · 2^-19` unnecessary block downloads.
2. **Genuine chunk collisions**: some unrelated `OP_RETURN` chunk equals a
   candidate beacon. With `U` total indexed chunks on the chain and `b`-bit
   beacons, this costs `U · c / 2^b` downloads over a full scan.

With conservative estimates `U = 2^30` chunks (order 10^9; hundreds of
millions of `OP_RETURN` outputs at a few chunks each), `c = 2` candidates
per block for a single held key (two epochs) and `B = 10^6` blocks:

| Beacon length | Collision downloads `U·c/2^b` | GCS downloads `B·c·2^-19` | Dominant source | Verdict          |
|--------------:|------------------------------:|--------------------------:|-----------------|------------------|
|       8 bytes |                             ~0 |                        ~4 | GCS             | wasteful size    |
|   **4 bytes** |                        **~0.5** |                    **~4** | **GCS**         | **chosen**       |
|       3 bytes |                          ~128 |                        ~4 | collisions      | ~250 MB junk     |
|       2 bytes |                       ~32,000 |                        ~4 | collisions      | unusable         |

Both terms scale linearly with the number of held keys. At 4 bytes the
beacon-dependent term hides below the GCS noise floor that exists at *any*
beacon length, so nothing is gained above 4 bytes; at 3 bytes collisions
dominate and worsen as `U` grows. False positives never affect correctness,
since every candidate is verified by the layer-1 AEAD tag, so the choice is
purely a bandwidth trade-off.

### Slot count: why 16 slots

With one beacon per participant the slot field must hold `n ≤ 16` beacons,
and every configuration up to sixteen participants produces an
identically-shaped field. Sixteen also bounds the index at sixteen elements
per `OP_RETURN` output regardless of payload size. Envelope sizes for common
configurations:

| Configuration        | `n` | entries  | envelope before payload |
|----------------------|----:|---------:|------------------------:|
| single-sig (1-of-1)  |   1 |   64 B   |                   304 B |
| 2-of-2, 1-of-2       |   2 |  128 B   |                   368 B |
| 2-of-3, 3-of-3       |   3 |  192 B   |                   432 B |
| 3-of-5               |   5 |  320 B   |                   560 B |
| 4-of-7               |   7 |  448 B   |                   688 B |

(Envelope before payload = 64 + 64 + 96 + 64·n + 16 bytes; the payload
ciphertext adds its own length.)

### Why Shamir only

The previous design offered an XOR-of-subsets mode as a hash-only
alternative to Shamir sharing. With ECDH-derived per-participant secrets and
a recoverer that learns `r` from the schema, a single mode that always emits
exactly one 64-byte entry per participant is simpler, hides `r` in the
envelope shape, and is never larger. Shamir sharing over the secp256k1
scalar field reuses arithmetic every wallet already ships; for `r = 1` the
polynomial is constant and the share is a plain masked key.

### Why no explicit nonces

The previous design derived a payload-bound nonce to survive accidental
version reuse. Here the ephemeral scalar `e` already commits to the key set
and both plaintexts, so both AEAD keys are unique per distinct publication by
construction and a fixed nonce is safe. This is the same SIV-style property
moved one level up, and it saves 24 bytes.

### Why one output and no marker

Compact filter elements are derived per output, so an earlier design used
one output per beacon. Indexing multiple aligned chunks per output removes
that need: all beacons share one output, position-independently matchable,
and the output count does not leak the participant count.

### Why no magic value

A magic prefix would only help third parties enumerate protocol outputs, an
anti-goal. The beacons themselves are the discovery mechanism, and the index
covers all `OP_RETURN` outputs regardless of content, so a magic value adds
nothing for the owner and subtracts deniability. Without it (and without any
plaintext version or length byte), the entire push is indistinguishable from
random data, and the set of "possible backups" is every sufficiently long
`OP_RETURN` output on the chain.

## Security Considerations

**Backup private keys are the key material.** Whoever holds `r` of the `n`
backup private keys can read the descriptor; whoever holds one can read the
schema; whoever holds a backup *public* key can locate. Nothing that appears
in PSBTs, on chain, or in signing operations is an input to any derivation.

| Adversary knows                                          | Locate | Read schema | Read descriptor | Forge |
|----------------------------------------------------------|:------:|:-----------:|:---------------:|:-----:|
| nothing (chain observer)                                 | no     | no          | no              | no    |
| all account xpubs, all PSBTs, full spend history         | no     | no          | no              | no    |
| one or more backup public keys                           | yes    | no          | no              | yes   |
| fewer than `r` backup private keys                       | yes    | yes         | no              | yes   |
| `r` or more backup private keys                          | yes    | yes         | yes             | yes   |

**Leaked backup public keys.** A coordinator database, or the participant
list of a co-signing service, contains backup public keys. Their leak lets an
attacker learn that the affected seeds have backups, how many, and when
they were published, but nothing about their content or the wallets'
shape. Backup public keys SHOULD nonetheless be treated as confidential
configuration and MUST NOT be placed in PSBTs.

**No sender authentication (forgery).** ECIES provides confidentiality
against anyone lacking the private key, but anyone who holds the backup
public keys can construct an output that authenticates under every
participant's key with arbitrary content and an arbitrary `v`. A forged
descriptor containing the victim's real account xpub alongside
attacker-controlled keys would appear as the "latest version" and hide the
genuine backup by version ordering. The attack requires the same leaked
material as locating and is detectable: the forged wallet has no on-chain
history, while the genuine one does. Recoverers therefore MUST keep every
authenticated backup per `wallet_id` rather than discarding lower versions,
SHOULD verify the recovered descriptor against chain history before
presenting it as the wallet, and SHOULD warn whenever multiple authenticated
backups exist for one `wallet_id` or the highest version has no history.
Cryptographic sender authentication would require a secret shared between
publisher and participants, which is precisely what this design removes;
the procedural mitigation is preferred.

**Weak seeds.** As discussed in the Rationale, single-key discovery reduces
the cost of attacking a multisig built entirely from enumerable seeds from
combinatorial to linear in the seed space, and key stretching only
multiplies that linear cost. Wallets whose participants include at least one
key from a non-enumerable source are unaffected. Publishers SHOULD make
users aware that a multisig of identical weak devices gains no protection
from its threshold against an attacker who can enumerate that device's seed
space.

**Hardware decryption oracle.** The device operation `x(b·E)` for an
attacker-supplied `E` decrypts any backup addressed to that device.
Devices MUST gate it behind on-device confirmation that names the operation
("Decrypt wallet backup?"), and SHOULD display the beacon or `wallet_id`
derived on the host so the user can correlate the request with what the
wallet software claims to be doing.

**`r = 1` configurations** (required for policies that decay to single-key
spending, and for single-signature wallets) have a single-private-key
security floor for the descriptor. Publishers SHOULD make this explicit to
users. It remains strictly stronger than BIP 138's single-*xpub* floor.

**Linkability.** The transaction publishing the backup may be funded from
the wallet itself, publicly linking "this wallet published a backup"; this
has no cryptographic effect on the scheme. Publishers wanting unlinkability
SHOULD fund the transaction from unrelated coins. Publications of the same
key in different epochs are mutually unlinkable to observers; publications
of the same key within one epoch share a beacon value.

**Replay.** An attacker can re-publish an old (superseded) backup output in
a new transaction. Recoverers select by highest authenticated `v`, never by
chain position, which defeats rollback; forging a higher `v` requires the
backup public keys (see forgery above).

**Beacon griefing.** Anyone can copy the (public) beacon bytes of an
observed backup into their own outputs, adding false positives for that
specific key's recovery. The recovery outcome is unaffected (the layer-1
AEAD rejects them); the cost is bounded extra downloads.

**Availability.** The scheme depends on `OP_RETURN` relay policy for the
envelope size (432 bytes plus payload for a 2-of-3). Where policy
constrains data carrier size below the envelope size, publication requires
miner cooperation or policy-relaxed relays; this affects publication only,
never recovery of already-confirmed backups.

## Backward Compatibility

This BIP defines a new format and changes no existing one. The payload
content encoding is shared with [BIP 138], so recovered payloads are
interoperable with BIP 138 tooling; the envelope, access structure, key
material and all derivation tags are deliberately distinct, so publishing
both for the same wallet does not create cross-scheme key reuse. Seeds
whose signing devices do not implement the backup key operations can still
participate in wallets backed up under this BIP, but do not count toward
`n` or `r`.

## Test Vectors

To be added: derivation vectors (backup key pairs from test seeds,
ephemeral key, ElligatorSwift encoding, per-participant secrets, wraps,
shares, beacons for several epochs) for 1-of-1, 2-of-3 and 3-of-5 key sets,
a complete 2-of-3 envelope with and without hints, and a discovery-index
vector (block with known `OP_RETURN` outputs and the resulting chunk
filter).

## Reference Implementation

To be added. A prototype of the discovery index (the 4-byte-chunk
`OP_RETURN` compact filter set, served with BIP 157-style header chains
over HTTP) exists in [block-dn].

## Acknowledgements

This proposal builds on the backup scheme of [BIP 138] by Pyth
(@pythcoiner), which in turn builds on work by @bigspider. The move from
extended public keys to dedicated backup key pairs, and the single-key
discovery requirement, came out of implementation review of an earlier
xpub-based draft of this proposal.

## Changelog

* **0.2.0** (2026-09-02): Replace xpub-derived secrets with per-seed backup
  key pairs and multi-recipient ECIES; add the single-key schema layer;
  single-key, epoch-bound beacons; ElligatorSwift point encoding; key
  stretching; drop the subset wrapping mode and explicit nonces.
* **0.1.0** (2026-08-23): Initial draft (xpub-based threshold design).

## Copyright

This BIP is licensed under the BSD 2-Clause License.

[^path]: A purpose-only path (`m/XXX'`) would suffice today; the extra
    hardened index leaves room for future key roles under the same purpose
    without touching the backup key. Hardening both steps guarantees that no
    non-hardened xpub anywhere in the tree can derive `B`.

[^oracle]: With physical access to an unlocked device an attacker can sign
    anyway, so the oracle risk is one of *silent* use by compromised host
    software. On-device confirmation is the same mitigation devices apply to
    signing and to xpub export.

[^version]: A publisher that keeps local state MAY use any strictly
    increasing sequence. Using the tip height makes the "latest version"
    rule coincide with "most recently constructed", needs no state, and the
    recoverer's `v ≤ h` check rejects outputs claiming a future height.

[^hints]: The master key fingerprint is the first four bytes of
    `HASH160` of the seed's master public key, as used in descriptor key
    origins; it identifies a device to its owner without being a key.

[^ellswift]: The ElligatorSwift encoding of a given point is not unique;
    the reference encoder consumes 32 bytes of auxiliary randomness to
    select one uniformly. Deriving that randomness from `e` keeps the
    publication deterministic while `e` itself stays secret, so the
    uniformity argument is unaffected.

[^deterministic]: Deterministic derivation makes publishing stateless and
    idempotent and removes the CSPRNG from the publisher's trusted
    computing base; a publisher with a bad randomness source produces a
    backup exactly as secure as one with a good source, because the only
    secret input is the (unpredictable to outsiders) key set and plaintext.
    Note that `e` is secret precisely because it is a hash of the backup
    public keys, which are confidential configuration.

[^shamir]: The mask values `h_i` are derived from each participant's ECDH
    secret, so no per-participant state is needed; the published
    corrections `d_i` shift those values onto the polynomial. Any `r` points
    reconstruct `P(0)`; fewer points reveal nothing about it
    (information-theoretically, for coefficients that are uniform to anyone
    not knowing `e`, which they are for anyone lacking a preimage of the
    ephemeral hash).

[^nonce]: The hazard a nonce normally guards against is one key encrypting
    two different messages. Here two different messages produce two
    different `e` and hence two different keys, and identical messages
    produce byte-identical outputs, which is the intended idempotence.

[^padding]: Padding coarsens the only remaining observable, the output
    size. 64-byte buckets keep overhead under one filter chunk row while
    grouping typical descriptor payloads into few size classes.

[^slots]: Sorting removes any information from beacon order; derived filler
    makes every configuration produce an identically-shaped field. Filler
    collides with a real beacon only with probability ~2^-32 per slot, and
    such a collision is harmless (the AEAD step rejects).

[^nomagic]: Indistinguishability is load-bearing for the threat model: a
    chain observer cannot even enumerate which outputs are backups, so
    bulk-collection attacks must treat every `OP_RETURN` output as a
    candidate against every stolen key.

[^statelesspub]: If the previous publication is unconfirmed, two
    publications may share a `v`. They have different plaintexts (or are
    identical and harmless), so the cryptography is unaffected; the
    recoverer merely sees two authenticated backups with equal `v` and
    surfaces both.

[^chunks]: Only complete 4-byte chunks become elements: the backup slot
    field always occupies 64 bytes, so all sixteen chunks exist for backup
    outputs; short foreign outputs simply contribute fewer elements.
    Sixteen chunks bound the index growth to at most 16 elements per
    `OP_RETURN` output regardless of payload size.

[^minlen]: The smallest possible envelope is a 1-of-1 wallet with an empty
    payload: 64 + 64 + 96 + 64 + 16 = 304 bytes. Requiring at least 288
    bytes (the fixed part plus one entry) rejects most foreign outputs
    before any cryptography is attempted.

[^replay]: Confirmation depth of the *highest-version* backup is still
    relevant: recoverers SHOULD prefer a confirmed backup over an
    unconfirmed one and MAY require a minimum depth before acting on it.

[BIP 32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
[BIP 138]: https://github.com/bitcoin/bips/pull/1951
[BIP 157]: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
[BIP 158]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
[BIP 324]: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
[BIP 340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[BIP 380]: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
[BIP 388]: https://github.com/bitcoin/bips/blob/master/bip-0388.mediawiki
[ElligatorSwift]: https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki#elligatorswift-encoding-of-curve-x-coordinates
[Argon2id]: https://www.rfc-editor.org/rfc/rfc9106
[RFC 9106]: https://www.rfc-editor.org/rfc/rfc9106
[RFC 8439]: https://www.rfc-editor.org/rfc/rfc8439
[block-dn]: https://github.com/guggero/block-dn
