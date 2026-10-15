# Zero-Knowledge Non-Membership Proofs on Midnight

Four Compact patterns for proving you're NOT in a set — without revealing who you are.

### ▶ [Run the live demo](https://non-membership.pages.dev/)

Deploy the contracts, register members, and build a real non-membership proof against the preprod
network — the sparse and indexed Merkle patterns each render the tree as you go, so you can watch
the authentication path fold from leaf to root. It runs on testnet with real proofs, so it needs a
Midnight wallet, a proof server, and test tokens first: see
[Running the live demo](#running-the-live-demo). This repository is what's running underneath.

> [!WARNING]
> **The keys in this repository are demo keys. Do not deploy them.**
>
> The four directories at the repo root (`nullifier-pattern/`, `blocklist-exclusion/`,
> `sparse-merkle/`, `indexed-merkle/`) hold the prover and verifier keys the live demo fetches at
> runtime. They are **not** production credentials, they carry no security guarantee, and they are
> tied to demo contracts running on a test network. Anyone can regenerate them from the source
> here. Generate your own — see [Using this in your own project](#using-this-in-your-own-project).
> If you maintain this repository, read [The published demo keys](#the-published-demo-keys) before
> touching those directories.

This repository holds the contracts, their witness implementations, the off-chain tree
implementations that build the proofs, and instructions for compiling everything. The demo's UI
lives elsewhere; there is no DApp code here.

## Patterns

| # | Pattern | Contract | Witness |
|---|---------|----------|---------|
| 1 | Nullifier-based "already-used" prevention | [`contracts/nullifier-pattern.compact`](contracts/nullifier-pattern.compact) | [`witnesses/nullifier-witnesses.js`](witnesses/nullifier-witnesses.js) |
| 2 | Attribute-based blocklist exclusion | [`contracts/blocklist-exclusion.compact`](contracts/blocklist-exclusion.compact) | [`witnesses/blocklist-witnesses.js`](witnesses/blocklist-witnesses.js) |
| 3 | Sparse Merkle tree non-membership | [`contracts/sparse-merkle-non-membership.compact`](contracts/sparse-merkle-non-membership.compact) | [`witnesses/sparse-merkle-witnesses.js`](witnesses/sparse-merkle-witnesses.js) |
| 4 | Indexed Merkle tree non-membership | [`contracts/indexed-merkle-non-membership.compact`](contracts/indexed-merkle-non-membership.compact) | [`witnesses/indexed-merkle-witnesses.js`](witnesses/indexed-merkle-witnesses.js) |

**Pattern 1 — nullifier.** The chain enforces uniqueness: the user derives a deterministic
nullifier `hash(domain, secret, action)` inside the circuit, and the contract asserts it is not
already in the on-chain `Set` before inserting it. No off-chain data structure needed.

**Pattern 2 — blocklist exclusion.** The blocklist stores domain-separated hashes of blocked
attribute values. The circuit hashes the user's witness-provided credential attribute and asserts
it matches no blocklist entry. The attribute itself never leaves the proof.

**Pattern 3 — sparse Merkle tree.** Only the tree root lives on-chain. The witness supplies the
authentication path for position `H(element)`; the circuit folds leaf → root and asserts the leaf
is empty (non-membership), and that the recomputed root matches the on-chain root. Works for
arbitrarily large sets, but leaf position is hash-derived, so it carries collision risk.

**Pattern 4 — indexed Merkle tree.** Proves `low.key < target < low.nextKey` by exhibiting the
predecessor leaf in a key-sorted tree. This is the structure used by Aztec, Polygon ID, and
Semaphore v4. No collision risk — each leaf stores its actual key — and depth scales with active
entries rather than key width. The cost is more involved insertion: each new key rewrites the
predecessor's `nextKey` pointer and inserts a new leaf.

## Running the live demo

The demo generates real zero-knowledge proofs and submits real transactions to Midnight's preprod
network. Nothing is simulated, so there is some setup. Three things are required:

**1. A Midnight wallet.** Any wallet that implements the Midnight DApp connector works. Two
options:

| Wallet | Where |
|--------|-------|
| Moth | [github.com/shieldedtech/moth-wallet](https://github.com/shieldedtech/moth-wallet) |
| Lace | [lace.io](https://www.lace.io/) — install the Midnight build |

Whichever you use, create a wallet and switch the network to **preprod**. Save the seed phrase.

**2. A proof server.** ZK proof generation runs locally, not in the browser — the demo expects a
proof server reachable at `localhost:6300`. Setup instructions:
[docs.midnight.network/guides/run-proof-server](https://docs.midnight.network/guides/run-proof-server).
The status indicator at the top of the demo turns green once it can reach it.

**3. Test tokens (tmNIGHT).** Every transaction burns DUST, and DUST accrues from held NIGHT. Claim
test NIGHT from the Nethermind preprod faucet:
[midnight-tmnight-preprod.nethermind.dev](https://midnight-tmnight-preprod.nethermind.dev/) — paste
your wallet's unshielded address. Tokens arrive in a minute or two, then give DUST a few minutes to
accrue before your first transaction.

You do **not** need the Compact CLI to run the demo; it connects to already-deployed contracts. You
need it only to build the contracts yourself, below.

## Prerequisites for building

- [Node.js](https://nodejs.org/) v22+
- [Compact CLI](https://docs.midnight.network/) with compiler v0.31.0+

Verify your installation:

```bash
compact --version          # CLI version, e.g. 0.5.1
compact compile --version  # compiler version, e.g. 0.31.1
compact check              # check for a newer compiler
```

All four contracts declare `pragma language_version >= 0.23;` and are verified to compile with
compiler 0.31.1.

## Compiling

```bash
npm install
npm run compile:all
```

That runs [`scripts/compile-all.sh`](scripts/compile-all.sh), which invokes `compact compile` on
each contract and writes to `compiled/<name>/`:

```
compiled/<name>/contract/index.js       JS contract API
compiled/<name>/contract/index.d.ts     generated types (Witnesses, Circuits, Contract)
compiled/<name>/zkir/<circuit>.zkir     circuit IR (.bzkir is the binary form)
compiled/<name>/keys/<circuit>.prover   PLONK prover key
compiled/<name>/keys/<circuit>.verifier PLONK verifier key
compiled/<name>/compiler/contract-info.json  circuit metadata
```

`compiled/` is gitignored — it is build output, ~138 MB, and reproducible from this source. The
published demo keys live in the per-pattern directories at the repo root (see below).

To compile a single contract, pass its base name:

```bash
scripts/compile-all.sh indexed-merkle-non-membership
```

Or invoke the compiler directly:

```bash
compact compile contracts/nullifier-pattern.compact compiled/nullifier-pattern
```

Proving-key generation dominates compile time. For a fast syntax and type check that skips it:

```bash
compact compile --skip-zk contracts/nullifier-pattern.compact /tmp/check
```

## Circuits

| Contract | Output directory | Exported circuits |
|----------|------------------|-------------------|
| `nullifier-pattern` | `nullifier-pattern/` | `registerMember`, `performAction` |
| `blocklist-exclusion` | `blocklist-exclusion/` | `registerUser`, `blockAttribute`, `unblockAttribute`, `proveNotBlocked` |
| `sparse-merkle-non-membership` | `sparse-merkle/` | `updateRoot`, `registerMember`, `registerMembersBatch`, `proveNonMembership`, `proveMembership` |
| `indexed-merkle-non-membership` | `indexed-merkle/` | `updateRoot`, `registerMember`, `registerMembersBatch`, `proveNonMembership`, `proveMembership` |

## Witnesses and off-chain trees

Each contract's witnesses are implemented in `witnesses/`. They follow the standard Compact
witness signature — `(context, ...args) => [privateState, returnValue]` — and read from a
private-state object described at the top of each file.

`localSecretKey` has no fallback: if `privateState.secretKey` is absent it throws rather than
substituting a default. Supply a real key source — an HSM, an environment-supplied keyfile with
`0o600` permissions, or a per-deployment `crypto.randomBytes(32)` persisted out of band.

Patterns 3 and 4 need an off-chain tree to build their proofs. Both implementations live in
`offchain/` and hash with the same domain separators as their contracts, so the roots agree:

| Off-chain module | Serves |
|------------------|--------|
| [`offchain/sparse-merkle-tree.ts`](offchain/sparse-merkle-tree.ts) | Pattern 3 — `getNonMembershipProof(element)` |
| [`offchain/indexed-merkle-tree.ts`](offchain/indexed-merkle-tree.ts) | Pattern 4 — predecessor and membership proofs |

The sparse tree's `saveToStorage` / `loadFromStorage` helpers are browser-only; everything else
runs under Node.

A round-trip consistency check for the indexed tree — build a tree, take a predecessor proof, fold
it leaf-to-root with the same primitives the circuit uses, and confirm the root matches:

```bash
npm test
```

## Repository layout

```
contracts/                  Compact smart contracts (4 patterns)
witnesses/                  Witness implementations, one module per contract

offchain/
  sparse-merkle-tree.ts     Pattern 3 off-chain tree
  indexed-merkle-tree.ts    Pattern 4 off-chain tree
  __test__/
    indexed-merkle-roundtrip.ts   Consistency check against circuit hashing

scripts/
  compile-all.sh            Compile every contract into compiled/

compiled/                   Build output (gitignored; npm run compile:all)

blocklist-exclusion/        DEMO keys, served to the live demo at runtime.
indexed-merkle/             Prover/verifier keys, zkir, and contract-info.json
nullifier-pattern/          per pattern. Do not move or rename — the demo
sparse-merkle/              fetches them. Never reuse them in your own project.
```

## The published demo keys

The four per-pattern directories at the repo root are build artifacts from the deployed demo. They
serve two purposes, and the first one is load-bearing.

> [!IMPORTANT]
> **The live demo fetches these files at runtime. Do not move, rename, or delete them.**
>
> Prover keys reach 36.7 MB, over Cloudflare Pages' 25 MB per-file limit, so the demo cannot ship
> them in its own bundle. It fetches them from this repository over `raw.githubusercontent.com`
> instead. This repository is the demo's asset host, not just a published record of it.
>
> The demo pins a specific commit (`KEYS_COMMIT_SHA`), so ordinary commits here cannot break it —
> only a deliberate SHA bump on the demo side picks up new artifacts. Rewriting history that a
> pinned SHA points at would break it.

**What they're for, first:** serving the deployed demo, as above.

**What they're for, second:** verifying that the demo runs the contracts in this repository and
nothing else. Rebuild from source and compare:

```bash
npm run compile:all
cmp compiled/sparse-merkle/keys/proveNonMembership.verifier \
    sparse-merkle/keys/proveNonMembership.verifier
```

With compiler 0.31.1, all 32 prover/verifier key files and all 32 zkir files reproduce
byte-for-byte. The four `contract-info.json` files differ by one line — the committed set was
built with 0.31.0, so `"compiler-version"` reads `0.31.0` rather than `0.31.1`. The circuit
definitions in them are identical.

**What they're not.** They are not production credentials and carry no security guarantee. They
belong to demo contracts on a test network, they are public, and anyone can regenerate them.
Verifier keys pin circuit identity, so reusing these would pin your deployment to *these*
circuits — including their demo-scale parameters (depth-8 trees, 256 leaf positions, an
8-entry blocklist snapshot) and their admin model, in which a single key set by the constructor
controls registration and root updates.

They are also large: `sparse-merkle/keys/registerMembersBatch.prover` alone is 36.7 MB, and the
four directories total roughly 250 MB. That is most of this repository's clone size.

## Using this in your own project

1. Copy the contract and its witness module, and adjust the tree depths and batch sizes — the
   values here are tuned for demo readability and proof speed, not production capacity. Each
   contract's header comment says what a production deployment would want instead.
2. Review the admin model. All four contracts set `admin` in the constructor from
   `localSecretKey()` and gate registration behind it. That is a single point of failure, fine
   for a demo and probably not for you.
3. Run `npm run compile:all` to generate **your own** keys into `compiled/`. Never ship the ones
   in this repository.
4. Read Pattern 3's own caveats before choosing it — leaf positions are hash-derived, so it
   carries collision risk that Pattern 4 does not. Pattern 4 (indexed Merkle) is the
   production-grade choice.

## License

Apache-2.0

## Author

[Bob Blessing-Hartley](https://www.linkedin.com/in/bobblessinghartley/) — CTO, [Shielded Technologies](https://shielded.io)

*The views and opinions in this project are my own and do not represent those of my employer or the Midnight Network.*
