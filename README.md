# Zero-Knowledge Non-Membership Proofs on Midnight

Four Compact patterns for proving you're NOT in a set — without revealing who you are.

This repository holds the contracts, their witness implementations, the off-chain tree
implementations that build the proofs, and instructions for compiling everything. There is no
DApp or UI here.

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

## Prerequisites

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
private-state object described at the top of each file. Each module also exports a deterministic
`ADMIN_SECRET` for demo use; replace it for any real deployment.

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

blocklist-exclusion/        Published demo keys — prover/verifier keys, zkir,
indexed-merkle/             and contract-info.json for each pattern.
nullifier-pattern/          Reproducible from this source: all 32 key files
sparse-merkle/              rebuild byte-for-byte with compiler 0.31.1.
```

## License

Apache-2.0

## Author

[Bob Blessing-Hartley](https://www.linkedin.com/in/bobblessinghartley/) — CTO, [Shielded Technologies](https://shielded.io)

*The views and opinions in this project are my own and do not represent those of my employer or the Midnight Network.*
