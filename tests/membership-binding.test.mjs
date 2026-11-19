// SPDX-License-Identifier: Apache-2.0
//
// Regression test: each gated circuit must bind the member path to the
// caller's own key. An outsider replaying a registered member's (public)
// path must be refused.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import {
  CompactTypeBytes,
  CompactTypeVector,
  convertBigintToBytes,
  createCircuitContext,
  createConstructorContext,
  dummyContractAddress,
  persistentHash,
} from '@midnight-ntwrk/compact-runtime';

import makeNullifierWitnesses from '../witnesses/nullifier-witnesses.js';
import makeBlocklistWitnesses from '../witnesses/blocklist-witnesses.js';
import makeSparseWitnesses from '../witnesses/sparse-merkle-witnesses.js';
import makeIndexedWitnesses from '../witnesses/indexed-merkle-witnesses.js';

// Override to run against another build, e.g. an unfixed contract.
const COMPILED = process.env.COMPILED_DIR ?? fileURLToPath(new URL('../compiled/', import.meta.url));
const load = (name) => import(`${COMPILED.replace(/\/?$/, '/')}${name}/contract/index.js`);

const B32 = new CompactTypeBytes(32);
const V2 = new CompactTypeVector(2, B32);
const V3 = new CompactTypeVector(3, B32);
const pad = (s) => { const o = new Uint8Array(32); o.set(new TextEncoder().encode(s)); return o; };
const key = (b) => new Uint8Array(32).fill(b);
const pkOf = (domain, sk) => persistentHash(V2, [pad(domain), sk]);

const ADMIN_SK = key(0xa0);
const MEMBER_SK = key(0x11);
const OUTSIDER_SK = key(0x55);
const DEPTH = 8;
const MAX_KEY = (1n << 248n) - 1n;
const COIN_PK = '00'.repeat(32);
const ADDR = dummyContractAddress();

// Fresh context per call so each call can run with its own private state.
async function deploy(C, witnesses) {
  const contract = new C.Contract(witnesses);
  const init = await contract.initialState(createConstructorContext({ secretKey: ADMIN_SK }, COIN_PK));
  let state = init.currentContractState;
  return {
    ledger: () => C.ledger(state.data ?? state),
    async call(name, privateState, ...args) {
      const ctx = createCircuitContext({
        circuitId: name,
        contractAddress: ADDR,
        coinPublicKeyOrZswapState: COIN_PK,
        contractState: state,
        privateState,
      });
      const r = await contract.circuits[name](ctx, ...args);
      state = r.context.queryContexts[ADDR]?.state ?? r.context.callContext.currentQueryContext.state;
      return r;
    },
  };
}

// Fixed-depth binary tree over explicit leaf positions; fold order matches the contracts.
function positionalTree(domain, leafAt) {
  const node = (l, r) => persistentHash(V3, [pad(domain), l, r]);
  const sub = (base, lvl) =>
    lvl === 0 ? leafAt(base) : node(sub(base, lvl - 1), sub(base + (1 << (lvl - 1)), lvl - 1));
  return {
    root: () => sub(0, DEPTH),
    path(pos) {
      const siblings = [], directions = [];
      for (let k = 0; k < DEPTH; k++) {
        directions.push(((pos >> k) & 1) === 1);
        siblings.push(sub(((pos >> k) ^ 1) << k, k));
      }
      return { siblings, directions };
    },
  };
}

// Mirrors dapp/src/lib/sparse-merkle-tree.ts: position = first DEPTH bits of H(pos-domain, element).
function sparseTree(elements) {
  const position = (e) => {
    const h = persistentHash(V2, [pad('sparse:pos:'), e]);
    let pos = 0;
    for (let i = 0; i < DEPTH; i++) if (h[i >> 3] & (1 << (i & 7))) pos |= 1 << (DEPTH - 1 - i);
    return pos;
  };
  const leaves = new Map(elements.map((e) => [position(e), persistentHash(V2, [new Uint8Array(32), e])]));
  const t = positionalTree('sparse:node:', (p) => leaves.get(p) ?? new Uint8Array(32));
  const proof = (e) => ({ leafValue: leaves.get(position(e)) ?? new Uint8Array(32), ...t.path(position(e)) });
  return { root: t.root, getNonMembershipProof: proof, position, leaves, pathAt: t.path };
}

// Mirrors dapp/src/lib/indexed-merkle-tree.ts: sorted linked leaves behind a {0, MAX} sentinel.
function indexedTree(keys) {
  const sorted = [0n, ...[...keys].sort((a, b) => (a < b ? -1 : 1))];
  const leaves = sorted.map((k, i) => ({ key: k, nextKey: sorted[i + 1] ?? MAX_KEY }));
  const kb = (k) => convertBigintToBytes(32, k, 'test');
  const t = positionalTree('indexed:node:', (p) =>
    leaves[p] ? persistentHash(V3, [pad('indexed:leaf:'), kb(leaves[p].key), kb(leaves[p].nextKey)]) : new Uint8Array(32));
  const at = (i) => ({ low: leaves[i], ...t.path(i) });
  return {
    root: t.root,
    getPredecessorProof: (target) => at(leaves.findIndex((l) => l.key < target && target < l.nextKey)),
    getMembershipProof: (target) => at(leaves.findIndex((l) => l.key === target)),
  };
}

// Registers MEMBER (plus neighbours) and returns the member's genuine path.
async function registerMember(c, domain, circuit = 'registerMember', tree = 'members') {
  const memberPk = pkOf(domain, MEMBER_SK);
  for (const pk of [key(1), memberPk, key(2)]) await c.call(circuit, { secretKey: ADMIN_SK }, pk);
  const path = c.ledger()[tree].findPathForLeaf(memberPk);
  assert.ok(path, 'member path not found');
  assert.deepEqual(path.leaf, memberPk, 'members are inserted as their public key');
  assert.equal(c.ledger()[tree].findPathForLeaf(pkOf(domain, OUTSIDER_SK)), undefined);
  return path;
}

const REFUSED = /Member path is not for this key/;

test('nullifier-pattern performAction', async (t) => {
  const C = await load('nullifier-pattern');
  const c = await deploy(C, makeNullifierWitnesses());
  const memberPath = await registerMember(c, 'nonmem:pk:');
  await t.test('member succeeds', async () => {
    await c.call('performAction', { secretKey: MEMBER_SK, memberPath }, C.ActionType.vote);
    assert.equal(c.ledger().actionCount, 1n);
  });
  await t.test('outsider with a member path is refused', async () => {
    await assert.rejects(c.call('performAction', { secretKey: OUTSIDER_SK, memberPath }, C.ActionType.vote), REFUSED);
  });
});

test('blocklist-exclusion proveNotBlocked', async (t) => {
  // The shipped witness looks the path up by key; the outsider replays the member's instead.
  let replay = null;
  const base = makeBlocklistWitnesses();
  const witnesses = {
    ...base,
    getRegistryPath: (ctx, pk) => (replay ? [ctx.privateState, replay] : base.getRegistryPath(ctx, pk)),
  };
  const c = await deploy(await load('blocklist-exclusion'), witnesses);
  const memberPath = await registerMember(c, 'blocklist:pk:', 'registerUser', 'registry');
  const ps = (sk) => ({ secretKey: sk, credentialAttribute: pad('GB'), blocklistSnapshot: [], blocklistCount: 0n });
  await t.test('member succeeds', async () => {
    await c.call('proveNotBlocked', ps(MEMBER_SK));
    assert.equal(c.ledger().clearanceCount, 1n);
  });
  await t.test('outsider with a member path is refused', async () => {
    replay = memberPath;
    await assert.rejects(c.call('proveNotBlocked', ps(OUTSIDER_SK)), REFUSED);
  });
});

test('sparse-merkle proveNonMembership / proveMembership', async (t) => {
  const c = await deploy(await load('sparse-merkle'), makeSparseWitnesses());
  const present = pad('present');
  const absent = pad('absent');
  const sparse = sparseTree([present]);
  await c.call('updateRoot', { secretKey: ADMIN_SK }, sparse.root());
  const memberPath = await registerMember(c, 'sparse:pk:');
  const ps = (sk) => ({ secretKey: sk, memberPath, sparseTree: sparse });
  for (const [circuit, element] of [['proveNonMembership', absent], ['proveMembership', present]]) {
    await t.test(`${circuit}: member succeeds`, async () => {
      await c.call(circuit, ps(MEMBER_SK), element);
    });
    await t.test(`${circuit}: outsider with a member path is refused`, async () => {
      await assert.rejects(c.call(circuit, ps(OUTSIDER_SK), element), REFUSED);
    });
  }
  assert.equal(c.ledger().proofCount, 2n);
});

// The sparse proof must sit at the element's own slot and, for membership, hold that element's marker.
test('sparse-merkle proofs are bound to the element', async (t) => {
  const c = await deploy(await load('sparse-merkle'), makeSparseWitnesses());
  const present = pad('present');
  const real = sparseTree([present]);
  await c.call('updateRoot', { secretKey: ADMIN_SK }, real.root());
  const memberPath = await registerMember(c, 'sparse:pk:');
  // A tree whose proofs all come from one chosen slot, whatever element is asked about.
  const fromSlot = (pos) => ({ ...real, getNonMembershipProof: () =>
    ({ leafValue: real.leaves.get(pos) ?? new Uint8Array(32), ...real.pathAt(pos) }) });
  const asMember = (tree) => ({ secretKey: MEMBER_SK, memberPath, sparseTree: tree });
  const occupied = real.position(present);
  const empty = (occupied + 1) % (1 << DEPTH);
  let absent = 0, collides = 0;
  for (let i = 0; !absent || !collides; i++) {
    const e = pad(`other-${i}`);
    if (real.position(e) === occupied) collides ||= e; else absent ||= e;
  }

  await t.test('non-membership of a present element via an empty slot is refused', async () => {
    await assert.rejects(c.call('proveNonMembership', asMember(fromSlot(empty)), present), /not at the element's position/);
  });
  await t.test('membership of an absent element via an occupied slot is refused', async () => {
    await assert.rejects(c.call('proveMembership', asMember(fromSlot(occupied)), absent), /not at the element's position/);
  });
  await t.test('membership of an element that only shares a slot is refused', async () => {
    await assert.rejects(c.call('proveMembership', asMember(real), collides), /Leaf belongs to another element/);
  });
  assert.equal(c.ledger().proofCount, 0n);
});

test('indexed-merkle proveNonMembership / proveMembership', async (t) => {
  const c = await deploy(await load('indexed-merkle'), makeIndexedWitnesses());
  const indexed = indexedTree([100n, 300n]);
  await c.call('updateRoot', { secretKey: ADMIN_SK }, indexed.root());
  const memberPath = await registerMember(c, 'indexed:pk:');
  const ps = (sk) => ({ secretKey: sk, memberPath, indexedTree: indexed });
  for (const [circuit, target] of [['proveNonMembership', 200n], ['proveMembership', 100n]]) {
    await t.test(`${circuit}: member succeeds`, async () => {
      await c.call(circuit, ps(MEMBER_SK), target);
    });
    await t.test(`${circuit}: outsider with a member path is refused`, async () => {
      await assert.rejects(c.call(circuit, ps(OUTSIDER_SK), target), REFUSED);
    });
  }
  assert.equal(c.ledger().proofCount, 2n);
});
