// Round-trip sanity test: build a tree, get a predecessor proof, manually
// fold it leaf-to-root using the same hashing primitives the contract uses,
// and confirm the computed root matches tree.root. If this passes, the
// off-chain implementation is internally consistent.
//
// Run via: npx tsx src/lib/__test__/indexed-merkle-roundtrip.ts

import {
  persistentHash,
  convertFieldToBytes,
  CompactTypeBytes,
  CompactTypeVector,
} from '@midnight-ntwrk/compact-runtime';
import { IndexedMerkleTree, MAX_KEY } from '../indexed-merkle-tree.js';

const BYTES32 = new CompactTypeBytes(32);
const VEC3 = new CompactTypeVector(3, BYTES32);

const NODE_DOMAIN = new Uint8Array(32);
NODE_DOMAIN.set(new TextEncoder().encode('indexed:node:'), 0);
const LEAF_DOMAIN = new Uint8Array(32);
LEAF_DOMAIN.set(new TextEncoder().encode('indexed:leaf:'), 0);

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function hex(b: Uint8Array): string {
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

function foldRoot(
  low: { key: bigint; nextKey: bigint },
  siblings: Uint8Array[],
  directions: boolean[],
): Uint8Array {
  let acc = persistentHash(VEC3, [
    LEAF_DOMAIN,
    convertFieldToBytes(32, low.key, 'roundtrip'),
    convertFieldToBytes(32, low.nextKey, 'roundtrip'),
  ]);
  for (let i = 0; i < siblings.length; i++) {
    acc = directions[i]
      ? persistentHash(VEC3, [NODE_DOMAIN, siblings[i], acc])
      : persistentHash(VEC3, [NODE_DOMAIN, acc, siblings[i]]);
  }
  return acc;
}

const tree = new IndexedMerkleTree(8);
tree.insert(100n);
tree.insert(200n);
tree.insert(50n);
tree.insert(175n);
tree.insert(10n);

const targets = [
  { name: 'between 50 and 100', target: 75n },
  { name: 'between 100 and 175', target: 150n },
  { name: 'after largest real', target: 999_999n },
  { name: 'before smallest real', target: 5n },
];

let allOk = true;
for (const { name, target } of targets) {
  try {
    const proof = tree.getPredecessorProof(target);
    const folded = foldRoot(proof.low, proof.siblings, proof.directions);
    const treeRoot = tree.root;
    const ok = bytesEq(folded, treeRoot);
    console.log(
      `[${ok ? 'OK' : 'FAIL'}] ${name} (target=${target}): low=(${proof.low.key}, ${proof.low.nextKey})`,
    );
    if (!ok) {
      console.log('   folded:', hex(folded));
      console.log('   tree:  ', hex(treeRoot));
      allOk = false;
    }
  } catch (e) {
    console.log(`[ERR] ${name} (target=${target}): ${(e as Error).message}`);
    allOk = false;
  }
}

console.log('---');
console.log('Negative test: predecessor proof for key that IS in tree');
try {
  tree.getPredecessorProof(100n);
  console.log('[FAIL] expected throw for present key');
  allOk = false;
} catch (e) {
  console.log(`[OK] correctly threw: ${(e as Error).message}`);
}

console.log('---');
console.log('Membership proofs: roundtrip the present keys');
for (const k of [50n, 100n, 200n, 175n, 10n]) {
  try {
    const proof = tree.getMembershipProof(k);
    if (proof.low.key !== k) {
      console.log(`[FAIL] key=${k} returned leaf with key=${proof.low.key}`);
      allOk = false;
      continue;
    }
    const folded = foldRoot(proof.low, proof.siblings, proof.directions);
    const ok = bytesEq(folded, tree.root);
    console.log(`[${ok ? 'OK' : 'FAIL'}] membership key=${k}: leaf=(${proof.low.key}, ${proof.low.nextKey})`);
    if (!ok) allOk = false;
  } catch (e) {
    console.log(`[ERR] membership key=${k}: ${(e as Error).message}`);
    allOk = false;
  }
}

console.log('---');
console.log('Negative test: membership proof for key NOT in tree');
try {
  tree.getMembershipProof(999n);
  console.log('[FAIL] expected throw for absent key');
  allOk = false;
} catch (e) {
  console.log(`[OK] correctly threw: ${(e as Error).message}`);
}

console.log('---');
console.log('Sanity: MAX_KEY =', MAX_KEY.toString(16));
console.log('Tree size:', tree.size);

if (!allOk) {
  throw new Error('Roundtrip test had failures (see output above)');
}
