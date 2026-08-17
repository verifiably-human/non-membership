// Indexed Merkle Tree Non-Membership — witness implementations
//
// Witnesses declared in indexed-merkle-non-membership.compact:
//   witness localSecretKey(): Bytes<32>;
//   witness getMemberPath(pk: Bytes<32>): MerkleTreePath<10, Bytes<32>>;
//   witness getPredecessorProof(target: Uint<248>):
//     [IndexedLeaf, Vector<8, Bytes<32>>, Vector<8, Boolean>];
//
//   where IndexedLeaf = { key: bigint, nextKey: bigint }
//
// Private state shape:
//   {
//     secretKey: Uint8Array,
//     memberPath?: MerkleTreePath,
//     indexedTree: IndexedMerkleTree,   // off-chain sorted-leaf store
//   }
//
// The off-chain IndexedMerkleTree maintains a sorted list of
// { key, nextKey } leaves plus the genesis sentinel { 0, 2^248 - 1 }.
// Insertion is the admin's responsibility; this shim only reads
// predecessor proofs to construct non-membership witnesses.
//
// secretKey must be supplied by the caller — there is no fallback.

export default function makeWitnesses() {
  return {
    localSecretKey: (context) => {
      const key = context.privateState?.secretKey;
      if (!key) {
        throw new Error('secretKey not initialized in private state');
      }
      return [context.privateState, key];
    },

    getMemberPath: (context, _pk) => {
      const path = context.privateState?.memberPath ?? null;
      return [context.privateState, path];
    },

    getPredecessorProof: (context, target) => {
      const tree = context.privateState?.indexedTree;
      if (!tree) {
        throw new Error('Indexed Merkle tree not initialized in private state');
      }

      const proof = tree.getPredecessorProof(target);

      return [
        context.privateState,
        [
          { key: proof.low.key, nextKey: proof.low.nextKey },
          proof.siblings,
          proof.directions,
        ],
      ];
    },

    getMembershipProof: (context, target) => {
      const tree = context.privateState?.indexedTree;
      if (!tree) {
        throw new Error('Indexed Merkle tree not initialized in private state');
      }

      const proof = tree.getMembershipProof(target);

      return [
        context.privateState,
        [
          { key: proof.low.key, nextKey: proof.low.nextKey },
          proof.siblings,
          proof.directions,
        ],
      ];
    },
  };
}
