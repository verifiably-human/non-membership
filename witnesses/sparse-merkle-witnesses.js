// Sparse Merkle Tree Non-Membership — witness implementations
//
// Witnesses declared in sparse-merkle-non-membership.compact:
//   witness localSecretKey(): Bytes<32>;
//   witness getMemberPath(pk: Bytes<32>): MerkleTreePath<10, Bytes<32>>;
//   witness getSparseProof(element: Bytes<32>):
//     [Bytes<32>, Vector<8, Bytes<32>>, Vector<8, Boolean>];
//
// Private state shape:
//   {
//     secretKey: Uint8Array,
//     memberPath?: MerkleTreePath,
//     sparseTree: SparseMerkleTree,   // the off-chain tree instance
//   }
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

    getSparseProof: (context, element) => {
      const tree = context.privateState?.sparseTree;
      if (!tree) {
        throw new Error('Sparse Merkle tree not initialized in private state');
      }

      const proof = tree.getNonMembershipProof(element);

      return [
        context.privateState,
        [proof.leafValue, proof.siblings, proof.directions],
      ];
    },
  };
}
