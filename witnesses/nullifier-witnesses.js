// Nullifier Pattern — witness implementations
//
// Witnesses declared in nullifier-pattern.compact:
//   witness localSecretKey(): Bytes<32>;
//   witness getMemberPath(pk: Bytes<32>): MerkleTreePath<10, Bytes<32>>;
//
// Private state shape:
//   { secretKey: Uint8Array, memberPath?: MerkleTreePath }
//
// secretKey must be supplied by the caller — there is no fallback. Use
// a real key source (HSM, environment-supplied keyfile with 0o600 perms,
// or per-deployment crypto.randomBytes(32) persisted out-of-band).

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
      // The Merkle path is provided by the SDK's public data provider
      // when using findDeployedContract. For deployment (constructor),
      // this witness is not called.
      const path = context.privateState?.memberPath ?? null;
      return [context.privateState, path];
    },
  };
}
