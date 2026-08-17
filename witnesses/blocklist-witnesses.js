// Attribute-Based Blocklist Exclusion — witness implementations
//
// Witnesses declared in blocklist-exclusion.compact:
//   witness localSecretKey(): Bytes<32>;
//   witness getRegistryPath(pk: Bytes<32>): MerkleTreePath<10, Bytes<32>>;
//   witness getCredentialAttribute(): Bytes<32>;
//   witness getBlocklistSnapshot(): Vector<8, Bytes<32>>;
//   witness getBlocklistCount(): Uint<64>;
//
// Private state shape:
//   {
//     secretKey: Uint8Array,
//     credentialAttribute: Uint8Array,   // raw attribute (e.g., jurisdiction code padded to 32 bytes)
//     blocklistSnapshot: Uint8Array[],   // attribute hashes from on-chain blocklist
//     blocklistCount: bigint,
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

    getRegistryPath: (context, pk) => {
      const path = context.ledger.registry.findPathForLeaf(pk);
      if (!path) throw new Error('User not found in registry');
      return [context.privateState, path];
    },

    getCredentialAttribute: (context) => {
      const attr = context.privateState?.credentialAttribute;
      if (!attr) throw new Error('No credential attribute in private state');
      return [context.privateState, attr];
    },

    getBlocklistSnapshot: (context) => {
      const snapshot = context.privateState?.blocklistSnapshot ?? [];
      const padded = [];
      for (let i = 0; i < 8; i++) {
        padded.push(snapshot[i] ?? new Uint8Array(32));
      }
      return [context.privateState, padded];
    },

    getBlocklistCount: (context) => {
      const count = context.privateState?.blocklistCount ?? 0n;
      return [context.privateState, count];
    },
  };
}
