#!/usr/bin/env bash
set -euo pipefail

# Compile every Compact contract in contracts/ into compiled/<name>/.
#
# Output per contract:
#   compiled/<name>/contract/index.{js,d.ts}     JS API + TypeScript types
#   compiled/<name>/zkir/<circuit>.{zkir,bzkir}  circuit IR
#   compiled/<name>/keys/<circuit>.{prover,verifier} PLONK keys
#   compiled/<name>/compiler/contract-info.json  circuit metadata
#
# Usage:
#   scripts/compile-all.sh              # compile all contracts
#   scripts/compile-all.sh nullifier-pattern    # compile one

CONTRACTS=(
  nullifier-pattern
  blocklist-exclusion
  sparse-merkle-non-membership
  indexed-merkle-non-membership
)

if [ "$#" -gt 0 ]; then
  CONTRACTS=("$@")
fi

echo "Compact CLI:      $(compact --version)"
echo "Compact compiler: $(compact compile --version)"
echo ""

for contract in "${CONTRACTS[@]}"; do
  # <pattern>-non-membership.compact lands in compiled/<pattern>/
  out_name="${contract/sparse-merkle-non-membership/sparse-merkle}"
  out_name="${out_name/indexed-merkle-non-membership/indexed-merkle}"
  out_dir="compiled/$out_name"

  echo "==> Compiling contracts/$contract.compact → $out_dir"
  compact compile "contracts/$contract.compact" "$out_dir"
  echo ""
done

echo "All contracts compiled."
