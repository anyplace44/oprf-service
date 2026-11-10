#!/usr/bin/env bash
# Deploys the 2-of-3 OprfKeyRegistryV2 behind an ERC1967 proxy on an anvil
# chain from the committed artifacts, registers the peers and checks
# isContractReady(). Not idempotent: a second run on the same chain deploys
# to a new address.
#
# usage: ADMIN_KEY=0x.. PEER_ADDRS=a,b,c \
#   deploy-registry.sh <anvil-container> <rpc-url> <artifacts-dir>
#
# cast runs inside <anvil-container> (rpc-url as seen from there); bytecode is
# passed as arguments, so the artifacts dir is only read on the host.
# stdout: the proxy address, nothing else. Progress goes to stderr.
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <cast-container> <rpc-url> <artifacts-dir>" >&2; exit 2; }
CONTAINER=$1 RPC=$2 ART=$3
: "${ADMIN_KEY:?ADMIN_KEY not set}" "${PEER_ADDRS:?PEER_ADDRS not set}"
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

cast_() { docker exec "$CONTAINER" cast "$@"; }
deploy() { # <artifact> [library-address] [constructor-args-hex] -> deployed address
  local code # set -e is off inside $(...), hence the explicit returns
  code=$(python3 -I "$HERE/bytecode.py" "$1" ${2:+"$2"}) || return 1
  create "$code${3:-}" || return 1
}
create() { # <bytecode> -> deployed address
  cast_ send --json --rpc-url "$RPC" --private-key "$ADMIN_KEY" --create "$1" \
    | python3 -I -c 'import json,sys; r=json.load(sys.stdin); assert r["status"]=="0x1", r; print(r["contractAddress"])'
}

ADMIN=$(cast_ wallet address --private-key "$ADMIN_KEY")
VERIFIER=$(deploy "$ART/Verifier.13.json")
BJJ=$(deploy "$ART/BabyJubJub.json")
IMPL=$(deploy "$ART/OprfKeyRegistryV2.json" "$BJJ")
INIT=$(cast_ calldata "initialize(address,address,address,uint16,uint16)" \
  "$ADMIN" "$ADMIN" "$VERIFIER" 2 3)
ARGS=$(cast_ abi-encode "constructor(address,bytes)" "$IMPL" "$INIT")
PROXY=$(deploy "$ART/ERC1967Proxy.json" "" "${ARGS#0x}")
echo "verifier $VERIFIER, babyjubjub $BJJ, impl $IMPL, registry proxy $PROXY" >&2

cast_ send --rpc-url "$RPC" --private-key "$ADMIN_KEY" "$PROXY" \
  "registerOprfPeers(address[])" "[$PEER_ADDRS]" >&2
ready=$(cast_ call --rpc-url "$RPC" "$PROXY" "isContractReady()(bool)")
[ "$ready" = true ] || { echo "registry not ready after registering peers" >&2; exit 1; }
echo "$PROXY"
