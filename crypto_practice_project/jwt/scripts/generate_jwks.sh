#!/usr/bin/env bash
# generate_jwks.sh - Generate JSON Web Key Set (JWKS) for Ed25519 keys
#
# Usage:
#   ./generate_jwks.sh <public_key.pem> [kid]
#
# Output: JWKS JSON on stdout
#
# Examples:
#   ./generate_jwks.sh ../keys/ed25519_jwt_public.pem
#   ./generate_jwks.sh ../keys/ed25519_jwt_public.pem "key-2024-01" > jwks.json

set -euo pipefail

error() {
  echo "[ERROR] $*" >&2
}

# Validate arguments
if [[ $# -lt 1 ]] || [[ $# -gt 2 ]]; then
  error "Usage: $0 <public_key.pem> [kid]"
  exit 1
fi

PUBLIC_KEY="$1"
KID="${2:-$(basename "$PUBLIC_KEY" .pem)}"

# Validate public key exists
if [[ ! -f "$PUBLIC_KEY" ]]; then
  error "Public key not found: $PUBLIC_KEY"
  exit 1
fi

# Check dependencies
if ! command -v openssl &>/dev/null; then
  error "openssl is required"
  exit 1
fi

if ! command -v jq &>/dev/null; then
  error "jq is required"
  exit 1
fi

# Extract raw public key bytes (32 bytes for Ed25519)
# Ed25519 public keys are 32 bytes, but PEM includes headers
RAW_KEY=$(openssl pkey -pubin -in "$PUBLIC_KEY" -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')

if [[ -z "$RAW_KEY" ]]; then
  error "Failed to extract public key"
  exit 1
fi

# Build JWKS
jq -n \
  --arg kid "$KID" \
  --arg x "$RAW_KEY" \
  '{
    keys: [
      {
        kty: "OKP",
        crv: "Ed25519",
        use: "sig",
        kid: $kid,
        x: $x,
        alg: "EdDSA"
      }
    ]
  }'

exit 0
