#!/usr/bin/env bash
# validate_jwt_token.sh - Validate JWT tokens with Ed25519
#
# Usage:
#   ./validate_jwt_token.sh <token_file_or_string> [public_key]
#
# Environment variables:
#   PUBLIC_KEY    Public key path (default: auto-detect)
#   VERBOSE=1     Enable debug output
#   CHECK_EXP=1   Verify expiration (default: 1)
#   EXPECTED_ISS  Expected issuer
#   EXPECTED_AUD  Expected audience
#
# Examples:
#   ./validate_jwt_token.sh token.jwt
#   ./validate_jwt_token.sh "eyJhbGc..." ../keys/ed25519_jwt_public.pem
#   EXPECTED_ISS="myapp" ./validate_jwt_token.sh token.jwt

set -euo pipefail

# Configuration
PUBLIC_KEY="${PUBLIC_KEY:-../keys/ed25519_jwt_public.pem}"
VERBOSE="${VERBOSE:-0}"
CHECK_EXP="${CHECK_EXP:-1}"
EXPECTED_ISS="${EXPECTED_ISS:-}"
EXPECTED_AUD="${EXPECTED_AUD:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

debug() {
  if [[ "$VERBOSE" == "1" ]]; then
    echo -e "${YELLOW}[DEBUG]${NC} $*" >&2
  fi
}

error() {
  echo -e "${RED}[ERROR]${NC} $*" >&2
}

success() {
  echo -e "${GREEN}[SUCCESS]${NC} $*" >&2
}

# Base64url decode
base64url_decode() {
  local input="$1"
  # Add padding
  local padded="$input"
  case $((${#input} % 4)) in
    2) padded="${input}==" ;;
    3) padded="${input}=" ;;
  esac
  # Convert base64url to base64, then decode
  echo "$padded" | tr '_-' '/+' | base64 -d 2>/dev/null
}

# Get current timestamp
get_timestamp() {
  date +%s
}

# Validate arguments
if [[ $# -lt 1 ]] || [[ $# -gt 2 ]]; then
  error "Invalid arguments"
  echo "Usage: $0 <token_file_or_string> [public_key]" >&2
  exit 1
fi

TOKEN_INPUT="$1"
[[ -n "${2:-}" ]] && PUBLIC_KEY="$2"

# Read token
if [[ -f "$TOKEN_INPUT" ]]; then
  TOKEN=$(cat "$TOKEN_INPUT" | tr -d '\n')
  debug "Token read from file: $TOKEN_INPUT"
else
  TOKEN="$TOKEN_INPUT"
  debug "Token provided as string"
fi

# Validate public key
if [[ ! -f "$PUBLIC_KEY" ]]; then
  error "Public key not found: $PUBLIC_KEY"
  exit 1
fi

debug "Public key: $PUBLIC_KEY"

# Split JWT into parts
IFS='.' read -r ENC_HEADER ENC_PAYLOAD ENC_SIG <<< "$TOKEN"

if [[ -z "$ENC_HEADER" ]] || [[ -z "$ENC_PAYLOAD" ]] || [[ -z "$ENC_SIG" ]]; then
  error "Invalid JWT format (expected: header.payload.signature)"
  exit 1
fi

debug "JWT parts extracted"

# Decode header
HEADER=$(base64url_decode "$ENC_HEADER")
debug "Header: $HEADER"

# Decode payload
PAYLOAD=$(base64url_decode "$ENC_PAYLOAD")
debug "Payload: $PAYLOAD"

# Validate header algorithm
ALG=$(echo "$HEADER" | jq -r '.alg' 2>/dev/null)
if [[ "$ALG" != "EdDSA" ]]; then
  error "Unsupported algorithm: $ALG (expected: EdDSA)"
  exit 1
fi

success "Algorithm verified: EdDSA"

# Decode signature
SIG_BIN=$(base64url_decode "$ENC_SIG")
SIG_FILE=$(mktemp)
trap "rm -f $SIG_FILE" EXIT
printf '%s' "$SIG_BIN" > "$SIG_FILE"

debug "Signature decoded to temporary file"

# Verify signature
SIGNING_INPUT="${ENC_HEADER}.${ENC_PAYLOAD}"
if printf '%s' "$SIGNING_INPUT" | openssl pkeyutl -verify \
    -pubin -inkey "$PUBLIC_KEY" \
    -sigfile "$SIG_FILE" \
    -pkeyopt eddsa:1 2>/dev/null; then
  success "✓ Signature is VALID"
else
  error "✗ Signature is INVALID"
  exit 1
fi

# Validate claims
CURRENT_TIME=$(get_timestamp)

# Check expiration
if [[ "$CHECK_EXP" == "1" ]]; then
  EXP=$(echo "$PAYLOAD" | jq -r '.exp // empty' 2>/dev/null)
  if [[ -n "$EXP" ]]; then
    if [[ "$EXP" -lt "$CURRENT_TIME" ]]; then
      error "✗ Token has EXPIRED (exp: $EXP, now: $CURRENT_TIME)"
      exit 1
    else
      success "✓ Token not expired (expires in $((EXP - CURRENT_TIME))s)"
    fi
  else
    debug "No exp claim found"
  fi
fi

# Check issuer
if [[ -n "$EXPECTED_ISS" ]]; then
  ISS=$(echo "$PAYLOAD" | jq -r '.iss // empty' 2>/dev/null)
  if [[ "$ISS" != "$EXPECTED_ISS" ]]; then
    error "✗ Issuer mismatch (expected: $EXPECTED_ISS, got: $ISS)"
    exit 1
  fi
  success "✓ Issuer verified: $ISS"
fi

# Check audience
if [[ -n "$EXPECTED_AUD" ]]; then
  AUD=$(echo "$PAYLOAD" | jq -r '.aud // empty' 2>/dev/null)
  if [[ "$AUD" != "$EXPECTED_AUD" ]]; then
    error "✗ Audience mismatch (expected: $EXPECTED_AUD, got: $AUD)"
    exit 1
  fi
  success "✓ Audience verified: $AUD"
fi

# Print payload if verbose
if [[ "$VERBOSE" == "1" ]]; then
  echo ""
  echo "Decoded Payload:"
  echo "$PAYLOAD" | jq .
fi

success "✓ JWT is VALID"
exit 0