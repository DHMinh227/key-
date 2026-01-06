#!/usr/bin/env bash
# create_jwt_token.sh - Production-ready JWT token creation with Ed25519
#
# Usage: 
#   ./create_jwt_token.sh <payload.json> [output_file]
#   
# Environment variables:
#   VERBOSE=1           Enable debug output
#   EXP_HOURS=N         Set expiration hours (default: 1)
#   PRIVATE_KEY         Override private key path
#   KID                 Key ID for header (default: auto-detect from filename)
#   ISS                 Issuer claim
#   AUD                 Audience claim
#   JTI_ENABLED=1       Generate unique JWT ID
#
# Examples:
#   ./create_jwt_token.sh payload.json
#   ISS="myapp" AUD="api.example.com" ./create_jwt_token.sh payload.json
#   VERBOSE=1 KID="key-2024-01" ./create_jwt_token.sh payload.json token.jwt

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIVATE_KEY="${PRIVATE_KEY:-${SCRIPT_DIR}/../keys/ed25519_jwt_private.pem}"
VERBOSE="${VERBOSE:-0}"
EXP_HOURS="${EXP_HOURS:-1}"
ISS="${ISS:-}"
AUD="${AUD:-}"
JTI_ENABLED="${JTI_ENABLED:-0}"

# Auto-detect KID from key filename if not provided
if [[ -z "${KID:-}" ]]; then
  KID=$(basename "$PRIVATE_KEY" | sed 's/_private\.pem$//' | sed 's/^ed25519_jwt_//')
  [[ "$KID" == "ed25519_jwt_private.pem" ]] && KID="default"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Debug logging
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

warning() {
  echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

# Check dependencies
check_dependencies() {
  local missing=0
  for cmd in jq openssl base64; do
    if ! command -v "$cmd" &>/dev/null; then
      error "$cmd is required but not installed"
      missing=1
    fi
  done
  
  if [[ $missing -eq 1 ]]; then
    exit 1
  fi
  
  debug "All dependencies found"
}

# Portable UUID generation for jti
generate_uuid() {
  if command -v uuidgen &>/dev/null; then
    uuidgen | tr -d '\n'
  elif [[ -f /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid | tr -d '\n'
  else
    # Fallback: timestamp + random
    printf '%s-%s' "$(date +%s)" "$RANDOM$RANDOM"
  fi
}

# Portable timestamp (Unix epoch)
get_timestamp() {
  date +%s
}

# Strict base64url encoding (handles binary data safely)
base64url_encode() {
  # Use openssl base64 for better binary handling, then convert to base64url
  openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

# Validate arguments
if [[ $# -lt 1 ]] || [[ $# -gt 2 ]]; then
  error "Invalid number of arguments"
  echo "Usage: $0 <payload.json> [output_file]" >&2
  exit 1
fi

PAYLOAD_JSON="$1"
OUTPUT_FILE="${2:-}"

# Validate inputs
if [[ ! -f "$PAYLOAD_JSON" ]]; then
  error "Payload file not found: $PAYLOAD_JSON"
  exit 1
fi

if [[ ! -f "$PRIVATE_KEY" ]]; then
  error "Private key not found: $PRIVATE_KEY"
  exit 1
fi

# Validate JSON syntax
if ! jq empty "$PAYLOAD_JSON" 2>/dev/null; then
  error "Invalid JSON in payload file"
  exit 1
fi

debug "Payload file: $PAYLOAD_JSON"
debug "Private key: $PRIVATE_KEY"
debug "Key ID (kid): $KID"
debug "Expiration: $EXP_HOURS hours"

# Check dependencies
check_dependencies

# Build JWT header with kid
HEADER=$(jq -n \
  --arg alg "EdDSA" \
  --arg typ "JWT" \
  --arg kid "$KID" \
  '{alg: $alg, typ: $typ, kid: $kid}')

debug "Header: $HEADER"

# Build payload with standard claims
PAYLOAD_CONTENT=$(jq -c . "$PAYLOAD_JSON")
CURRENT_TIME=$(get_timestamp)

# Add standard claims
if ! echo "$PAYLOAD_CONTENT" | jq -e '.iat' >/dev/null 2>&1; then
  debug "Adding iat (issued at): $CURRENT_TIME"
  PAYLOAD_CONTENT=$(echo "$PAYLOAD_CONTENT" | jq --arg iat "$CURRENT_TIME" '. + {iat: ($iat | tonumber)}')
fi

if ! echo "$PAYLOAD_CONTENT" | jq -e '.exp' >/dev/null 2>&1; then
  EXP_TIME=$((CURRENT_TIME + EXP_HOURS * 3600))
  debug "Adding exp (expiration): $EXP_TIME"
  PAYLOAD_CONTENT=$(echo "$PAYLOAD_CONTENT" | jq --arg exp "$EXP_TIME" '. + {exp: ($exp | tonumber)}')
fi

if [[ -n "$ISS" ]]; then
  debug "Adding iss (issuer): $ISS"
  PAYLOAD_CONTENT=$(echo "$PAYLOAD_CONTENT" | jq --arg iss "$ISS" '. + {iss: $iss}')
fi

if [[ -n "$AUD" ]]; then
  debug "Adding aud (audience): $AUD"
  PAYLOAD_CONTENT=$(echo "$PAYLOAD_CONTENT" | jq --arg aud "$AUD" '. + {aud: $aud}')
fi

if [[ "$JTI_ENABLED" == "1" ]]; then
  JTI=$(generate_uuid)
  debug "Adding jti (JWT ID): $JTI"
  PAYLOAD_CONTENT=$(echo "$PAYLOAD_CONTENT" | jq --arg jti "$JTI" '. + {jti: $jti}')
fi

debug "Final payload: $PAYLOAD_CONTENT"

# Encode header and payload (strict base64url)
ENC_HEADER=$(printf '%s' "$HEADER" | base64url_encode)
ENC_PAYLOAD=$(printf '%s' "$PAYLOAD_CONTENT" | base64url_encode)

debug "Encoded header: $ENC_HEADER"
debug "Encoded payload: $ENC_PAYLOAD"

# Create signing input
SIGNING_INPUT="${ENC_HEADER}.${ENC_PAYLOAD}"
debug "Signing input: $SIGNING_INPUT"

# Sign using Ed25519
debug "Signing with Ed25519..."
RAW_SIG=$(printf '%s' "$SIGNING_INPUT" \
  | openssl pkeyutl -sign -inkey "$PRIVATE_KEY" -pkeyopt eddsa:1 \
  2>/dev/null)

if [[ -z "$RAW_SIG" ]]; then
  error "Signature generation failed"
  exit 1
fi

debug "Signature generated (${#RAW_SIG} bytes)"

# Base64url encode the signature (strict encoding)
ENC_SIG=$(printf '%s' "$RAW_SIG" | base64url_encode)
debug "Encoded signature: ${ENC_SIG:0:20}..."

# Construct final JWT
JWT="${ENC_HEADER}.${ENC_PAYLOAD}.${ENC_SIG}"

# Security check: Warn if key is world-readable
KEY_PERMS=$(stat -c %a "$PRIVATE_KEY" 2>/dev/null || stat -f %Lp "$PRIVATE_KEY" 2>/dev/null || echo "unknown")
if [[ "$KEY_PERMS" != "600" ]] && [[ "$KEY_PERMS" != "400" ]]; then
  warning "Private key has insecure permissions: $KEY_PERMS (should be 600 or 400)"
  warning "Run: chmod 600 $PRIVATE_KEY"
fi

# Output
if [[ -n "$OUTPUT_FILE" ]]; then
  printf '%s\n' "$JWT" > "$OUTPUT_FILE"
  success "JWT saved to: $OUTPUT_FILE"
  debug "Token length: ${#JWT} characters"
else
  printf '%s\n' "$JWT"
fi

debug "JWT creation complete"

# Return success
exit 0
