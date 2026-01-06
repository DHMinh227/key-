#!/bin/bash
set -e

echo "================================================"
echo "JWT Signing & Verification Test"
echo "================================================"
echo ""

if [ ! -f "jwt/keys/ed25519_jwt_private.pem" ]; then
    echo "ERROR: JWT keys not found!"
    exit 1
fi

echo "Keys found:"
echo "  Private: jwt/keys/ed25519_jwt_private.pem"
echo "  Public:  jwt/keys/ed25519_jwt_public.pem"
echo ""

echo "Creating test message..."
echo "Hello from JWT signing test - $(date)" > jwt/input/message.txt

echo "Message to sign:"
cat jwt/input/message.txt
echo ""

echo "================================================"
echo "Signing message..."
echo "================================================"

openssl pkeyutl -sign \
    -inkey jwt/keys/ed25519_jwt_private.pem \
    -rawin -in jwt/input/message.txt \
    -out jwt/output/signature.bin

echo "? Signature created: jwt/output/signature.bin"
echo "  Size: $(wc -c < jwt/output/signature.bin) bytes"
echo ""

echo "================================================"
echo "Verifying signature..."
echo "================================================"

openssl pkeyutl -verify \
    -pubin -inkey jwt/keys/ed25519_jwt_public.pem \
    -rawin -in jwt/input/message.txt \
    -sigfile jwt/output/signature.bin

if [ $? -eq 0 ]; then
    echo ""
    echo "??? SUCCESS! Signature is VALID ???"
else
    echo ""
    echo "??? FAILED! Signature is INVALID ???"
    exit 1
fi

echo ""
echo "================================================"
echo "Testing tampering detection..."
echo "================================================"

cp jwt/input/message.txt jwt/input/message_backup.txt

echo "TAMPERED" >> jwt/input/message.txt

echo "Attempting to verify tampered message..."

if openssl pkeyutl -verify \
    -pubin -inkey jwt/keys/ed25519_jwt_public.pem \
    -rawin -in jwt/input/message.txt \
    -sigfile jwt/output/signature.bin 2>&1; then
    echo "? ERROR: Should have failed!"
else
    echo "??? SUCCESS! Tampering detected ???"
fi

mv jwt/input/message_backup.txt jwt/input/message.txt

echo ""
echo "================================================"
echo "Test Complete!"
echo "================================================"