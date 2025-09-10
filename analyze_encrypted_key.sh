#!/bin/bash

echo "=== Analyzing Encrypted Private Key Structure ==="
echo

# Save the encrypted key to a file
cat > encrypted_key.pem << 'EOF'
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGkMGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBBbLaF5L8ETOFeOm5kj
sNYSAgMJJ8AwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEONA7IKGbBuFmEyH
9jDC/iIEQOEHJgW/5fQSzIOcnbiMhlcNnmVrIqzk1Nw1O7w35uiX0lftt/AIOZj4
4wuETg79ymhr9xQ4DnMUhjFid3VWRAU=
-----END ENCRYPTED PRIVATE KEY-----
EOF

# Extract just the base64 content
cat encrypted_key.pem | grep -v "BEGIN\|END" | tr -d '\n' > encrypted_key.b64

echo "Base64 content length: $(wc -c < encrypted_key.b64) characters"
echo

# Decode to binary and check size
base64 -d encrypted_key.b64 > encrypted_key.der
echo "Binary size: $(wc -c < encrypted_key.der) bytes"
echo

# Show hex dump of first part (ASN.1 structure)
echo "First 32 bytes (hex) showing ASN.1 structure:"
xxd -l 32 encrypted_key.der
echo

echo "=== Comparison ==="
echo
echo "Plain Ed25519 key: 32 bytes → ~44 base64 chars"
echo "Encrypted Ed25519 key: ~164 bytes → ~220 base64 chars"
echo
echo "The encrypted version contains:"
echo "  1. PKCS#8 wrapper structure"
echo "  2. Encryption algorithm identifiers (PBES2, PBKDF2, AES)"
echo "  3. Salt for key derivation"
echo "  4. Iteration count for PBKDF2"
echo "  5. IV for AES encryption"
echo "  6. The actual encrypted key data"

# Clean up
rm -f encrypted_key.pem encrypted_key.b64 encrypted_key.der