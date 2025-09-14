#!/bin/bash

# Test PKI server functionality

echo "=== Testing PKI Server ==="

# Test health
echo -n "Health check: "
curl -s http://localhost:8080/health | jq -r '.status // "ERROR"'

# Test CA status
echo -n "CA status: "
curl -s http://localhost:8080/api/v1/ca/status | jq -r '.initialized // "ERROR"'

# Test CA initialization
echo "Testing CA initialization..."
curl -s -X POST http://localhost:8080/api/v1/ca/init \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "Capsula Test CA",
    "organization": "Test Org", 
    "country": "US",
    "validity_days": 365,
    "key_algorithm": "Ed25519"
  }' | jq -r '.subject // "ERROR"'

echo "=== Test Complete ==="