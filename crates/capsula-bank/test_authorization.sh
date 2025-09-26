#!/bin/bash

# Test authorization API endpoints
BASE_URL="http://localhost:8080"

echo "Testing Authorization API Endpoints"
echo "===================================="

# Test 1: Grant permission
echo -e "\n1. Testing Grant Permission:"
curl -X POST "$BASE_URL/auth/grant" \
  -H "Content-Type: application/json" \
  -d '{
    "capsule_id": "test-capsule-123",
    "grantee": "user-456",
    "permissions": ["read", "write"],
    "expires_at": "2025-12-31T23:59:59Z",
    "metadata": {"purpose": "testing"}
  }' -w "\nStatus: %{http_code}\n"

# Test 2: Use token
echo -e "\n2. Testing Use Token:"
curl -X POST "$BASE_URL/auth/use" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "test-token-abc",
    "operation": "read",
    "capsule_id": "test-capsule-123"
  }' -w "\nStatus: %{http_code}\n"

# Test 3: List permissions
echo -e "\n3. Testing List Permissions:"
curl -X GET "$BASE_URL/auth/list?capsule_id=test-capsule-123&active_only=true" \
  -H "Accept: application/json" \
  -w "\nStatus: %{http_code}\n"

# Test 4: Revoke permission
echo -e "\n4. Testing Revoke Permission:"
curl -X POST "$BASE_URL/auth/revoke" \
  -H "Content-Type: application/json" \
  -d '{
    "token_id": "token-789",
    "reason": "Testing revocation"
  }' -w "\nStatus: %{http_code}\n"

echo -e "\nTesting complete!"