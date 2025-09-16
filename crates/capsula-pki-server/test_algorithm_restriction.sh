#!/bin/bash

# Test script for algorithm-based certificate restriction
set -e

PKI_SERVER_URL="http://localhost:13001"
TEST_USER="testuser_algorithm"

echo "🧪 Testing Algorithm-Based Certificate Restriction"
echo "=================================================="

# Function to test certificate creation
test_certificate_creation() {
    local username=$1
    local algorithm=$2
    local description=$3
    
    echo "📝 Test: $description"
    echo "   Creating $algorithm certificate for user: $username"
    
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -X POST "$PKI_SERVER_URL/certificate/create" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$username\",\"algorithm\":$algorithm}")
    
    # Extract HTTP status and body
    http_status=$(echo "$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
    body=$(echo "$response" | sed -E 's/HTTPSTATUS:[0-9]*$//')
    
    echo "   HTTP Status: $http_status"
    
    if [ "$http_status" = "201" ]; then
        echo "   ✅ Certificate created successfully"
        # Extract certificate ID from response
        cert_id=$(echo "$body" | python3 -c "import sys, json; print(json.load(sys.stdin).get('certificate_id', 'unknown'))" 2>/dev/null || echo "unknown")
        echo "   📋 Certificate ID: $cert_id"
        return 0
    elif [ "$http_status" = "400" ]; then
        echo "   ❌ Certificate creation rejected (400 Bad Request)"
        echo "   📄 Response: $body"
        return 1
    else
        echo "   ⚠️  Unexpected status: $http_status"
        echo "   📄 Response: $body"
        return 2
    fi
}

# Function to check if server is running
check_server() {
    echo "🔍 Checking if PKI server is running..."
    if curl -s "$PKI_SERVER_URL/health" > /dev/null; then
        echo "   ✅ Server is running"
        return 0
    else
        echo "   ❌ Server is not running. Please start the server first."
        echo "   💡 Run: cargo run"
        exit 1
    fi
}

# Function to list certificates for user
list_user_certificates() {
    local username=$1
    echo "📋 Listing certificates for user: $username"
    
    response=$(curl -s "$PKI_SERVER_URL/certificate/users/$username/certificates")
    echo "   Response: $response"
}

# Main test sequence
main() {
    check_server
    
    echo ""
    echo "🧹 Cleanup: Removing any existing certificates for test user..."
    # Note: In a real test, we might want to revoke existing certificates first
    
    echo ""
    echo "🚀 Starting Algorithm Restriction Tests"
    echo ""
    
    # Test 1: First Ed25519 certificate should succeed (default algorithm)
    echo "Test 1: Creating first Ed25519 certificate for $TEST_USER"
    if test_certificate_creation "$TEST_USER" "{\"type\":\"Ed25519\"}" "First Ed25519 certificate - should succeed"; then
        echo "   🎉 Test 1 PASSED: First Ed25519 certificate created successfully"
    else
        echo "   💥 Test 1 FAILED: First Ed25519 certificate should have been created"
        exit 1
    fi
    
    echo ""
    
    # Test 2: Second certificate with same algorithm should fail
    echo "Test 2: Creating second Ed25519 certificate for same user"
    if test_certificate_creation "$TEST_USER" "{\"type\":\"Ed25519\"}" "Second Ed25519 certificate - should fail"; then
        echo "   💥 Test 2 FAILED: Second Ed25519 certificate should have been rejected"
        exit 1
    else
        echo "   🎉 Test 2 PASSED: Second Ed25519 certificate correctly rejected"
    fi
    
    echo ""
    
    # Test 3: Same user with different algorithm should succeed
    echo "Test 3: Creating RSA certificate for same user (different algorithm)"
    if test_certificate_creation "$TEST_USER" "{\"type\":\"RSA\",\"key_size\":2048}" "RSA certificate for same user - should succeed"; then
        echo "   🎉 Test 3 PASSED: Same user can create certificate with different algorithm"
    else
        echo "   💥 Test 3 FAILED: Same user should be able to create certificate with different algorithm"
        exit 1
    fi
    
    echo ""
    
    # Test 4: Second RSA certificate should fail
    echo "Test 4: Creating second RSA certificate for same user"
    if test_certificate_creation "$TEST_USER" "{\"type\":\"RSA\",\"key_size\":2048}" "Second RSA certificate - should fail"; then
        echo "   💥 Test 4 FAILED: Second RSA certificate should have been rejected"
        exit 1
    else
        echo "   🎉 Test 4 PASSED: Second RSA certificate correctly rejected"
    fi
    
    echo ""
    
    # Test 5: Different user should be able to create Ed25519 certificate
    echo "Test 5: Creating Ed25519 certificate for different user"
    if test_certificate_creation "${TEST_USER}_different" "{\"type\":\"Ed25519\"}" "Ed25519 certificate for different user - should succeed"; then
        echo "   🎉 Test 5 PASSED: Different user can create Ed25519 certificate"
    else
        echo "   💥 Test 5 FAILED: Different user should be able to create Ed25519 certificate"
        exit 1
    fi
    
    echo ""
    echo "📊 Test Summary"
    echo "==============="
    list_user_certificates "$TEST_USER"
    
    echo ""
    echo "🎊 All tests completed successfully!"
    echo "✅ Algorithm-based certificate restriction is working correctly"
}

# Run the tests
main "$@"