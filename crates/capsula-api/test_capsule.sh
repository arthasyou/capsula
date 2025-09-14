#!/bin/bash

# Test Capsula API functionality

echo "=== Testing Capsula API ==="

# Test data
TEST_DATA="Hello, this is secret medical data for testing!"
TEST_DATA_B64=$(echo -n "$TEST_DATA" | base64)

echo "Original data: $TEST_DATA"
echo "Base64 data: $TEST_DATA_B64"
echo

# Test encapsulation
echo "Testing data encapsulation..."
ENCAPSULATE_RESPONSE=$(curl -s -X POST http://localhost:8081/api/v1/capsule/encapsulate \
  -H "Content-Type: application/json" \
  -d '{
    "data": "'$TEST_DATA_B64'",
    "data_type": "medical.blood_test",
    "producer": "Central Hospital",
    "owner": "Patient 001", 
    "recipient_id": "doctor123",
    "key_algorithm": "RSA",
    "expires_in_days": 30
  }')

echo "Encapsulate response:"
echo "$ENCAPSULATE_RESPONSE" | jq .
echo

# Extract capsule data and private key
CAPSULE_DATA=$(echo "$ENCAPSULATE_RESPONSE" | jq -r '.capsule_data')
PRIVATE_KEY=$(echo "$ENCAPSULATE_RESPONSE" | jq -r '.recipient_private_key')

if [ "$CAPSULE_DATA" != "null" ] && [ "$CAPSULE_DATA" != "" ]; then
    echo "✅ Encapsulation successful!"
    
    # Test verification
    echo "Testing capsule verification..."
    VERIFY_RESPONSE=$(curl -s -X POST http://localhost:8081/api/v1/capsule/verify \
      -H "Content-Type: application/json" \
      -d '{
        "capsule_data": "'$CAPSULE_DATA'",
        "user_id": "doctor123"
      }')
    
    echo "Verify response:"
    echo "$VERIFY_RESPONSE" | jq .
    echo
    
    # Test decapsulation
    echo "Testing data decapsulation..."
    DECAPSULATE_RESPONSE=$(curl -s -X POST http://localhost:8081/api/v1/capsule/decapsulate \
      -H "Content-Type: application/json" \
      -d '{
        "capsule_data": "'$CAPSULE_DATA'",
        "user_id": "doctor123",
        "private_key": "'$PRIVATE_KEY'"
      }')
    
    echo "Decapsulate response:"
    echo "$DECAPSULATE_RESPONSE" | jq .
    echo
    
    # Verify decrypted data
    DECRYPTED_DATA=$(echo "$DECAPSULATE_RESPONSE" | jq -r '.data')
    if [ "$DECRYPTED_DATA" != "null" ] && [ "$DECRYPTED_DATA" != "" ]; then
        DECRYPTED_TEXT=$(echo "$DECRYPTED_DATA" | base64 -d)
        echo "Decrypted data: $DECRYPTED_TEXT"
        
        if [ "$DECRYPTED_TEXT" = "$TEST_DATA" ]; then
            echo "✅ Full round-trip successful!"
        else
            echo "❌ Data mismatch!"
        fi
    else
        echo "❌ Decapsulation failed!"
    fi
else
    echo "❌ Encapsulation failed!"
fi

echo "=== Test Complete ==="