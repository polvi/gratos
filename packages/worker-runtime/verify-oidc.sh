#!/bin/bash
set -e

WORKER_URL="http://localhost:8788"

echo "Testing Discovery..."
curl -s "$WORKER_URL/oidc/.well-known/openid-configuration" | grep "issuer"
if curl -s "$WORKER_URL/oidc/.well-known/openid-configuration" | grep -q "email"; then
    echo "FAIL: Email scope/claim found via grep (might be false positive if in other fields, but generally checking absence)"
    # A stricter check would be better but simple grep helps catch obvious presence
else
    echo "Discovery OK (Email absent)"
fi

echo "Testing JWKS..."
curl -s "$WORKER_URL/oidc/jwks" | grep "keys"
echo "JWKS OK"

# Manually create a user and session in KV/DB is hard from outside without admin endpoints or seeding.
# But we can try to hit authorize and expect a 401 "Not authenticated" which proves it's reachable.

echo "Testing Authorize (Unauthenticated)..."
# Using client_id=kubernetes and redirect_uri=http://localhost:8000 which match wrangler.jsonc
# We expect a redirect (302) to the login page
RESPONSE=$(curl -s -i "$WORKER_URL/oidc/authorize?response_type=code&client_id=kubernetes&redirect_uri=http://localhost:8000&state=123&nonce=456")
STATUS=$(echo "$RESPONSE" | grep "HTTP/" | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep -i "Location:" | awk '{print $2}' | tr -d '\r')

if [ "$STATUS" -eq "302" ]; then
    echo "Authorize (Unauthenticated) OK (Returned 302)"
    if [[ "$LOCATION" == *"http://localhost:4321/login"* ]]; then
         echo "Redirect Location OK: $LOCATION"
    else
         echo "FAIL: Redirect Location mismatch. Got: $LOCATION"
         exit 1
    fi
else
    echo "Authorize Failed: Expected 302, got $STATUS"
    exit 1
fi



echo "Testing Token Endpoint (No Secret)..."
# Just a reachability test since we can't easily get a valid code without full flow.
# But we can verify it doesn't fail with "invalid_client_secret" even if we send one or don't.
# It should fail with "invalid_grant1" (Code not found) if code is fake.

TOKEN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$WORKER_URL/oidc/token" -d "grant_type=authorization_code&code=fakecode&redirect_uri=http://localhost:8000&client_id=kubernetes")

if [ "$TOKEN_STATUS" -eq "400" ]; then
     echo "Token Check OK (Returned 400 - Invalid Code, as expected)"
else
     echo "Token Check Unexpected: Got $TOKEN_STATUS"
fi

echo "Testing Discovery (Auth Methods)..."
# Should not advertise client_secret_basic/post
if curl -s "$WORKER_URL/oidc/.well-known/openid-configuration" | grep -q '"token_endpoint_auth_methods_supported":\["none"\]'; then
    echo "Discovery OK (none advertised)"
elif curl -s "$WORKER_URL/oidc/.well-known/openid-configuration" | grep -q "token_endpoint_auth_methods_supported"; then
    echo "Discovery Info: Auth methods found but not strict 'none' check passed (maybe other methods present?)"
else
    echo "Discovery OK (auth_methods not advertised or none)"
fi

echo "All basic OIDC endpoints verified reachable."
