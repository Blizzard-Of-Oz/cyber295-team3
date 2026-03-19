# Rate Limiting

This document describes the multi-dimensional rate limiting implementation for the Gmail MCP HTTP wrapper.

## Overview

Rate limiting prevents abuse by restricting the number of requests based on multiple factors (scopes) within time windows. The implementation uses Redis with TTL-based expiration for efficient, distributed rate limiting.

## Architecture

### Key Structure
Redis keys follow this pattern:
```
ratelimit:{scope}:{value}:{action}
```

- **scope**: The dimension being rate limited (e.g., `identity`, `ip`, `useragent`)
- **value**: The specific value for that scope (e.g., `user@example.com`, `192.168.1.1`, `Mozilla/5.0...`)
- **action**: Tool/action name (e.g., `send_email`, `search_emails`)

**Examples:**
- `ratelimit:identity:user@example.com:send_email` - Rate limit user's send_email action
- `ratelimit:ip:192.168.1.1:send_email` - Rate limit IP's send_email action
- `ratelimit:useragent:curl/7.88.1:search_emails` - Rate limit user agent's search action

### Multi-Scope Enforcement

Each request is checked against **all configured scopes**. If **any** scope is violated, the request is denied. This provides layered protection:

1. **Identity-based**: Limit per user (from `x-authenticated-user` header)
2. **IP-based**: Limit per IP address (from `x-user-ip` or `x-forwarded-for`)
3. **User-Agent-based**: Limit per client application (from `user-agent` header)
4. **Custom scopes**: You can add additional scopes as needed

### Algorithm
Fixed window rate limiting with TTL:
1. Check current count for each scope+value+action combination
2. If any count >= limit, reject with 429 status
3. If all counts < limits, increment all counters
4. On first request in window, set TTL to window duration

## Configuration

### Redis Setup

First, ensure Redis is running:
```bash
# macOS (using Homebrew)
brew install redis
brew services start redis

# Linux (Ubuntu/Debian)
sudo apt-get install redis-server
sudo systemctl start redis-server

# Docker
docker run -d -p 6379:6379 redis:7-alpine
```

### Environment Variables

Add these to your `.env` file:

```bash
# Redis connection
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_USERNAME=          # Optional, for Redis 6.0+ ACL authentication
REDIS_PASSWORD=          # Optional, leave empty if no password

# Enable/disable rate limiting
RATE_LIMIT_ENABLED=true  # Set to false to disable

# Default limits per scope (applied to all actions if not specifically configured)
RATE_LIMIT_IDENTITY_DEFAULT=20:60      # 20 requests per user per 60 seconds
RATE_LIMIT_IP_DEFAULT=100:60           # 100 requests per IP per 60 seconds
RATE_LIMIT_USERAGENT_DEFAULT=50:60     # 50 requests per user-agent per 60 seconds

# Action-specific limits by identity (user)
RATE_LIMIT_IDENTITY_SEND_EMAIL=3:60         # User can send 3 emails per minute
RATE_LIMIT_IDENTITY_SEARCH_EMAILS=20:60     # User can search 20 times per minute
RATE_LIMIT_IDENTITY_DELETE_EMAIL=10:60      # User can delete 10 emails per minute

# Action-specific limits by IP address
RATE_LIMIT_IP_SEND_EMAIL=10:60              # IP can send 10 emails per minute
RATE_LIMIT_IP_SEARCH_EMAILS=50:60           # IP can search 50 times per minute

# Action-specific limits by user agent
RATE_LIMIT_USERAGENT_SEND_EMAIL=20:60       # User agent can send 20 emails per minute
```

### Configuration Hierarchy

Rate limits are evaluated in this order:

1. **Specific scope+action**: `RATE_LIMIT_{SCOPE}_{ACTION}` (e.g., `RATE_LIMIT_IDENTITY_SEND_EMAIL`)
2. **Scope default**: `RATE_LIMIT_{SCOPE}_DEFAULT` (e.g., `RATE_LIMIT_IDENTITY_DEFAULT`)
3. **No limit**: If neither exists, requests are allowed without rate limiting for that scope

### Multi-Scope Behavior

When multiple scopes are configured:
- **ALL scopes are checked** on every request
- If **ANY scope** is exceeded, the request is **denied with 429**
- The response includes which scope was violated

Example scenario:
```bash
RATE_LIMIT_IDENTITY_SEND_EMAIL=3:60   # 3 per user per minute
RATE_LIMIT_IP_SEND_EMAIL=10:60        # 10 per IP per minute
```

- User A from IP 1.2.3.4 sends 3 emails → Further requests denied (identity limit)
- Three different users from IP 1.2.3.4 send 3 emails each (9 total) → Some requests allowed
- Four users from IP 1.2.3.4 send 3 emails each (12 total) → 11th request denied (IP limit)

### Rate Limit Format

Rate limits use the format: `count:window_seconds`

Examples:
- `3:60` = 3 requests per 60 seconds (1 minute)
- `100:3600` = 100 requests per 3600 seconds (1 hour)
- `1000:86400` = 1000 requests per 86400 seconds (1 day)

### Scope and Action Name Mapping

**Scopes** (built-in):
- `identity` - User identity from `x-authenticated-user` header
- `ip` - IP address from `x-user-ip` or `x-forwarded-for` headers
- `useragent` - User agent from `user-agent` header

**Action names** in environment variables:
- Convert to uppercase for env var
- Replace hyphens with underscores
- Add `RATE_LIMIT_{SCOPE}_` prefix

Examples:
- Tool: `send-email`, Scope: `identity` → Env var: `RATE_LIMIT_IDENTITY_SEND_EMAIL`
- Tool: `search_emails`, Scope: `ip` → Env var: `RATE_LIMIT_IP_SEARCH_EMAILS`
- Tool: `create-draft`, Scope: `useragent` → Env var: `RATE_LIMIT_USERAGENT_CREATE_DRAFT`

**Custom Scopes:**

You can add custom scopes by defining new headers and environment variables:

```bash
# Example: Rate limit by organization
RATE_LIMIT_ORG_DEFAULT=50:60
RATE_LIMIT_ORG_SEND_EMAIL=5:60
```

Then extract the org value in server.js and add to rate limit checks.

## Installation

1. Install the Redis dependency:
```bash
cd gmail-mcp-http
npm install
```

2. Configure environment variables in `.env` file

3. Start Redis if not already running

4. Start the server:
```bash
npm run dev
```

## Usage

### Making Requests

The rate limiter automatically checks all requests to `/call-tool`. No changes needed to client code.

### Response Headers

All responses include rate limit headers (from the most restrictive scope):
```
x-ratelimit-limit: 3          # Maximum requests allowed in window
x-ratelimit-remaining: 2      # Remaining requests in current window
x-ratelimit-window: 60        # Window duration in seconds
x-ratelimit-scope: identity   # Which scope these headers refer to
x-ratelimit-reset: 45         # Seconds until limit resets
```

### Rate Limit Exceeded Response

When rate limit is exceeded, the server returns HTTP 429:
```json
{
  "error": "Rate limit exceeded",
  "scope": "identity",
  "reason": "rate_limit_exceeded_identity",
  "limit": 3,
  "window": 60,
  "resetIn": 45,
  "message": "Rate limit exceeded for scope 'identity'. Limit: 3 requests per 60 seconds. Try again in 45 seconds."
}
```

**Possible reason values:**
- `rate_limit_exceeded_identity` - User identity limit exceeded
- `rate_limit_exceeded_ip` - IP address limit exceeded  
- `rate_limit_exceeded_useragent` - User agent limit exceeded
- `rate_limit_exceeded_{custom_scope}` - Custom scope limit exceeded

## API Endpoints

### Check Rate Limit Status

Get current rate limit status for a specific scope, value, and action:

```bash
GET /rate-limit/status?scope=identity&value=user@example.com&action=send_email
```

Query parameters:
- `scope` (optional, default: `identity`) - The rate limit scope
- `value` (optional, default: authenticated user) - The value for that scope
- `action` (required) - The action name

Response:
```json
{
  "enabled": true,
  "configured": true,
  "scope": "identity",
  "value": "user@example.com",
  "action": "send_email",
  "limit": 3,
  "window": 60,
  "current": 2,
  "remaining": 1,
  "resetIn": 42
}
```

**Examples:**

```bash
# Check identity limit
curl "http://localhost:3301/rate-limit/status?scope=identity&value=user@example.com&action=send_email"

# Check IP limit
curl "http://localhost:3301/rate-limit/status?scope=ip&value=192.168.1.1&action=send_email"

# Check user agent limit
curl "http://localhost:3301/rate-limit/status?scope=useragent&value=curl/7.88.1&action=search_emails"
```

### Reset Rate Limit (Demo/Testing Only)

Reset rate limit for a specific scope, value, and action. Only available when `ENABLE_DEMO_ROUTES=true`:

```bash
POST /rate-limit/reset
Content-Type: application/json

{
  "scope": "identity",
  "value": "user@example.com",
  "action": "send_email"
}
```

Response:
```json
{
  "success": true,
  "message": "Rate limit reset for identity:user@example.com:send_email"
}
```

**Examples:**

```bash
# Reset identity limit
curl -X POST http://localhost:3301/rate-limit/reset \
  -H "Content-Type: application/json" \
  -d '{"scope":"identity","value":"user@example.com","action":"send_email"}'

# Reset IP limit
curl -X POST http://localhost:3301/rate-limit/reset \
  -H "Content-Type: application/json" \
  -d '{"scope":"ip","value":"192.168.1.1","action":"send_email"}'
```

## Testing

### Automated Test Script

Use the provided `test-rate-limit.js` script to automate rate limit testing:

```bash
cd gmail-mcp-http
node test-rate-limit.js
```

#### Script Parameters

Configure the test using environment variables:

```bash
# Basic usage (with defaults)
node test-rate-limit.js

# Custom parameters
BASE_URL=http://localhost:3301        # Server URL (default: http://localhost:3301)
TEST_SCOPE=identity                   # Scope to test: identity, ip, or useragent (default: identity)
TEST_IDENTITY=user@example.com        # Identity value for testing (default: testuser@example.com)
TEST_IP=192.168.1.100                 # IP value for testing (default: 192.168.1.100)
TEST_ACTION=send_email                # Action to test (default: send_email)
NUM_REQUESTS=10                       # Number of requests to make (default: 10)
node test-rate-limit.js
```

#### Test Scenarios

**Test identity-based rate limiting (default):**
```bash
TEST_SCOPE=identity \
TEST_IDENTITY=john@example.com \
TEST_ACTION=send_email \
NUM_REQUESTS=5 \
node test-rate-limit.js
```

**Test IP-based rate limiting:**
```bash
TEST_SCOPE=ip \
TEST_IP=192.168.1.100 \
TEST_ACTION=send_email \
NUM_REQUESTS=15 \
node test-rate-limit.js
```

**Test user-agent rate limiting:**
```bash
TEST_SCOPE=useragent \
TEST_ACTION=search_emails \
NUM_REQUESTS=20 \
node test-rate-limit.js
```

**Test different server:**
```bash
BASE_URL=http://remote-server:3301 \
TEST_SCOPE=identity \
NUM_REQUESTS=5 \
node test-rate-limit.js
```

#### Script Output

The script performs 5 steps:

**Step 1: Check initial rate limit status**
```json
{
  "enabled": true,
  "configured": true,
  "scope": "identity",
  "value": "testuser@example.com",
  "action": "send_email",
  "limit": 3,
  "window": 60,
  "current": 0,
  "remaining": 3,
  "resetIn": null
}
```

**Step 2: Reset rate limit** (clears counters for clean testing)

**Step 3: Make multiple requests** (shows results for each request)
```
Request 1/10
  Status: 200 ✓
  Duration: 45ms
  Rate Limit: 2/3 remaining
  Window: 60s

Request 2/10
  Status: 200 ✓
  Duration: 32ms
  Rate Limit: 1/3 remaining
  Window: 60s

Request 3/10
  Status: 200 ✓
  Duration: 28ms
  Rate Limit: 0/3 remaining
  Window: 60s

Request 4/10
  Status: 429 ✗
  Duration: 15ms
  Error: Rate limit exceeded
  Reason: rate_limit_exceeded_identity
  Reset in: 55s
```

**Step 4: Summary**
```
Total Requests: 10
Successful: 3
Rate Limited (429): 7
Other Errors: 0
```

**Step 5: Check final rate limit status**

### Manual Testing

If you prefer manual testing with curl:

1. Configure a low limit for testing:
```bash
RATE_LIMIT_IDENTITY_SEND_EMAIL=3:60
RATE_LIMIT_IP_SEND_EMAIL=10:60
```

2. Make multiple requests from the same user:
```bash
# Request 1-3 (should succeed - within identity limit)
for i in {1..3}; do
  curl -X POST http://localhost:3301/call-tool \
    -H "Content-Type: application/json" \
    -H "x-authenticated-user: testuser@example.com" \
    -H "x-user-ip: 192.168.1.100" \
    -d '{"name":"send_email","arguments":{"to":"user@example.com","subject":"Test '$i'","body":"Test"}}'
  echo ""
done

# Request 4 (should fail - exceeds identity limit)
curl -v -X POST http://localhost:3301/call-tool \
  -H "Content-Type: application/json" \
  -H "x-authenticated-user: testuser@example.com" \
  -H "x-user-ip: 192.168.1.100" \
  -d '{"name":"send_email","arguments":{"to":"user@example.com","subject":"Test 4","body":"Test"}}'
```

3. Test IP-based rate limiting:
```bash
# Requests from 4 different users, same IP (should eventually hit IP limit)
for i in {1..11}; do
  curl -X POST http://localhost:3301/call-tool \
    -H "Content-Type: application/json" \
    -H "x-authenticated-user: user$i@example.com" \
    -H "x-user-ip: 192.168.1.200" \
    -d '{"name":"send_email","arguments":{"to":"recipient@example.com","subject":"Test","body":"Test"}}'
  echo ""
done
# 11th request should fail due to IP limit (10 per minute)
```

4. Check rate limit status for different scopes:
```bash
# Check identity limit
curl "http://localhost:3301/rate-limit/status?scope=identity&value=testuser@example.com&action=send_email"

# Check IP limit
curl "http://localhost:3301/rate-limit/status?scope=ip&value=192.168.1.100&action=send_email"
```

5. Reset limits (if needed):
```bash
# Reset identity limit
curl -X POST http://localhost:3301/rate-limit/reset \
  -H "Content-Type: application/json" \
  -d '{"scope":"identity","value":"testuser@example.com","action":"send_email"}'

# Reset IP limit
curl -X POST http://localhost:3301/rate-limit/reset \
  -H "Content-Type: application/json" \
  -d '{"scope":"ip","value":"192.168.1.100","action":"send_email"}'
```

## Production Considerations

### Redis Configuration

For production, consider:

1. **Persistence**: Enable Redis persistence (RDB or AOF)
2. **High Availability**: Use Redis Sentinel or Cluster
3. **Security**: 
   - Set `REDIS_PASSWORD`
   - Use TLS for Redis connections
   - Restrict Redis network access
4. **Monitoring**: Monitor Redis memory usage and performance

### Rate Limit Design

1. **Choose appropriate limits**: Balance security and user experience
2. **Per-action limits**: Different actions have different risk profiles
3. **Graduated response**: Consider warning users before hard limits
4. **Business logic**: Align limits with business requirements

### Fail-Open Behavior

The rate limiter fails open (allows requests) when:
- Redis is unavailable
- Redis connection fails
- Rate limiter encounters an error

This ensures service availability but monitor Redis health carefully.

### Disable Demo Routes

In production, disable demo/admin routes:
```bash
ENABLE_DEMO_ROUTES=false
```

This removes the `/rate-limit/reset` endpoint and other testing utilities.

## Monitoring

### Check Redis Status

```bash
redis-cli ping
# Should return: PONG

redis-cli info stats
# Shows Redis statistics
```

### View Rate Limit Keys

```bash
# List all rate limit keys
redis-cli --scan --pattern "ratelimit:*"

# List keys for specific scope
redis-cli --scan --pattern "ratelimit:identity:*"
redis-cli --scan --pattern "ratelimit:ip:*"

# Get current count for a specific key
redis-cli get "ratelimit:identity:user@example.com:send_email"
redis-cli get "ratelimit:ip:192.168.1.1:send_email"

# Show remaining TTL in seconds
redis-cli ttl "ratelimit:identity:user@example.com:send_email"

# View all keys with values and TTL
redis-cli --scan --pattern "ratelimit:*" | while read key; do
  value=$(redis-cli get "$key")
  ttl=$(redis-cli ttl "$key")
  echo "$key: $value (TTL: ${ttl}s)"
done
```

### Debug Logging

Enable debug logging to see rate limit operations:
```bash
DEBUG=true
```

Logs will show:
- Rate limit checks
- Redis connection status
- Current counts and limits
- Rate limit violations

## Troubleshooting

### Rate limiting not working

1. Check Redis is running:
```bash
redis-cli ping
```

2. Check environment variable:
```bash
echo $RATE_LIMIT_ENABLED
```

3. Check Redis connection in server logs

4. Verify `.env` file is loaded

### Rate limits too strict/loose

Adjust limits in `.env` file and restart server:
```bash
RATE_LIMIT_SEND_EMAIL=10:60  # Increase to 10 per minute
```

### Redis connection errors

1. Verify Redis is running
2. Check `REDIS_HOST` and `REDIS_PORT`
3. If using password, verify `REDIS_PASSWORD`
4. Check network connectivity
5. Review Redis logs

### Keys not expiring

Redis TTL should auto-expire keys. Verify:
```bash
redis-cli ttl "ratelimit:user@example.com:send_email"
# Should return positive number (seconds) or -2 (expired)
```

If TTL is -1, keys won't expire. This shouldn't happen with this implementation.

## Future Enhancements

Potential improvements:

1. **Sliding window**: More accurate rate limiting
2. **Distributed rate limiting**: Redis Cluster support
3. **Rate limit tiers**: Different limits for different user roles
4. **Custom strategies**: Leaky bucket, token bucket algorithms
5. **Analytics**: Track rate limit violations
6. **Dynamic limits**: Adjust limits based on load or user behavior
7. **Multi-action limits**: Composite limits across multiple actions
8. **Burst allowance**: Allow short bursts above the limit
