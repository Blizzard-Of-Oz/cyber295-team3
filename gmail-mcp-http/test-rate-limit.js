#!/usr/bin/env node

/**
 * Rate Limiting Test Script
 * 
 * This script tests the rate limiting functionality by making multiple requests
 * to the /call-tool endpoint and observing the rate limit enforcement.
 */

const BASE_URL = process.env.BASE_URL || "http://localhost:3301";
const TEST_IDENTITY = process.env.TEST_IDENTITY || "testuser@example.com";
const TEST_IP = process.env.TEST_IP || "192.168.1.100";
const TEST_SCOPE = process.env.TEST_SCOPE || "identity"; // "identity", "ip", or "useragent"
const TEST_ACTION = process.env.TEST_ACTION || "send_email";
const NUM_REQUESTS = process.env.NUM_REQUESTS || 10;

// Get the value for the scope
const getScopeValue = () => {
  switch (TEST_SCOPE.toLowerCase()) {
    case "ip":
      return TEST_IP;
    case "useragent":
      return "curl/7.88.1";
    case "identity":
    default:
      return TEST_IDENTITY;
  }
};

const TEST_VALUE = getScopeValue();

console.log("Rate Limiting Test Script");
console.log("=========================");
console.log(`Base URL: ${BASE_URL}`);
console.log(`Test Scope: ${TEST_SCOPE}`);
console.log(`Test Value: ${TEST_VALUE}`);
console.log(`Test Action: ${TEST_ACTION}`);
console.log(`Number of Requests: ${NUM_REQUESTS}\n`);

async function checkRateLimitStatus() {
  const url = `${BASE_URL}/rate-limit/status?scope=${encodeURIComponent(TEST_SCOPE)}&value=${encodeURIComponent(TEST_VALUE)}&action=${encodeURIComponent(TEST_ACTION)}`;
  const response = await fetch(url);
  const data = await response.json();
  return data;
}

async function resetRateLimit() {
  const url = `${BASE_URL}/rate-limit/reset`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      scope: TEST_SCOPE,
      value: TEST_VALUE,
      action: TEST_ACTION
    })
  });
  return response.json();
}

async function makeToolRequest(requestNum) {
  const url = `${BASE_URL}/call-tool`;
  const body = {
    name: TEST_ACTION,
    arguments: {
      to: "recipient@example.com",
      subject: `Test email ${requestNum}`,
      body: `This is test email number ${requestNum}`
    }
  };

  const headers = {
    "Content-Type": "application/json",
    "x-authenticated-user": TEST_IDENTITY
  };

  // Add scope-specific headers
  if (TEST_SCOPE.toLowerCase() === "ip") {
    headers["x-user-ip"] = TEST_IP;
  } else if (TEST_SCOPE.toLowerCase() === "useragent") {
    headers["user-agent"] = "curl/7.88.1";
  }

  const startTime = Date.now();
  const response = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body)
  });

  const duration = Date.now() - startTime;
  const rateLimitHeaders = {
    limit: response.headers.get("x-ratelimit-limit"),
    remaining: response.headers.get("x-ratelimit-remaining"),
    window: response.headers.get("x-ratelimit-window"),
    reset: response.headers.get("x-ratelimit-reset")
  };

  let responseData;
  try {
    responseData = await response.json();
  } catch (error) {
    responseData = { error: "Failed to parse response" };
  }

  return {
    requestNum,
    status: response.status,
    duration,
    rateLimitHeaders,
    success: response.ok,
    error: responseData.error || null,
    reason: responseData.reason || null,
    message: responseData.message || null
  };
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTest() {
  console.log("Step 1: Check initial rate limit status");
  console.log("-----------------------------------------");
  try {
    const initialStatus = await checkRateLimitStatus();
    console.log(JSON.stringify(initialStatus, null, 2));
    console.log("");
  } catch (error) {
    console.error("Failed to check status:", error.message);
  }

  console.log("Step 2: Reset rate limit (if available)");
  console.log("-----------------------------------------");
  try {
    const resetResult = await resetRateLimit();
    console.log(JSON.stringify(resetResult, null, 2));
    console.log("");
  } catch (error) {
    console.log("Reset endpoint not available (ENABLE_DEMO_ROUTES=false or error):", error.message);
    console.log("");
  }

  console.log("Step 3: Make multiple requests");
  console.log("-------------------------------");
  const results = [];

  for (let i = 1; i <= NUM_REQUESTS; i++) {
    console.log(`\nRequest ${i}/${NUM_REQUESTS}`);
    const result = await makeToolRequest(i);
    results.push(result);

    console.log(`  Status: ${result.status} ${result.success ? "✓" : "✗"}`);
    console.log(`  Duration: ${result.duration}ms`);
    
    if (result.rateLimitHeaders.limit) {
      console.log(`  Rate Limit: ${result.rateLimitHeaders.remaining}/${result.rateLimitHeaders.limit} remaining`);
      console.log(`  Window: ${result.rateLimitHeaders.window}s`);
      if (result.rateLimitHeaders.reset) {
        console.log(`  Reset in: ${result.rateLimitHeaders.reset}s`);
      }
    }

    if (!result.success) {
      console.log(`  Error: ${result.error}`);
      if (result.reason) {
        console.log(`  Reason: ${result.reason}`);
      }
      if (result.message) {
        console.log(`  Message: ${result.message}`);
      }
    }

    // Small delay between requests
    if (i < NUM_REQUESTS) {
      await sleep(100);
    }
  }

  console.log("\n\nStep 4: Summary");
  console.log("===============");
  const successful = results.filter(r => r.success).length;
  const rateLimited = results.filter(r => r.status === 429).length;
  const errors = results.filter(r => !r.success && r.status !== 429).length;

  console.log(`Total Requests: ${NUM_REQUESTS}`);
  console.log(`Successful: ${successful}`);
  console.log(`Rate Limited (429): ${rateLimited}`);
  console.log(`Other Errors: ${errors}`);

  if (rateLimited > 0) {
    const firstRateLimited = results.find(r => r.status === 429);
    console.log(`\nFirst rate limited at request: ${firstRateLimited.requestNum}`);
    console.log(`Rate limit: ${firstRateLimited.rateLimitHeaders.limit} requests/${firstRateLimited.rateLimitHeaders.window}s`);
  }

  console.log("\n\nStep 5: Check final rate limit status");
  console.log("---------------------------------------");
  try {
    const finalStatus = await checkRateLimitStatus();
    console.log(JSON.stringify(finalStatus, null, 2));
  } catch (error) {
    console.error("Failed to check status:", error.message);
  }
}

// Run the test
runTest().catch(error => {
  console.error("\nTest failed with error:");
  console.error(error);
  process.exit(1);
});
