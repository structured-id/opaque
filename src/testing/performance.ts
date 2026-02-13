/**
 * Performance testing utilities for end-to-end benchmarking.
 *
 * Measures:
 * - Client time: JavaScript computation time (WASM execution, policy validation)
 * - Network time: HTTP round-trip time (RTT)
 * - Server time: Backend processing time (returned in response headers)
 */

export interface CipherSuiteInfo {
  id: string;
  name: string;
  category: 'standard' | 'proprietary';
}

export interface OperationTiming {
  operation: string;
  clientTime: number; // ms - browser computation
  networkTime: number; // ms - request RTT
  serverTime: number; // ms - backend processing
  totalTime: number; // ms - total
}

export interface TestResult {
  timestamp: Date;
  suites: CipherSuiteInfo[];
  operations: OperationTiming[];
  summary: {
    avgClientTime: number;
    avgNetworkTime: number;
    avgServerTime: number;
  };
}

/**
 * Cipher suite definitions for performance testing
 */
export const TEST_SUITES: CipherSuiteInfo[] = [
  { id: 'ristretto255_sha512', name: 'Ristretto255-SHA512', category: 'standard' },
  { id: 'p256_sha256', name: 'P-256-SHA256', category: 'standard' },
  { id: 'p384_sha384', name: 'P-384-SHA384', category: 'standard' },
  { id: 'p521_sha512', name: 'P-521-SHA512', category: 'standard' },
  { id: 'proprietary_policy', name: 'Proprietary Policy Validation', category: 'proprietary' },
];

/**
 * Run full end-to-end performance test suite
 */
export async function runPerformanceTests(serverUrl: string = '/test'): Promise<TestResult> {
  const operations: OperationTiming[] = [];
  const startTime = performance.now();

  try {
    // Test 1: Policy validation (client-side)
    operations.push(await testPolicyValidation());

    // Test 2: Registration flow
    operations.push(await testRegistration(serverUrl));

    // Test 3: Password verification
    operations.push(await testPasswordVerification(serverUrl));

    // Test 4: Key derivation for each suite
    for (const suite of TEST_SUITES.filter((s) => s.category === 'standard')) {
      operations.push(await testKeyDerivation(suite, serverUrl));
    }
  } catch (error) {
    console.error('[perf-test] Error during performance testing:', error);
    throw error;
  }

  // Calculate summary
  const summary = {
    avgClientTime: operations.reduce((sum, op) => sum + op.clientTime, 0) / operations.length,
    avgNetworkTime: operations.reduce((sum, op) => sum + op.networkTime, 0) / operations.length,
    avgServerTime: operations.reduce((sum, op) => sum + op.serverTime, 0) / operations.length,
  };

  return {
    timestamp: new Date(),
    suites: TEST_SUITES,
    operations,
    summary,
  };
}

/**
 * Test policy validation (client-side only)
 */
async function testPolicyValidation(): Promise<OperationTiming> {
  const clientStart = performance.now();

  // Simulate password policy validation
  const passwords = ['Test@123456', 'Valid.Pass99', 'Complex!Pwd000'];
  for (const pwd of passwords) {
    // Validate length
    pwd.length >= 8;
    // Check character classes
    /[A-Z]/.test(pwd);
    /[a-z]/.test(pwd);
    /\d/.test(pwd);
  }

  const clientTime = performance.now() - clientStart;

  return {
    operation: 'Policy Validation (Client)',
    clientTime,
    networkTime: 0,
    serverTime: 0,
    totalTime: clientTime,
  };
}

/**
 * Test user registration
 */
async function testRegistration(serverUrl: string): Promise<OperationTiming> {
  const clientStart = performance.now();

  try {
    const networkStart = performance.now();

    const response = await fetch(`${serverUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: `test_${Date.now()}`,
        password: 'Test@123456',
      }),
    });

    const networkTime = performance.now() - networkStart;
    const data = await response.json();
    const serverTime = data.serverTime || 0;
    const clientTime = performance.now() - clientStart - networkTime;

    return {
      operation: 'Registration',
      clientTime,
      networkTime,
      serverTime,
      totalTime: performance.now() - clientStart,
    };
  } catch (error) {
    console.warn('[perf-test] Registration test failed:', error);
    return {
      operation: 'Registration',
      clientTime: 0,
      networkTime: 0,
      serverTime: 0,
      totalTime: 0,
    };
  }
}

/**
 * Test password verification
 */
async function testPasswordVerification(serverUrl: string): Promise<OperationTiming> {
  const clientStart = performance.now();

  try {
    const networkStart = performance.now();

    const response = await fetch(`${serverUrl}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'test_user',
        password: 'Test@123456',
      }),
    });

    const networkTime = performance.now() - networkStart;
    const data = await response.json();
    const serverTime = data.serverTime || 0;
    const clientTime = performance.now() - clientStart - networkTime;

    return {
      operation: 'Password Verification',
      clientTime,
      networkTime,
      serverTime,
      totalTime: performance.now() - clientStart,
    };
  } catch (error) {
    console.warn('[perf-test] Verification test failed:', error);
    return {
      operation: 'Password Verification',
      clientTime: 0,
      networkTime: 0,
      serverTime: 0,
      totalTime: 0,
    };
  }
}

/**
 * Test key derivation for a specific cipher suite
 */
async function testKeyDerivation(
  suite: CipherSuiteInfo,
  serverUrl: string,
): Promise<OperationTiming> {
  const clientStart = performance.now();

  try {
    const networkStart = performance.now();

    const response = await fetch(`${serverUrl}/derive-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        suite: suite.id,
        password: 'Test@123456',
      }),
    });

    const networkTime = performance.now() - networkStart;
    const data = await response.json();
    const serverTime = data.serverTime || 0;
    const clientTime = performance.now() - clientStart - networkTime;

    return {
      operation: `Key Derivation (${suite.name})`,
      clientTime,
      networkTime,
      serverTime,
      totalTime: performance.now() - clientStart,
    };
  } catch (error) {
    console.warn(`[perf-test] Key derivation test for ${suite.id} failed:`, error);
    return {
      operation: `Key Derivation (${suite.name})`,
      clientTime: 0,
      networkTime: 0,
      serverTime: 0,
      totalTime: 0,
    };
  }
}

/**
 * Format timing results for display
 */
export function formatTimingResults(result: TestResult): string {
  let output = '\n╔════════════════════════════════════════════════════════════╗\n';
  output += '║         OPAQUE End-to-End Performance Test Results          ║\n';
  output += '╚════════════════════════════════════════════════════════════╝\n\n';

  // Cipher suites
  output += '📊 Supported Cipher Suites:\n';
  result.suites.forEach((suite) => {
    const category = suite.category === 'proprietary' ? '🔐 Proprietary' : '📐 Standard (RFC 9807)';
    output += `   ${category}: ${suite.name}\n`;
  });

  output += '\n⏱️  Operation Timings:\n';
  output += '┌────────────────────────────┬──────────┬──────────┬──────────┬──────────┐\n';
  output += '│ Operation                  │ Client   │ Network  │ Server   │ Total    │\n';
  output += '├────────────────────────────┼──────────┼──────────┼──────────┼──────────┤\n';

  result.operations.forEach((op) => {
    const opName = op.operation.padEnd(26);
    const client = `${op.clientTime.toFixed(2)}ms`.padStart(8);
    const network = `${op.networkTime.toFixed(2)}ms`.padStart(8);
    const server = `${op.serverTime.toFixed(2)}ms`.padStart(8);
    const total = `${op.totalTime.toFixed(2)}ms`.padStart(8);

    output += `│ ${opName} │ ${client} │ ${network} │ ${server} │ ${total} │\n`;
  });

  output += '└────────────────────────────┴──────────┴──────────┴──────────┴──────────┘\n';

  output += '\n📈 Summary:\n';
  output += `   Average Client Time:  ${result.summary.avgClientTime.toFixed(2)}ms (browser computation)\n`;
  output += `   Average Network Time: ${result.summary.avgNetworkTime.toFixed(2)}ms (HTTP RTT)\n`;
  output += `   Average Server Time:  ${result.summary.avgServerTime.toFixed(2)}ms (backend processing)\n`;

  output += `\n⏰ Test completed at: ${result.timestamp.toLocaleTimeString()}\n`;

  return output;
}
