/**
 * Hidden debug footer for performance testing.
 *
 * Activated by: 5 rapid Ctrl+Click events (within 1 second)
 * Shows: Performance test dashboard with timing breakdowns
 */

import { runPerformanceTests, formatTimingResults } from './performance.js';

let clickCount = 0;
let lastClickTime = 0;
let footerElement: HTMLDivElement | null = null;
let isFooterVisible = false;

/**
 * Initialize debug footer (call once at app startup)
 */
export function initDebugFooter(): void {
  if (typeof document === 'undefined') {
    // Server-side environment
    return;
  }

  // Listen for Ctrl+Click
  document.addEventListener('click', handleClickEvent, { capture: true });

  // Create footer HTML (hidden initially)
  createFooterElement();

  console.debug('[debug-footer] Initialized. Trigger with: Ctrl+Click (5x rapid)');
}

/**
 * Handle click events to detect the activation pattern
 */
function handleClickEvent(event: MouseEvent): void {
  // Check if Ctrl (or Cmd on Mac) is held
  const isCtrlHeld = event.ctrlKey || event.metaKey;

  if (!isCtrlHeld) {
    clickCount = 0;
    lastClickTime = 0;
    return;
  }

  const now = performance.now();

  // Reset counter if more than 1 second has passed
  if (now - lastClickTime > 1000) {
    clickCount = 1;
  } else {
    clickCount++;
  }

  lastClickTime = now;

  // Check if we've reached 5 clicks within 1 second
  if (clickCount === 5) {
    toggleFooter();
    clickCount = 0;
    lastClickTime = 0;
  }
}

/**
 * Create the footer DOM element
 */
function createFooterElement(): void {
  if (footerElement) return;

  footerElement = document.createElement('div');
  footerElement.id = 'opaque-debug-footer';
  footerElement.innerHTML = `
    <style>
      #opaque-debug-footer {
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        background: #1a1a1a;
        color: #00ff00;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        max-height: 70vh;
        overflow-y: auto;
        border-top: 2px solid #00ff00;
        padding: 12px;
        z-index: 999999;
        display: none;
        box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.5);
      }

      #opaque-debug-footer.visible {
        display: block;
      }

      #opaque-debug-footer button {
        background: #00ff00;
        color: #000;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
        cursor: pointer;
        font-family: 'Courier New', monospace;
        font-weight: bold;
        margin-bottom: 16px;
      }

      #opaque-debug-footer button:hover {
        background: #00dd00;
      }

      #opaque-debug-footer button:active {
        transform: scale(0.98);
      }

      #opaque-debug-footer .loading {
        color: #ffaa00;
        margin-top: 8px;
      }

      #opaque-debug-footer .error {
        color: #ff5555;
        margin-top: 8px;
      }

      #opaque-debug-footer .results {
        white-space: pre-wrap;
        word-break: break-word;
        margin-top: 12px;
        padding: 12px;
        background: #0a0a0a;
        border: 1px solid #00ff00;
        border-radius: 4px;
      }

      #opaque-debug-footer .close-btn {
        position: absolute;
        top: 8px;
        right: 12px;
        background: #ff5555;
        color: #fff;
        border: none;
        padding: 4px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-weight: bold;
      }

      #opaque-debug-footer .close-btn:hover {
        background: #ff3333;
      }
    </style>

    <button class="close-btn" onclick="document.getElementById('opaque-debug-footer').classList.remove('visible')">✕</button>

    <div style="margin-top: 20px;">
      <h3 style="margin: 0 0 12px 0; color: #ffaa00;">⚙️ OPAQUE Performance Testing Dashboard</h3>

      <button onclick="document.querySelector('#opaque-debug-footer').runTests()">
        ▶️ Run Performance Tests
      </button>

      <div id="status-message" style="display: none;"></div>
      <div id="test-results"></div>
    </div>
  `;

  document.body.appendChild(footerElement);

  // Bind runTests method
  (footerElement as any).runTests = runPerformanceTests;
}

/**
 * Toggle footer visibility
 */
function toggleFooter(): void {
  if (!footerElement) return;

  isFooterVisible = !isFooterVisible;

  if (isFooterVisible) {
    footerElement.classList.add('visible');
    console.info('[debug-footer] Opened. Click "Run Performance Tests" to start benchmarking.');
  } else {
    footerElement.classList.remove('visible');
    console.info('[debug-footer] Closed.');
  }
}

/**
 * Extended footer element with test runner capability
 */
declare global {
  interface HTMLDivElement {
    runTests?: () => Promise<void>;
  }
}

// Override runTests to be actual test runner
Object.defineProperty(HTMLDivElement.prototype, 'runTests', {
  value: async function () {
    if (this.id !== 'opaque-debug-footer') return;

    const statusEl = document.getElementById('status-message');
    const resultsEl = document.getElementById('test-results');

    if (!statusEl || !resultsEl) return;

    try {
      statusEl.style.display = 'block';
      statusEl.className = 'loading';
      statusEl.textContent = '⏳ Running performance tests... (this may take a few seconds)';
      resultsEl.innerHTML = '';

      const result = await runPerformanceTests();

      statusEl.style.display = 'none';
      resultsEl.className = 'results';
      resultsEl.textContent = formatTimingResults(result);

      console.info('[debug-footer] Tests completed', result);
    } catch (error) {
      statusEl.style.display = 'block';
      statusEl.className = 'error';
      statusEl.textContent = `❌ Test failed: ${error instanceof Error ? error.message : String(error)}`;

      console.error('[debug-footer] Test error:', error);
    }
  },
  writable: true,
  configurable: true,
});

/**
 * Programmatic control: show/hide footer
 */
export function showDebugFooter(): void {
  if (!footerElement) createFooterElement();
  if (!isFooterVisible) toggleFooter();
}

export function hideDebugFooter(): void {
  if (isFooterVisible) toggleFooter();
}
