/**
 * Content script — detects OTP / 2FA input fields and auto-fills matching codes.
 *
 * Detection strategy (in priority order):
 *  1. input[autocomplete="one-time-code"]  — the web standard
 *  2. Inputs with names/ids/aria-labels that match common 2FA patterns
 *  3. Single short (<= 8 digit) numeric input following a text like "code", "OTP", etc.
 *
 * Security:
 *  • Runs only when the autofill setting is enabled (checked via background).
 *  • Only fills plaintext (unencrypted) accounts — encrypted secrets
 *    require the master password in the popup.
 *  • Never reads the code directly — asks the background service worker,
 *    which generates it.
 *  • A small visual banner lets the user confirm or dismiss.
 */

(() => {
  // Avoid running in iframes to prevent duplicate banners
  if (window !== window.top) return;

  // Debounce: only run once per page load
  let hasRun = false;

  const OTP_FIELD_PATTERNS = [
    /otp/i, /one.?time/i, /two.?factor/i, /2fa/i, /totp/i, /hotp/i,
    /verif(y|ication).?code/i, /security.?code/i, /auth(entication|enticator)?.?code/i,
    /mfa/i, /token/i, /passcode/i, /pin.?code/i,
  ];

  /**
   * Find candidate OTP input elements in the DOM.
   */
  function findOtpInputs() {
    const candidates = [];

    // 1. Standard autocomplete="one-time-code"
    document.querySelectorAll('input[autocomplete="one-time-code"]').forEach((el) => {
      if (isVisible(el)) candidates.push(el);
    });
    if (candidates.length) return candidates;

    // 2. Name / id / placeholder / aria-label pattern matching on text/number/tel inputs
    const inputs = document.querySelectorAll(
      'input[type="text"], input[type="number"], input[type="tel"], input:not([type])'
    );
    for (const el of inputs) {
      if (!isVisible(el)) continue;
      const haystack = [
        el.name, el.id, el.placeholder,
        el.getAttribute('aria-label'), el.getAttribute('aria-placeholder'),
      ].filter(Boolean).join(' ');

      if (OTP_FIELD_PATTERNS.some((re) => re.test(haystack))) {
        // Extra guard: OTP fields are short (4-8 digits)
        const max = parseInt(el.maxLength, 10);
        if (!max || (max >= 4 && max <= 8)) {
          candidates.push(el);
        }
      }
    }

    return candidates;
  }

  function isVisible(el) {
    if (!el.offsetParent && getComputedStyle(el).position !== 'fixed') return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }

  /**
   * Show a non-intrusive confirmation banner with the autofill option.
   */
  function showBanner(code, issuer, inputEl) {
    // Remove any previous banner
    const prev = document.getElementById('auth-ext-autofill-banner');
    if (prev) prev.remove();

    const banner = document.createElement('div');
    banner.id = 'auth-ext-autofill-banner';
    Object.assign(banner.style, {
      position: 'fixed',
      bottom: '20px',
      right: '20px',
      zIndex: '2147483647',
      background: '#1a1a2e',
      color: '#e0e0e0',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: '14px',
      padding: '14px 18px',
      borderRadius: '12px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      maxWidth: '360px',
      animation: 'auth-ext-slide-in 0.25s ease',
    });

    // Add animation keyframes
    if (!document.getElementById('auth-ext-style')) {
      const style = document.createElement('style');
      style.id = 'auth-ext-style';
      style.textContent = `
        @keyframes auth-ext-slide-in {
          from { transform: translateY(20px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
      `;
      document.head.appendChild(style);
    }

    const maskedCode = code.slice(0, 3) + '***';

    banner.innerHTML = `
      <div style="flex:1;min-width:0">
        <div style="font-weight:600;margin-bottom:4px">🔐 Authenticator</div>
        <div style="font-size:12px;opacity:0.8">Fill <strong>${escapeHtml(issuer)}</strong> code (${maskedCode})?</div>
      </div>
      <button id="auth-ext-fill-btn" style="
        background:#4f8cff; color:#fff; border:none; padding:8px 16px;
        border-radius:8px; cursor:pointer; font-size:13px; font-weight:600;
        white-space:nowrap;
      ">Fill</button>
      <button id="auth-ext-dismiss-btn" style="
        background:transparent; color:#888; border:none; cursor:pointer;
        font-size:18px; padding:4px 6px; line-height:1;
      ">&times;</button>
    `;

    document.body.appendChild(banner);

    document.getElementById('auth-ext-fill-btn').addEventListener('click', () => {
      fillInput(inputEl, code);
      banner.remove();
    });

    document.getElementById('auth-ext-dismiss-btn').addEventListener('click', () => {
      banner.remove();
    });

    // Auto-dismiss after 15 seconds
    setTimeout(() => banner.remove(), 15000);
  }

  function fillInput(el, code) {
    el.focus();
    el.value = code;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  /**
   * Main detection + autofill flow.
   */
  async function detect() {
    if (hasRun) return;

    const otpInputs = findOtpInputs();
    if (otpInputs.length === 0) return;

    hasRun = true;

    // Ask background for a matching code for this domain
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'AUTOFILL_REQUEST',
        hostname: location.hostname,
      });

      if (!response || !response.code) return;
      showBanner(response.code, response.issuer, otpInputs[0]);
    } catch {
      // Extension context may be invalidated — ignore
    }
  }

  // Run detection once DOM is ready, with a small delay for SPAs
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(detect, 800);
  } else {
    window.addEventListener('DOMContentLoaded', () => setTimeout(detect, 800));
  }

  // Re-detect on SPA navigation (URL changes without page reload)
  let lastUrl = location.href;
  const observer = new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      hasRun = false;
      setTimeout(detect, 1000);
    }
  });
  observer.observe(document.body || document.documentElement, { childList: true, subtree: true });
})();
