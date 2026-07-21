/**
 * Background service worker — context-menu autofill and background OTP generation.
 */

// Import shared modules to remove duplicate codes
importScripts('lib/totp.js', 'lib/crypto.js', 'lib/storage.js');

const SETTINGS_KEY = 'authenticator_settings';

// --- Context Menu (created / removed dynamically based on setting) ---

async function ensureContextMenu() {
  const { [SETTINGS_KEY]: settings = {} } = await chrome.storage.local.get(SETTINGS_KEY);
  const enabled = settings.autoFill !== false; // default true
  // Remove first to avoid duplicate-ID errors
  try { await chrome.contextMenus.remove('autofill-2fa'); } catch { /* not present */ }
  if (enabled) {
    chrome.contextMenus.create({
      id: 'autofill-2fa',
      title: 'Autofill 2FA Code',
      contexts: ['editable'],
    });
  }
}

chrome.runtime.onInstalled.addListener(() => ensureContextMenu());
chrome.runtime.onStartup.addListener(() => ensureContextMenu());

// Listen for setting changes so the menu appears/disappears immediately
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes[SETTINGS_KEY]) ensureContextMenu();
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'autofill-2fa') return;
  if (!tab?.id) return;

  // Immediately mark the active element before async/popup operations lose focus
  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        window.__authenticatorTarget = document.activeElement;
      }
    });
  } catch (e) {
    // ignore — might fail on restricted pages
  }

  try {
    // Restore session key inside crypto.js module
    await tryRestoreSession();

    // Get accounts (automatically decrypted if session key is active)
    const accounts = await getDecryptedAccounts();
    if (accounts.length === 0) return;

    // For each account, generate the code
    const codes = [];
    for (const account of accounts) {
      if (!account.secret) continue; // can't decrypt or missing

      try {
        const { code } = await generateTOTP(account.secret, account);
        codes.push({
          issuer: account.issuer,
          label: account.label,
          code,
          id: account.id,
          websites: account.websites || [],
        });
      } catch {
        // skip invalid accounts
      }
    }

    if (codes.length === 0) return;

    // --- Domain matching ---
    let tabHostname = '';
    try {
      tabHostname = new URL(tab.url).hostname.toLowerCase();
    } catch { /* ignore */ }

    const matched = tabHostname
      ? codes.filter(entry =>
          entry.websites.some(domain => {
            const d = domain.toLowerCase();
            return tabHostname === d || tabHostname.endsWith('.' + d);
          })
        )
      : [];

    // If exactly one domain-matched account, autofill directly + submit
    if (matched.length === 1) {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: fillCodeAndSubmit,
        args: [matched[0].code],
      });
      return;
    }

    // If multiple matched, show only those in the picker
    // If no matched, show all accounts
    const pickerCodes = matched.length > 0 ? matched : codes;
    await chrome.storage.session.set({
      autofill_codes: pickerCodes,
      autofill_tabId: tab.id,
    });
    chrome.action.openPopup();
  } catch (err) {
    console.error('Autofill error:', err);
  }
});

/**
 * Fills the focused/active input element with the given code and submits the form.
 * Uses native value setters for React/Vue/Angular compatibility.
 * Runs in the page context via executeScript.
 */
function fillCodeAndSubmit(code) {
  const el = window.__authenticatorTarget || document.activeElement;
  if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
    // Use native property setters for React/Vue/Angular compatibility
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    )?.set;
    const nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLTextAreaElement.prototype, 'value'
    )?.set;

    if (el.tagName === 'INPUT' && nativeInputValueSetter) {
      nativeInputValueSetter.call(el, code);
    } else if (el.tagName === 'TEXTAREA' && nativeTextAreaValueSetter) {
      nativeTextAreaValueSetter.call(el, code);
    } else {
      el.value = code;
    }

    // Fire events that frameworks listen to
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));

    // Auto-submit: try submitting the parent form or pressing Enter
    el.focus();
    setTimeout(() => {
      // Try to find and click a submit button in the form
      const form = el.closest('form');
      if (form) {
        const submitBtn = form.querySelector(
          'button[type="submit"], input[type="submit"], button:not([type])'
        );
        if (submitBtn) {
          submitBtn.click();
          return;
        }
        // If no submit button, trigger form submit
        form.requestSubmit ? form.requestSubmit() : form.submit();
        return;
      }
      // No form found — simulate Enter key press
      el.dispatchEvent(new KeyboardEvent('keydown', {
        key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true
      }));
      el.dispatchEvent(new KeyboardEvent('keypress', {
        key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true
      }));
      el.dispatchEvent(new KeyboardEvent('keyup', {
        key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true
      }));
    }, 100);
  }

  if (window.__authenticatorTarget) {
    delete window.__authenticatorTarget;
  }
}

