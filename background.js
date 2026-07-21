/**
 * Background service worker — context-menu autofill and background OTP generation.
 */

const SETTINGS_KEY = 'authenticator_settings';

// --- Crypto helpers for decrypting secrets in background context ---
// The background service worker needs to decrypt secrets when a master
// password is active. It reads the session password from chrome.storage.session
// (set by the popup on unlock) and re-derives the CryptoKey.

const BG_CRYPTO_STORAGE_KEY = 'authenticator_crypto';
const BG_PBKDF2_ITERATIONS = 100000;
const BG_SALT_BYTES = 16;
const BG_IV_BYTES = 12;
const BG_VERIFICATION_TOKEN = 'authenticator-verified';
const BG_SESSION_PW_KEY = 'authenticator_session_pw';
const BG_SESSION_TS_KEY = 'authenticator_session_ts';
const BG_SESSION_DURATION = 24 * 60 * 60 * 1000;

function bgBufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function bgBase64ToBuf(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function bgDeriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: BG_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function bgDecryptString(key, { iv, ciphertext }) {
  const dec = new TextDecoder();
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bgBase64ToBuf(iv) },
    key,
    bgBase64ToBuf(ciphertext)
  );
  return dec.decode(plainBuf);
}

/**
 * Try to get the decryption key from the session password.
 * Returns null if no session is active or password is invalid.
 */
async function bgGetSessionKey() {
  const sessionData = await chrome.storage.session.get([BG_SESSION_PW_KEY, BG_SESSION_TS_KEY]);
  const pw = sessionData[BG_SESSION_PW_KEY];
  const ts = sessionData[BG_SESSION_TS_KEY];
  if (!pw || !ts) return null;
  if ((Date.now() - ts) >= BG_SESSION_DURATION) return null;

  const cryptoData = await chrome.storage.local.get(BG_CRYPTO_STORAGE_KEY);
  const cd = cryptoData[BG_CRYPTO_STORAGE_KEY];
  if (!cd || !cd.salt) return null;

  const salt = bgBase64ToBuf(cd.salt);
  const key = await bgDeriveKey(pw, salt);

  // Verify the key is correct
  try {
    const dec = new TextDecoder();
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bgBase64ToBuf(cd.verification.iv) },
      key,
      bgBase64ToBuf(cd.verification.ciphertext)
    );
    if (dec.decode(plainBuf) === BG_VERIFICATION_TOKEN) return key;
    return null;
  } catch {
    return null;
  }
}

/**
 * Decrypt a single account's secret if it is encrypted.
 * Returns the plaintext secret string, or null if decryption fails.
 */
async function bgDecryptSecret(account, decryptionKey) {
  if (typeof account.secret === 'string') return account.secret;
  if (!account.secret || !account.secret.iv || !decryptionKey) return null;
  try {
    return await bgDecryptString(decryptionKey, account.secret);
  } catch {
    return null;
  }
}

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
    // Get accounts and generate codes
    const result = await chrome.storage.local.get('authenticator_accounts');
    const accounts = result.authenticator_accounts || [];
    if (accounts.length === 0) return;

    // Try to get decryption key from session (if master password is active)
    const decryptionKey = await bgGetSessionKey();

    // For each account, generate the code
    const codes = [];
    for (const account of accounts) {
      const secret = await bgDecryptSecret(account, decryptionKey);
      if (!secret) continue; // can't decrypt — skip

      try {
        const code = await generateOTPCode(secret, account);
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

// --- Inline OTP generation for background context ---
// Duplicated minimal TOTP logic here because service workers can't import popup scripts.

const BG_BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function bgBase32Decode(input) {
  const str = input.toUpperCase().replace(/[\s=]/g, '');
  const out = [];
  let buffer = 0, bitsLeft = 0;
  for (const char of str) {
    const val = BG_BASE32.indexOf(char);
    if (val === -1) throw new Error('Invalid Base32');
    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) { bitsLeft -= 8; out.push((buffer >>> bitsLeft) & 0xff); }
  }
  return new Uint8Array(out);
}

function bgIntToBytes(num) {
  const bytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { bytes[i] = num & 0xff; num = Math.floor(num / 256); }
  return bytes;
}

const BG_ALGO_MAP = { 'SHA-1': 'SHA-1', 'SHA-256': 'SHA-256', 'SHA-512': 'SHA-512', 'SHA1': 'SHA-1', 'SHA256': 'SHA-256', 'SHA512': 'SHA-512' };

async function generateOTPCode(secret, account) {
  const key = bgBase32Decode(secret);
  const algo = BG_ALGO_MAP[account.algorithm] || 'SHA-1';
  const digits = account.digits || 6;
  const period = account.period || 30;
  const type = account.type || 'totp';

  let counter;
  if (type === 'hotp') {
    counter = account.counter || 0;
  } else {
    counter = Math.floor(Math.floor(Date.now() / 1000) / period);
  }

  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: algo }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, bgIntToBytes(counter)));
  const offset = sig[sig.length - 1] & 0x0f;
  const truncated = ((sig[offset] & 0x7f) << 24) | ((sig[offset+1] & 0xff) << 16) | ((sig[offset+2] & 0xff) << 8) | (sig[offset+3] & 0xff);
  return (truncated % Math.pow(10, digits)).toString().padStart(digits, '0');
}

