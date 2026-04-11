/**
 * Background service worker — context menu autofill, domain autofill, and keyboard shortcut support.
 */

const SETTINGS_KEY = 'authenticator_settings';

// --- Context Menu ---

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'autofill-2fa',
    title: 'Autofill 2FA Code',
    contexts: ['editable'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'autofill-2fa') return;
  if (!tab?.id) return;

  try {
    // Get accounts and generate codes
    const result = await chrome.storage.local.get('authenticator_accounts');
    const accounts = result.authenticator_accounts || [];
    if (accounts.length === 0) return;

    // For each account, generate the code (need totp logic in SW)
    const codes = [];
    for (const account of accounts) {
      let secret = account.secret;
      // If secret is encrypted, we can't decode without the session key
      if (typeof secret === 'object' && secret.iv) continue;

      try {
        const code = await generateOTPCode(secret, account);
        codes.push({ issuer: account.issuer, label: account.label, code, id: account.id });
      } catch {
        // skip invalid accounts
      }
    }

    if (codes.length === 0) return;

    // If only one account, autofill directly
    if (codes.length === 1) {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: fillCode,
        args: [codes[0].code],
      });
      return;
    }

    // Multiple accounts — show in popup (user chooses via popup)
    // Store the codes temporarily so popup can show a picker
    await chrome.storage.session.set({ autofill_codes: codes, autofill_tabId: tab.id });
    chrome.action.openPopup();
  } catch (err) {
    console.error('Autofill error:', err);
  }
});

/**
 * Fills the focused/active input element with the given code.
 * Runs in the page context via executeScript.
 */
function fillCode(code) {
  const el = document.activeElement;
  if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
    el.value = code;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
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

// --- Domain-to-issuer matching for content script autofill ---

/**
 * Known mappings from common hostnames → issuer names.
 * Falls back to fuzzy substring matching against issuer for unknown domains.
 */
const DOMAIN_ALIASES = {
  'accounts.google.com': ['google'],
  'github.com': ['github'],
  'login.microsoftonline.com': ['microsoft'],
  'amazon.com': ['amazon', 'aws'],
  'signin.aws.amazon.com': ['aws', 'amazon'],
  'facebook.com': ['facebook', 'meta'],
  'twitter.com': ['twitter', 'x'],
  'x.com': ['twitter', 'x'],
  'login.live.com': ['microsoft', 'outlook', 'hotmail'],
  'discord.com': ['discord'],
  'accounts.snapchat.com': ['snapchat'],
  'id.apple.com': ['apple'],
  'dropbox.com': ['dropbox'],
  'slack.com': ['slack'],
  'gitlab.com': ['gitlab'],
  'bitbucket.org': ['bitbucket', 'atlassian'],
  'id.atlassian.com': ['atlassian', 'jira', 'bitbucket'],
  'linkedin.com': ['linkedin'],
  'twitch.tv': ['twitch'],
  'store.steampowered.com': ['steam'],
  'login.yahoo.com': ['yahoo'],
};

/**
 * Match a hostname to an account issuer.
 * Returns the best matching account or null.
 */
function matchDomainToAccount(hostname, accounts) {
  const host = hostname.toLowerCase();

  // 1. Try exact domain-alias lookup
  for (const [domain, aliases] of Object.entries(DOMAIN_ALIASES)) {
    if (host === domain || host.endsWith('.' + domain)) {
      for (const account of accounts) {
        const issuerLower = (account.issuer || '').toLowerCase();
        if (aliases.some((alias) => issuerLower.includes(alias))) {
          return account;
        }
      }
    }
  }

  // 2. Fuzzy: check if the main domain word appears in any issuer
  //    e.g. "login.example.com" → "example" matches issuer "Example Corp"
  const parts = host.split('.');
  // Get the main domain part (e.g. "github" from "github.com")
  const domainWord = parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  if (domainWord.length >= 3) {
    for (const account of accounts) {
      const issuerLower = (account.issuer || '').toLowerCase();
      if (issuerLower.includes(domainWord)) {
        return account;
      }
    }
  }

  return null;
}

// --- Message handler for content script autofill requests ---

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'AUTOFILL_REQUEST') return false;

  (async () => {
    try {
      // Check if autofill is enabled in settings
      const settingsResult = await chrome.storage.local.get(SETTINGS_KEY);
      const settings = settingsResult[SETTINGS_KEY] || {};
      if (settings.autoFill === false) {
        sendResponse(null);
        return;
      }

      // Get accounts
      const result = await chrome.storage.local.get('authenticator_accounts');
      const accounts = result.authenticator_accounts || [];
      if (accounts.length === 0) {
        sendResponse(null);
        return;
      }

      // Find a matching account for this hostname
      const match = matchDomainToAccount(message.hostname, accounts);
      if (!match) {
        sendResponse(null);
        return;
      }

      // Only works for unencrypted secrets
      if (typeof match.secret === 'object' && match.secret.iv) {
        sendResponse(null);
        return;
      }

      const code = await generateOTPCode(match.secret, match);
      sendResponse({ code, issuer: match.issuer });
    } catch {
      sendResponse(null);
    }
  })();

  return true; // keep message channel open for async response
});
