/**
 * Crypto module — master password, PBKDF2 key derivation, AES-256-GCM encrypt/decrypt.
 * Uses Web Crypto API exclusively (zero dependencies).
 */

const CRYPTO_STORAGE_KEY = 'authenticator_crypto';
const PBKDF2_ITERATIONS = 100000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const VERIFICATION_TOKEN = 'authenticator-verified';

// --- Helpers ---

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

// --- Key Derivation ---

/**
 * Derive an AES-256-GCM CryptoKey from a password and salt using PBKDF2.
 * @param {string} password
 * @param {Uint8Array} salt
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// --- Encrypt / Decrypt ---

/**
 * Encrypt a UTF-8 string with AES-256-GCM.
 * @param {CryptoKey} key
 * @param {string} plaintext
 * @returns {Promise<{ iv: string, ciphertext: string }>}  base64-encoded fields
 */
async function encryptString(key, plaintext) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(plaintext)
  );
  return {
    iv: bufToBase64(iv),
    ciphertext: bufToBase64(ciphertext),
  };
}

/**
 * Decrypt an AES-256-GCM ciphertext back to a UTF-8 string.
 * @param {CryptoKey} key
 * @param {{ iv: string, ciphertext: string }} encrypted  base64-encoded fields
 * @returns {Promise<string>}
 */
async function decryptString(key, { iv, ciphertext }) {
  const dec = new TextDecoder();
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBuf(iv) },
    key,
    base64ToBuf(ciphertext)
  );
  return dec.decode(plainBuf);
}

// --- Master Password Management ---

/**
 * Check if a master password has been set up.
 * @returns {Promise<boolean>}
 */
async function isMasterPasswordSet() {
  const data = await chrome.storage.local.get(CRYPTO_STORAGE_KEY);
  return !!(data[CRYPTO_STORAGE_KEY] && data[CRYPTO_STORAGE_KEY].salt);
}

/**
 * Set up a new master password.
 * Generates a random salt, derives a key, encrypts a verification token,
 * and stores salt + verification ciphertext.
 * @param {string} password
 * @returns {Promise<CryptoKey>} the derived key (for immediate use)
 */
async function setupMasterPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const key = await deriveKey(password, salt);

  // Encrypt a known token so we can verify the password later
  const verification = await encryptString(key, VERIFICATION_TOKEN);

  await chrome.storage.local.set({
    [CRYPTO_STORAGE_KEY]: {
      salt: bufToBase64(salt),
      verification,
    },
  });

  return key;
}

/**
 * Verify a master password by trying to decrypt the verification token.
 * @param {string} password
 * @returns {Promise<CryptoKey|null>} the derived key if correct, null if wrong
 */
async function verifyMasterPassword(password) {
  const data = await chrome.storage.local.get(CRYPTO_STORAGE_KEY);
  const cryptoData = data[CRYPTO_STORAGE_KEY];
  if (!cryptoData || !cryptoData.salt) return null;

  const salt = base64ToBuf(cryptoData.salt);
  const key = await deriveKey(password, salt);

  try {
    const token = await decryptString(key, cryptoData.verification);
    if (token === VERIFICATION_TOKEN) return key;
    return null;
  } catch {
    // Decryption failed → wrong password
    return null;
  }
}

/**
 * Change master password: re-encrypts verification token and all account secrets.
 * @param {CryptoKey} oldKey - current valid key
 * @param {string} newPassword
 * @returns {Promise<CryptoKey>} the new key
 */
async function changeMasterPassword(oldKey, newPassword) {
  // Re-derive with new salt
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const newKey = await deriveKey(newPassword, salt);

  // Re-encrypt verification token
  const verification = await encryptString(newKey, VERIFICATION_TOKEN);

  await chrome.storage.local.set({
    [CRYPTO_STORAGE_KEY]: {
      salt: bufToBase64(salt),
      verification,
    },
  });

  // Re-encrypt all account secrets
  const accounts = await getAccounts();
  for (const account of accounts) {
    if (account.secret && typeof account.secret === 'object') {
      // Decrypt with old key, re-encrypt with new key
      const plainSecret = await decryptString(oldKey, account.secret);
      account.secret = await encryptString(newKey, plainSecret);
    }
  }
  await saveAccounts(accounts);

  return newKey;
}

// --- Session Key Cache ---
// The derived key is held in memory for the popup session.
// For 24-hour persistence across popup opens, we store a salted hash of the
// password in chrome.storage.session (MV3 in-memory storage, never written to
// disk, cleared on browser restart). We never store the raw password.

const SESSION_TS_KEY = 'authenticator_session_ts';
const SESSION_HASH_KEY = 'authenticator_session_hash';
const SESSION_SALT_KEY = 'authenticator_session_salt';
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours in ms

let _sessionKey = null;

function setSessionKey(key) {
  _sessionKey = key;
}

function getSessionKey() {
  return _sessionKey;
}

function clearSessionKey() {
  _sessionKey = null;
  chrome.storage.session.remove([SESSION_HASH_KEY, SESSION_SALT_KEY, SESSION_TS_KEY]);
}

/**
 * Persist a session token derived from the password (never stores the raw password).
 * Uses a random salt + PBKDF2 to produce a session verification hash.
 * The actual CryptoKey is held in memory only (_sessionKey).
 * @param {string} password
 */
async function persistSession(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 10000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  chrome.storage.session.set({
    [SESSION_HASH_KEY]: bufToBase64(bits),
    [SESSION_SALT_KEY]: bufToBase64(salt),
    [SESSION_TS_KEY]: Date.now(),
  });
}

/**
 * Try to restore the session key from session storage (within 24h window).
 * Since we only store a hash (not the password), the CryptoKey can only be
 * restored if it's still in memory. This method checks if the session is
 * still valid and the in-memory key is available.
 * @returns {Promise<CryptoKey|null>} the restored key, or null if expired/unavailable
 */
async function tryRestoreSession() {
  // If in-memory key is already set, just validate the timestamp
  if (_sessionKey) {
    const data = await chrome.storage.session.get(SESSION_TS_KEY);
    const ts = data[SESSION_TS_KEY];
    if (ts && (Date.now() - ts) < SESSION_DURATION) {
      return _sessionKey;
    }
    // Expired
    _sessionKey = null;
    chrome.storage.session.remove([SESSION_HASH_KEY, SESSION_SALT_KEY, SESSION_TS_KEY]);
    return null;
  }
  return null;
}
