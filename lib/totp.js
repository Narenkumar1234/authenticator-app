/**
 * OTP generator — TOTP (RFC 6238) and HOTP (RFC 4226).
 * Supports SHA-1, SHA-256, SHA-512, configurable digits (6/8) and period.
 * Zero dependencies — uses Web Crypto API.
 */

const OTP_DEFAULTS = {
  type: 'totp',
  algorithm: 'SHA-1',
  digits: 6,
  period: 30,
  counter: 0,
};

// --- Base32 Decoding (RFC 4648) ---

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const base32Cache = new Map();
const cryptoKeyCache = new Map();

function base32Decode(input) {
  const str = input.toUpperCase().replace(/[\s=]/g, '');
  if (base32Cache.has(str)) return base32Cache.get(str);

  const out = [];
  let buffer = 0;
  let bitsLeft = 0;

  for (const char of str) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) throw new Error(`Invalid Base32 character: ${char}`);
    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      out.push((buffer >>> bitsLeft) & 0xff);
    }
  }
  const result = new Uint8Array(out);
  base32Cache.set(str, result);
  return result;
}

// --- HMAC via Web Crypto (SHA-1, SHA-256, SHA-512) ---

const ALGO_MAP = {
  'SHA-1': 'SHA-1',
  'SHA-256': 'SHA-256',
  'SHA-512': 'SHA-512',
  'SHA1': 'SHA-1',
  'SHA256': 'SHA-256',
  'SHA512': 'SHA-512',
};

async function hmacSign(key, message, algorithm) {
  const hash = ALGO_MAP[algorithm] || 'SHA-1';
  let cacheKey = hash + ':';
  for (let i = 0; i < key.length; i++) cacheKey += key[i] + ',';

  let cryptoKey = cryptoKeyCache.get(cacheKey);
  if (!cryptoKey) {
    cryptoKey = await crypto.subtle.importKey(
      'raw', key, { name: 'HMAC', hash }, false, ['sign']
    );
    cryptoKeyCache.set(cacheKey, cryptoKey);
  }
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, message);
  return new Uint8Array(sig);
}

// --- OTP Core ---

function intToBytes(num) {
  const bytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    bytes[i] = num & 0xff;
    num = Math.floor(num / 256);
  }
  return bytes;
}

function dynamicTruncate(hmac) {
  const offset = hmac[hmac.length - 1] & 0x0f;
  return (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  );
}

/**
 * Generate an OTP code. Works for both TOTP and HOTP.
 *
 * @param {string} secret - Base32-encoded secret key
 * @param {object} [opts] - optional overrides
 * @param {string} [opts.type='totp'] - 'totp' or 'hotp'
 * @param {string} [opts.algorithm='SHA-1'] - hash algorithm
 * @param {number} [opts.digits=6] - number of digits (6 or 8)
 * @param {number} [opts.period=30] - TOTP time step in seconds
 * @param {number} [opts.counter=0] - HOTP counter value
 * @returns {Promise<{ code: string, remaining: number }>}
 */
async function generateTOTP(secret, opts = {}) {
  const type = opts.type || OTP_DEFAULTS.type;
  const algorithm = opts.algorithm || OTP_DEFAULTS.algorithm;
  const digits = opts.digits || OTP_DEFAULTS.digits;
  const period = opts.period || OTP_DEFAULTS.period;

  const key = base32Decode(secret);
  let counter, remaining;

  if (type === 'hotp') {
    counter = opts.counter || 0;
    remaining = -1; // HOTP doesn't expire on a timer
  } else {
    const epoch = Math.floor(Date.now() / 1000);
    counter = Math.floor(epoch / period);
    remaining = period - (epoch % period);
  }

  const counterBytes = intToBytes(counter);
  const hmac = await hmacSign(key, counterBytes, algorithm);
  const truncated = dynamicTruncate(hmac);
  const otp = truncated % Math.pow(10, digits);
  const code = otp.toString().padStart(digits, '0');

  return { code, remaining };
}

/**
 * Format a code with a space in the middle: "123 456" or "1234 5678"
 */
function formatCode(code) {
  const mid = Math.ceil(code.length / 2);
  return code.slice(0, mid) + ' ' + code.slice(mid);
}
