/**
 * Account storage layer using chrome.storage.local.
 * Supports encrypted secrets when a master password is active (via crypto.js).
 *
 * Account schema (stored):
 * {
 *   id: string,
 *   issuer: string,
 *   label: string,
 *   secret: string | { iv: string, ciphertext: string },
 *   type: 'totp' | 'hotp',       // default 'totp'
 *   algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512',  // default 'SHA-1'
 *   digits: 6 | 8,               // default 6
 *   period: number,              // default 30 (TOTP only)
 *   counter: number,             // HOTP only, default 0
 *   sortOrder: number,           // for drag-and-drop reorder
 *   createdAt: number
 * }
 */

const STORAGE_KEY = 'authenticator_accounts';
const SYNC_ENABLED_KEY = 'authenticator_sync_enabled';

/**
 * Check if sync is enabled.
 */
async function isSyncEnabled() {
  const data = await chrome.storage.local.get(SYNC_ENABLED_KEY);
  return !!data[SYNC_ENABLED_KEY];
}

/**
 * Enable or disable Chrome sync.
 * When enabling, pushes local data to sync storage.
 * When disabling, removes sync data.
 */
async function setSyncEnabled(enabled) {
  await chrome.storage.local.set({ [SYNC_ENABLED_KEY]: enabled });
  if (enabled) {
    await pushToSync();
  } else {
    // Remove all chunked sync keys
    await clearSyncData();
  }
}

/**
 * Remove all chunked sync data.
 */
async function clearSyncData() {
  const meta = await chrome.storage.sync.get(`${STORAGE_KEY}_chunks`);
  const count = meta[`${STORAGE_KEY}_chunks`];
  const keysToRemove = [`${STORAGE_KEY}_chunks`];
  if (count) {
    for (let i = 0; i < count; i++) keysToRemove.push(`${STORAGE_KEY}_${i}`);
  }
  await chrome.storage.sync.remove(keysToRemove);
}

/**
 * Push local accounts to chrome.storage.sync.
 * Splits into chunks if data is large (sync has 8KB per-item limit).
 */
async function pushToSync() {
  const accounts = await getAccounts();
  const json = JSON.stringify(accounts);
  // chrome.storage.sync max per item: ~8KB. Split into chunks if needed.
  const CHUNK_SIZE = 7000; // safe limit per chunk
  const chunks = [];
  for (let i = 0; i < json.length; i += CHUNK_SIZE) {
    chunks.push(json.slice(i, i + CHUNK_SIZE));
  }
  const syncData = { [`${STORAGE_KEY}_chunks`]: chunks.length };
  for (let i = 0; i < chunks.length; i++) {
    syncData[`${STORAGE_KEY}_${i}`] = chunks[i];
  }
  await chrome.storage.sync.set(syncData);
}

/**
 * Pull accounts from chrome.storage.sync into local storage.
 * @returns {Promise<Array|null>} the pulled accounts, or null if nothing to pull
 */
async function pullFromSync() {
  const meta = await chrome.storage.sync.get(`${STORAGE_KEY}_chunks`);
  const count = meta[`${STORAGE_KEY}_chunks`];
  if (!count) return null;

  const keys = [];
  for (let i = 0; i < count; i++) keys.push(`${STORAGE_KEY}_${i}`);
  const data = await chrome.storage.sync.get(keys);

  let json = '';
  for (let i = 0; i < count; i++) {
    json += data[`${STORAGE_KEY}_${i}`] || '';
  }
  try {
    const accounts = JSON.parse(json);
    if (Array.isArray(accounts)) {
      await saveAccounts(accounts);
    }
    return accounts;
  } catch {
    return null;
  }
}

/**
 * Get all accounts from storage (raw — secrets may be encrypted objects).
 * @returns {Promise<Array>}
 */
async function getAccounts() {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  return result[STORAGE_KEY] || [];
}

/**
 * Get all accounts with secrets decrypted (if encryption is active).
 * Call this instead of getAccounts() when you need to read secret values.
 * @returns {Promise<Array>} accounts with plaintext secrets
 */
async function getDecryptedAccounts() {
  const accounts = await getAccounts();
  const key = getSessionKey();
  if (!key) return accounts; // no encryption active

  const decrypted = [];
  for (const account of accounts) {
    const copy = { ...account };
    if (copy.secret && typeof copy.secret === 'object' && copy.secret.iv) {
      try {
        copy.secret = await decryptString(key, copy.secret);
      } catch {
        copy.secret = null; // can't decrypt — corrupted or wrong key
      }
    }
    decrypted.push(copy);
  }
  return decrypted;
}

/**
 * Save the full accounts array to storage.
 * @param {Array} accounts
 */
async function saveAccounts(accounts) {
  await chrome.storage.local.set({ [STORAGE_KEY]: accounts });
  // Push to sync in background (non-blocking)
  isSyncEnabled().then(enabled => { if (enabled) pushToSync(); });
}

/**
 * Add a new account. Secret is encrypted if a master password is active.
 * @param {{ issuer: string, label: string, secret: string }} data
 * @returns {Promise<object>} the created account (with encrypted secret in storage)
 */
async function addAccount({ issuer, label, secret, type, algorithm, digits, period, counter }) {
  const accounts = await getAccounts();

  const normalizedSecret = secret.replace(/\s/g, '').toUpperCase();

  const key = getSessionKey();
  const storedSecret = key
    ? await encryptString(key, normalizedSecret)
    : normalizedSecret;

  const account = {
    id: crypto.randomUUID(),
    issuer: issuer.trim(),
    label: label.trim(),
    secret: storedSecret,
    type: type || 'totp',
    algorithm: algorithm || 'SHA-1',
    digits: digits || 6,
    period: period || 30,
    counter: counter || 0,
    sortOrder: accounts.length,
    createdAt: Date.now(),
  };

  accounts.push(account);
  await saveAccounts(accounts);
  return account;
}

/**
 * Update an existing account's issuer and label.
 * @param {string} id
 * @param {{ issuer?: string, label?: string }} updates
 * @returns {Promise<object|null>} updated account or null if not found
 */
async function updateAccount(id, updates) {
  const accounts = await getAccounts();
  const idx = accounts.findIndex((a) => a.id === id);
  if (idx === -1) return null;

  if (updates.issuer !== undefined) accounts[idx].issuer = updates.issuer.trim();
  if (updates.label !== undefined) accounts[idx].label = updates.label.trim();
  if (updates.type !== undefined) accounts[idx].type = updates.type;
  if (updates.algorithm !== undefined) accounts[idx].algorithm = updates.algorithm;
  if (updates.digits !== undefined) accounts[idx].digits = updates.digits;
  if (updates.period !== undefined) accounts[idx].period = updates.period;
  if (updates.counter !== undefined) accounts[idx].counter = updates.counter;

  await saveAccounts(accounts);
  return accounts[idx];
}

/**
 * Delete an account by ID.
 * @param {string} id
 * @returns {Promise<boolean>} true if deleted
 */
async function deleteAccount(id) {
  const accounts = await getAccounts();
  const filtered = accounts.filter((a) => a.id !== id);
  if (filtered.length === accounts.length) return false;
  await saveAccounts(filtered);
  return true;
}

/**
 * Increment HOTP counter for an account after code use.
 * @param {string} id
 * @returns {Promise<number>} new counter value
 */
async function incrementHotpCounter(id) {
  const accounts = await getAccounts();
  const idx = accounts.findIndex((a) => a.id === id);
  if (idx === -1) return 0;
  accounts[idx].counter = (accounts[idx].counter || 0) + 1;
  await saveAccounts(accounts);
  return accounts[idx].counter;
}

/**
 * Reorder accounts: move account at fromIndex to toIndex.
 * @param {number} fromIndex
 * @param {number} toIndex
 */
async function reorderAccount(fromIndex, toIndex) {
  const accounts = await getAccounts();
  if (fromIndex < 0 || fromIndex >= accounts.length) return;
  if (toIndex < 0 || toIndex >= accounts.length) return;

  const [moved] = accounts.splice(fromIndex, 1);
  accounts.splice(toIndex, 0, moved);
  await saveAccounts(accounts);
}

/**
 * Migrate all plaintext secrets to encrypted form.
 * Called once when master password is first set up.
 * @param {CryptoKey} key
 */
async function migrateSecretsToEncrypted(key) {
  const accounts = await getAccounts();
  let migrated = false;

  for (const account of accounts) {
    if (typeof account.secret === 'string') {
      account.secret = await encryptString(key, account.secret);
      migrated = true;
    }
  }

  if (migrated) await saveAccounts(accounts);
}
