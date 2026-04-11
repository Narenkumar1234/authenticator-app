/**
 * Import/Export module for authenticator accounts.
 *
 * Export: encrypts all accounts with a user-provided export password → JSON file download.
 * Import: decrypts a JSON file with the export password → merges into storage.
 * Also supports importing otpauth:// URIs (standard QR code format).
 */

// --- otpauth:// URI parsing ---

/**
 * Parse an otpauth:// URI into an account object.
 * Format: otpauth://totp/Issuer:label?secret=BASE32&issuer=Issuer&algorithm=SHA256&digits=8&period=60
 *         otpauth://hotp/Issuer:label?secret=BASE32&counter=0
 * @param {string} uri
 * @returns {object|null}
 */
function parseOtpauthUri(uri) {
  try {
    const url = new URL(uri);
    if (url.protocol !== 'otpauth:') return null;

    const type = url.hostname; // 'totp' or 'hotp'
    if (type !== 'totp' && type !== 'hotp') return null;

    let path = decodeURIComponent(url.pathname.replace(/^\//, ''));
    let issuer = url.searchParams.get('issuer') || '';
    let label = path;

    const colonIdx = path.indexOf(':');
    if (colonIdx !== -1) {
      if (!issuer) issuer = path.slice(0, colonIdx).trim();
      label = path.slice(colonIdx + 1).trim();
    }

    const secret = url.searchParams.get('secret');
    if (!secret) return null;

    const account = {
      issuer: issuer || 'Unknown',
      label: label || 'Account',
      secret: secret.toUpperCase().replace(/\s/g, ''),
      type,
    };

    // Optional params
    const algo = url.searchParams.get('algorithm');
    if (algo) account.algorithm = algo.toUpperCase();

    const digits = parseInt(url.searchParams.get('digits'), 10);
    if (digits === 6 || digits === 8) account.digits = digits;

    if (type === 'totp') {
      const period = parseInt(url.searchParams.get('period'), 10);
      if (period > 0) account.period = period;
    } else {
      const counter = parseInt(url.searchParams.get('counter'), 10);
      account.counter = isNaN(counter) ? 0 : counter;
    }

    return account;
  } catch {
    return null;
  }
}

// --- Export ---

/**
 * Export all accounts as an encrypted JSON file.
 * Uses a separate export password (not the master password).
 * @param {string} exportPassword
 * @returns {Promise<void>} triggers a file download
 */
async function exportAccounts(exportPassword) {
  // Get decrypted accounts
  const accounts = await getDecryptedAccounts();

  // Strip internal fields, keep only what's needed for restore
  const exportData = accounts.map((a) => ({
    issuer: a.issuer,
    label: a.label,
    secret: a.secret,
    type: a.type || 'totp',
    algorithm: a.algorithm || 'SHA-1',
    digits: a.digits || 6,
    period: a.period || 30,
    counter: a.counter || 0,
    createdAt: a.createdAt,
  }));

  const payload = JSON.stringify({
    version: 1,
    exportedAt: Date.now(),
    accounts: exportData,
  });

  // Encrypt with export password
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const key = await deriveKey(exportPassword, salt);
  const encrypted = await encryptString(key, payload);

  const fileData = JSON.stringify({
    format: 'authenticator-export',
    version: 1,
    salt: bufToBase64(salt),
    data: encrypted,
  });

  // Trigger download
  const blob = new Blob([fileData], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `authenticator-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// --- Import ---

/**
 * Import accounts from an encrypted JSON backup file.
 * @param {File} file
 * @param {string} importPassword
 * @param {'merge'|'replace'} mode
 * @returns {Promise<{ imported: number, skipped: number }>}
 */
async function importAccountsFromFile(file, importPassword, mode) {
  const text = await file.text();

  // Handle .txt files as otpauth:// URI lists (no password needed)
  if (file.name.endsWith('.txt')) {
    return await importFromOtpauthUris(text);
  }

  let fileData;

  try {
    fileData = JSON.parse(text);
  } catch {
    throw new Error('Invalid file format');
  }

  if (fileData.format !== 'authenticator-export' || !fileData.data) {
    throw new Error('Not a valid Authenticator backup file');
  }

  // Decrypt
  const salt = base64ToBuf(fileData.salt);
  const key = await deriveKey(importPassword, salt);

  let payload;
  try {
    const decrypted = await decryptString(key, fileData.data);
    payload = JSON.parse(decrypted);
  } catch {
    throw new Error('Wrong password or corrupted file');
  }

  if (!payload.accounts || !Array.isArray(payload.accounts)) {
    throw new Error('Invalid backup data');
  }

  return await mergeImportedAccounts(payload.accounts, mode);
}

/**
 * Import accounts from otpauth:// URIs (one per line).
 * @param {string} text - newline-separated otpauth:// URIs
 * @returns {Promise<{ imported: number, skipped: number }>}
 */
async function importFromOtpauthUris(text) {
  const lines = text
    .split(/[\r\n]+/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith('otpauth://'));

  const parsed = lines
    .map(parseOtpauthUri)
    .filter((a) => a !== null);

  if (parsed.length === 0) {
    throw new Error('No valid otpauth:// URIs found');
  }

  return await mergeImportedAccounts(parsed, 'merge');
}

/**
 * Merge imported accounts into storage.
 * @param {Array} newAccounts - array of { issuer, label, secret }
 * @param {'merge'|'replace'} mode
 * @returns {Promise<{ imported: number, skipped: number }>}
 */
async function mergeImportedAccounts(newAccounts, mode) {
  if (mode === 'replace') {
    // Clear existing and add all new
    const sessionKey = getSessionKey();
    const toSave = [];
    for (const a of newAccounts) {
      const secret = a.secret.replace(/\s/g, '').toUpperCase();
      toSave.push({
        id: crypto.randomUUID(),
        issuer: a.issuer || 'Unknown',
        label: a.label || 'Account',
        secret: sessionKey ? await encryptString(sessionKey, secret) : secret,
        type: a.type || 'totp',
        algorithm: a.algorithm || 'SHA-1',
        digits: a.digits || 6,
        period: a.period || 30,
        counter: a.counter || 0,
        sortOrder: toSave.length,
        createdAt: a.createdAt || Date.now(),
      });
    }
    await saveAccounts(toSave);
    return { imported: toSave.length, skipped: 0 };
  }

  // Merge mode — skip duplicates (same issuer + label)
  const existing = await getDecryptedAccounts();
  const existingKeys = new Set(
    existing.map((a) => `${a.issuer.toLowerCase()}:${a.label.toLowerCase()}`)
  );

  const sessionKey = getSessionKey();
  let imported = 0;
  let skipped = 0;
  const allAccounts = await getAccounts();

  for (const a of newAccounts) {
    const dedupKey = `${(a.issuer || '').toLowerCase()}:${(a.label || '').toLowerCase()}`;
    if (existingKeys.has(dedupKey)) {
      skipped++;
      continue;
    }

    const secret = (a.secret || '').replace(/\s/g, '').toUpperCase();
    allAccounts.push({
      id: crypto.randomUUID(),
      issuer: a.issuer || 'Unknown',
      label: a.label || 'Account',
      secret: sessionKey ? await encryptString(sessionKey, secret) : secret,
      type: a.type || 'totp',
      algorithm: a.algorithm || 'SHA-1',
      digits: a.digits || 6,
      period: a.period || 30,
      counter: a.counter || 0,
      sortOrder: allAccounts.length,
      createdAt: a.createdAt || Date.now(),
    });
    imported++;
  }

  await saveAccounts(allAccounts);
  return { imported, skipped };
}
