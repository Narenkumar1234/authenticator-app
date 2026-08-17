/**
 * Popup controller — wires up the UI to the TOTP engine, storage, crypto, and import/export layers.
 */

// --- DOM References ---
const $accountList = document.getElementById('account-list');
const $emptyState = document.getElementById('empty-state');
const $searchInput = document.getElementById('search-input');
const $formOverlay = document.getElementById('form-overlay');
const $formTitle = document.getElementById('form-title');
const $accountForm = document.getElementById('account-form');
const $inputIssuer = document.getElementById('input-issuer');
const $inputLabel = document.getElementById('input-label');
const $inputSecret = document.getElementById('input-secret');
const $secretField = document.getElementById('secret-field');
const $inputWebsites = document.getElementById('input-websites');
const $deleteDialog = document.getElementById('delete-dialog');
const $deleteAccountName = document.getElementById('delete-account-name');
const $toast = document.getElementById('toast');

// Advanced form fields
const $advancedToggle = document.getElementById('btn-advanced-toggle');
const $advancedFields = document.getElementById('advanced-fields');
const $advancedArrow = document.getElementById('advanced-arrow');
const $inputType = document.getElementById('input-type');
const $inputAlgorithm = document.getElementById('input-algorithm');
const $inputDigits = document.getElementById('input-digits');
const $inputPeriod = document.getElementById('input-period');
const $inputCounter = document.getElementById('input-counter');
const $periodField = document.getElementById('period-field');
const $counterField = document.getElementById('counter-field');

// Lock screen
const $lockScreen = document.getElementById('lock-screen');
const $lockTitle = document.getElementById('lock-title');
const $lockSubtitle = document.getElementById('lock-subtitle');
const $lockForm = document.getElementById('lock-form');
const $lockPassword = document.getElementById('lock-password');
const $lockPasswordConfirm = document.getElementById('lock-password-confirm');
const $lockConfirmField = document.getElementById('lock-confirm-field');
const $lockError = document.getElementById('lock-error');
const $btnUnlock = document.getElementById('btn-unlock');
const $btnSkipSetup = document.getElementById('btn-skip-setup');

// Import/Export
const $ieOverlay = document.getElementById('ie-overlay');

// QR Scanner
const $scanOverlay = document.getElementById('scan-overlay');
const $scanResult = document.getElementById('scan-result');
const $scanResultDetails = document.getElementById('scan-result-details');
const $successOverlay = document.getElementById('success-overlay');
let pendingScanAccount = null;  // account parsed from QR, awaiting user confirmation

// --- State ---
let accounts = [];
let editingId = null;
let deletingId = null;
let toastTimer = null;
let refreshTimer = null;
let isSettingUp = false;   // true when creating master password for first time
let autoCopyEnabled = true; // loaded from settings at init

// --- Theme ---

async function loadTheme() {
  const result = await chrome.storage.local.get('authenticator_theme');
  const theme = result.authenticator_theme || 'light';
  applyTheme(theme);
}

function applyTheme(theme) {
  document.body.setAttribute('data-theme', theme);
  document.getElementById('menu-theme-icon-sun').classList.toggle('hidden', theme === 'dark');
  document.getElementById('menu-theme-icon-moon').classList.toggle('hidden', theme !== 'dark');
  const label = document.getElementById('menu-theme-label');
  if (label) label.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
}

async function toggleTheme() {
  const current = document.body.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  await chrome.storage.local.set({ authenticator_theme: next });
}

// Load theme immediately (before lock screen appears)
loadTheme();

// --- Issuer Colors ---
const ISSUER_COLORS = {
  google: '#ea4335',
  github: '#24292e',
  microsoft: '#00a4ef',
  amazon: '#ff9900',
  facebook: '#1877f2',
  twitter: '#1da1f2',
  x: '#000000',
  apple: '#333333',
  dropbox: '#0061fe',
  slack: '#611f69',
  discord: '#5865f2',
  steam: '#1b2838',
  twitch: '#9146ff',
  reddit: '#ff4500',
  linkedin: '#0a66c2',
  bitbucket: '#0052cc',
  gitlab: '#fc6d26',
  digitalocean: '#0080ff',
  aws: '#ff9900',
  cloudflare: '#f38020',
  stripe: '#635bff',
  paypal: '#003087',
  coinbase: '#0052ff',
  binance: '#f0b90b',
};

function getIssuerColor(issuer) {
  const key = issuer.toLowerCase().replace(/[^a-z]/g, '');
  if (ISSUER_COLORS[key]) return ISSUER_COLORS[key];
  // Deterministic color from string hash
  let hash = 0;
  for (const ch of issuer) hash = ((hash << 5) - hash + ch.charCodeAt(0)) | 0;
  const hue = ((hash % 360) + 360) % 360;
  return `hsl(${hue}, 55%, 48%)`;
}

function getInitials(issuer) {
  const words = issuer.trim().split(/\s+/);
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
  return issuer.slice(0, 2).toUpperCase();
}

// --- Rendering ---

async function renderAccounts() {
  const query = $searchInput.value.toLowerCase().trim();
  const filtered = accounts.filter((a) => {
    if (!query) return true;
    return (
      a.issuer.toLowerCase().includes(query) ||
      a.label.toLowerCase().includes(query)
    );
  });

  if (accounts.length === 0) {
    $accountList.classList.add('hidden');
    $emptyState.classList.remove('hidden');
    return;
  }

  $emptyState.classList.add('hidden');
  $accountList.classList.remove('hidden');

  // Generate codes for all visible accounts
  const entries = await Promise.all(
    filtered.map(async (account) => {
      const opts = {
        type: account.type || 'totp',
        algorithm: account.algorithm || 'SHA-1',
        digits: account.digits || 6,
        period: account.period || 30,
        counter: account.counter || 0,
      };
      const { code, remaining } = await generateTOTP(account.secret, opts);
      return { account, code, remaining, opts };
    })
  );

  // Check if we can do an in-place update
  const currentNodes = Array.from($accountList.children);
  const canUpdateInPlace = currentNodes.length === entries.length && 
    entries.every((entry, i) => currentNodes[i].dataset.id === entry.account.id);

  if (canUpdateInPlace) {
    // Just update the code and progress bar
    entries.forEach((entry, i) => {
      const node = currentNodes[i];
      const isHotp = entry.opts.type === 'hotp';
      const pct = isHotp ? 100 : (entry.remaining / entry.opts.period) * 100;
      const urgent = !isHotp && entry.remaining <= 5;
      
      const codeEl = node.querySelector('.account-code');
      if (codeEl) codeEl.textContent = formatCode(entry.code);
      
      const fillEl = node.querySelector('.countdown-fill');
      if (fillEl) {
        fillEl.style.width = `${pct}%`;
        if (urgent) fillEl.classList.add('urgent');
        else fillEl.classList.remove('urgent');
      }
      
      // Update copy button code attribute
      const copyBtn = node.querySelector('.btn-copy');
      if (copyBtn) copyBtn.dataset.code = entry.code;
    });
    return;
  }

  // Full re-render
  $accountList.innerHTML = entries
    .map(({ account, code, remaining, opts }) => {
      const color = getIssuerColor(account.issuer);
      const initials = getInitials(account.issuer);
      const isHotp = opts.type === 'hotp';
      const period = opts.period;
      const pct = isHotp ? 100 : (remaining / period) * 100;
      const urgent = !isHotp && remaining <= 5 ? 'urgent' : '';
      const formattedCode = formatCode(code);
      const avatarHtml = `<div class="account-avatar" style="background:${color}">${initials}</div>`;
      const typeBadge = isHotp ? '<span class="account-badge">HOTP</span>' : '';

      return `
        <div class="account-item" data-id="${account.id}" draggable="true">
          ${avatarHtml}
          <div class="account-info">
            <div class="account-issuer">${escapeHtml(account.issuer)}${typeBadge}</div>
            <div class="account-label">${escapeHtml(account.label)}</div>
          </div>
          <div class="account-code-section">
            <div class="account-code">${formattedCode}</div>
            ${isHotp ? '' : `<div class="countdown-bar"><div class="countdown-fill ${urgent}" style="width:${pct}%"></div></div>`}
          </div>
          <div class="account-actions">
            <button class="drag-handle" title="Drag to reorder" aria-label="Drag to reorder">
              <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" opacity="0.45">
                <circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/>
                <circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/>
                <circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/>
              </svg>
            </button>
            <button class="btn-copy" data-code="${code}" title="Copy code">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
              </svg>
            </button>
            <button class="btn-edit-account" data-id="${account.id}" title="Edit">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
              </svg>
            </button>
            <button class="btn-delete-account" data-id="${account.id}" title="Delete">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                <polyline points="3 6 5 6 21 6"/>
                <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                <path d="M10 11v6"/>
                <path d="M14 11v6"/>
                <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
              </svg>
            </button>
          </div>
        </div>`;
    })
    .join('');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// --- Toast ---

function showToast(message, duration = 2000) {
  $toast.textContent = message;
  $toast.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $toast.classList.add('hidden'), duration);
}

// --- Copy ---

async function copyCode(code) {
  try {
    await navigator.clipboard.writeText(code);
    showToast('Copied!');
  } catch {
    showToast('Copy failed');
  }
}

// Advance HOTP counter after code is used
async function handleHotpAdvance(accountId) {
  const acct = accounts.find((a) => a.id === accountId);
  if (acct && (acct.type === 'hotp')) {
    await incrementHotpCounter(accountId);
    accounts = await getAccounts();
    renderAccounts();
  }
}

// --- Form (Add / Edit) ---

function resetAdvancedFields() {
  $advancedFields.classList.add('hidden');
  $advancedArrow.innerHTML = '&#9654;';
  $inputType.value = 'totp';
  $inputAlgorithm.value = 'SHA-1';
  $inputDigits.value = '6';
  $inputPeriod.value = '30';
  $inputCounter.value = '0';
  $periodField.classList.remove('hidden');
  $counterField.classList.add('hidden');
}

function openAddForm() {
  const isStandaloneTab = window.innerWidth > 420;
  if (!isStandaloneTab) {
    // If inside compact popup, open in tab so switching windows won't lose the form
    chrome.tabs.create({ url: chrome.runtime.getURL('popup/popup.html?add=1') });
    window.close();
    return;
  }

  // Inside standalone tab — show the drawer directly
  showAddDrawer();
}

function showAddDrawer() {
  editingId = null;
  $formTitle.textContent = 'Add Account';
  $inputIssuer.value = '';
  $inputLabel.value = '';
  $inputSecret.value = '';
  $inputWebsites.value = '';
  $secretField.classList.remove('hidden');
  $inputSecret.setAttribute('required', '');
  resetAdvancedFields();
  $formOverlay.classList.remove('hidden');
  $inputIssuer.focus();
}

function openEditForm(id) {
  const account = accounts.find((a) => a.id === id);
  if (!account) return;
  editingId = id;
  $formTitle.textContent = 'Edit Account';
  $inputIssuer.value = account.issuer;
  $inputLabel.value = account.label;
  $inputSecret.value = '';
  $inputWebsites.value = (account.websites || []).join(', ');
  // Hide secret field when editing (can't change secret)
  $secretField.classList.add('hidden');
  $inputSecret.removeAttribute('required');
  // Populate advanced fields
  $inputType.value = account.type || 'totp';
  $inputAlgorithm.value = account.algorithm || 'SHA-1';
  $inputDigits.value = String(account.digits || 6);
  $inputPeriod.value = String(account.period || 30);
  $inputCounter.value = String(account.counter || 0);
  // Show/hide period vs counter
  const isHotp = (account.type === 'hotp');
  $periodField.classList.toggle('hidden', isHotp);
  $counterField.classList.toggle('hidden', !isHotp);
  // Collapse advanced section
  $advancedFields.classList.add('hidden');
  $advancedArrow.innerHTML = '&#9654;';
  $formOverlay.classList.remove('hidden');
  $inputIssuer.focus();
}

function closeForm() {
  $formOverlay.classList.add('hidden');
  // Restore required attribute on secret
  $inputSecret.setAttribute('required', '');
  resetAdvancedFields();
}

async function handleFormSubmit(e) {
  e.preventDefault();

  const advancedData = {
    type: $inputType.value,
    algorithm: $inputAlgorithm.value,
    digits: parseInt($inputDigits.value, 10),
    period: parseInt($inputPeriod.value, 10) || 30,
    counter: parseInt($inputCounter.value, 10) || 0,
  };

  const websitesRaw = $inputWebsites.value;
  const websites = websitesRaw
    ? websitesRaw.split(',').map(s => s.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')).filter(Boolean)
    : [];

  if (editingId) {
    // Update existing
    await updateAccount(editingId, {
      issuer: $inputIssuer.value,
      label: $inputLabel.value,
      websites,
      ...advancedData,
    });
    showToast('Account updated');
  } else {
    // Validate secret before saving
    const secret = $inputSecret.value.replace(/\s/g, '').toUpperCase();
    try {
      await generateTOTP(secret, advancedData);
    } catch {
      showToast('Invalid secret key');
      $inputSecret.focus();
      return;
    }

    await addAccount({
      issuer: $inputIssuer.value,
      label: $inputLabel.value,
      secret: $inputSecret.value,
      websites,
      ...advancedData,
    });
    showToast('Account added');
  }

  closeForm();
  accounts = await getDecryptedAccounts();
  renderAccounts();
}

// --- Delete ---

function openDeleteDialog(id) {
  const account = accounts.find((a) => a.id === id);
  if (!account) return;
  deletingId = id;
  $deleteAccountName.textContent = `${account.issuer} (${account.label})`;
  $deleteDialog.classList.remove('hidden');
}

function closeDeleteDialog() {
  deletingId = null;
  $deleteDialog.classList.add('hidden');
}

async function confirmDelete() {
  if (!deletingId) return;
  await deleteAccount(deletingId);
  closeDeleteDialog();
  showToast('Account deleted');
  accounts = await getDecryptedAccounts();
  renderAccounts();
}

// --- Event Listeners ---

// Add button (header)
document.getElementById('btn-add').addEventListener('click', openAddForm);

// Add button (empty state)
document.getElementById('btn-add-empty').addEventListener('click', openAddForm);

// Buy me a coffee link (compact popup footer)
const $linkBmc = document.getElementById('link-bmc');
if ($linkBmc) {
  $linkBmc.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: 'https://buymeacoffee.com/narenkumar' });
  });
}

// Floating BMC widget toggle (full tab view)
const $btnBmcToggle = document.getElementById('btn-bmc-toggle');
const $bmcContainer = document.getElementById('bmc-widget-container');
const $bmcIconCoffee = document.getElementById('bmc-icon-coffee');
const $bmcIconChevron = document.getElementById('bmc-icon-chevron');

if ($btnBmcToggle && $bmcContainer) {
  $btnBmcToggle.addEventListener('click', (e) => {
    e.stopPropagation();
    const isHidden = $bmcContainer.classList.toggle('hidden');
    if ($bmcIconCoffee && $bmcIconChevron) {
      $bmcIconCoffee.classList.toggle('hidden', !isHidden);
      $bmcIconChevron.classList.toggle('hidden', isHidden);
    }
  });

  // Close widget when clicking outside
  document.addEventListener('click', (e) => {
    if (!$bmcContainer.contains(e.target) && e.target !== $btnBmcToggle && !$btnBmcToggle.contains(e.target)) {
      $bmcContainer.classList.add('hidden');
      if ($bmcIconCoffee && $bmcIconChevron) {
        $bmcIconCoffee.classList.remove('hidden');
        $bmcIconChevron.classList.add('hidden');
      }
    }
  });
}

// Scan QR button (empty state)
document.getElementById('btn-scan-empty').addEventListener('click', openScanOverlay);

// Form submit
$accountForm.addEventListener('submit', handleFormSubmit);

// Form close
document.getElementById('btn-form-close').addEventListener('click', closeForm);

// Advanced toggle
$advancedToggle.addEventListener('click', () => {
  const hidden = $advancedFields.classList.toggle('hidden');
  $advancedArrow.innerHTML = hidden ? '&#9654;' : '&#9660;';
});

// Toggle period / counter field based on OTP type
$inputType.addEventListener('change', () => {
  const isHotp = $inputType.value === 'hotp';
  $periodField.classList.toggle('hidden', isHotp);
  $counterField.classList.toggle('hidden', !isHotp);
});

// Close form on overlay click
$formOverlay.addEventListener('click', (e) => {
  if (e.target === $formOverlay) closeForm();
});

// Delete dialog buttons
document.getElementById('btn-delete-cancel').addEventListener('click', closeDeleteDialog);
document.getElementById('btn-delete-confirm').addEventListener('click', confirmDelete);

// Close delete dialog on overlay click
$deleteDialog.addEventListener('click', (e) => {
  if (e.target === $deleteDialog) closeDeleteDialog();
});

// Account list click delegation
$accountList.addEventListener('click', async (e) => {
  const dragHandle = e.target.closest('.drag-handle');
  if (dragHandle) {
    e.stopPropagation();
    return;
  }

  const copyBtn = e.target.closest('.btn-copy');
  if (copyBtn) {
    e.stopPropagation();
    const code = copyBtn.dataset.code;
    const item = copyBtn.closest('.account-item');
    copyCode(code);
    if (item) await handleHotpAdvance(item.dataset.id);
    return;
  }

  const editBtn = e.target.closest('.btn-edit-account');
  if (editBtn) {
    e.stopPropagation();
    openEditForm(editBtn.dataset.id);
    return;
  }

  const deleteBtn = e.target.closest('.btn-delete-account');
  if (deleteBtn) {
    e.stopPropagation();
    openDeleteDialog(deleteBtn.dataset.id);
    return;
  }

  // Click on the account row itself → copy code (only if auto-copy enabled)
  const item = e.target.closest('.account-item');
  if (item && autoCopyEnabled) {
    const codeEl = item.querySelector('.account-code');
    if (codeEl) {
      copyCode(codeEl.textContent.replace(/\s/g, ''));
      await handleHotpAdvance(item.dataset.id);
    }
  }
});

// --- Drag-and-drop reorder ---
let dragSrcIndex = null;

$accountList.addEventListener('dragstart', (e) => {
  const item = e.target.closest('.account-item');
  if (!item) return;
  dragSrcIndex = [...$accountList.children].indexOf(item);
  item.classList.add('dragging');
  e.dataTransfer.effectAllowed = 'move';
});

$accountList.addEventListener('dragover', (e) => {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  const item = e.target.closest('.account-item');
  if (!item || item.classList.contains('dragging')) return;
  const rect = item.getBoundingClientRect();
  const mid = rect.top + rect.height / 2;
  item.classList.toggle('drag-over-top', e.clientY < mid);
  item.classList.toggle('drag-over-bottom', e.clientY >= mid);
});

$accountList.addEventListener('dragleave', (e) => {
  const item = e.target.closest('.account-item');
  if (item) {
    item.classList.remove('drag-over-top', 'drag-over-bottom');
  }
});

$accountList.addEventListener('drop', async (e) => {
  e.preventDefault();
  const target = e.target.closest('.account-item');
  if (!target || dragSrcIndex === null) return;

  // Clear all drag classes
  $accountList.querySelectorAll('.account-item').forEach((el) => {
    el.classList.remove('dragging', 'drag-over-top', 'drag-over-bottom');
  });

  const toIndex = [...$accountList.children].indexOf(target);
  if (dragSrcIndex !== toIndex) {
    await reorderAccount(dragSrcIndex, toIndex);
    accounts = await getAccounts();
    renderAccounts();
  }
  dragSrcIndex = null;
});

$accountList.addEventListener('dragend', () => {
  $accountList.querySelectorAll('.account-item').forEach((el) => {
    el.classList.remove('dragging', 'drag-over-top', 'drag-over-bottom');
  });
  dragSrcIndex = null;
});

// Search
$searchInput.addEventListener('input', () => {
  renderAccounts();
});

// --- Lock / Unlock ---

// Kebab menu toggle
const $kebabMenu = document.getElementById('kebab-menu');
document.getElementById('btn-kebab').addEventListener('click', (e) => {
  e.stopPropagation();
  $kebabMenu.classList.toggle('hidden');
});

// Close kebab menu when clicking outside
document.addEventListener('click', () => {
  $kebabMenu.classList.add('hidden');
});
$kebabMenu.addEventListener('click', (e) => {
  e.stopPropagation();
});

// Kebab > Import / Export
document.getElementById('menu-import-export').addEventListener('click', () => {
  $kebabMenu.classList.add('hidden');
  $ieOverlay.classList.remove('hidden');
});

// Kebab > Lock
document.getElementById('menu-lock').addEventListener('click', async () => {
  $kebabMenu.classList.add('hidden');
  const hasPassword = await isMasterPasswordSet();
  if (!hasPassword) {
    showToast('Set a master password in Settings first');
    return;
  }
  lockApp();
});

// Kebab > Theme
document.getElementById('menu-theme').addEventListener('click', () => {
  $kebabMenu.classList.add('hidden');
  toggleTheme();
});

// Settings button
document.getElementById('btn-settings').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

/**
 * Show the lock screen. Clears the session key and stops the refresh loop.
 */
function lockApp() {
  clearSessionKey();
  clearInterval(refreshTimer);
  refreshTimer = null;
  accounts = [];
  $accountList.innerHTML = '';
  showLockScreen(false);
}

/**
 * Display the lock screen.
 * @param {boolean} isSetup - true if this is first-time password setup
 */
function showLockScreen(isSetup) {
  isSettingUp = isSetup;
  $lockScreen.classList.remove('hidden');
  $lockPassword.value = '';
  $lockPasswordConfirm.value = '';
  $lockError.classList.add('hidden');

  if (isSetup) {
    $lockTitle.textContent = 'Set Master Password';
    $lockSubtitle.textContent = 'Protect your accounts with a master password';
    $btnUnlock.textContent = 'Set Password';
    $lockConfirmField.classList.remove('hidden');
    $lockPasswordConfirm.setAttribute('required', '');
    $btnSkipSetup.classList.remove('hidden');
  } else {
    $lockTitle.textContent = 'Unlock Authenticator';
    $lockSubtitle.textContent = 'Enter your master password';
    $btnUnlock.textContent = 'Unlock';
    $lockConfirmField.classList.add('hidden');
    $lockPasswordConfirm.removeAttribute('required');
    $btnSkipSetup.classList.add('hidden');
  }

  $lockPassword.focus();
}

function hideLockScreen() {
  $lockScreen.classList.add('hidden');
  $searchInput.focus();
}

function showLockError(msg) {
  $lockError.textContent = msg;
  $lockError.classList.remove('hidden');
}

// Lock form submit
$lockForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  $lockError.classList.add('hidden');

  const password = $lockPassword.value;

  if (isSettingUp) {
    // Setting up master password for the first time
    const confirm = $lockPasswordConfirm.value;
    if (password !== confirm) {
      showLockError('Passwords do not match');
      return;
    }
    if (password.length < 4) {
      showLockError('Password must be at least 4 characters');
      return;
    }

    try {
      const key = await setupMasterPassword(password);
      setSessionKey(key);
      persistSession(password);

      // Migrate any existing plaintext secrets
      await migrateSecretsToEncrypted(key);

      hideLockScreen();
      showToast('Master password set');
      accounts = await getDecryptedAccounts();
      startRefreshLoop();
      checkAutoOpenAdd();
    } catch (err) {
      showLockError('Setup failed. Try again.');
    }
  } else {
    // Unlocking with existing password
    try {
      const key = await verifyMasterPassword(password);
      if (!key) {
        showLockError('Wrong password');
        $lockPassword.select();
        return;
      }

      setSessionKey(key);
      persistSession(password);
      hideLockScreen();
      accounts = await getDecryptedAccounts();
      startRefreshLoop();
      checkAutoOpenAdd();
    } catch {
      showLockError('Unlock failed. Try again.');
    }
  }
});

// Skip setup button
$btnSkipSetup.addEventListener('click', async () => {
  hideLockScreen();
  accounts = await getDecryptedAccounts();
  startRefreshLoop();
  checkAutoOpenAdd();
});

// --- Import / Export ---

// Close import/export overlay
document.getElementById('btn-ie-close').addEventListener('click', () => {
  $ieOverlay.classList.add('hidden');
});

$ieOverlay.addEventListener('click', (e) => {
  if (e.target === $ieOverlay) $ieOverlay.classList.add('hidden');
});

// Export form
document.getElementById('export-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = document.getElementById('export-password').value;
  try {
    await exportAccounts(password);
    showToast('Backup exported');
    document.getElementById('export-password').value = '';
  } catch (err) {
    showToast(err.message || 'Export failed');
  }
});

// Import from file — toggle password field based on file type
const $importFile = document.getElementById('import-file');
const $importPassword = document.getElementById('import-password');
$importFile.addEventListener('change', () => {
  const isTxt = $importFile.files[0] && $importFile.files[0].name.endsWith('.txt');
  $importPassword.closest('.form-field').classList.toggle('hidden', isTxt);
  if (isTxt) {
    $importPassword.removeAttribute('required');
  } else {
    $importPassword.setAttribute('required', '');
  }
});

document.getElementById('import-file-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById('import-file');
  const password = document.getElementById('import-password').value;
  const mode = document.querySelector('input[name="import-mode"]:checked').value;

  if (!fileInput.files.length) {
    showToast('Select a file');
    return;
  }

  try {
    const result = await importAccountsFromFile(fileInput.files[0], password, mode);
    showToast(`Imported ${result.imported}, skipped ${result.skipped}`);
    $ieOverlay.classList.add('hidden');
    accounts = await getDecryptedAccounts();
    renderAccounts();
  } catch (err) {
    showToast(err.message || 'Import failed');
  }
});

// Import from URIs
document.getElementById('import-uri-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = document.getElementById('import-uris').value;

  if (!text.trim()) {
    showToast('Paste at least one URI');
    return;
  }

  try {
    const result = await importFromOtpauthUris(text);
    showToast(`Imported ${result.imported}, skipped ${result.skipped}`);
    document.getElementById('import-uris').value = '';
    $ieOverlay.classList.add('hidden');
    accounts = await getDecryptedAccounts();
    renderAccounts();
  } catch (err) {
    showToast(err.message || 'Import failed');
  }
});

// --- QR Code Scanner ---

function openScanOverlay() {
  $scanOverlay.classList.remove('hidden');
  $scanResult.classList.add('hidden');
  $successOverlay.classList.add('hidden');
  document.getElementById('scan-section-screen').classList.remove('hidden');
  document.getElementById('scan-section-upload').classList.remove('hidden');
  pendingScanAccount = null;
}

function closeScanOverlay() {
  $scanOverlay.classList.add('hidden');
  $scanResult.classList.add('hidden');
  pendingScanAccount = null;
}

function showScanResult(account) {
  pendingScanAccount = account;
  // Hide the scan input sections, show only the result
  document.getElementById('scan-section-screen').classList.add('hidden');
  document.getElementById('scan-section-upload').classList.add('hidden');
  document.getElementById('scan-issuer').value = account.issuer;
  document.getElementById('scan-label').value = account.label;
  $scanResult.classList.remove('hidden');
}

// Open scan overlay
document.getElementById('btn-scan-qr').addEventListener('click', openScanOverlay);

// Close scan overlay
document.getElementById('btn-scan-close').addEventListener('click', closeScanOverlay);
$scanOverlay.addEventListener('click', (e) => {
  if (e.target === $scanOverlay) closeScanOverlay();
});

// Scan from current tab (screen capture)
document.getElementById('btn-scan-screen').addEventListener('click', async () => {
  const btn = document.getElementById('btn-scan-screen');
  btn.textContent = 'Scanning…';
  btn.disabled = true;

  try {
    if (!isBarcodeDetectorAvailable()) {
      showToast('QR scanning not supported in this browser');
      return;
    }

    const found = await scanFromTab();
    if (found.length === 0) {
      showToast('No QR code found on the page');
      return;
    }

    showScanResult(found[0]);
    if (found.length > 1) {
      showToast(`Found ${found.length} QR codes — showing first`);
    }
  } catch (err) {
    showToast(err.message || 'Scan failed');
  } finally {
    btn.textContent = 'Scan Current Tab';
    btn.disabled = false;
  }
});

// Scan from uploaded image
document.getElementById('scan-image-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById('scan-image-file');
  if (!fileInput.files.length) {
    showToast('Select an image');
    return;
  }

  try {
    if (!isBarcodeDetectorAvailable()) {
      showToast('QR scanning not supported in this browser');
      return;
    }

    const found = await scanFromImage(fileInput.files[0]);
    if (found.length === 0) {
      showToast('No QR code found in the image');
      return;
    }

    showScanResult(found[0]);
    if (found.length > 1) {
      showToast(`Found ${found.length} QR codes — showing first`);
    }
  } catch (err) {
    showToast(err.message || 'Scan failed');
  }
});

// Add scanned account
document.getElementById('btn-scan-add').addEventListener('click', async () => {
  if (!pendingScanAccount) return;

  // Read edited values from inputs
  const issuer = document.getElementById('scan-issuer').value.trim();
  const label = document.getElementById('scan-label').value.trim();
  if (!issuer && !label) {
    showToast('Service or Account name is required');
    return;
  }
  pendingScanAccount.issuer = issuer || 'Unknown';
  pendingScanAccount.label = label;

  try {
    await addAccount(pendingScanAccount);
    // Hide result, show tick inside the overlay
    $scanResult.classList.add('hidden');
    await showSuccessTick();
    closeScanOverlay();
    accounts = await getDecryptedAccounts();
    renderAccounts();
  } catch (err) {
    showToast(err.message || 'Failed to add account');
  }
});

/**
 * Show animated tick mark inside the scan overlay, then auto-dismiss.
 */
function showSuccessTick() {
  return new Promise((resolve) => {
    $successOverlay.classList.remove('hidden');
    setTimeout(() => {
      $successOverlay.classList.add('hidden');
      resolve();
    }, 1200);
  });
}

// --- Autofill Picker (multi-account context menu flow) ---

const $autofillPicker = document.getElementById('autofill-picker');
const $autofillPickerList = document.getElementById('autofill-picker-list');
const $pickerSearchInput = document.getElementById('picker-search-input');

let activePickerCodes = [];
let activePickerTabId = null;

function closeAutofillPicker() {
  $autofillPicker.classList.add('hidden');
  $autofillPickerList.innerHTML = '';
  if ($pickerSearchInput) $pickerSearchInput.value = '';
  activePickerCodes = [];
  activePickerTabId = null;
  chrome.storage.session.remove(['autofill_codes', 'autofill_tabId']);
}

document.getElementById('btn-picker-close').addEventListener('click', closeAutofillPicker);
$autofillPicker.addEventListener('click', (e) => {
  if (e.target === $autofillPicker) closeAutofillPicker();
});

// Focus search input when the picker opens
function focusPickerSearch() {
  if ($pickerSearchInput) {
    $pickerSearchInput.focus();
  }
}

// Render the filtered picker list
function renderPickerList(query = '') {
  const cleanQuery = query.toLowerCase().trim();
  const filtered = activePickerCodes.filter((entry) => {
    if (!cleanQuery) return true;
    return (
      entry.issuer.toLowerCase().includes(cleanQuery) ||
      entry.label.toLowerCase().includes(cleanQuery)
    );
  });

  if (filtered.length === 0) {
    $autofillPickerList.innerHTML = '<div style="text-align:center;padding:20px;opacity:0.6;font-size:13px;">No matching accounts</div>';
    return;
  }

  $autofillPickerList.innerHTML = filtered.map((entry) => {
    const color = getIssuerColor(entry.issuer);
    const initials = getInitials(entry.issuer);
    const masked = entry.code.slice(0, 3) + '***';
    return `
      <button class="picker-item" data-code="${escapeHtml(entry.code)}" data-tab="${activePickerTabId}">
        <div class="account-avatar" style="background:${color}">${initials}</div>
        <div class="picker-item-info">
          <div class="picker-item-issuer">${escapeHtml(entry.issuer)}</div>
          <div class="picker-item-label">${escapeHtml(entry.label)}</div>
        </div>
        <div class="picker-item-code">${masked}</div>
      </button>`;
  }).join('');
}

// Bind search input listener
if ($pickerSearchInput) {
  $pickerSearchInput.addEventListener('input', (e) => {
    renderPickerList(e.target.value);
  });
}

/**
 * Check if the popup was opened for an autofill pick, and show the picker.
 */
async function checkAutofillPicker() {
  const data = await chrome.storage.session.get(['autofill_codes', 'autofill_tabId']);
  const codes = data.autofill_codes;
  const tabId = data.autofill_tabId;
  if (!codes || !codes.length || !tabId) return false;

  activePickerCodes = codes;
  activePickerTabId = tabId;

  // Initial render of the picker list
  renderPickerList('');

  // Handle clicks
  $autofillPickerList.addEventListener('click', async (e) => {
    const btn = e.target.closest('.picker-item');
    if (!btn) return;
    const code = btn.dataset.code;
    const tid = parseInt(btn.dataset.tab, 10);
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tid },
        func: (c) => {
          const el = window.__authenticatorTarget || document.activeElement;
          if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA')) {
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
              window.HTMLInputElement.prototype, 'value'
            )?.set;
            const nativeTextAreaValueSetter = Object.getOwnPropertyDescriptor(
              window.HTMLTextAreaElement.prototype, 'value'
            )?.set;

            if (el.tagName === 'INPUT' && nativeInputValueSetter) {
              nativeInputValueSetter.call(el, c);
            } else if (el.tagName === 'TEXTAREA' && nativeTextAreaValueSetter) {
              nativeTextAreaValueSetter.call(el, c);
            } else {
              el.value = c;
            }

            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));

            // Auto-submit
            el.focus();
            setTimeout(() => {
              const form = el.closest('form');
              if (form) {
                const submitBtn = form.querySelector(
                  'button[type="submit"], input[type="submit"], button:not([type])'
                );
                if (submitBtn) { submitBtn.click(); return; }
                form.requestSubmit ? form.requestSubmit() : form.submit();
                return;
              }
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
        },
        args: [code],
      });
      showToast('Code filled');
    } catch {
      // Fallback: copy to clipboard
      await navigator.clipboard.writeText(code);
      showToast('Copied (could not fill — try pasting)');
    }
    closeAutofillPicker();
  });

  $autofillPicker.classList.remove('hidden');
  setTimeout(focusPickerSearch, 100); // Wait for transition/render
  return true;
}

// --- Refresh Loop ---

function startRefreshLoop() {
  // Render immediately, then every second
  renderAccounts();
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(renderAccounts, 1000);
}

// --- Init ---

function checkAutoOpenAdd() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('add') === '1') {
    showAddDrawer();
  }
}

async function init() {
  // Check if we were opened for an autofill pick (multi-account context menu)
  const isPickerMode = await checkAutofillPicker();

  // Load user settings
  const settingsResult = await chrome.storage.local.get('authenticator_settings');
  const settings = settingsResult['authenticator_settings'] || {};
  autoCopyEnabled = settings.autoCopy !== false; // default true

  const hasPassword = await isMasterPasswordSet();

  if (hasPassword) {
    // Try to restore session from 24h cache (chrome.storage.session)
    const restoredKey = await tryRestoreSession();
    if (restoredKey) {
      setSessionKey(restoredKey);
      accounts = await getDecryptedAccounts();
      startRefreshLoop();
      checkAutoOpenAdd();
    } else {
      if (!isPickerMode) showLockScreen(false);
    }
  } else {
    // No master password — skip lock screen, go straight to accounts
    accounts = await getDecryptedAccounts();
    startRefreshLoop();
    checkAutoOpenAdd();
  }
}

// Keep autoCopy in sync if changed from settings page while popup is open
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes['authenticator_settings']) {
    const s = changes['authenticator_settings'].newValue || {};
    autoCopyEnabled = s.autoCopy !== false;
  }
});

init();
