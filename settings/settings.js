/**
 * Settings page controller.
 */

const SETTINGS_KEY = 'authenticator_settings';
const THEME_KEY = 'authenticator_theme';

// --- Helpers ---

function showToast(msg, duration = 2000) {
  const $toast = document.getElementById('settings-toast');
  $toast.textContent = msg;
  $toast.classList.remove('hidden');
  setTimeout(() => $toast.classList.add('hidden'), duration);
}

// --- Load Settings ---

async function loadSettings() {
  const result = await chrome.storage.local.get([SETTINGS_KEY, THEME_KEY]);
  const settings = result[SETTINGS_KEY] || {};
  const theme = result[THEME_KEY] || 'light';

  // Apply theme
  document.body.setAttribute('data-theme', theme);
  document.getElementById('setting-theme').value = theme;

  // Auto-copy
  document.getElementById('setting-autocopy').checked = !!settings.autoCopy;

  // Auto-fill (default enabled)
  document.getElementById('setting-autofill').checked = settings.autoFill !== false;

  // Show correct password section
  const hasPassword = await isMasterPasswordSet();
  document.getElementById('pw-not-set').classList.toggle('hidden', hasPassword);
  document.getElementById('pw-set').classList.toggle('hidden', !hasPassword);
}

// --- Theme ---

document.getElementById('setting-theme').addEventListener('change', async (e) => {
  const theme = e.target.value;
  document.body.setAttribute('data-theme', theme);
  await chrome.storage.local.set({ [THEME_KEY]: theme });
  showToast('Theme updated');
});

// --- Auto-copy ---

document.getElementById('setting-autocopy').addEventListener('change', async (e) => {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  const settings = result[SETTINGS_KEY] || {};
  settings.autoCopy = e.target.checked;
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
  showToast('Setting saved');
});

// --- Auto-fill ---

document.getElementById('setting-autofill').addEventListener('change', async (e) => {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  const settings = result[SETTINGS_KEY] || {};
  settings.autoFill = e.target.checked;
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
  showToast('Setting saved');
});

// --- Change Password ---

document.getElementById('btn-show-change-pw').addEventListener('click', () => {
  document.getElementById('change-pw-form').classList.toggle('hidden');
});

document.getElementById('btn-cancel-pw').addEventListener('click', () => {
  document.getElementById('change-pw-form').classList.add('hidden');
  document.getElementById('pw-error').classList.add('hidden');
  document.getElementById('change-pw-form').reset();
});

// --- Setup Password (first time) ---

document.getElementById('btn-show-setup-pw').addEventListener('click', () => {
  document.getElementById('setup-pw-form').classList.toggle('hidden');
});

document.getElementById('btn-cancel-setup-pw').addEventListener('click', () => {
  document.getElementById('setup-pw-form').classList.add('hidden');
  document.getElementById('setup-pw-error').classList.add('hidden');
  document.getElementById('setup-pw-form').reset();
});

document.getElementById('setup-pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const $error = document.getElementById('setup-pw-error');
  $error.classList.add('hidden');

  const newPw = document.getElementById('setup-pw-new').value;
  const confirm = document.getElementById('setup-pw-confirm').value;

  if (newPw !== confirm) {
    $error.textContent = 'Passwords do not match';
    $error.classList.remove('hidden');
    return;
  }

  if (newPw.length < 4) {
    $error.textContent = 'Password must be at least 4 characters';
    $error.classList.remove('hidden');
    return;
  }

  try {
    const key = await setupMasterPassword(newPw);
    // Migrate existing plaintext secrets
    await migrateSecretsToEncrypted(key);
    document.getElementById('setup-pw-form').classList.add('hidden');
    document.getElementById('setup-pw-form').reset();
    // Swap UI: hide "set up" row, show "change" row
    document.getElementById('pw-not-set').classList.add('hidden');
    document.getElementById('pw-set').classList.remove('hidden');
    showToast('Master password set');
  } catch (err) {
    $error.textContent = err.message || 'Setup failed';
    $error.classList.remove('hidden');
  }
});

document.getElementById('change-pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const $error = document.getElementById('pw-error');
  $error.classList.add('hidden');

  const current = document.getElementById('pw-current').value;
  const newPw = document.getElementById('pw-new').value;
  const confirm = document.getElementById('pw-confirm').value;

  if (newPw !== confirm) {
    $error.textContent = 'New passwords do not match';
    $error.classList.remove('hidden');
    return;
  }

  if (newPw.length < 4) {
    $error.textContent = 'Password must be at least 4 characters';
    $error.classList.remove('hidden');
    return;
  }

  try {
    const oldKey = await verifyMasterPassword(current);
    if (!oldKey) {
      $error.textContent = 'Current password is incorrect';
      $error.classList.remove('hidden');
      return;
    }

    await changeMasterPassword(oldKey, newPw);
    document.getElementById('change-pw-form').classList.add('hidden');
    document.getElementById('change-pw-form').reset();
    showToast('Password changed');
  } catch (err) {
    $error.textContent = err.message || 'Failed to change password';
    $error.classList.remove('hidden');
  }
});

// --- Clear All Data ---

document.getElementById('btn-clear-all').addEventListener('click', () => {
  document.getElementById('confirm-dialog').classList.remove('hidden');
});

document.getElementById('btn-confirm-cancel').addEventListener('click', () => {
  document.getElementById('confirm-dialog').classList.add('hidden');
});

document.getElementById('btn-confirm-clear').addEventListener('click', async () => {
  await chrome.storage.local.clear();
  document.getElementById('confirm-dialog').classList.add('hidden');
  showToast('All data cleared');
  setTimeout(() => window.close(), 1000);
});

// --- Chrome Sync ---

const $syncToggle = document.getElementById('setting-sync');
const $syncActions = document.getElementById('sync-actions');

$syncToggle.addEventListener('change', async (e) => {
  await setSyncEnabled(e.target.checked);
  $syncActions.classList.toggle('hidden', !e.target.checked);
  if (e.target.checked) {
    await pushToSync();
    showToast('Sync enabled — data pushed');
  } else {
    showToast('Sync disabled');
  }
});

document.getElementById('btn-sync-push').addEventListener('click', async () => {
  await pushToSync();
  showToast('Pushed to sync');
});

document.getElementById('btn-sync-pull').addEventListener('click', async () => {
  await pullFromSync();
  showToast('Pulled from sync');
});

// --- Init ---

async function loadSyncState() {
  const enabled = await isSyncEnabled();
  $syncToggle.checked = enabled;
  $syncActions.classList.toggle('hidden', !enabled);
}

async function init() {
  await loadSettings();
  await loadSyncState();
}

init();
