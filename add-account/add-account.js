/**
 * Add Account (standalone tab) — handles the add-account form when opened
 * in a new tab instead of the popup overlay.
 *
 * This page exists because Chrome extension popups close when they lose
 * focus, making it impossible to copy-paste a secret key from another tab.
 * Opening this form in a tab solves that problem.
 */

// --- DOM References ---
const $accountForm = document.getElementById('account-form');
const $inputIssuer = document.getElementById('input-issuer');
const $inputLabel = document.getElementById('input-label');
const $inputSecret = document.getElementById('input-secret');
const $inputWebsites = document.getElementById('input-websites');
const $toast = document.getElementById('toast');

// Advanced fields
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

// Lock section
const $lockSection = document.getElementById('lock-section');
const $lockForm = document.getElementById('lock-form');
const $lockPassword = document.getElementById('lock-password');
const $lockError = document.getElementById('lock-error');

// Success state
const $successState = document.getElementById('success-state');

// --- State ---
let toastTimer = null;

// --- Theme ---

async function loadTheme() {
  const result = await chrome.storage.local.get('authenticator_theme');
  const theme = result.authenticator_theme || 'light';
  document.body.setAttribute('data-theme', theme);
}

loadTheme();

// --- Toast ---

function showToast(message, duration = 2500) {
  $toast.textContent = message;
  $toast.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $toast.classList.add('hidden'), duration);
}

// --- Advanced Toggle ---

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

// --- Lock Form ---

$lockForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  $lockError.classList.add('hidden');

  const password = $lockPassword.value;

  try {
    const key = await verifyMasterPassword(password);
    if (!key) {
      $lockError.textContent = 'Wrong password';
      $lockError.classList.remove('hidden');
      $lockPassword.select();
      return;
    }

    setSessionKey(key);
    // Also persist the session so the popup stays unlocked
    persistSession(password);

    // Show the form, hide the lock
    $lockSection.classList.add('hidden');
    $accountForm.classList.remove('hidden');
    $inputIssuer.focus();
  } catch {
    $lockError.textContent = 'Unlock failed. Try again.';
    $lockError.classList.remove('hidden');
  }
});

// --- Form Submit ---

$accountForm.addEventListener('submit', async (e) => {
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

  // Validate secret
  const secret = $inputSecret.value.replace(/\s/g, '').toUpperCase();
  try {
    await generateTOTP(secret, advancedData);
  } catch {
    showToast('Invalid secret key');
    $inputSecret.focus();
    return;
  }

  try {
    await addAccount({
      issuer: $inputIssuer.value,
      label: $inputLabel.value,
      secret: $inputSecret.value,
      websites,
      ...advancedData,
    });

    // Show success state
    $accountForm.classList.add('hidden');
    $successState.classList.remove('hidden');
  } catch (err) {
    showToast(err.message || 'Failed to add account');
  }
});

// --- Success Actions ---

document.getElementById('btn-add-another').addEventListener('click', () => {
  // Reset form and show it again
  $accountForm.reset();
  $advancedFields.classList.add('hidden');
  $advancedArrow.innerHTML = '&#9654;';
  $inputType.value = 'totp';
  $inputAlgorithm.value = 'SHA-1';
  $inputDigits.value = '6';
  $inputPeriod.value = '30';
  $inputCounter.value = '0';
  $periodField.classList.remove('hidden');
  $counterField.classList.add('hidden');

  $successState.classList.add('hidden');
  $accountForm.classList.remove('hidden');
  $inputIssuer.focus();
});

document.getElementById('btn-close-tab').addEventListener('click', () => {
  window.close();
});

// --- Init ---

async function init() {
  const hasPassword = await isMasterPasswordSet();

  if (hasPassword) {
    // Try to restore session from 24h cache
    const restoredKey = await tryRestoreSession();
    if (restoredKey) {
      setSessionKey(restoredKey);
      // Session is valid — go straight to form
      $accountForm.classList.remove('hidden');
      $inputIssuer.focus();
    } else {
      // Need to unlock first
      $lockSection.classList.remove('hidden');
      $lockPassword.focus();
    }
  } else {
    // No master password — show form directly
    $accountForm.classList.remove('hidden');
    $inputIssuer.focus();
  }
}

init();
