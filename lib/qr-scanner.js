/**
 * QR Code Scanner module.
 *
 * Uses the native BarcodeDetector API (Chrome 83+) for zero-dependency QR decoding.
 * Provides two scanning modes:
 *   1. scanFromTab()  — captures the active tab screenshot and decodes QR codes
 *   2. scanFromImage() — decodes QR codes from a user-uploaded image file
 *
 * Both return an array of decoded otpauth:// account objects (via parseOtpauthUri).
 */

/**
 * Check if BarcodeDetector is available.
 * @returns {boolean}
 */
function isBarcodeDetectorAvailable() {
  return typeof BarcodeDetector !== 'undefined';
}

/**
 * Detect QR codes in an ImageBitmapSource (ImageBitmap, HTMLImageElement, etc.).
 * @param {ImageBitmapSource} source
 * @returns {Promise<string[]>} raw string values from detected QR codes
 */
async function detectQRCodes(source) {
  if (!isBarcodeDetectorAvailable()) {
    throw new Error('QR scanning is not supported in this browser');
  }

  const detector = new BarcodeDetector({ formats: ['qr_code'] });
  const results = await detector.detect(source);
  return results.map((r) => r.rawValue);
}

/**
 * Capture the visible tab and scan for QR codes containing otpauth:// URIs.
 * Requires the `activeTab` permission.
 * @returns {Promise<Array<{ issuer: string, label: string, secret: string }>>}
 */
async function scanFromTab() {
  // Capture the currently visible tab as a PNG data URL
  const dataUrl = await chrome.tabs.captureVisibleTab(null, { format: 'png' });

  // Load into an image element
  const img = await loadImage(dataUrl);

  // Detect QR codes
  const values = await detectQRCodes(img);

  // Parse only otpauth:// URIs
  return parseQRResults(values);
}

/**
 * Scan a user-uploaded image file for QR codes containing otpauth:// URIs.
 * @param {File} file — image file (png, jpg, etc.)
 * @returns {Promise<Array<{ issuer: string, label: string, secret: string }>>}
 */
async function scanFromImage(file) {
  const dataUrl = await readFileAsDataURL(file);
  const img = await loadImage(dataUrl);
  const values = await detectQRCodes(img);
  return parseQRResults(values);
}

/**
 * Load an image from a data URL and wait for it to be ready.
 * @param {string} src — data URL or regular URL
 * @returns {Promise<HTMLImageElement>}
 */
function loadImage(src) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('Failed to load image'));
    img.src = src;
  });
}

/**
 * Read a File as a data URL string.
 * @param {File} file
 * @returns {Promise<string>}
 */
function readFileAsDataURL(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsDataURL(file);
  });
}

/**
 * Filter and parse QR code values into otpauth:// account objects.
 * @param {string[]} values — raw QR code strings
 * @returns {Array<{ issuer: string, label: string, secret: string }>}
 */
function parseQRResults(values) {
  const accounts = [];
  for (const val of values) {
    if (val.startsWith('otpauth://')) {
      const parsed = parseOtpauthUri(val);
      if (parsed) accounts.push(parsed);
    }
  }
  return accounts;
}
