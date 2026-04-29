/**
 * Clipboard helper — copy text with a green toast feedback.
 */
function copyToClipboard(text, buttonEl) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Prompt copied to clipboard');
    if (buttonEl) {
      const orig = buttonEl.textContent;
      buttonEl.textContent = '✓ COPIED';
      buttonEl.classList.add('copied');
      setTimeout(() => {
        buttonEl.textContent = orig;
        buttonEl.classList.remove('copied');
      }, 2000);
    }
  }).catch(() => {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast('Prompt copied to clipboard');
  });
}

let _toastTimeout = null;

function showToast(message) {
  let toast = document.getElementById('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    toast.className = 'toast';
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(_toastTimeout);
  _toastTimeout = setTimeout(() => toast.classList.remove('visible'), 2500);
}
