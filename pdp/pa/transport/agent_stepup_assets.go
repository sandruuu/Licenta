package transport

import "net/http"

const stepUpBrowserJS = `
(() => {
  const root = document.getElementById('stepup-root');
  if (!root) return;
  const challengeID = root.dataset.challengeId || '';
  const csrfToken = root.dataset.csrfToken || '';
  const expiresAt = root.dataset.expiresAt ? Date.parse(root.dataset.expiresAt) : 0;
  const expiryMessage = 'Verification expired. Try accessing the protected resource again.';
  let expired = false;
  const alertIcon = '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>';

  function statusNode() {
    let status = document.getElementById('webauthn-status');
    if (status) return status;
    let slot = root.querySelector('.stepup-message-slot');
    if (!slot) {
      slot = document.createElement('div');
      slot.className = 'stepup-message-slot';
      const methods = root.querySelector('.methods');
      if (methods) {
        root.insertBefore(slot, methods);
      } else {
        root.appendChild(slot);
      }
    }
    status = document.createElement('div');
    status.id = 'webauthn-status';
    status.className = 'webauthn-status';
    status.setAttribute('aria-live', 'polite');
    slot.appendChild(status);
    return status;
  }

  function setupOTPInputs() {
    const groups = document.querySelectorAll('.otp');
    for (const group of groups) {
      const inputs = Array.from(group.querySelectorAll('.otp-digit'));
      const form = group.closest('form');
      const hidden = form ? form.querySelector('.otp-value') : null;

      function sync() {
        if (hidden) hidden.value = inputs.map((input) => input.value.replace(/\D/g, '').slice(0, 1)).join('');
      }

      function focus(index) {
        const target = inputs[index];
        if (!target) return;
        target.focus();
        target.select();
      }

      function writeDigits(start, value) {
        const digits = value.replace(/\D/g, '').slice(0, inputs.length - start);
        if (!digits) {
          inputs[start].value = '';
          sync();
          return;
        }
        for (let offset = 0; offset < digits.length; offset++) {
          inputs[start + offset].value = digits[offset];
        }
        sync();
        focus(Math.min(start + digits.length, inputs.length - 1));
      }

      inputs.forEach((input, index) => {
        input.addEventListener('input', (event) => writeDigits(index, event.target.value));
        input.addEventListener('paste', (event) => {
          const value = event.clipboardData.getData('text');
          if (!value) return;
          event.preventDefault();
          writeDigits(index, value);
        });
        input.addEventListener('keydown', (event) => {
          if (event.key === 'Backspace' && !input.value && index > 0) {
            event.preventDefault();
            inputs[index - 1].value = '';
            sync();
            focus(index - 1);
          }
          if (event.key === 'ArrowLeft' && index > 0) {
            event.preventDefault();
            focus(index - 1);
          }
          if (event.key === 'ArrowRight' && index < inputs.length - 1) {
            event.preventDefault();
            focus(index + 1);
          }
        });
      });

      if (form) form.addEventListener('submit', sync);
      sync();
    }
  }

  function b64urlToBuffer(value) {
    const pad = '='.repeat((4 - value.length % 4) % 4);
    const b64 = (value + pad).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  function bufferToB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function mapCredentialList(list) {
    return (list || []).map((cred) => ({ ...cred, id: b64urlToBuffer(cred.id) }));
  }

  function prepareRequestOptions(options) {
    const publicKey = options.publicKey || options;
    publicKey.challenge = b64urlToBuffer(publicKey.challenge);
    if (publicKey.allowCredentials) publicKey.allowCredentials = mapCredentialList(publicKey.allowCredentials);
    return publicKey;
  }

  function prepareCreationOptions(options) {
    const publicKey = options.publicKey || options;
    publicKey.challenge = b64urlToBuffer(publicKey.challenge);
    if (publicKey.user && typeof publicKey.user.id === 'string') publicKey.user.id = b64urlToBuffer(publicKey.user.id);
    if (publicKey.excludeCredentials) publicKey.excludeCredentials = mapCredentialList(publicKey.excludeCredentials);
    return publicKey;
  }

  function credentialToJSON(cred) {
    const response = { clientDataJSON: bufferToB64url(cred.response.clientDataJSON) };
    if (cred.response.attestationObject) response.attestationObject = bufferToB64url(cred.response.attestationObject);
    if (cred.response.authenticatorData) response.authenticatorData = bufferToB64url(cred.response.authenticatorData);
    if (cred.response.signature) response.signature = bufferToB64url(cred.response.signature);
    if (cred.response.userHandle) response.userHandle = bufferToB64url(cred.response.userHandle);
    if (cred.response.getTransports) response.transports = cred.response.getTransports();
    return {
      id: cred.id,
      rawId: bufferToB64url(cred.rawId),
      type: cred.type,
      response,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    };
  }

  function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }[char]));
  }

  function clearStatus() {
    const status = document.getElementById('webauthn-status');
    if (status) status.innerHTML = '';
  }

  function showError(message) {
    const status = statusNode();
    status.innerHTML = '<div class="page-alert stepup-alert" role="alert">' + alertIcon + '<span>' + escapeHTML(message) + '</span></div>';
  }

  function showRecoveryCodes(codes) {
    if (!Array.isArray(codes) || codes.length === 0) return false;
    root.classList.add('recovery-codes-stepup');
    root.innerHTML =
      '<div class="brand">' +
      '<div class="brand-icon"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="logo-ring" cx="50" cy="50" r="44" fill="none" stroke="currentColor" stroke-width="8"/><path class="logo-check" d="M30 52.5 44 66 71 34" fill="none" stroke="currentColor" stroke-width="9" stroke-linecap="round" stroke-linejoin="round"/></svg></div>' +
      '<div class="brand-title">TrustCloud</div>' +
      '</div>' +
      '<div class="stepup-heading"><h1>Verification complete</h1><p class="stepup-copy">Save these recovery codes before closing this page. Each code can be used once if you lose access to your MFA method.</p></div>' +
      '<div class="recovery-codes">' + codes.map((code) => '<code>' + escapeHTML(code) + '</code>').join('') + '</div>' +
      '<p class="stepup-copy recovery-complete-copy">You can close this tab and try to access the resource again.</p>' +
      '<a class="button-link" href="/verify/' + encodeURIComponent(challengeID) + '?completed=1">I saved these codes</a>';
    return true;
  }

  function isExpired() {
    return Number.isFinite(expiresAt) && expiresAt > 0 && Date.now() >= expiresAt;
  }

  function setControlsDisabled(disabled) {
    root.querySelectorAll('button,input:not([type="hidden"]),select,textarea').forEach((control) => {
      control.disabled = disabled;
    });
    root.querySelectorAll('a.method-link,a.button-link').forEach((link) => {
      if (disabled) {
        link.setAttribute('aria-disabled', 'true');
        link.dataset.previousTabIndex = link.getAttribute('tabindex') || '';
        link.setAttribute('tabindex', '-1');
      } else {
        link.removeAttribute('aria-disabled');
        if (link.dataset.previousTabIndex) {
          link.setAttribute('tabindex', link.dataset.previousTabIndex);
        } else {
          link.removeAttribute('tabindex');
        }
      }
    });
  }

  function markExpired() {
    if (!isExpired()) return false;
    if (!expired) {
      expired = true;
      root.classList.add('stepup-expired');
      setControlsDisabled(true);
      showError(expiryMessage);
    }
    return true;
  }

  function requireActive(event) {
    if (!markExpired()) return true;
    if (event) event.preventDefault();
    return false;
  }

  function scheduleExpiry() {
    if (!Number.isFinite(expiresAt) || expiresAt <= 0) return;
    const delay = expiresAt - Date.now();
    if (delay <= 0) {
      markExpired();
      return;
    }
    window.setTimeout(markExpired, delay);
  }

  async function verifyWebAuthn() {
    const button = document.getElementById('webauthn-verify-button');
    if (!button || !requireActive()) return;
    try {
      button.disabled = true;
      clearStatus();
      const begin = await fetch('/api/step-up/webauthn/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ challenge_id: challengeID }),
      });
      if (!begin.ok) throw new Error('passkey verification failed');
      if (!requireActive()) return;
      const options = await begin.json();
      const credential = await navigator.credentials.get({ publicKey: prepareRequestOptions(options) });
      if (!requireActive()) return;
      const finish = await fetch('/api/step-up/webauthn/finish?challenge_id=' + encodeURIComponent(challengeID), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify(credentialToJSON(credential)),
      });
      if (!finish.ok) throw new Error('passkey verification failed');
      clearStatus();
      window.location.href = '/verify/' + encodeURIComponent(challengeID) + '?completed=1';
    } catch (_) {
      if (markExpired()) return;
      showError('Passkey verification failed. Try again.');
      if (button) button.disabled = false;
    }
  }

  async function registerWebAuthn() {
    const button = document.getElementById('webauthn-register-button');
    if (!button || !requireActive()) return;
    try {
      button.disabled = true;
      clearStatus();
      const begin = await fetch('/api/step-up/webauthn/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ challenge_id: challengeID }),
      });
      if (!begin.ok) throw new Error('passkey setup failed');
      if (!requireActive()) return;
      const options = await begin.json();
      const credential = await navigator.credentials.create({ publicKey: prepareCreationOptions(options) });
      if (!requireActive()) return;
      const finish = await fetch('/api/step-up/webauthn/register/finish?challenge_id=' + encodeURIComponent(challengeID), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify(credentialToJSON(credential)),
      });
      if (!finish.ok) throw new Error('passkey setup failed');
      const result = await finish.json().catch(() => ({}));
      clearStatus();
      if (showRecoveryCodes(result.recovery_codes)) return;
      window.location.href = '/verify/' + encodeURIComponent(challengeID) + '?completed=1';
    } catch (_) {
      if (markExpired()) return;
      showError('Passkey setup failed. Try again.');
      if (button) button.disabled = false;
    }
  }

  setupOTPInputs();
  root.querySelectorAll('form').forEach((form) => {
    form.addEventListener('submit', requireActive);
  });
  root.querySelectorAll('a.method-link,a.button-link').forEach((link) => {
    link.addEventListener('click', requireActive);
  });
  scheduleExpiry();

  const verifyButton = document.getElementById('webauthn-verify-button');
  if (verifyButton) verifyButton.addEventListener('click', verifyWebAuthn);
  const registerButton = document.getElementById('webauthn-register-button');
  if (registerButton) registerButton.addEventListener('click', registerWebAuthn);
})();
`

func (s *Server) handleStepUpBrowserAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	setNoStoreHeaders(w)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write([]byte(stepUpBrowserJS))
}
