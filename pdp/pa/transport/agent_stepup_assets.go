package transport

import "net/http"

const stepUpBrowserJS = `
(() => {
  const root = document.getElementById('stepup-root');
  if (!root) return;
  const challengeID = root.dataset.challengeId || '';
  const csrfToken = root.dataset.csrfToken || '';
  const status = document.getElementById('webauthn-status');
  const alertIcon = '<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>';

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
    if (status) status.innerHTML = '';
  }

  function showError(message) {
    if (!status) return;
    status.innerHTML = '<div class="page-alert stepup-alert" role="alert">' + alertIcon + '<span>' + escapeHTML(message) + '</span></div>';
  }

  async function verifyWebAuthn() {
    const button = document.getElementById('webauthn-verify-button');
    try {
      button.disabled = true;
      clearStatus();
      const begin = await fetch('/api/step-up/webauthn/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ challenge_id: challengeID }),
      });
      if (!begin.ok) throw new Error('passkey verification failed');
      const options = await begin.json();
      const credential = await navigator.credentials.get({ publicKey: prepareRequestOptions(options) });
      const finish = await fetch('/api/step-up/webauthn/finish?challenge_id=' + encodeURIComponent(challengeID), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify(credentialToJSON(credential)),
      });
      if (!finish.ok) throw new Error('passkey verification failed');
      clearStatus();
      window.location.href = '/browser/step-up/' + encodeURIComponent(challengeID) + '?completed=1';
    } catch (_) {
      showError('Passkey verification failed. Try again.');
      if (button) button.disabled = false;
    }
  }

  async function registerWebAuthn() {
    const button = document.getElementById('webauthn-register-button');
    try {
      button.disabled = true;
      clearStatus();
      const begin = await fetch('/api/step-up/webauthn/register/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ challenge_id: challengeID }),
      });
      if (!begin.ok) throw new Error('passkey setup failed');
      const options = await begin.json();
      const credential = await navigator.credentials.create({ publicKey: prepareCreationOptions(options) });
      const finish = await fetch('/api/step-up/webauthn/register/finish?challenge_id=' + encodeURIComponent(challengeID), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify(credentialToJSON(credential)),
      });
      if (!finish.ok) throw new Error('passkey setup failed');
      clearStatus();
      window.location.href = '/browser/step-up/' + encodeURIComponent(challengeID) + '?completed=1';
    } catch (_) {
      showError('Passkey setup failed. Try again.');
      if (button) button.disabled = false;
    }
  }

  setupOTPInputs();

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
