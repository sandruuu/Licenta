import { apiJSON, base64urlToBuffer, bufferToBase64url } from './loginUtils';

export async function authenticateWithWebAuthn(token) {
  const options = await apiJSON('/api/mfa/webauthn/authenticate/begin', {
    method: 'POST',
    body: JSON.stringify({ mfa_token: token }),
  });

  options.publicKey.challenge = base64urlToBuffer(options.publicKey.challenge);
  if (options.publicKey.allowCredentials) {
    options.publicKey.allowCredentials = options.publicKey.allowCredentials.map((credential) => ({
      ...credential,
      id: base64urlToBuffer(credential.id),
    }));
  }

  const assertion = await navigator.credentials.get({ publicKey: options.publicKey });
  const assertionJSON = JSON.stringify({
    id: assertion.id,
    rawId: bufferToBase64url(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
      clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
      signature: bufferToBase64url(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : '',
    },
  });

  return apiJSON(`/api/mfa/webauthn/authenticate/finish?mfa_token=${encodeURIComponent(token)}`, {
    method: 'POST',
    body: assertionJSON,
  });
}
