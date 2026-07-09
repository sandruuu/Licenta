export function b64urlToBuffer(value) {
  const pad = '='.repeat((4 - (value.length % 4)) % 4);
  const b64 = (value + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = window.atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let index = 0; index < bin.length; index += 1) bytes[index] = bin.charCodeAt(index);
  return bytes.buffer;
}

export function bufferToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = '';
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return window.btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function mapCredentialList(list) {
  return (list || []).map((credential) => ({ ...credential, id: b64urlToBuffer(credential.id) }));
}

export function prepareCreationOptions(options) {
  const publicKey = options.publicKey || options;
  publicKey.challenge = b64urlToBuffer(publicKey.challenge);
  if (publicKey.user && typeof publicKey.user.id === 'string') publicKey.user.id = b64urlToBuffer(publicKey.user.id);
  if (publicKey.excludeCredentials) publicKey.excludeCredentials = mapCredentialList(publicKey.excludeCredentials);
  return publicKey;
}

export function prepareRequestOptions(options) {
  const publicKey = options.publicKey || options;
  publicKey.challenge = b64urlToBuffer(publicKey.challenge);
  if (publicKey.allowCredentials) publicKey.allowCredentials = mapCredentialList(publicKey.allowCredentials);
  return publicKey;
}

export function credentialToJSON(credential) {
  const response = { clientDataJSON: bufferToB64url(credential.response.clientDataJSON) };
  if (credential.response.attestationObject) response.attestationObject = bufferToB64url(credential.response.attestationObject);
  if (credential.response.authenticatorData) response.authenticatorData = bufferToB64url(credential.response.authenticatorData);
  if (credential.response.signature) response.signature = bufferToB64url(credential.response.signature);
  if (credential.response.userHandle) response.userHandle = bufferToB64url(credential.response.userHandle);
  if (credential.response.getTransports) response.transports = credential.response.getTransports();
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    response,
    clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
  };
}
