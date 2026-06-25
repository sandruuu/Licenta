const MIN_PASSWORD_LENGTH = 15;
const MAX_PASSWORD_LENGTH = 256;

const COMMON_PASSWORDS = new Set([
  '123456789',
  '1234567890',
  '123456789012345',
  '111111111111111',
  'aaaaaaaaaaaaaaa',
  'administrator',
  'adminadminadmin',
  'letmeinletmein',
  'passwordpassword',
  'passwordpassword1',
  'qwertyqwerty',
  'trustcloud',
  'trustcloudtrust',
  'trustcloud2026',
  'trust-cloud',
  'trust cloud',
]);

export const passwordPolicyRequirements = [
  'Use at least 15 characters.',
  'Use at most 256 characters.',
  'Do not use common, predictable, or repetitive passwords.',
  'Do not use account information such as the username or email address.',
];

function normalize(value = '') {
  return String(value).normalize('NFC');
}

function policyKey(value = '') {
  return normalize(value).trim().toLowerCase();
}

function passwordLength(value = '') {
  return [...normalize(value)].length;
}

function isSingleRepeatedCharacter(value) {
  const chars = [...value];
  return chars.length > 1 && chars.every((char) => char === chars[0]);
}

function accountValues(account = {}) {
  const values = [account.email, account.username, account.id, account.organizationId].filter(Boolean);
  for (const value of [account.email, account.username]) {
    const [localPart] = String(value || '').split('@');
    if (localPart) values.push(localPart);
  }
  return values;
}

export function getPasswordPolicyIssues(password, options = {}) {
  const issues = [];
  const normalized = normalize(password);
  const key = policyKey(normalized);
  const length = passwordLength(normalized);

  if (!normalized) {
    issues.push('Enter the new password.');
  } else {
    if (length < MIN_PASSWORD_LENGTH) {
      issues.push(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
    }
    if (length > MAX_PASSWORD_LENGTH) {
      issues.push(`Use at most ${MAX_PASSWORD_LENGTH} characters.`);
    }
    if (COMMON_PASSWORDS.has(key) || isSingleRepeatedCharacter(key)) {
      issues.push('Use a password that is not common, predictable, or repetitive.');
    }
    if (accountValues(options.account).some((value) => key && key === policyKey(value))) {
      issues.push('Do not use your email address, username, or account identifiers.');
    }
    if (options.currentPassword && normalized === normalize(options.currentPassword)) {
      issues.push('Use a password different from the current password.');
    }
  }

  if (options.checkConfirmation && normalized !== normalize(options.confirmPassword)) {
    issues.push('The confirmation must match the new password.');
  }

  return [...new Set(issues)];
}

export function formatPasswordPolicyError(err, fallback = 'Password could not be changed') {
  const message = err?.message || '';
  const details = Array.isArray(err?.details) ? err.details : [];
  const lower = message.toLowerCase();

  if (lower.includes('at least')) {
    return { message: 'The password is too short.', details: details.length ? details : passwordPolicyRequirements };
  }
  if (lower.includes('at most')) {
    return { message: 'The password is too long.', details: details.length ? details : passwordPolicyRequirements };
  }
  if (lower.includes('common') || lower.includes('predictable') || lower.includes('repeated') || lower.includes('service name')) {
    return { message: 'The password is too easy to guess.', details: details.length ? details : passwordPolicyRequirements };
  }
  if (lower.includes('account information')) {
    return { message: 'The password is based on account information.', details: details.length ? details : passwordPolicyRequirements };
  }
  if (lower.includes('temporary password')) {
    return { message: 'Use a password different from the temporary password.', details };
  }
  if (lower.includes('current password') && lower.includes('different')) {
    return { message: 'Use a password different from the current password.', details };
  }
  if (lower.includes('confirmation')) {
    return { message: 'The confirmation must match the new password.', details };
  }

  return { message: message || fallback, details };
}
