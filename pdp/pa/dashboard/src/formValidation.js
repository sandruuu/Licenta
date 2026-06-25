export function isBlank(value) {
  return String(value ?? '').trim() === '';
}

export function requiredFieldsMessage(fields) {
  const requiredFields = fields.filter(Boolean);
  if (requiredFields.length === 1) return `${requiredFields[0]} is required.`;
  return `Complete the required fields: ${requiredFields.join(', ')}.`;
}
