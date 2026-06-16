export function copyText(text) {
  if (!text) return;
  navigator.clipboard.writeText(text).catch(() => {});
}
