export function flagEmoji(cc?: string): string {
  if (!cc) return "";
  const code = cc.toUpperCase();
  return code.replace(/./g, c => String.fromCodePoint(127397 + c.charCodeAt(0)));
}
