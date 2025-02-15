export function isUrlEncoded(str: string): boolean {
  const pattern = /%[0-9A-F]{2}/i;
  return pattern.test(str);
}
