/** Copy text to the clipboard; false when the browser refuses. */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** DoH URL form for a token, or the placeholder form when no token is given. */
export function dohUrl(host: string, token = '<token>'): string {
  return `https://${host}/dns-query/${token}`;
}
