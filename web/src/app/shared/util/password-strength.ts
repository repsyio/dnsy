export interface Strength {
  /** 0 (too short) to 4. */
  score: number;
  label: string;
  hints: string[];
}

export const MIN_PASSWORD = 8;

const LABELS = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong'];

/** Local, advisory strength estimate; the server only enforces the minimum length. */
export function passwordStrength(pw: string): Strength {
  const hints: string[] = [];
  if (pw.length < MIN_PASSWORD) hints.push(`Use at least ${MIN_PASSWORD} characters.`);
  if (pw.length < 12) hints.push('12 or more characters is better.');
  if (!(/[a-z]/.test(pw) && /[A-Z]/.test(pw))) hints.push('Mix upper and lower case letters.');
  if (!/\d/.test(pw)) hints.push('Add a digit.');
  if (!/[^A-Za-z0-9]/.test(pw)) hints.push('Add a symbol.');
  if (pw.length < MIN_PASSWORD) return { score: 0, label: LABELS[0], hints };
  let score = 1;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return { score, label: LABELS[score], hints };
}
