// Master-password policy, shared by every client. The master password is the sole
// protection for the vault (and, in the offline desktop app, the only thing
// standing between a stolen .passwd file and its contents), so a weak one is the
// dominant risk against offline brute force. This favors length: a short
// passphrase clears the bar, while short strings must at least mix character types.

export const MIN_MASTER_PASSWORD_LENGTH = 12;

// Returns a human-readable reason the password is too weak, or null if acceptable.
export function masterPasswordIssue(password: string): string | null {
  if (password.length < MIN_MASTER_PASSWORD_LENGTH) {
    return `Use at least ${MIN_MASTER_PASSWORD_LENGTH} characters (a short passphrase works well).`;
  }
  // 16+ characters is long enough to be a passphrase; accept it as-is.
  if (password.length >= 16) return null;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (classes < 2) {
    return "Mix in another character type, or use a longer passphrase.";
  }
  return null;
}
