import bcrypt from 'bcryptjs';

export const hashPassword = (plain: string) => bcrypt.hash(plain, 12);
export const verifyPassword = (plain: string, hash: string) => bcrypt.compare(plain, hash);

const HISTORY_DEPTH = 4;

// True if `plain` matches the current password hash or any of the last
// HISTORY_DEPTH-1 previous hashes (PCI DSS 8.3.7 — no reuse of last 4 passwords).
export async function matchesPasswordHistory(plain: string, currentHash: string, history: string[]): Promise<boolean> {
  if (await verifyPassword(plain, currentHash)) return true;
  for (const oldHash of history.slice(0, HISTORY_DEPTH - 1)) {
    if (await verifyPassword(plain, oldHash)) return true;
  }
  return false;
}

// Push the outgoing hash onto the history, capped at HISTORY_DEPTH-1 entries.
export function pushPasswordHistory(outgoingHash: string, history: string[]): string[] {
  return [outgoingHash, ...history].slice(0, HISTORY_DEPTH - 1);
}
