interface SecurityFactors {
  emailVerified: boolean;
  phoneVerified: boolean;
  twoFaEnabled: boolean;
  walletCount: number;
}

export function calcSecurityScore(f: SecurityFactors): number {
  let score = 0;
  if (f.emailVerified) score += 30;
  if (f.twoFaEnabled) score += 30;
  if (f.phoneVerified) score += 20;
  if (f.walletCount > 0) score += 20;
  return score;
}
