// Standalone Typosquatting & Levenshtein Distance Detection Engine

const MONITORED_BRANDS = [
  "paypal.com", "google.com", "amazon.com", "apple.com", "facebook.com",
  "microsoft.com", "netflix.com", "chase.com", "bankofamerica.com",
  "wellsfargo.com", "binance.com", "coinbase.com", "instagram.com",
  "twitter.com", "linkedin.com", "youtube.com", "github.com"
];

/**
 * Computes Levenshtein edit distance between two strings
 */
function levenshteinDistance(s1, s2) {
  const m = s1.length;
  const n = s2.length;
  const dp = Array.from({ length: m + 1 }, () => new Uint8Array(n + 1));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (s1[i - 1] === s2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

/**
 * Detects typosquatting brand spoofing on a target domain
 */
export function detectTyposquatting(domain) {
  if (!domain) return { isTyposquatted: false };

  const domainClean = domain.toLowerCase().trim();
  const domainCore = domainClean.split(".")[0];

  // Common visual character replacements (e.g. paypa1 -> paypal, goog1e -> google)
  const normalizedCore = domainCore
    .replace(/1/g, "l")
    .replace(/0/g, "o")
    .replace(/5/g, "s")
    .replace(/rn/g, "m")
    .replace(/vv/g, "w");

  for (const targetBrand of MONITORED_BRANDS) {
    if (domainClean === targetBrand) {
      return { isTyposquatted: false, isExactMatch: true };
    }

    const brandCore = targetBrand.split(".")[0];

    // Skip if domain core is identical to brand core
    if (domainCore === brandCore) continue;

    // Check Levenshtein distance on raw core and normalized core
    const rawDist = levenshteinDistance(domainCore, brandCore);
    const normDist = levenshteinDistance(normalizedCore, brandCore);
    const minDist = Math.min(rawDist, normDist);

    // If edit distance is 1 or 2 on strings >= 4 chars, flag typosquatting
    if (brandCore.length >= 4 && minDist >= 1 && minDist <= 2) {
      return {
        isTyposquatted: true,
        targetBrand: targetBrand,
        editDistance: minDist
      };
    }
  }

  return { isTyposquatted: false };
}
