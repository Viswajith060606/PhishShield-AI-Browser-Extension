export function predictPhishingRisk(features) {
  let score = 0.0;
  const threatReasons = [];

  if (features.typosquatting_info && features.typosquatting_info.isTyposquatted) {
    score += 3.5;
    threatReasons.push(`Typosquatting brand impersonation detected (Impersonating brand '${features.typosquatting_info.targetBrand}')`);
  }

  if (features.is_ip_address) {
    score += 3.5;
    threatReasons.push("Raw IP address host usage (bypasses domain registration)");
  }

  if (features.is_punycode) {
    score += 3.2;
    threatReasons.push("Punycode domain obfuscation detected (internationalized domain spoofing)");
  }

  if (features.has_at) {
    score += 2.5;
    threatReasons.push("URL contains '@' redirection symbol to obscure destination host");
  }

  if (features.has_double_slash_path) {
    score += 2.2;
    threatReasons.push("URL contains '//' path redirection sequence");
  }

  if (features.is_high_risk_tld && features.suspicious_keywords_count >= 1) {
    score += 2.2;
    threatReasons.push("High-risk TLD combined with sensitive brand keywords");
  }

  if (features.suspicious_keywords_count >= 3) {
    score += 2.2;
    threatReasons.push(`High density of sensitive phishing keywords in URL (${features.suspicious_keywords_count})`);
  } else if (features.suspicious_keywords_count >= 1) {
    score += 1.2;
    threatReasons.push(`Sensitive phishing keyword present in URL (${features.suspicious_keywords_count})`);
  }

  if (!features.is_https) {
    score += 1.2;
    threatReasons.push("Unencrypted HTTP connection");
  }

  if (features.hyphen_count >= 2 && features.suspicious_keywords_count >= 1) {
    score += 1.5;
    threatReasons.push("Hyphenated domain structure matching brand impersonation patterns");
  }

  if (features.subdomain_count >= 4) {
    score += 1.5;
    threatReasons.push(`Excessive subdomains count (${features.subdomain_count}) mimicking brand domains`);
  }

  if (features.dot_count >= 4) {
    score += 1.0;
    threatReasons.push(`Unusual dot count (${features.dot_count}) in URL structure`);
  }

  if (features.url_length >= 50) {
    score += 0.8;
    threatReasons.push(`Suspiciously long URL string (${features.url_length} characters)`);
  }

  if (features.domain_age_days !== undefined && features.domain_age_days >= 0 && features.domain_age_days < 30) {
    score += 2.2;
    threatReasons.push(`Newly Registered Domain (NRD) registered only ${features.domain_age_days} days ago`);
  }

  // Sigmoid probability mapping: 1 / (1 + exp(-(score - 2.0)))
  const bias = 2.0;
  const probability = 1.0 / (1.0 + Math.exp(-(score - bias)));
  const roundedProb = Math.round(probability * 10000) / 10000;

  return {
    phishingProbability: roundedProb,
    threatReasons: threatReasons
  };
}
