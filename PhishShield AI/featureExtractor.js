import { detectTyposquatting } from "./typosquattingEngine.js";

const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "bank", "secure", "account", "update", "paypal",
  "signin", "webscr", "cmd", "admin", "credential", "billing", "confirm",
  "password", "auth", "security", "wallet", "token", "service", "support", "amazon"
];

const TRUSTED_DOMAINS = new Set([
  "google.com", "gmail.com", "youtube.com", "github.com", "microsoft.com",
  "apple.com", "amazon.com", "wikipedia.org", "openai.com", "linkedin.com",
  "twitter.com", "x.com", "facebook.com", "instagram.com", "netflix.com",
  "cloudflare.com", "stackoverflow.com", "reddit.com", "yahoo.com", "bing.com",
  "gstatic.com", "googleusercontent.com"
]);

const HIGH_RISK_TLDS = new Set([
  "xyz", "top", "site", "online", "work", "click", "link", "club",
  "info", "live", "space", "monster", "buzz", "tech", "download",
  "support", "security", "vip", "casa", "icu"
]);

/**
 * Extracts domain and TLD from hostname
 */
function extractDomainInfo(hostname) {
  const cleanHost = hostname.toLowerCase().split(":")[0];
  const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(cleanHost);
  if (isIp) {
    return { domain: cleanHost, subdomain: "", subdomainCount: 0 };
  }

  const parts = cleanHost.split(".");
  if (parts.length <= 2) {
    return { domain: parts.join("."), subdomain: "", subdomainCount: 0 };
  }

  // Handle common 2-part TLDs like co.uk, com.au
  const twoPartTlds = ["co.uk", "com.au", "co.in", "com.br", "co.jp"];
  const lastTwo = parts.slice(-2).join(".");
  
  if (twoPartTlds.includes(lastTwo) && parts.length >= 3) {
    const domain = parts.slice(-3).join(".");
    const sub = parts.slice(0, -3).join(".");
    return { domain, subdomain: sub, subdomainCount: parts.length - 3 };
  }

  const domain = parts.slice(-2).join(".");
  const sub = parts.slice(0, -2).join(".");
  return { domain, subdomain: sub, subdomainCount: parts.length - 2 };
}

/**
 * Extracts structural & lexical feature dict from a given URL
 */
export function extractFeatures(urlStr) {
  let urlObj;
  try {
    urlObj = new URL(urlStr.startsWith("http") ? urlStr : "http://" + urlStr);
  } catch (e) {
    urlObj = { hostname: "", pathname: "", search: "", protocol: "http:" };
  }

  const fullUrl = urlStr;
  const hostname = urlObj.hostname || "";
  const pathAndQuery = (urlObj.pathname || "") + (urlObj.search || "");

  const domainInfo = extractDomainInfo(hostname);
  const domain = domainInfo.domain;

  const urlLength = fullUrl.length;
  const dotCount = (fullUrl.match(/\./g) || []).length;
  const hyphenCount = (fullUrl.match(/-/g) || []).length;
  const hasAt = fullUrl.includes("@");
  const hasDoubleSlashPath = pathAndQuery.includes("//");

  const isIpAddress = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
  const isPunycode = hostname.toLowerCase().includes("xn--");
  const isHttps = urlObj.protocol === "https:";

  const urlLower = fullUrl.toLowerCase();
  let suspiciousKeywordsCount = 0;
  SUSPICIOUS_KEYWORDS.forEach((kw) => {
    if (urlLower.includes(kw)) suspiciousKeywordsCount++;
  });

  const isTrustedDomain = TRUSTED_DOMAINS.has(domain.toLowerCase());

  const domainParts = domain.split(".");
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : "";
  const isHighRiskTld = HIGH_RISK_TLDS.has(tld.toLowerCase());

  const typoInfo = detectTyposquatting(domain);

  return {
    url: fullUrl,
    domain: domain,
    subdomain: domainInfo.subdomain,
    subdomain_count: domainInfo.subdomainCount,
    is_trusted_domain: isTrustedDomain,
    is_high_risk_tld: isHighRiskTld,
    typosquatting_info: typoInfo,
    url_length: urlLength,
    dot_count: dotCount,
    hyphen_count: hyphenCount,
    has_at: hasAt,
    has_double_slash_path: hasDoubleSlashPath,
    is_ip_address: isIpAddress,
    is_punycode: isPunycode,
    is_https: isHttps,
    suspicious_keywords_count: suspiciousKeywordsCount,
    domain_length: domain.length
  };
}
