// Standalone PhishTank Threat Intelligence API Module

const PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Checks if a URL is registered in PhishTank's verified phishing database.
 */
export async function checkPhishTank(url) {
  if (!url || !url.startsWith("http")) {
    return { inDatabase: false, isPhish: false };
  }

  // 1. Check Chrome local storage cache
  const cacheKey = `pt_cache_${encodeURIComponent(url)}`;
  try {
    const cached = await new Promise((resolve) => {
      chrome.storage.local.get([cacheKey], (res) => resolve(res[cacheKey]));
    });

    if (cached && (Date.now() - cached.timestamp < CACHE_TTL_MS)) {
      return cached.data;
    }
  } catch (e) {
    // Cache read error fallback
  }

  // 2. Query PhishTank API via CORS Fetch
  try {
    const formData = new URLSearchParams();
    formData.append("url", url);
    formData.append("format", "json");
    formData.append("app_key", "phishshield_ai_extension");

    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), 4000) : null;

    const fetchOptions = {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "phishshield-ai/2.0"
      },
      body: formData.toString()
    };
    if (controller) {
      fetchOptions.signal = controller.signal;
    }

    const response = await fetch(PHISHTANK_API_URL, fetchOptions);
    if (timeoutId) clearTimeout(timeoutId);

    if (response.ok) {
      const json = await response.json();
      const resultData = json.results || {};
      const urlInfo = resultData[url] || Object.values(resultData)[0];

      if (urlInfo) {
        const inDatabase = Boolean(urlInfo.in_database);
        const isValidPhish = Boolean(urlInfo.valid);
        const isPhish = inDatabase && isValidPhish;

        const resultObj = {
          inDatabase: inDatabase,
          isPhish: isPhish,
          verifiedBy: isPhish ? "PhishTank Verified Phishing Database" : null,
          phishDetailUrl: urlInfo.phish_detail_page || null,
          phishId: urlInfo.phish_id || null
        };

        // Save to storage cache
        chrome.storage.local.set({
          [cacheKey]: { timestamp: Date.now(), data: resultObj }
        });

        return resultObj;
      }
    }
  } catch (error) {
    console.warn("[PhishShield ThreatIntel] PhishTank API query warning/timeout:", error);
  }

  return { inDatabase: false, isPhish: false };
}
