// Standalone WHOIS & RDAP Domain Age Intelligence Module

const RDAP_ENDPOINT = "https://rdap.org/domain/";
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days cache

/**
 * Checks Domain Registration Age via RDAP API lookup
 */
export async function getDomainAgeInfo(domain) {
  if (!domain || domain.includes(":") || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
    return { domainAgeDays: -1, isNewlyRegistered: false, creationDate: null };
  }

  const domainClean = domain.toLowerCase().trim();
  const cacheKey = `rdap_cache_${domainClean}`;

  // Check Chrome local storage cache
  try {
    const cached = await new Promise((resolve) => {
      chrome.storage.local.get([cacheKey], (res) => resolve(res[cacheKey]));
    });

    if (cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
      return cached.data;
    }
  } catch (e) {}

  try {
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), 2000) : null;

    const fetchOptions = { method: "GET" };
    if (controller) fetchOptions.signal = controller.signal;

    const response = await fetch(`${RDAP_ENDPOINT}${domainClean}`, fetchOptions);
    if (timeoutId) clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      const events = data.events || [];
      const registrationEvent = events.find(
        (e) => e.eventAction === "registration" || e.eventAction === "created" || e.eventAction === "create"
      );

      if (registrationEvent && registrationEvent.eventDate) {
        const createDate = new Date(registrationEvent.eventDate);
        const now = new Date();
        const diffMs = now.getTime() - createDate.getTime();
        const ageDays = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));

        const resultObj = {
          domainAgeDays: ageDays,
          isNewlyRegistered: ageDays < 30,
          creationDate: createDate.toISOString().split("T")[0]
        };

        chrome.storage.local.set({
          [cacheKey]: { timestamp: Date.now(), data: resultObj }
        });

        return resultObj;
      }
    }
  } catch (e) {
    // Timeout or network fallback
  }

  return { domainAgeDays: -1, isNewlyRegistered: false, creationDate: null };
}
