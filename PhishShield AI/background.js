// Standalone Extension Service Worker Background Script

import { extractFeatures } from "./featureExtractor.js";
import { checkPhishTank } from "./threatIntel.js";
import { predictPhishingRisk } from "./mlEngine.js";
import { analyzeWithGemini } from "./geminiClient.js";
import { getDomainAgeInfo } from "./whoisIntel.js";

const analysisCache = new Map();

function isAnalyzableUrl(url) {
  if (!url) return false;
  return url.startsWith("http://") || url.startsWith("https://");
}

function updateBadge(tabId, verdict) {
  let badgeText = "";
  let badgeColor = "#64748B";

  if (verdict === "Safe") {
    badgeText = "SAFE";
    badgeColor = "#10B981";
  } else if (verdict === "Suspicious") {
    badgeText = "WARN";
    badgeColor = "#F59E0B";
  } else if (verdict === "Malicious") {
    badgeText = "ALERT";
    badgeColor = "#EF4444";
  }

  chrome.action.setBadgeText({ tabId, text: badgeText });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
}

/**
 * Core Standalone Phishing Detection Pipeline with Strict Timeout Races
 */
async function analyzeUrlStandalone(tabId, url) {
  if (!isAnalyzableUrl(url)) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return null;
  }

  // 1. Extract structural features client-side (< 2ms)
  const features = extractFeatures(url);

  // 1b. Fetch Domain WHOIS / RDAP Creation Age
  const domainAgeInfo = await Promise.race([
    getDomainAgeInfo(features.domain),
    new Promise((resolve) => setTimeout(() => resolve({ domainAgeDays: -1 }), 800))
  ]);
  features.domain_age_days = domainAgeInfo.domainAgeDays;
  features.creation_date = domainAgeInfo.creationDate;

  // Read custom rules & settings with 500ms race timeout
  const settings = await Promise.race([
    new Promise((resolve) => {
      chrome.storage.local.get(["customWhitelist", "customBlacklist", "enablePhishTank", "geminiApiKey"], (res) => resolve(res || {}));
    }),
    new Promise((resolve) => setTimeout(() => resolve({}), 500))
  ]);

  const customWhitelist = settings.customWhitelist || [];
  const customBlacklist = settings.customBlacklist || [];
  const domainLower = features.domain.toLowerCase();

  // Custom Blacklist Check
  if (customBlacklist.some((d) => d && domainLower.endsWith(d))) {
    const customMalicious = {
      url: url,
      verdict: "Malicious",
      confidence: 1.0,
      ml_probability: 1.0,
      decision_source: "Custom User Blacklist",
      threat_reasons: ["Domain is explicitly listed on your custom blocked blacklist"],
      user_explanation: "WARNING: This domain has been blocked according to your custom settings.",
      features: features
    };
    cacheAndNotify(tabId, url, customMalicious);
    return customMalicious;
  }

  // Custom Whitelist Check
  if (customWhitelist.some((d) => d && domainLower.endsWith(d))) {
    const customSafe = {
      url: url,
      verdict: "Safe",
      confidence: 1.0,
      ml_probability: 0.0001,
      decision_source: "Custom User Whitelist",
      threat_reasons: [],
      user_explanation: "This domain is explicitly trusted according to your custom whitelist.",
      features: features
    };
    cacheAndNotify(tabId, url, customSafe);
    return customSafe;
  }

  // Pipeline Step 0: High-Trust Verified Domain Safeguard
  if (
    features.is_trusted_domain &&
    !features.is_punycode &&
    !features.is_ip_address &&
    !features.has_at &&
    !features.has_double_slash_path
  ) {
    const safeResult = {
      url: url,
      verdict: "Safe",
      confidence: 1.0,
      ml_probability: 0.0001,
      decision_source: "Verified Domain Safeguard",
      threat_reasons: [],
      user_explanation: "This website belongs to a verified legitimate service.",
      features: features
    };
    cacheAndNotify(tabId, url, safeResult);
    return safeResult;
  }

  // Ask content script for DOM context snapshot (800ms race)
  let domContext = {};
  if (tabId) {
    try {
      domContext = await Promise.race([
        new Promise((resolve) => {
          chrome.tabs.sendMessage(tabId, { action: "get_dom_context" }, (res) => {
            if (chrome.runtime.lastError || !res) resolve({});
            else resolve(res);
          });
        }),
        new Promise((resolve) => setTimeout(() => resolve({}), 800))
      ]);
    } catch (e) {
      domContext = {};
    }
  }

  // Pipeline Step 1: PhishTank Threat Intelligence API Lookup (1000ms race)
  const enablePhishTank = settings.enablePhishTank !== false;
  if (enablePhishTank) {
    try {
      const ptResult = await Promise.race([
        checkPhishTank(url),
        new Promise((resolve) => setTimeout(() => resolve({ inDatabase: false, isPhish: false }), 1000))
      ]);
      if (ptResult && ptResult.isPhish) {
        const phishTankResult = {
          url: url,
          verdict: "Malicious",
          confidence: 1.0,
          ml_probability: 1.0,
          decision_source: "PhishTank Threat Intelligence API",
          threat_reasons: [
            "Verified match in global PhishTank phishing database",
            "Confirmed malicious credential harvesting target"
          ],
          user_explanation: "ALERT: This URL is listed in the official PhishTank database as an active phishing website. Do not enter credentials.",
          features: features
        };
        cacheAndNotify(tabId, url, phishTankResult);
        return phishTankResult;
      }
    } catch (e) {}
  }

  // Pipeline Step 2: Client ML Feature Classifier Engine
  const mlResult = predictPhishingRisk(features);
  const prob = mlResult.phishingProbability;

  // Case A: High Confidence Malicious (prob >= 0.70)
  if (prob >= 0.70) {
    const malResult = {
      url: url,
      verdict: "Malicious",
      confidence: Math.round(prob * 100) / 100,
      ml_probability: prob,
      decision_source: "Standalone Client ML Engine",
      threat_reasons: mlResult.threatReasons,
      user_explanation: "Warning: High-risk phishing structural patterns detected on this URL.",
      features: features
    };
    cacheAndNotify(tabId, url, malResult);
    return malResult;
  }

  // Case B: High Confidence Safe (prob < 0.20)
  if (prob < 0.20) {
    const safeResult = {
      url: url,
      verdict: "Safe",
      confidence: Math.round((1.0 - prob) * 100) / 100,
      ml_probability: prob,
      decision_source: "Standalone Client ML Engine",
      threat_reasons: [],
      user_explanation: "This URL displays normal structural metrics.",
      features: features
    };
    cacheAndNotify(tabId, url, safeResult);
    return safeResult;
  }

  // Case C: Borderline (0.20 <= prob < 0.70) -> Call Gemini API if Key available (2500ms race)
  const apiKey = settings.geminiApiKey || "";
  let geminiResult = null;
  if (apiKey) {
    let imageBase64 = null;
    if (tabId) {
      try {
        const tab = await chrome.tabs.get(tabId);
        if (tab && tab.windowId) {
          imageBase64 = await new Promise((resolve) => {
            chrome.tabs.captureVisibleTab(tab.windowId, { format: "jpeg", quality: 40 }, (dataUrl) => {
              if (chrome.runtime.lastError || !dataUrl) resolve(null);
              else resolve(dataUrl);
            });
          });
        }
      } catch (e) {}
    }

    try {
      geminiResult = await Promise.race([
        analyzeWithGemini(apiKey, url, prob, features, domContext, imageBase64),
        new Promise((resolve) => setTimeout(() => resolve(null), 2500))
      ]);
    } catch (e) {}
  }

  if (!geminiResult) {
    geminiResult = {
      verdict: prob >= 0.45 ? "Suspicious" : "Safe",
      confidence: Math.round(prob * 100) / 100,
      threat_reasons: mlResult.threatReasons,
      user_explanation: apiKey ? "Site evaluated by Local Engine (AI query timed out)." : "Site evaluated by Local Engine."
    };
  }

  const finalResult = {
    url: url,
    verdict: geminiResult.verdict,
    confidence: geminiResult.confidence,
    ml_probability: prob,
    decision_source: apiKey ? "Google Gemini LLM REST API" : "Standalone Client Engine",
    threat_reasons: geminiResult.threat_reasons,
    user_explanation: geminiResult.user_explanation,
    features: features
  };

  cacheAndNotify(tabId, url, finalResult);
  return finalResult;
}

function cacheAndNotify(tabId, url, resultData) {
  analysisCache.set(url, resultData);
  chrome.storage.local.set({ [url]: resultData });

  if (tabId) {
    updateBadge(tabId, resultData.verdict);

    if (resultData.verdict === "Malicious") {
      chrome.tabs.sendMessage(tabId, {
        action: "show_security_alert",
        data: resultData
      }, () => {
        if (chrome.runtime.lastError) { /* silent */ }
      });
    }
  }
}

// Navigation event listeners
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    analyzeUrlStandalone(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && isAnalyzableUrl(tab.url)) {
      const cached = analysisCache.get(tab.url);
      if (cached) {
        updateBadge(tab.id, cached.verdict);
      } else {
        analyzeUrlStandalone(tab.id, tab.url);
      }
    }
  } catch (e) {}
});

// Messages from popup.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyze_custom_url") {
    let rawUrl = (request.url || "").trim();
    if (rawUrl && !rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) {
      rawUrl = "http://" + rawUrl;
    }
    analyzeUrlStandalone(null, rawUrl).then((result) => {
      sendResponse({ success: true, data: result });
    }).catch((err) => {
      sendResponse({ success: false, error: err.message });
    });
    return true;
  }

  if (request.action === "analyze_current_tab") {
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs.length > 0 && tabs[0].url) {
        const activeTab = tabs[0];
        const result = await analyzeUrlStandalone(activeTab.id, activeTab.url);
        sendResponse({ success: true, data: result });
      } else {
        sendResponse({ success: false, error: "No active URL found" });
      }
    });
    return true;
  }

  if (request.action === "get_cached_analysis") {
    const url = request.url;
    if (analysisCache.has(url)) {
      sendResponse({ data: analysisCache.get(url) });
    } else {
      chrome.storage.local.get([url], (res) => {
        sendResponse({ data: res[url] || null });
      });
    }
    return true;
  }
});
