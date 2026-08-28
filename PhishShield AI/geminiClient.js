// Direct REST API client for Google Gemini LLM Structured Analysis

const GEMINI_REST_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent";
const GEMINI_FALLBACK_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.0-flash:generateContent";

/**
 * Analyzes URL and DOM context directly via Google Gemini REST API
 */
export async function analyzeWithGemini(apiKey, url, mlProbability, features, domContext = {}, imageBase64 = null) {
  if (!apiKey) {
    return _fallbackRuleAnalysis(url, mlProbability, features, domContext, "Gemini API key not configured");
  }

  const prompt = `
You are an expert Cybersecurity Phishing Analyst. Evaluate the following website for phishing threats.

Target URL: ${url}
ML Phishing Probability: ${mlProbability}

Extracted Features:
${JSON.stringify(features, null, 2)}

DOM Context Scraped from Browser:
${JSON.stringify(domContext || {}, null, 2)}

Perform a comprehensive security audit by analyzing:
1. Domain legitimacy & brand impersonation (e.g. typosquatting, subdomains, punycode).
2. Visual layout analysis of tab screenshot (if attached): Detect visual brand cloning, fake login forms, or logo spoofing versus actual host domain.
3. DOM Context anomalies (e.g. login form submitting to external domain, HTTP form submission, password inputs on non-standard domains).
4. Lexical structure of the URL.

Return your analysis adhering strictly to the JSON schema.
`;

  const parts = [{ text: prompt }];

  if (imageBase64) {
    const rawData = imageBase64.includes("base64,") ? imageBase64.split("base64,")[1] : imageBase64;
    parts.push({
      inline_data: {
        mime_type: "image/jpeg",
        data: rawData
      }
    });
  }

  const payload = {
    contents: [{ parts: parts }],
    generationConfig: {
      temperature: 0.2,
      response_mime_type: "application/json",
      response_schema: {
        type: "OBJECT",
        properties: {
          verdict: { type: "STRING", enum: ["Safe", "Suspicious", "Malicious"] },
          confidence: { type: "NUMBER" },
          threat_reasons: { type: "ARRAY", items: { type: "STRING" } },
          user_explanation: { type: "STRING" }
        },
        required: ["verdict", "confidence", "threat_reasons", "user_explanation"]
      }
    }
  };

  const endpoints = [
    `${GEMINI_REST_ENDPOINT}?key=${apiKey}`,
    `${GEMINI_FALLBACK_ENDPOINT}?key=${apiKey}`
  ];

  for (const endpoint of endpoints) {
    try {
      const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
      const timeoutId = controller ? setTimeout(() => controller.abort(), 8000) : null;

      const fetchOptions = {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      };
      if (controller) {
        fetchOptions.signal = controller.signal;
      }

      const response = await fetch(endpoint, fetchOptions);
      if (timeoutId) clearTimeout(timeoutId);

      if (response.ok) {
        const jsonRes = await response.json();
        const candidate = jsonRes.candidates && jsonRes.candidates[0];
        if (candidate && candidate.content && candidate.content.parts && candidate.content.parts[0]) {
          const rawText = candidate.content.parts[0].text;
          const parsed = JSON.parse(rawText);
          return {
            verdict: parsed.verdict || "Suspicious",
            confidence: parsed.confidence || 0.8,
            threat_reasons: parsed.threat_reasons || [],
            user_explanation: parsed.user_explanation || "Site evaluated by Gemini AI."
          };
        }
      } else {
        const errText = await response.text();
        console.warn("[PhishShield GeminiClient] API error response:", response.status, errText);
      }
    } catch (e) {
      console.warn("[PhishShield GeminiClient] Endpoint query attempt error:", e);
    }
  }

  return _fallbackRuleAnalysis(url, mlProbability, features, domContext, "Gemini API query failed");
}

function _fallbackRuleAnalysis(url, mlProb, features, domContext = {}, reason = "") {
  const dom = domContext || {};
  const threats = [];

  if (features.is_punycode) {
    threats.push("Punycode domain obfuscation detected");
  }
  if (features.is_ip_address) {
    threats.push("Host is a raw IP address");
  }
  if (features.is_high_risk_tld && features.suspicious_keywords_count >= 1) {
    threats.push("High-risk TLD combined with sensitive brand keywords");
  }
  if (features.suspicious_keywords_count >= 2) {
    threats.push(`High density of sensitive phishing keywords in URL (${features.suspicious_keywords_count})`);
  }
  if (features.hyphen_count >= 2 && features.suspicious_keywords_count >= 1) {
    threats.push("Hyphenated domain structure matching brand impersonation patterns");
  }
  if (!features.is_https) {
    threats.push("Connection lacks HTTPS encryption");
  }
  if (dom.password_fields_count > 0 && !features.is_https) {
    threats.push("Password input detected on insecure HTTP connection");
  }

  let verdict = "Safe";
  if (mlProb >= 0.70 || threats.length >= 2) {
    verdict = "Malicious";
  } else if (mlProb >= 0.30 || threats.length >= 1) {
    verdict = "Suspicious";
  }

  let explanation = "Automated client rule engine analysis.";
  if (reason.includes("not configured")) {
    explanation = "Site evaluated by Local Engine. (Tip: Enter your Gemini API Key in Settings for AI reasoning).";
  } else if (reason.includes("failed")) {
    explanation = "Site evaluated by Local Engine. (Gemini API key or network connection issue).";
  }

  return {
    verdict: verdict,
    confidence: Math.round(mlProb * 100) / 100,
    threat_reasons: threats,
    user_explanation: explanation
  };
}
